//
// This file is a part of UERANSIM project.
// Copyright (c) 2027 ALI GUNGOR.
//
// Fresh-target eNB bearer bootstrap after an ECM-IDLE inter-eNB cell
// reselection. Two independently created eNB instances are driven through the
// production radio and S1AP paths: the source one holds the UE's established
// session, and the target one has never seen it, so nothing about that session
// is present there until the UE reselects into it and the network answers with
// its own Initial Context Setup Request. The target is never prepared by hand.

#include <ext/doctest/doctest.h>

#include <algorithm>
#include <optional>

#include <lte/enb/codec.hpp>
#include <lte/enb/config.hpp>
#include <lte/enb/multiplexer.hpp>
#include <lte/enb/ue_registry.hpp>
#include <lte/enb/user_plane.hpp>
#include <lte/ue/radio_link.hpp>
#include <lib/udp/server.hpp>

namespace
{
using namespace lte::enb;
using lte::ue::link::BearerInventory;
using lte::ue::link::MessageType;

struct CapturedS1ap
{
    uint16_t stream{};
    std::vector<uint8_t> pdu;
};

class CaptureSender final : public IS1apSender
{
  public:
    void sendS1ap(uint16_t stream, const std::vector<uint8_t> &pdu) override
    {
        sent.push_back(CapturedS1ap{stream, pdu});
    }

    [[nodiscard]] size_t count(uint8_t procedureCode) const
    {
        return count(procedureCode, s1ap::S1apPdu::Kind::INITIATING);
    }

    [[nodiscard]] size_t count(uint8_t procedureCode, s1ap::S1apPdu::Kind kind) const
    {
        size_t total = 0;
        for (const auto &item : sent)
        {
            const auto pdu = s1ap::ProbeS1apPdu(item.pdu.data(), item.pdu.size());
            if (pdu.kind == kind && pdu.procedureCode == procedureCode)
                ++total;
        }
        return total;
    }

    std::vector<CapturedS1ap> sent;
};

// Each eNB gets its own identifier, its own simulated-radio endpoint and its
// own S1-U endpoint. Two eNB instances must never share an S1-U IP/UDP pair.
EnbConfig TestEnbConfig(uint32_t enbId, const std::string &s1uAddress)
{
    EnbConfig config{};
    config.plmn = {"460", "02"};
    config.enbId = enbId;
    config.tac = 1;
    config.localAddress = "127.0.0.1";
    config.mmeAddress = "127.0.0.2";
    config.mmePort = 36412;
    config.ueLinkAddress = "127.0.0.1";
    config.ueLinkPort = 0;
    config.s1uAddress = s1uAddress;
    config.s1uPort = 0;
    config.allowLoopbackS1u = true;
    config.maxUes = 8;
    return config;
}

struct FakeUe
{
    explicit FakeUe(uint32_t id) : ueId(id)
    {
    }
    udp::UdpServer radio{"127.0.0.1", 0};
    uint32_t ueId;
};

void SendRadio(EnbMultiplexer &mux, const FakeUe &ue, MessageType type, std::vector<uint8_t> payload,
               const InetAddress &from)
{
    const auto frame = lte::ue::link::Encode({type, ue.ueId, std::move(payload)});
    mux.handleRadioFrame(frame.data(), frame.size(), from);
}

void SendRadio(EnbMultiplexer &mux, const FakeUe &ue, MessageType type, std::vector<uint8_t> payload)
{
    SendRadio(mux, ue, type, std::move(payload), ue.radio.LocalAddress());
}

// Everything the eNB has sent to this radio endpoint since the last call.
std::vector<lte::ue::link::Message> DrainRadio(FakeUe &ue)
{
    std::vector<lte::ue::link::Message> frames;
    uint8_t buffer[4096];
    InetAddress peer;
    for (;;)
    {
        const int received = ue.radio.Receive(buffer, sizeof(buffer), 10, peer);
        if (received <= 0)
            break;
        frames.push_back(lte::ue::link::Decode(buffer, static_cast<size_t>(received)));
    }
    return frames;
}

size_t CountType(const std::vector<lte::ue::link::Message> &frames, MessageType type)
{
    return static_cast<size_t>(std::count_if(frames.begin(), frames.end(),
                                             [type](const auto &frame) { return frame.type == type; }));
}

bool Contains(const std::vector<uint8_t> &haystack, const std::vector<uint8_t> &needle)
{
    return std::search(haystack.begin(), haystack.end(), needle.begin(), needle.end()) != haystack.end();
}

// MMEC || M-TMSI || protected NAS, the identity prefix of a plain mobility
// uplink.
std::vector<uint8_t> MobilityNas(const std::vector<uint8_t> &nas, uint32_t mTmsi = 0x12345678)
{
    std::vector<uint8_t> payload{0x05,
                                 static_cast<uint8_t>(mTmsi >> 24U), static_cast<uint8_t>(mTmsi >> 16U),
                                 static_cast<uint8_t>(mTmsi >> 8U), static_cast<uint8_t>(mTmsi)};
    payload.insert(payload.end(), nas.begin(), nas.end());
    return payload;
}

// The same uplink, additionally declaring the bearer inventory the UE holds.
std::vector<uint8_t> MobilityContextNas(const BearerInventory &inventory, const std::vector<uint8_t> &nas,
                                        uint32_t mTmsi = 0x12345678)
{
    auto payload = MobilityNas({}, mTmsi);
    const auto declared = lte::ue::link::EncodeBearerInventory(inventory);
    payload.insert(payload.end(), declared.begin(), declared.end());
    payload.insert(payload.end(), nas.begin(), nas.end());
    return payload;
}

const std::vector<uint8_t> ProtectedTauRequest{0x37, 0x01, 0x02, 0x03, 0x04, 0x00, 0x07, 0x48};

// The PDN address the UE's NAS assigned it. The UE restates it on every bearer
// transport confirmation because a cell that never saw the session's Attach
// has no other way of learning it.
std::array<uint8_t, 4> PdnAddress(uint32_t ueId)
{
    return {10, 45, 0, static_cast<uint8_t>(ueId)};
}

s1ap::ErabToBeSetupItem Item(uint8_t ebi, uint8_t qci, uint32_t sgwTeid, bool nasPresent = false,
                             std::vector<uint8_t> nasPdu = {})
{
    s1ap::ErabToBeSetupItem item{};
    item.erabId = ebi;
    item.qci = qci;
    item.transportLayerAddress = {127, 0, 0, 2};
    item.gtpTeid = TeidToBytes(sgwTeid);
    item.nasPduPresent = nasPresent;
    item.nasPdu = std::move(nasPdu);
    return item;
}

// Two eNB instances that share nothing but the UE radio: separate S1AP
// senders, separate UE registries, separate simulated-radio endpoints,
// separate S1-U endpoints and different eNB identifiers.
struct TwoEnb
{
    CaptureSender sourceWire, targetWire;
    EnbMultiplexer source{TestEnbConfig(0x19B, "127.0.0.1"), sourceWire};
    EnbMultiplexer target{TestEnbConfig(0x2C1, "127.0.0.3"), targetWire};
    FakeUe ue{1};
};

// Brings the UE's EPS session up on the source eNB through the production
// paths only: a fresh Attach uplink, a network-authored Initial Context Setup
// Request, the UE's bearer-ready confirmation, and one network-authored E-RAB
// Setup Request per dedicated bearer. Nothing is written into the source
// registry by hand either.
void EstablishOnSource(TwoEnb &lab, const std::vector<uint8_t> &dedicatedEbis,
                       std::vector<uint32_t> *accessTeids = nullptr)
{
    auto &source = lab.source;
    auto &ue = lab.ue;
    SendRadio(source, ue, MessageType::NAS_UPLINK, {0x41, 0x01, 0x02, 0x03});
    auto *entry = source.registry().find(ue.ueId);
    REQUIRE(entry != nullptr);
    REQUIRE(entry->s1 == UeS1State::CONTEXT_PENDING);

    s1ap::InitialContextSetupRequest request{};
    request.mmeUeS1apId = 200 + ue.ueId;
    request.enbUeS1apId = entry->enbUeS1apId;
    request.ueAmbrUl = 1000;
    request.ueAmbrDl = 2000;
    request.erabs = {Item(5, 9, 30 + ue.ueId)};
    const auto pdu = s1ap::EncodeInitialContextSetupRequest(request);
    source.handleS1ap(pdu.data(), pdu.size(), 1);
    REQUIRE(entry->bearer.signalingEstablished());
    REQUIRE_FALSE(entry->bearer.restorationPending());

    SendRadio(source, ue, MessageType::BEARER_READY, {5, 10, 45, 0, static_cast<uint8_t>(ue.ueId)});
    REQUIRE(entry->bearer.active());
    REQUIRE(entry->s1 == UeS1State::BEARER_ACTIVE);

    for (const uint8_t ebi : dedicatedEbis)
    {
        s1ap::ErabSetupRequest setup{};
        setup.mmeUeS1apId = 200 + ue.ueId;
        setup.enbUeS1apId = entry->enbUeS1apId;
        setup.erabs = {Item(ebi, 7, 30 + ue.ueId + ebi, true, {0x2E, 0x01})};
        const auto frame = s1ap::EncodeErabSetupRequest(setup);
        source.handleS1ap(frame.data(), frame.size(), 1);
        SendRadio(source, ue, MessageType::BEARER_ACTIVATED, {ebi});
    }
    REQUIRE(entry->dedicatedBearers.size() == dedicatedEbis.size());
    if (accessTeids != nullptr)
    {
        // The access TEIDs this session is using on the source cell. They are
        // only meaningful while the access is alive, so a caller that needs
        // them after the idle transition asks for them here.
        accessTeids->clear();
        accessTeids->push_back(entry->bearer.parameters().localTeid);
        for (const auto &dedicated : entry->dedicatedBearers)
            accessTeids->push_back(dedicated.parameters().localTeid);
    }
}

// The controlled ECM-IDLE transition: the UE asks for one and the network
// answers with its UE Context Release Command.
void GoIdle(EnbMultiplexer &mux, const FakeUe &ue, uint32_t mmeUeS1apId)
{
    auto *entry = mux.registry().find(ue.ueId);
    REQUIRE(entry != nullptr);
    REQUIRE(entry->s1 == UeS1State::BEARER_ACTIVE);
    SendRadio(mux, ue, MessageType::S1_CONTEXT_RELEASE_REQUEST, {entry->bearer.parameters().erabId});
    const auto command = s1ap::EncodeUeContextReleaseCommand(mmeUeS1apId, entry->enbUeS1apId, "radioNetwork", 20);
    mux.handleS1ap(command.data(), command.size(), 1);
    REQUIRE(entry->s1 == UeS1State::IDLE_RETAINED);
    REQUIRE(entry->bearer.logicalConfirmed());
}

void GoIdleOnSource(TwoEnb &lab)
{
    GoIdle(lab.source, lab.ue, 200 + lab.ue.ueId);
}

void GoIdleOnTarget(TwoEnb &lab, uint32_t mmeUeS1apId)
{
    GoIdle(lab.target, lab.ue, mmeUeS1apId);
}

// The reselection uplink into the target cell, carrying the protected TAU and
// the bearer inventory the UE holds from its own NAS-confirmed contexts.
void ReselectToTarget(TwoEnb &lab, const BearerInventory &inventory)
{
    SendRadio(lab.target, lab.ue, MessageType::NAS_UPLINK_MOBILITY_CONTEXT,
              MobilityContextNas(inventory, ProtectedTauRequest));
}

s1ap::InitialContextSetupRequest TargetIcsr(TwoEnb &lab, std::vector<s1ap::ErabToBeSetupItem> erabs)
{
    s1ap::InitialContextSetupRequest request{};
    request.mmeUeS1apId = 500 + lab.ue.ueId;
    const auto *entry = lab.target.registry().find(lab.ue.ueId);
    REQUIRE(entry != nullptr);
    request.enbUeS1apId = entry->enbUeS1apId;
    request.ueAmbrUl = 1000;
    request.ueAmbrDl = 2000;
    request.erabs = std::move(erabs);
    return request;
}

void DeliverIcsr(TwoEnb &lab, const s1ap::InitialContextSetupRequest &request)
{
    const auto pdu = s1ap::EncodeInitialContextSetupRequest(request);
    lab.target.handleS1ap(pdu.data(), pdu.size(), 1);
}

// The UE accepts the fresh transport of one bearer of the new access, naming
// the access epoch it is confirming and restating the PDN address its own NAS
// already assigned.
void Confirm(EnbMultiplexer &mux, const FakeUe &ue, uint8_t ebi, uint32_t generation,
             const std::array<uint8_t, 4> &address)
{
    SendRadio(mux, ue, MessageType::BEARER_TRANSPORT_READY,
              lte::ue::link::EncodeBearerTransportReady(ebi, generation, address));
}

void ConfirmOnTarget(TwoEnb &lab, uint8_t ebi, uint32_t generation)
{
    Confirm(lab.target, lab.ue, ebi, generation, PdnAddress(lab.ue.ueId));
}
} // namespace

TEST_CASE("lte/mobility_target: a fresh target begins with none of the session's bearer context")
{
    TwoEnb lab;
    EstablishOnSource(lab, {6, 7});
    GoIdleOnSource(lab);
    auto *sourceEntry = lab.source.registry().find(lab.ue.ueId);
    REQUIRE(sourceEntry != nullptr);

    // The two registries are independent objects, and the target has never
    // been handed a copy of anything the source holds.
    CHECK(lab.target.registry().size() == 0);
    CHECK(lab.target.registry().find(lab.ue.ueId) == nullptr);
    CHECK(lab.source.registry().find(lab.ue.ueId) != nullptr);

    ReselectToTarget(lab, BearerInventory{5, {6, 7}});
    auto *targetEntry = lab.target.registry().find(lab.ue.ueId);
    REQUIRE(targetEntry != nullptr);

    // What arrived is a claim and an S1 connection, not a bearer: the target
    // holds no logical EPS bearer context of its own until the network says so.
    CHECK(targetEntry->s1 == UeS1State::CONTEXT_PENDING);
    CHECK(targetEntry->mobilityBootstrap);
    REQUIRE(targetEntry->declaredBearers.has_value());
    CHECK(targetEntry->declaredBearers->defaultEbi == 5);
    CHECK(targetEntry->declaredBearers->dedicatedEbis == std::vector<uint8_t>{6, 7});
    CHECK_FALSE(targetEntry->bearer.logicalExists());
    CHECK(targetEntry->dedicatedBearers.empty());
    CHECK(targetEntry != sourceEntry);
}

TEST_CASE("lte/mobility_target: a default-only bootstrap restores one bearer and its own fresh TEIDs")
{
    TwoEnb lab;
    std::vector<uint32_t> sourceTeids;
    EstablishOnSource(lab, {}, &sourceTeids);
    REQUIRE(sourceTeids.size() == 1);
    const uint32_t sourceTeid = sourceTeids.front();
    GoIdleOnSource(lab);
    DrainRadio(lab.ue);
    lab.sourceWire.sent.clear();
    lab.targetWire.sent.clear();

    ReselectToTarget(lab, BearerInventory{5, {}});
    REQUIRE(lab.targetWire.count(12) == 1);
    CHECK(Contains(lab.targetWire.sent.front().pdu, ProtectedTauRequest));

    DeliverIcsr(lab, TargetIcsr(lab, {Item(5, 9, 30 + lab.ue.ueId)}));
    auto *entry = lab.target.registry().find(lab.ue.ueId);
    REQUIRE(entry != nullptr);

    // The network answered and the target established exactly the default
    // bearer, on a local TEID of its own. The source's TEIDs belong to the
    // access being left and cannot receive anything here.
    CHECK(entry->bearer.signalingEstablished());
    CHECK_FALSE(entry->bearer.logicalConfirmed());
    CHECK(entry->bearer.restorationPending());
    CHECK_FALSE(entry->bearer.active());
    CHECK(entry->bearer.parameters().erabId == 5);
    CHECK(entry->bearer.parameters().localTeid != sourceTeid);
    CHECK(lab.target.registry().findByLocalTeid(sourceTeid) == nullptr);
    CHECK(entry->dedicatedBearers.empty());
    CHECK(lab.targetWire.count(9, s1ap::S1apPdu::Kind::SUCCESSFUL_OUTCOME) == 1);

    // The UE is told about its default bearer first and about nothing else.
    const auto frames = DrainRadio(lab.ue);
    REQUIRE(CountType(frames, MessageType::S1_CONTEXT_RESTORED) == 1);
    CHECK(CountType(frames, MessageType::DEDICATED_BEARER_RESTORED) == 0);
    const auto restored = lte::ue::link::DecodeBearerRestoration(frames.front().payload);
    CHECK(restored.first == 5);
    CHECK(restored.second == entry->accessGeneration);
    CHECK(restored.second != 0);
}

TEST_CASE("lte/mobility_target: several E-RABs in one request take their roles from the declaration")
{
    TwoEnb lab;
    EstablishOnSource(lab, {6, 7});
    GoIdleOnSource(lab);
    DrainRadio(lab.ue);
    lab.targetWire.sent.clear();

    ReselectToTarget(lab, BearerInventory{5, {6, 7}});
    // The network lists the E-RABs in an order that names the default last. No
    // role may be inferred from that order, so the declaration is what decides
    // which one is the default bearer.
    DeliverIcsr(lab, TargetIcsr(lab, {Item(6, 7, 31), Item(7, 7, 32), Item(5, 9, 30)}));
    auto *entry = lab.target.registry().find(lab.ue.ueId);
    REQUIRE(entry != nullptr);

    REQUIRE(entry->bearer.signalingEstablished());
    CHECK(entry->bearer.parameters().erabId == 5);
    CHECK(entry->bearer.parameters().linkedDefaultEbi == 0);
    REQUIRE(entry->dedicatedBearers.size() == 2);
    for (const auto &dedicated : entry->dedicatedBearers)
    {
        CHECK(dedicated.kind() == BearerKind::DEDICATED);
        CHECK(dedicated.parameters().linkedDefaultEbi == 5);
        CHECK(dedicated.restorationPending());
        CHECK_FALSE(dedicated.active());
    }
    CHECK(lab.targetWire.count(9, s1ap::S1apPdu::Kind::SUCCESSFUL_OUTCOME) == 1);

    // Default first, then the dedicated bearers, whatever order the MME used.
    const auto frames = DrainRadio(lab.ue);
    REQUIRE(frames.size() == 3);
    CHECK(frames[0].type == MessageType::S1_CONTEXT_RESTORED);
    CHECK(frames[1].type == MessageType::DEDICATED_BEARER_RESTORED);
    CHECK(frames[2].type == MessageType::DEDICATED_BEARER_RESTORED);
    CHECK(lte::ue::link::DecodeBearerRestoration(frames[0].payload).first == 5);
    CHECK(lte::ue::link::DecodeBearerRestoration(frames[1].payload).first == 6);
    CHECK(lte::ue::link::DecodeBearerRestoration(frames[2].payload).first == 7);
}

TEST_CASE("lte/mobility_target: a dedicated E-RAB set up later is still a restored bearer")
{
    TwoEnb lab;
    EstablishOnSource(lab, {6});
    GoIdleOnSource(lab);
    DrainRadio(lab.ue);
    lab.targetWire.sent.clear();

    ReselectToTarget(lab, BearerInventory{5, {6}});
    DeliverIcsr(lab, TargetIcsr(lab, {Item(5, 9, 30)}));
    auto *entry = lab.target.registry().find(lab.ue.ueId);
    REQUIRE(entry != nullptr);
    REQUIRE(entry->bearer.signalingEstablished());
    REQUIRE(entry->dedicatedBearers.empty());
    REQUIRE(CountType(DrainRadio(lab.ue), MessageType::S1_CONTEXT_RESTORED) == 1);

    // The network adds the dedicated bearer afterwards, in its own procedure.
    // It is one the UE declared, so it is a restoration of a bearer its NAS
    // already confirmed and its fresh transport is generation-bound rather
    // than announced as a brand-new bearer.
    s1ap::ErabSetupRequest setup{};
    setup.mmeUeS1apId = 500 + lab.ue.ueId;
    setup.enbUeS1apId = entry->enbUeS1apId;
    setup.erabs = {Item(6, 7, 31, true, {0x2E, 0x01})};
    const auto pdu = s1ap::EncodeErabSetupRequest(setup);
    lab.target.handleS1ap(pdu.data(), pdu.size(), 1);

    REQUIRE(entry->dedicatedBearers.size() == 1);
    CHECK(entry->dedicatedBearers[0].parameters().erabId == 6);
    CHECK(entry->dedicatedBearers[0].parameters().linkedDefaultEbi == 5);
    CHECK(entry->dedicatedBearers[0].restorationPending());

    auto frames = DrainRadio(lab.ue);
    REQUIRE(CountType(frames, MessageType::DEDICATED_BEARER_RESTORED) == 1);
    REQUIRE(CountType(frames, MessageType::NAS_DOWNLINK) == 1);

    // It confirms generation-bound and only after its default bearer is ready.
    const uint32_t generation = entry->accessGeneration;
    ConfirmOnTarget(lab, 6, generation - 1);
    CHECK(entry->dedicatedBearers[0].restorationPending());
    ConfirmOnTarget(lab, 6, generation);
    CHECK(entry->dedicatedBearers[0].restorationPending());
    ConfirmOnTarget(lab, 5, generation);
    REQUIRE(entry->bearer.active());
    ConfirmOnTarget(lab, 6, generation);
    CHECK(entry->dedicatedBearers[0].active());
}

TEST_CASE("lte/mobility_target: a dedicated E-RAB the UE never declared is a new bearer")
{
    TwoEnb lab;
    EstablishOnSource(lab, {6});
    GoIdleOnSource(lab);
    DrainRadio(lab.ue);
    lab.targetWire.sent.clear();

    ReselectToTarget(lab, BearerInventory{5, {6}});
    DeliverIcsr(lab, TargetIcsr(lab, {Item(5, 9, 30)}));
    auto *entry = lab.target.registry().find(lab.ue.ueId);
    REQUIRE(entry != nullptr);
    REQUIRE(entry->bearer.signalingEstablished());
    REQUIRE(CountType(DrainRadio(lab.ue), MessageType::S1_CONTEXT_RESTORED) == 1);
    ConfirmOnTarget(lab, 5, entry->accessGeneration);
    REQUIRE(entry->bearer.active());

    // EBI 8 was never part of the session the UE described, so the network is
    // creating it here and now: it is confirmed as a new bearer, not restored.
    s1ap::ErabSetupRequest setup{};
    setup.mmeUeS1apId = 500 + lab.ue.ueId;
    setup.enbUeS1apId = entry->enbUeS1apId;
    setup.erabs = {Item(8, 7, 32, true, {0x2E, 0x02})};
    const auto pdu = s1ap::EncodeErabSetupRequest(setup);
    lab.target.handleS1ap(pdu.data(), pdu.size(), 1);

    REQUIRE(entry->dedicatedBearers.size() == 1);
    CHECK_FALSE(entry->dedicatedBearers[0].restorationPending());
    const auto frames = DrainRadio(lab.ue);
    CHECK(CountType(frames, MessageType::DEDICATED_BEARER_RESTORED) == 0);
    REQUIRE(CountType(frames, MessageType::NAS_DOWNLINK) == 1);
    SendRadio(lab.target, lab.ue, MessageType::BEARER_ACTIVATED, {8});
    CHECK(entry->dedicatedBearers[0].active());
}

TEST_CASE("lte/mobility_target: a genuine TAU establishes no bearer at all")
{
    TwoEnb lab;
    EstablishOnSource(lab, {6});
    GoIdleOnSource(lab);
    DrainRadio(lab.ue);
    lab.targetWire.sent.clear();

    // The Update is carried to the MME and the network never asks for a bearer
    // context here, so the target must not invent one.
    ReselectToTarget(lab, BearerInventory{5, {6}});
    auto *entry = lab.target.registry().find(lab.ue.ueId);
    REQUIRE(entry != nullptr);
    CHECK(lab.targetWire.count(12) == 1);
    CHECK(Contains(lab.targetWire.sent.front().pdu, ProtectedTauRequest));
    CHECK(entry->s1 == UeS1State::CONTEXT_PENDING);
    CHECK_FALSE(entry->bearer.logicalExists());
    CHECK(entry->dedicatedBearers.empty());
    CHECK(lab.targetWire.count(9, s1ap::S1apPdu::Kind::SUCCESSFUL_OUTCOME) == 0);
    CHECK(lab.targetWire.count(9, s1ap::S1apPdu::Kind::UNSUCCESSFUL_OUTCOME) == 0);
    CHECK(DrainRadio(lab.ue).empty());
}

TEST_CASE("lte/mobility_target: an idle UE retained after a genuine TAU may still request service")
{
    TwoEnb lab;
    EstablishOnSource(lab, {});
    GoIdleOnSource(lab);
    DrainRadio(lab.ue);
    lab.targetWire.sent.clear();

    // With the active flag clear the Update is carried to the MME and the
    // network answers with a UE Context Release Command. This cell is asked for
    // no bearer context, so it ends up holding none of the session's own.
    ReselectToTarget(lab, BearerInventory{5, {}});
    auto *entry = lab.target.registry().find(lab.ue.ueId);
    REQUIRE(entry != nullptr);
    const auto release = s1ap::EncodeUeContextReleaseCommand(500 + lab.ue.ueId, entry->enbUeS1apId, "nas", 0);
    lab.target.handleS1ap(release.data(), release.size(), 1);
    REQUIRE(entry->s1 == UeS1State::IDLE_RETAINED);
    CHECK_FALSE(entry->bearer.logicalExists());
    CHECK(entry->dedicatedBearers.empty());
    // This access never carried bearer transport, so its release tells the UE
    // nothing and the epoch count the two ends share does not move either.
    CHECK(entry->accessGeneration == 1);

    // A page through this cell would have the UE answer with a Service Request,
    // and the frame is forwarded rather than refused: holding none of the
    // session's bearers, this cell cannot decide what the request restores.
    lab.targetWire.sent.clear();
    DrainRadio(lab.ue);
    SendRadio(lab.target, lab.ue, MessageType::SERVICE_REQUEST, {0x05, 0x12, 0x34, 0x56, 0x78, 0xC7, 0x00, 0xAA, 0xBB});
    CHECK(entry->s1 == UeS1State::CONTEXT_PENDING);
    CHECK(lab.targetWire.count(12) == 1);

    // The network answers with the session's one bearer on a TEID of this cell,
    // and this is a restoration rather than a new bearer: the UE has already
    // confirmed the bearer in its own NAS and is asked to confirm this fresh
    // transport, which is the only thing here that is new.
    DeliverIcsr(lab, TargetIcsr(lab, {Item(5, 9, 30 + lab.ue.ueId)}));
    REQUIRE(entry->bearer.signalingEstablished());
    CHECK_FALSE(entry->bearer.logicalConfirmed());
    CHECK(entry->bearer.restorationPending());
    const auto frames = DrainRadio(lab.ue);
    REQUIRE(CountType(frames, MessageType::S1_CONTEXT_RESTORED) == 1);
    const auto restored = lte::ue::link::DecodeBearerRestoration(frames.front().payload);
    CHECK(restored.first == 5);
    CHECK(restored.second == entry->accessGeneration);
    CHECK(restored.second != 0);
}

TEST_CASE("lte/mobility_target: a request without the declared default bearer is refused whole")
{
    TwoEnb lab;
    EstablishOnSource(lab, {6});
    GoIdleOnSource(lab);
    DrainRadio(lab.ue);
    lab.targetWire.sent.clear();

    ReselectToTarget(lab, BearerInventory{5, {6}});
    // The network never offered the default bearer the UE holds. Establishing
    // only the dedicated one would leave a bearer with nothing to be dedicated
    // to, so the whole request is refused and nothing is established.
    DeliverIcsr(lab, TargetIcsr(lab, {Item(6, 7, 31)}));
    auto *entry = lab.target.registry().find(lab.ue.ueId);
    REQUIRE(entry != nullptr);
    CHECK_FALSE(entry->bearer.logicalExists());
    CHECK(entry->dedicatedBearers.empty());
    CHECK(entry->bearer.parameters().localTeid == 0);
    CHECK(lab.targetWire.count(9, s1ap::S1apPdu::Kind::UNSUCCESSFUL_OUTCOME) == 1);
    CHECK(lab.targetWire.count(9, s1ap::S1apPdu::Kind::SUCCESSFUL_OUTCOME) == 0);
    CHECK(DrainRadio(lab.ue).empty());
}

TEST_CASE("lte/mobility_target: an E-RAB the UE never confirmed is not established")
{
    TwoEnb lab;
    EstablishOnSource(lab, {6});
    GoIdleOnSource(lab);
    DrainRadio(lab.ue);
    lab.targetWire.sent.clear();

    ReselectToTarget(lab, BearerInventory{5, {6}});
    // EBI 8 is offered by the network but is not in the declaration. The
    // declaration can only restrict what the network authorized, so it is
    // failed per item while the two the UE did confirm go through.
    DeliverIcsr(lab, TargetIcsr(lab, {Item(5, 9, 30), Item(6, 7, 31), Item(8, 7, 32)}));
    auto *entry = lab.target.registry().find(lab.ue.ueId);
    REQUIRE(entry != nullptr);
    REQUIRE(entry->bearer.signalingEstablished());
    REQUIRE(entry->dedicatedBearers.size() == 1);
    CHECK(entry->dedicatedBearers[0].parameters().erabId == 6);
    CHECK(lab.target.registry().findBearer(*entry, 8) == nullptr);

    const auto frames = DrainRadio(lab.ue);
    CHECK(CountType(frames, MessageType::S1_CONTEXT_RESTORED) == 1);
    CHECK(CountType(frames, MessageType::DEDICATED_BEARER_RESTORED) == 1);
}

TEST_CASE("lte/mobility_target: a mobility uplink that declares nothing cannot be given bearer roles")
{
    TwoEnb lab;
    EstablishOnSource(lab, {});
    GoIdleOnSource(lab);
    DrainRadio(lab.ue);
    lab.targetWire.sent.clear();

    // The older mobility uplink names its session but not its bearers. On a
    // cell that has never seen the Attach the E-RAB list marks no roles, so
    // nothing is established rather than guessed at.
    SendRadio(lab.target, lab.ue, MessageType::NAS_UPLINK_MOBILITY, MobilityNas(ProtectedTauRequest));
    auto *entry = lab.target.registry().find(lab.ue.ueId);
    REQUIRE(entry != nullptr);
    REQUIRE(entry->mobilityBootstrap);
    CHECK_FALSE(entry->declaredBearers.has_value());

    DeliverIcsr(lab, TargetIcsr(lab, {Item(5, 9, 30)}));
    CHECK_FALSE(entry->bearer.logicalExists());
    CHECK(lab.targetWire.count(9, s1ap::S1apPdu::Kind::UNSUCCESSFUL_OUTCOME) == 1);
}

TEST_CASE("lte/mobility_target: a declaration contradicting the retained default bearer is refused")
{
    TwoEnb lab;
    EstablishOnSource(lab, {6, 7});
    GoIdleOnSource(lab);
    DrainRadio(lab.ue);
    lab.targetWire.sent.clear();

    // The UE really does reselect into the target and its session is really
    // established there, so the next reselection into the same cell finds a
    // target that legitimately holds the session.
    ReselectToTarget(lab, BearerInventory{5, {6, 7}});
    DeliverIcsr(lab, TargetIcsr(lab, {Item(5, 9, 30), Item(6, 7, 31), Item(7, 7, 32)}));
    auto *entry = lab.target.registry().find(lab.ue.ueId);
    REQUIRE(entry != nullptr);
    ConfirmOnTarget(lab, 5, entry->accessGeneration);
    ConfirmOnTarget(lab, 6, entry->accessGeneration);
    ConfirmOnTarget(lab, 7, entry->accessGeneration);
    REQUIRE(entry->bearer.active());
    GoIdleOnTarget(lab, 500 + lab.ue.ueId);
    DrainRadio(lab.ue);
    lab.targetWire.sent.clear();

    // Now the declaration names a different default bearer from the one this
    // cell holds. Neither side of the contradiction is believed, so nothing is
    // set up and the retained session is not touched.
    ReselectToTarget(lab, BearerInventory{6, {7}});
    DeliverIcsr(lab, TargetIcsr(lab, {Item(6, 7, 31), Item(7, 7, 32)}));
    CHECK(lab.targetWire.count(9, s1ap::S1apPdu::Kind::UNSUCCESSFUL_OUTCOME) == 1);
    CHECK(lab.targetWire.count(9, s1ap::S1apPdu::Kind::SUCCESSFUL_OUTCOME) == 0);
    CHECK(entry->bearer.parameters().erabId == 5);
    CHECK(entry->bearer.logicalConfirmed());
    REQUIRE(entry->dedicatedBearers.size() == 2);
    CHECK_FALSE(entry->bearer.signalingEstablished());
    CHECK(DrainRadio(lab.ue).empty());
}

TEST_CASE("lte/mobility_target: an invalid QoS fails its own E-RAB and no other")
{
    TwoEnb lab;
    EstablishOnSource(lab, {6});
    GoIdleOnSource(lab);
    DrainRadio(lab.ue);
    lab.targetWire.sent.clear();

    ReselectToTarget(lab, BearerInventory{5, {6}});
    DeliverIcsr(lab, TargetIcsr(lab, {Item(5, 9, 30), Item(6, 0, 31)}));
    auto *entry = lab.target.registry().find(lab.ue.ueId);
    REQUIRE(entry != nullptr);
    REQUIRE(entry->bearer.signalingEstablished());
    CHECK(entry->bearer.parameters().qci == 9);
    CHECK(entry->dedicatedBearers.empty());
    const auto frames = DrainRadio(lab.ue);
    CHECK(CountType(frames, MessageType::S1_CONTEXT_RESTORED) == 1);
    CHECK(CountType(frames, MessageType::DEDICATED_BEARER_RESTORED) == 0);
}

TEST_CASE("lte/mobility_target: a duplicated E-RAB identity refuses the whole request")
{
    TwoEnb lab;
    EstablishOnSource(lab, {});
    GoIdleOnSource(lab);
    DrainRadio(lab.ue);
    lab.targetWire.sent.clear();

    ReselectToTarget(lab, BearerInventory{5, {}});
    DeliverIcsr(lab, TargetIcsr(lab, {Item(5, 9, 30), Item(5, 7, 31)}));
    auto *entry = lab.target.registry().find(lab.ue.ueId);
    REQUIRE(entry != nullptr);
    CHECK_FALSE(entry->bearer.logicalExists());
    CHECK(lab.targetWire.count(9, s1ap::S1apPdu::Kind::UNSUCCESSFUL_OUTCOME) == 1);
    CHECK(lab.targetWire.count(9, s1ap::S1apPdu::Kind::SUCCESSFUL_OUTCOME) == 0);
}

TEST_CASE("lte/mobility_target: the source's access TEIDs resolve nowhere on the target")
{
    TwoEnb lab;
    std::vector<uint32_t> sourceTeids;
    EstablishOnSource(lab, {6, 7}, &sourceTeids);
    REQUIRE(sourceTeids.size() == 3);
    GoIdleOnSource(lab);

    ReselectToTarget(lab, BearerInventory{5, {6, 7}});
    DeliverIcsr(lab, TargetIcsr(lab, {Item(5, 9, 30), Item(6, 7, 31), Item(7, 7, 32)}));
    auto *targetEntry = lab.target.registry().find(lab.ue.ueId);
    REQUIRE(targetEntry != nullptr);

    // Every TEID of the target is its own, and none of the source's TEIDs
    // resolves to anything here, so a packet sent to an old one cannot be
    // forwarded onto this access.
    std::vector<uint32_t> targetTeids{targetEntry->bearer.parameters().localTeid};
    for (const auto &dedicated : targetEntry->dedicatedBearers)
        targetTeids.push_back(dedicated.parameters().localTeid);
    REQUIRE(targetTeids.size() == sourceTeids.size());
    for (const uint32_t teid : sourceTeids)
    {
        CHECK(lab.target.registry().findByLocalTeid(teid) == nullptr);
        CHECK(std::find(targetTeids.begin(), targetTeids.end(), teid) == targetTeids.end());
    }
    for (const uint32_t teid : targetTeids)
        CHECK(lab.target.registry().findByLocalTeid(teid) != nullptr);
}

TEST_CASE("lte/mobility_target: a response that cannot leave the eNB publishes no transport")
{
    TwoEnb lab;
    EstablishOnSource(lab, {6});
    GoIdleOnSource(lab);
    DrainRadio(lab.ue);
    lab.targetWire.sent.clear();

    ReselectToTarget(lab, BearerInventory{5, {6}});
    auto *entry = lab.target.registry().find(lab.ue.ueId);
    REQUIRE(entry != nullptr);
    lab.target.armLossBeforeNextS1apSend();

    DeliverIcsr(lab, TargetIcsr(lab, {Item(5, 9, 30), Item(6, 7, 31)}));
    CHECK(lab.target.injectionTriggered());
    lab.target.clearInjection();

    // The outcome never left the eNB, so the bearers it would have reported do
    // not exist: no TEID is bound and nothing is forwardable.
    CHECK_FALSE(entry->bearer.logicalExists());
    CHECK(entry->dedicatedBearers.empty());
    CHECK(entry->bearer.parameters().localTeid == 0);
    CHECK(lab.targetWire.count(9, s1ap::S1apPdu::Kind::SUCCESSFUL_OUTCOME) == 0);
    CHECK(DrainRadio(lab.ue).empty());
}

TEST_CASE("lte/mobility_target: a bootstrapped bearer forwards nothing before the UE confirms it")
{
    TwoEnb lab;
    EstablishOnSource(lab, {});
    GoIdleOnSource(lab);
    DrainRadio(lab.ue);
    lab.targetWire.sent.clear();

    ReselectToTarget(lab, BearerInventory{5, {}});
    DeliverIcsr(lab, TargetIcsr(lab, {Item(5, 9, 30)}));
    auto *entry = lab.target.registry().find(lab.ue.ueId);
    REQUIRE(entry != nullptr);
    REQUIRE(entry->bearer.signalingEstablished());
    REQUIRE(entry->bearer.restorationPending());

    // A confirmation from the access being left carries the old generation and
    // is refused. So is one naming another bearer. Until the UE confirms this
    // access's transport, the bearer is not forwardable in either direction.
    const uint32_t generation = entry->accessGeneration;
    ConfirmOnTarget(lab, 5, generation - 1);
    CHECK(entry->bearer.restorationPending());
    CHECK_FALSE(entry->bearer.active());
    ConfirmOnTarget(lab, 6, generation);
    CHECK(entry->bearer.restorationPending());
    CHECK_FALSE(entry->bearer.active());
    CHECK(entry->s1 == UeS1State::CONTEXT_ESTABLISHED);

    ConfirmOnTarget(lab, 5, generation);
    CHECK(entry->bearer.active());
    CHECK_FALSE(entry->bearer.restorationPending());
    CHECK(entry->s1 == UeS1State::BEARER_ACTIVE);
}

TEST_CASE("lte/mobility_target: a restoration notification that cannot reach the UE forwards nothing")
{
    TwoEnb lab;
    EstablishOnSource(lab, {});
    GoIdleOnSource(lab);
    DrainRadio(lab.ue);
    lab.targetWire.sent.clear();

    // The radio endpoint cannot receive, which is exactly the case where the
    // target's restoration notification cannot be delivered.
    const InetAddress unreachable{};
    SendRadio(lab.target, lab.ue, MessageType::NAS_UPLINK_MOBILITY_CONTEXT,
              MobilityContextNas(BearerInventory{5, {}}, ProtectedTauRequest), unreachable);
    auto *entry = lab.target.registry().find(lab.ue.ueId);
    REQUIRE(entry != nullptr);
    const size_t rejected = lab.target.recoveryCounters().staleMessagesRejected;

    DeliverIcsr(lab, TargetIcsr(lab, {Item(5, 9, 30)}));

    // The response did leave the eNB, so the network has a consistent view and
    // the transport is committed. What must never happen is forwarding on it:
    // without the UE's confirmation nothing moves, and the failure to notify
    // the UE is reported instead of being swallowed.
    CHECK(lab.targetWire.count(9, s1ap::S1apPdu::Kind::SUCCESSFUL_OUTCOME) == 1);
    CHECK(entry->bearer.signalingEstablished());
    CHECK(entry->bearer.restorationPending());
    CHECK_FALSE(entry->bearer.active());
    CHECK(lab.target.recoveryCounters().staleMessagesRejected > rejected);
    CHECK(DrainRadio(lab.ue).empty());
}

TEST_CASE("lte/mobility_target: source and target count access epochs independently")
{
    TwoEnb lab;
    EstablishOnSource(lab, {});
    GoIdleOnSource(lab);
    REQUIRE(lab.source.registry().find(lab.ue.ueId)->accessGeneration == 1);

    // The UE reselects back into the source cell and leaves again, so the
    // source has really seen more access epochs than the target ever will.
    SendRadio(lab.source, lab.ue, MessageType::NAS_UPLINK_MOBILITY_CONTEXT,
              MobilityContextNas(BearerInventory{5, {}}, ProtectedTauRequest));
    auto *sourceEntry = lab.source.registry().find(lab.ue.ueId);
    REQUIRE(sourceEntry != nullptr);
    s1ap::InitialContextSetupRequest request{};
    request.mmeUeS1apId = 200 + lab.ue.ueId;
    request.enbUeS1apId = sourceEntry->enbUeS1apId;
    request.ueAmbrUl = 1000;
    request.ueAmbrDl = 2000;
    request.erabs = {Item(5, 9, 30 + lab.ue.ueId)};
    const auto pdu = s1ap::EncodeInitialContextSetupRequest(request);
    lab.source.handleS1ap(pdu.data(), pdu.size(), 1);
    Confirm(lab.source, lab.ue, 5, sourceEntry->accessGeneration, PdnAddress(lab.ue.ueId));
    REQUIRE(sourceEntry->bearer.active());
    GoIdleOnSource(lab);
    const uint32_t sourceGeneration = sourceEntry->accessGeneration;
    REQUIRE(sourceGeneration == 2);

    ReselectToTarget(lab, BearerInventory{5, {}});
    DeliverIcsr(lab, TargetIcsr(lab, {Item(5, 9, 30)}));
    auto *targetEntry = lab.target.registry().find(lab.ue.ueId);
    REQUIRE(targetEntry != nullptr);

    // The two eNBs count their own access epochs and the numbers really
    // differ. Neither of them is zero, and the epoch of the access being left
    // is not accepted on the new one.
    CHECK(targetEntry->accessGeneration != sourceGeneration);
    CHECK(targetEntry->accessGeneration != 0);
    CHECK(sourceEntry->accessGeneration == sourceGeneration);
    ConfirmOnTarget(lab, 5, sourceGeneration);
    CHECK_FALSE(targetEntry->bearer.active());
    ConfirmOnTarget(lab, 5, targetEntry->accessGeneration);
    CHECK(targetEntry->bearer.active());
}

TEST_CASE("lte/mobility_target: a transport confirmation only ever confirms the assigned PDN address")
{
    TwoEnb lab;
    EstablishOnSource(lab, {6});
    GoIdleOnSource(lab);
    DrainRadio(lab.ue);
    lab.targetWire.sent.clear();

    // On the fresh target the eNB has no address of its own, so the UE has to
    // name the one its NAS assigned. A confirmation that names none cannot
    // make the bearer forwardable.
    ReselectToTarget(lab, BearerInventory{5, {6}});
    DeliverIcsr(lab, TargetIcsr(lab, {Item(5, 9, 30), Item(6, 7, 31)}));
    auto *entry = lab.target.registry().find(lab.ue.ueId);
    REQUIRE(entry != nullptr);
    const uint32_t generation = entry->accessGeneration;
    SendRadio(lab.target, lab.ue, MessageType::BEARER_TRANSPORT_READY,
              lte::ue::link::EncodeBearerRestoration(5, generation));
    CHECK_FALSE(entry->bearer.active());
    Confirm(lab.target, lab.ue, 5, generation, PdnAddress(lab.ue.ueId));
    REQUIRE(entry->bearer.active());
    CHECK(entry->bearer.ueIpv4() == PdnAddress(lab.ue.ueId));

    // A dedicated bearer belongs to the PDN connection of its default bearer,
    // so it must name the same address and cannot borrow another one.
    Confirm(lab.target, lab.ue, 6, generation, {10, 45, 0, 99});
    CHECK_FALSE(entry->dedicatedBearers[0].active());
    Confirm(lab.target, lab.ue, 6, generation, PdnAddress(lab.ue.ueId));
    CHECK(entry->dedicatedBearers[0].active());

    // A cell that already holds the address never lets a later confirmation
    // replace it, and that holds on the source cell the session came from too.
    DrainRadio(lab.ue);
    SendRadio(lab.source, lab.ue, MessageType::NAS_UPLINK_MOBILITY_CONTEXT,
              MobilityContextNas(BearerInventory{5, {}}, ProtectedTauRequest));
    auto *sourceEntry = lab.source.registry().find(lab.ue.ueId);
    REQUIRE(sourceEntry != nullptr);
    s1ap::InitialContextSetupRequest request{};
    request.mmeUeS1apId = 200 + lab.ue.ueId;
    request.enbUeS1apId = sourceEntry->enbUeS1apId;
    request.ueAmbrUl = 1000;
    request.ueAmbrDl = 2000;
    request.erabs = {Item(5, 9, 30 + lab.ue.ueId)};
    const auto pdu = s1ap::EncodeInitialContextSetupRequest(request);
    lab.source.handleS1ap(pdu.data(), pdu.size(), 1);
    REQUIRE(sourceEntry->bearer.restorationPending());
    Confirm(lab.source, lab.ue, 5, sourceEntry->accessGeneration, {10, 45, 0, 99});
    CHECK_FALSE(sourceEntry->bearer.active());
    Confirm(lab.source, lab.ue, 5, sourceEntry->accessGeneration, PdnAddress(lab.ue.ueId));
    CHECK(sourceEntry->bearer.active());
    CHECK(sourceEntry->bearer.ueIpv4() == PdnAddress(lab.ue.ueId));
}

TEST_CASE("lte/mobility_target: a frame from an endpoint that does not own the UE identity is refused")
{
    TwoEnb lab;
    EstablishOnSource(lab, {});
    GoIdleOnSource(lab);
    ReselectToTarget(lab, BearerInventory{5, {}});
    auto *first = lab.target.registry().find(lab.ue.ueId);
    REQUIRE(first != nullptr);
    const size_t rejected = lab.target.recoveryCounters().staleMessagesRejected;

    // A second radio endpoint must not claim the identity of the UE the target
    // is already serving, and an endpoint that owns one identity must not
    // borrow another. The served context is untouched by either attempt.
    FakeUe intruder{2};
    SendRadio(lab.target, lab.ue, MessageType::NAS_UPLINK_MOBILITY_CONTEXT,
              MobilityContextNas(BearerInventory{5, {}}, ProtectedTauRequest), intruder.radio.LocalAddress());
    SendRadio(lab.target, intruder, MessageType::NAS_UPLINK_MOBILITY_CONTEXT,
              MobilityContextNas(BearerInventory{5, {}}, ProtectedTauRequest, 0x87654321),
              lab.ue.radio.LocalAddress());

    CHECK(lab.target.registry().find(lab.ue.ueId) == first);
    CHECK(lab.target.registry().findByPeer(intruder.radio.LocalAddress()) == nullptr);
    CHECK(lab.target.registry().find(2) == nullptr);
    CHECK(lab.target.recoveryCounters().staleMessagesRejected == rejected + 2);
}

TEST_CASE("lte/mobility_target: two independent UEs bootstrap at the same target without mixing")
{
    TwoEnb lab;
    FakeUe second{2};
    EstablishOnSource(lab, {6});
    GoIdleOnSource(lab);
    DrainRadio(lab.ue);
    lab.targetWire.sent.clear();

    ReselectToTarget(lab, BearerInventory{5, {6}});
    SendRadio(lab.target, second, MessageType::NAS_UPLINK_MOBILITY_CONTEXT,
              MobilityContextNas(BearerInventory{8, {9}}, ProtectedTauRequest, 0x87654321));
    REQUIRE(lab.target.registry().size() == 2);

    auto *first = lab.target.registry().find(lab.ue.ueId);
    auto *other = lab.target.registry().find(second.ueId);
    REQUIRE(first != nullptr);
    REQUIRE(other != nullptr);
    REQUIRE(first != other);

    // Each UE is set up from its own declaration and its own network answer,
    // and neither bearer set nor TEID can leak into the other.
    DeliverIcsr(lab, TargetIcsr(lab, {Item(5, 9, 30), Item(6, 7, 31)}));
    s1ap::InitialContextSetupRequest request{};
    request.mmeUeS1apId = 700 + second.ueId;
    request.enbUeS1apId = other->enbUeS1apId;
    request.ueAmbrUl = 1000;
    request.ueAmbrDl = 2000;
    request.erabs = {Item(8, 9, 40), Item(9, 7, 41)};
    DeliverIcsr(lab, request);

    REQUIRE(first->bearer.parameters().erabId == 5);
    REQUIRE(other->bearer.parameters().erabId == 8);
    REQUIRE(first->dedicatedBearers.size() == 1);
    REQUIRE(other->dedicatedBearers.size() == 1);
    CHECK(first->dedicatedBearers[0].parameters().erabId == 6);
    CHECK(other->dedicatedBearers[0].parameters().erabId == 9);
    CHECK(first->bearer.parameters().localTeid != other->bearer.parameters().localTeid);
    CHECK(lab.target.registry().findByLocalTeid(first->bearer.parameters().localTeid) == first);
    CHECK(lab.target.registry().findByLocalTeid(other->bearer.parameters().localTeid) == other);
    CHECK(CountType(DrainRadio(lab.ue), MessageType::S1_CONTEXT_RESTORED) == 1);
    CHECK(CountType(DrainRadio(second), MessageType::S1_CONTEXT_RESTORED) == 1);
}

TEST_CASE("lte/mobility_target: a stale frame from the previous access is refused on the target")
{
    TwoEnb lab;
    EstablishOnSource(lab, {6});
    GoIdleOnSource(lab);
    DrainRadio(lab.ue);
    lab.targetWire.sent.clear();

    ReselectToTarget(lab, BearerInventory{5, {6}});
    DeliverIcsr(lab, TargetIcsr(lab, {Item(5, 9, 30), Item(6, 7, 31)}));
    auto *entry = lab.target.registry().find(lab.ue.ueId);
    REQUIRE(entry != nullptr);
    REQUIRE(entry->bearer.restorationPending());
    const size_t rejected = lab.target.recoveryCounters().staleMessagesRejected;

    // A frame that belonged to the access being left names that access's
    // generation, and one that names no epoch at all is refused just the same.
    // Neither can make the new transport usable.
    const uint32_t generation = entry->accessGeneration;
    ConfirmOnTarget(lab, 5, generation + 7);
    ConfirmOnTarget(lab, 5, 0);
    CHECK(entry->bearer.restorationPending());
    CHECK_FALSE(entry->bearer.active());
    CHECK(entry->s1 == UeS1State::CONTEXT_ESTABLISHED);
    CHECK(lab.target.recoveryCounters().staleMessagesRejected >= rejected + 2);
}
