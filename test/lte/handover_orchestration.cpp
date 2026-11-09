//
// This file is a part of UERANSIM project.
// Copyright (c) 2027 ALİ GÜNGÖR.
//
// https://github.com/aligungr/UERANSIM/
// See README, LICENSE, and CONTRIBUTING files for licensing details.
//

// Phase 18-D: the trusted two-eNB coordination contract.
//
// These cases drive the source-provenance extractor, the coordination channel
// and the source-side Handover Command gate. The source session they work from
// is always read out of a real `EnbUeEntry` that was brought up through the
// production establishment path — `handleRadioFrame`, `handleS1ap` and the
// registry's own allocator and binder — so nothing here can close a
// requirement with a record a test assembled out of fields it chose.
//
// Where a case needs a specific state in order to show a refusal, it arranges
// that state and then asserts that the production gate refused it and moved
// nothing. It never asserts that a hand-built state is the transition under
// test.

#include <ext/doctest/doctest.h>

#include <algorithm>
#include <array>
#include <chrono>
#include <cstdint>
#include <functional>
#include <optional>
#include <string>
#include <thread>
#include <utility>
#include <vector>

#include <lib/udp/server.hpp>
#include <lte/enb/codec.hpp>
#include <lte/enb/handover_admission.hpp>
#include <lte/enb/handover_orchestration.hpp>
#include <lte/enb/handover_preparation.hpp>
#include <lte/enb/multiplexer.hpp>
#include <lte/enb/ue_registry.hpp>
#include <lte/enb/user_plane.hpp>
#include <lte/ue/radio_link.hpp>

namespace
{

using namespace lte::enb;
using namespace lte::enb::s1ap;
namespace link = lte::ue::link;
using lte::UeAmbr;

constexpr uint32_t SourceEnbId = 0x0012345u;
constexpr uint32_t TargetEnbId = 0x00ABCDEu;
constexpr uint32_t MmeUeS1apId = 201;

const Plmn &TestPlmn()
{
    static const Plmn plmn{"460", "02"};
    return plmn;
}

EnbIdentity SourceIdentity()
{
    return EnbIdentity{TestPlmn(), SourceEnbId, 1};
}

EnbIdentity TargetIdentity()
{
    return EnbIdentity{TestPlmn(), TargetEnbId, 2};
}

EutranCgi CgiOf(const EnbIdentity &identity)
{
    return EutranCgi{identity.plmn, (identity.enbId & 0xFFFFFU) << 8U};
}

std::array<uint8_t, 4> Ip(uint8_t a, uint8_t b, uint8_t c, uint8_t d)
{
    return {a, b, c, d};
}

EnbConfig TestEnbConfig(uint32_t enbId, const std::string &s1uAddress, uint32_t tac = 1)
{
    EnbConfig config{};
    config.plmn = TestPlmn();
    config.enbId = enbId;
    config.tac = tac;
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

class CaptureSender final : public IS1apSender
{
  public:
    void sendS1ap(uint16_t stream, const std::vector<uint8_t> &pdu) override
    {
        sent.emplace_back(stream, pdu);
    }
    std::vector<std::pair<uint16_t, std::vector<uint8_t>>> sent;
};

// A UE radio endpoint that is a real UDP socket, so what the source's
// production radio sender writes can be read back exactly as written.
struct FakeUe
{
    explicit FakeUe(uint32_t id) : ueId(id)
    {
    }
    udp::UdpServer radio{"127.0.0.1", 0};
    uint32_t ueId;
};

void SendRadio(EnbMultiplexer &mux, const FakeUe &ue, link::MessageType type, std::vector<uint8_t> payload)
{
    const auto frame = link::Encode({type, ue.ueId, std::move(payload)});
    mux.handleRadioFrame(frame.data(), frame.size(), ue.radio.LocalAddress());
}

std::vector<link::Message> DrainRadio(FakeUe &ue)
{
    std::vector<link::Message> frames;
    uint8_t buffer[4096];
    InetAddress peer;
    for (;;)
    {
        const int received = ue.radio.Receive(buffer, sizeof(buffer), 10, peer);
        if (received <= 0)
            break;
        frames.push_back(link::Decode(buffer, static_cast<size_t>(received)));
    }
    return frames;
}

// One network-authored E-RAB. A dedicated E-RAB is refused by the eNB without
// a NAS activation to carry to the UE, so one is stated here rather than the
// item being quietly accepted without it.
s1ap::ErabToBeSetupItem Item(uint8_t ebi, uint8_t qci, uint32_t sgwTeid, std::vector<uint8_t> nasPdu = {})
{
    s1ap::ErabToBeSetupItem item{};
    item.erabId = ebi;
    item.qci = qci;
    item.priorityLevel = 5;
    item.transportLayerAddress = Ip(127, 0, 0, 9);
    item.gtpTeid = TeidToBytes(sgwTeid);
    item.nasPduPresent = !nasPdu.empty();
    item.nasPdu = std::move(nasPdu);
    return item;
}

// The PDN address the UE's own NAS assigned. The network never invents one.
std::array<uint8_t, 4> PdnAddress(uint32_t ueId)
{
    return {10, 45, 0, static_cast<uint8_t>(ueId)};
}

struct SourceLab
{
    CaptureSender wire;
    EnbConfig config{TestEnbConfig(SourceEnbId, "127.0.0.1")};
    EnbMultiplexer mux{config, wire};
    FakeUe ue{1};
    EnbUeEntry *entry{};
    uint32_t defaultTeid{};

    // Brings one UE's EPS session up on this source through the production
    // establishment path only: a fresh Attach uplink, a network-authored
    // Initial Context Setup Request carrying the UE-AMBR and the default
    // bearer, the UE's bearer-ready confirmation, and one network-authored
    // E-RAB Setup Request per dedicated bearer. Nothing is written into the
    // registry by hand. `activate` stops short of the UE's bearer
    // confirmation, which is how a session with no network-confirmed PDN
    // address is reached through production.
    void establish(const std::vector<uint8_t> &dedicatedEbis = {}, bool activate = true)
    {
        SendRadio(mux, ue, link::MessageType::NAS_UPLINK, {0x41, 0x01, 0x02, 0x03});
        entry = mux.registry().find(ue.ueId);
        REQUIRE(entry != nullptr);
        REQUIRE(entry->s1 == UeS1State::CONTEXT_PENDING);

        s1ap::InitialContextSetupRequest request{};
        request.mmeUeS1apId = MmeUeS1apId;
        request.enbUeS1apId = entry->enbUeS1apId;
        request.ueAmbrUl = 1000;
        request.ueAmbrDl = 2000;
        request.erabs = {Item(5, 9, 30 + ue.ueId)};
        const auto pdu = s1ap::EncodeInitialContextSetupRequest(request);
        mux.handleS1ap(pdu.data(), pdu.size(), 1);
        REQUIRE(entry->bearer.signalingEstablished());
        defaultTeid = entry->bearer.parameters().localTeid;
        REQUIRE(defaultTeid != 0);

        if (activate)
        {
            SendRadio(mux, ue, link::MessageType::BEARER_READY, {5, 10, 45, 0, static_cast<uint8_t>(ue.ueId)});
            REQUIRE(entry->bearer.active());
            REQUIRE(entry->s1 == UeS1State::BEARER_ACTIVE);
        }

        for (const uint8_t ebi : dedicatedEbis)
        {
            s1ap::ErabSetupRequest setup{};
            setup.mmeUeS1apId = MmeUeS1apId;
            setup.enbUeS1apId = entry->enbUeS1apId;
            setup.erabs = {Item(ebi, 7, 30 + ue.ueId + ebi, {0x2E, 0x01})};
            const auto frame = s1ap::EncodeErabSetupRequest(setup);
            mux.handleS1ap(frame.data(), frame.size(), 1);
            SendRadio(mux, ue, link::MessageType::BEARER_ACTIVATED, {ebi});
        }
        REQUIRE(entry->dedicatedBearers.size() == dedicatedEbis.size());

        // Whatever the establishment sent to the UE is not the traffic of any
        // of these cases, so it is cleared before the action under test.
        DrainRadio(ue);
    }
};

// The authorized target the coordinator may select. Nothing about it is
// discovered: every field is explicit simulator configuration.
HandoverTargetBinding TargetBinding(uint64_t associationEpoch = 1)
{
    HandoverTargetBinding binding;
    binding.identity = TargetIdentity();
    binding.cgi = CgiOf(TargetIdentity());
    binding.tai = Tai{TargetIdentity().plmn, TargetIdentity().tac};
    binding.radioEndpoint = InetAddress{"127.0.0.5", 47000};
    binding.s1uAddress = Ip(127, 0, 0, 3);
    binding.encryptionAlgorithms = {0x80, 0x00};
    binding.integrityAlgorithms = {0x40, 0x00};
    binding.associationEpoch = associationEpoch;
    binding.permittedSource = SourceIdentity();
    binding.ready = true;
    return binding;
}

} // namespace

// --- A: source provenance ---------------------------------------------------

TEST_CASE("lte/handover/orchestration: a source session is read out of the live source registry")
{
    SourceLab lab;
    lab.establish({6});

    const SourceSession session =
        ExtractSourceSession(*lab.entry, SourceIdentity(), CgiOf(SourceIdentity()), lab.mux.associationEpoch());
    CHECK(session.isVerified());
    CHECK(session.sourceCell.enbId == SourceEnbId);
    CHECK(session.sourceCgi.cellId == CgiOf(SourceIdentity()).cellId);
    CHECK(session.associationEpoch == lab.mux.associationEpoch());
    CHECK(session.mmeUeS1apId == MmeUeS1apId);
    CHECK(session.enbUeS1apId == lab.entry->enbUeS1apId);
    CHECK(session.radioUeId == lab.ue.ueId);
    CHECK(session.radioPeer == lab.ue.radio.LocalAddress());
    CHECK(session.defaultEbi == 5);
    CHECK(session.ueIpv4 == PdnAddress(lab.ue.ueId));
    CHECK(session.accessGeneration == lab.entry->accessGeneration);
    CHECK(session.ueAmbr.downlink == 2000);
    CHECK(session.ueAmbr.uplink == 1000);

    REQUIRE(session.roles.size() == 2);
    CHECK(session.roles[0].role == BearerRole::DEFAULT);
    CHECK(session.roles[0].erabId == 5);
    CHECK_FALSE(session.roles[0].linkedDefaultErabId.has_value());
    CHECK(session.roles[1].role == BearerRole::DEDICATED);
    CHECK(session.roles[1].erabId == 6);
    REQUIRE(session.roles[1].linkedDefaultErabId.has_value());
    CHECK(*session.roles[1].linkedDefaultErabId == 5);
    // QCI and ARP come out of the one bearer context, so the NAS and the S1AP
    // statements of a bearer's QoS cannot be read apart here.
    CHECK(session.roles[0].qci == 9);
    CHECK(session.roles[1].qci == 7);
    CHECK(session.roles[0].priorityLevel == 5);

    REQUIRE(session.erabs.size() == 2);
    CHECK(session.erabs[0].erabId == 5);
    CHECK(session.erabs[0].sgwTeid == TeidToBytes(30 + lab.ue.ueId));
    CHECK(session.erabs[0].sgwAddress == Ip(127, 0, 0, 9));
    CHECK(session.erabs[1].erabId == 6);
    CHECK(session.erabs[1].sgwTeid == TeidToBytes(30 + lab.ue.ueId + 6));
}

TEST_CASE("lte/handover/orchestration: a deliberately reordered bearer list yields the same roles")
{
    SourceLab lab;
    lab.establish({6, 7});
    const SourceSession forward =
        ExtractSourceSession(*lab.entry, SourceIdentity(), CgiOf(SourceIdentity()), lab.mux.associationEpoch());
    REQUIRE(forward.roles.size() == 3);

    // The registry holds the dedicated bearers in the order the network set
    // them up. Reversing that order is the network's business and changes no
    // role.
    std::reverse(lab.entry->dedicatedBearers.begin(), lab.entry->dedicatedBearers.end());
    const SourceSession reversed =
        ExtractSourceSession(*lab.entry, SourceIdentity(), CgiOf(SourceIdentity()), lab.mux.associationEpoch());

    REQUIRE(reversed.roles.size() == forward.roles.size());
    for (size_t i = 0; i < forward.roles.size(); ++i)
    {
        CHECK(reversed.roles[i].erabId == forward.roles[i].erabId);
        CHECK(reversed.roles[i].role == forward.roles[i].role);
        CHECK(reversed.roles[i].linkedDefaultErabId == forward.roles[i].linkedDefaultErabId);
        CHECK(reversed.roles[i].qci == forward.roles[i].qci);
    }
    // The E-RAB list is emitted in readiness order — the default first, then
    // the dedicated ones by ascending identity — so two records of one session
    // are equal whatever order the registry holds them in.
    CHECK(reversed.erabs[0].erabId == 5);
    CHECK(reversed.erabs[1].erabId == 6);
    CHECK(reversed.erabs[2].erabId == 7);
}

TEST_CASE("lte/handover/orchestration: an unverified source session is refused and is not built at all")
{
    // A default-constructed coordination record is the only session a caller
    // can reach without the extractor, and it is refused rather than treated
    // as a verified one. Setting `identityKnown` by hand at the target is
    // exactly what this gate exists to stop.
    CoordinationRecord blank;
    CHECK_FALSE(blank.source.isVerified());

    HandoverCoordinator coordinator{ExecutionMode::ISOLATED_SIMULATOR};
    CoordinationRefusalRecord failure;
    CHECK_FALSE(coordinator.openTransaction(blank.source, TargetBinding(), MmeUeS1apId, 1, 1,
                                            std::chrono::seconds{5}, nullptr, &failure));
    CHECK(failure.refusal == CoordinationRefusal::SOURCE_PROVENANCE_NOT_ESTABLISHED);
    CHECK(coordinator.size() == 0);

    const HandoverTargetBinding *selected = nullptr;
    CHECK_FALSE(HandoverCoordinator::SelectTarget(blank.source, {TargetBinding()}, TargetEnbId, selected, &failure));
    CHECK(failure.refusal == CoordinationRefusal::SOURCE_PROVENANCE_NOT_ESTABLISHED);
}

TEST_CASE("lte/handover/orchestration: a source session cannot be reached through a fabricated entry")
{
    SourceLab lab;

    SUBCASE("a provisional context is not a source")
    {
        EnbUeEntry &provisional = lab.mux.registry().allocateProvisional();
        CHECK(UeRegistry::isProvisional(provisional));
        CHECK_THROWS_AS(ExtractSourceSession(provisional, SourceIdentity(), CgiOf(SourceIdentity()), 1),
                        SourceProvenanceError);
    }

    SUBCASE("a source identity naming two networks is refused")
    {
        lab.establish();
        const EutranCgi otherNetwork{Plmn{"001", "01"}, CgiOf(SourceIdentity()).cellId};
        CHECK_THROWS_AS(ExtractSourceSession(*lab.entry, SourceIdentity(), otherNetwork, 1), SourceProvenanceError);
        const EutranCgi otherCell{TestPlmn(), CgiOf(TargetIdentity()).cellId};
        CHECK_THROWS_AS(ExtractSourceSession(*lab.entry, SourceIdentity(), otherCell, 1), SourceProvenanceError);
    }

    SUBCASE("no association epoch is no source")
    {
        lab.establish();
        CHECK_THROWS_AS(ExtractSourceSession(*lab.entry, SourceIdentity(), CgiOf(SourceIdentity()), 0),
                        SourceProvenanceError);
    }

    SUBCASE("a source with no s1 connection is refused")
    {
        lab.establish();
        lab.entry->s1 = UeS1State::NO_S1;
        CHECK_THROWS_AS(ExtractSourceSession(*lab.entry, SourceIdentity(), CgiOf(SourceIdentity()), 1),
                        SourceProvenanceError);
    }

    SUBCASE("a source with no network-confirmed pdn address is refused")
    {
        // The address is the one the UE's own NAS assigned and this eNB
        // validated at bearer activation. Before that confirmation there is no
        // session address to preserve and nothing may be claimed for one.
        lab.establish({}, false);
        CHECK(lab.entry->bearer.ueIpv4() == std::array<uint8_t, 4>{});
        CHECK_THROWS_AS(ExtractSourceSession(*lab.entry, SourceIdentity(), CgiOf(SourceIdentity()), 1),
                        SourceProvenanceError);
    }

    SUBCASE("a source with no negotiated ue-ambr is refused")
    {
        lab.establish();
        lab.entry->ueAmbr.reset();
        CHECK_THROWS_AS(ExtractSourceSession(*lab.entry, SourceIdentity(), CgiOf(SourceIdentity()), 1),
                        SourceProvenanceError);
    }

    SUBCASE("a dedicated bearer not linked to the session default is refused")
    {
        lab.establish();
        // The registry refuses to add such a bearer, so the malformed state is
        // arranged directly and the extractor is what refuses to describe it.
        // The link is a plausible EPS bearer identity in its own right — the
        // bearer layer accepts it — that simply names a bearer this session
        // does not hold as its default.
        BearerContext unlinked{BearerKind::DEDICATED};
        BearerParameters parameters{};
        parameters.erabId = 6;
        parameters.qci = 7;
        parameters.ueId = lab.ue.ueId;
        parameters.sgwAddress = Ip(127, 0, 0, 9);
        parameters.sgwTeid = 0x0E0F1011u;
        parameters.localTeid = 0x0BADBEEFu;
        parameters.linkedDefaultEbi = 7;
        unlinked.establish(parameters, false);
        lab.entry->dedicatedBearers.push_back(std::move(unlinked));
        CHECK_THROWS_AS(ExtractSourceSession(*lab.entry, SourceIdentity(), CgiOf(SourceIdentity()), 1),
                        SourceProvenanceError);
    }
}

// --- B: coordinator binding --------------------------------------------------

TEST_CASE("lte/handover/orchestration: an open transaction binds the source and the target and nothing else")
{
    SourceLab lab;
    lab.establish({6});
    const SourceSession session =
        ExtractSourceSession(*lab.entry, SourceIdentity(), CgiOf(SourceIdentity()), lab.mux.associationEpoch());

    HandoverCoordinator coordinator{ExecutionMode::ISOLATED_SIMULATOR};
    CoordinationRecord record;
    CoordinationRefusalRecord failure;
    REQUIRE(coordinator.openTransaction(session, TargetBinding(), MmeUeS1apId, lab.mux.associationEpoch(), 1,
                                        std::chrono::seconds{30}, &record, &failure));
    CHECK(record.source.isVerified());
    CHECK(record.mmeUeS1apId == MmeUeS1apId);
    CHECK(record.target.enbId == TargetEnbId);
    CHECK(record.sourceAssociationEpoch == lab.mux.associationEpoch());
    CHECK(record.targetAssociationEpoch == 1);
    CHECK(record.targetRadioEndpoint == TargetBinding().radioEndpoint);
    CHECK(record.pdnAddress == session.ueIpv4);
    CHECK(record.state == OrchestrationState::SOURCE_CONNECTED);
    CHECK(record.transaction.mmeUeS1apId == MmeUeS1apId);

    // The arrival token is what the target preparation issues, and until the
    // component that learned it has bound it the record is incomplete and
    // authorizes nothing at all.
    CHECK(record.arrivalToken == 0);
    CHECK_FALSE(record.complete());
}

TEST_CASE("lte/handover/orchestration: a live epc process refuses every coordination entry point")
{
    SourceLab lab;
    lab.establish();
    const SourceSession session =
        ExtractSourceSession(*lab.entry, SourceIdentity(), CgiOf(SourceIdentity()), lab.mux.associationEpoch());

    HandoverCoordinator live{ExecutionMode::LIVE_EPC};
    CHECK_FALSE(live.enabled());
    CHECK(std::string(ToString(live.mode())) == "LIVE_EPC");

    CoordinationRefusalRecord failure;
    CHECK_FALSE(live.openTransaction(session, TargetBinding(), MmeUeS1apId, 1, 1, std::chrono::seconds{30}, nullptr,
                                     &failure));
    CHECK(failure.refusal == CoordinationRefusal::LIVE_MODE_DISABLED);
    CHECK(live.size() == 0);

    const HandoverTransactionId id{MmeUeS1apId, 1, 0};
    CHECK_FALSE(live.bindPreparation(id, 1234, &failure));
    CHECK(failure.refusal == CoordinationRefusal::LIVE_MODE_DISABLED);
    CHECK_FALSE(live.advance(id, OrchestrationState::HANDOVER_PREPARING, &failure));
    CHECK(failure.refusal == CoordinationRefusal::LIVE_MODE_DISABLED);
    CHECK_FALSE(live.cancel(id, &failure));
    CHECK(failure.refusal == CoordinationRefusal::LIVE_MODE_DISABLED);
    CHECK(live.find(id) == nullptr);
}

TEST_CASE("lte/handover/orchestration: a stale association epoch on either side is refused")
{
    SourceLab lab;
    lab.establish();
    const SourceSession session =
        ExtractSourceSession(*lab.entry, SourceIdentity(), CgiOf(SourceIdentity()), lab.mux.associationEpoch());

    HandoverCoordinator coordinator{ExecutionMode::ISOLATED_SIMULATOR};
    CoordinationRefusalRecord failure;
    CHECK_FALSE(coordinator.openTransaction(session, TargetBinding(), MmeUeS1apId, lab.mux.associationEpoch() + 1, 1,
                                            std::chrono::seconds{30}, nullptr, &failure));
    CHECK(failure.refusal == CoordinationRefusal::STALE_ASSOCIATION_EPOCH);

    CHECK_FALSE(coordinator.openTransaction(session, TargetBinding(5), MmeUeS1apId, lab.mux.associationEpoch(), 1,
                                            std::chrono::seconds{30}, nullptr, &failure));
    CHECK(failure.refusal == CoordinationRefusal::STALE_ASSOCIATION_EPOCH);
    CHECK(coordinator.size() == 0);
}

TEST_CASE("lte/handover/orchestration: a target not permitted for this source is refused")
{
    SourceLab lab;
    lab.establish();
    const SourceSession session =
        ExtractSourceSession(*lab.entry, SourceIdentity(), CgiOf(SourceIdentity()), lab.mux.associationEpoch());

    HandoverCoordinator coordinator{ExecutionMode::ISOLATED_SIMULATOR};
    CoordinationRefusalRecord failure;

    HandoverTargetBinding unpermitted = TargetBinding();
    unpermitted.permittedSource = TargetIdentity();
    CHECK_FALSE(coordinator.openTransaction(session, unpermitted, MmeUeS1apId, 1, 1, std::chrono::seconds{30},
                                            nullptr, &failure));
    CHECK(failure.refusal == CoordinationRefusal::TARGET_NOT_PERMITTED);

    HandoverTargetBinding unready = TargetBinding();
    unready.ready = false;
    CHECK_FALSE(coordinator.openTransaction(session, unready, MmeUeS1apId, 1, 1, std::chrono::seconds{30}, nullptr,
                                            &failure));
    CHECK(failure.refusal == CoordinationRefusal::TARGET_NOT_READY);

    // A source may not hand a UE over to the cell it is already serving.
    HandoverTargetBinding self = TargetBinding();
    self.identity = SourceIdentity();
    CHECK_FALSE(coordinator.openTransaction(session, self, MmeUeS1apId, 1, 1, std::chrono::seconds{30}, nullptr,
                                            &failure));
    CHECK(failure.refusal == CoordinationRefusal::TARGET_NOT_PERMITTED);
    CHECK(coordinator.size() == 0);
}

TEST_CASE("lte/handover/orchestration: one live transaction per ue session and a dead one is replaced")
{
    SourceLab lab;
    lab.establish();
    const SourceSession session =
        ExtractSourceSession(*lab.entry, SourceIdentity(), CgiOf(SourceIdentity()), lab.mux.associationEpoch());

    HandoverCoordinator coordinator{ExecutionMode::ISOLATED_SIMULATOR};
    CoordinationRecord record;
    CoordinationRefusalRecord failure;
    REQUIRE(coordinator.openTransaction(session, TargetBinding(), MmeUeS1apId, 1, 1, std::chrono::seconds{30},
                                        &record, &failure));
    CHECK(coordinator.size() == 1);

    CHECK_FALSE(coordinator.openTransaction(session, TargetBinding(), MmeUeS1apId, 1, 1, std::chrono::seconds{30},
                                            nullptr, &failure));
    CHECK(failure.refusal == CoordinationRefusal::CONFLICTING_HANDOVER_PENDING);
    CHECK(coordinator.size() == 1);

    // A cancelled transaction authorizes nothing and is never revived, but the
    // next attempt for the same UE is a fresh one in its place rather than a
    // continuation of the dead one.
    REQUIRE(coordinator.cancel(record.transaction, &failure));
    REQUIRE(coordinator.openTransaction(session, TargetBinding(), MmeUeS1apId, 1, 1, std::chrono::seconds{30},
                                        &record, &failure));
    CHECK(coordinator.size() == 1);
    CHECK(record.state == OrchestrationState::SOURCE_CONNECTED);
}

TEST_CASE("lte/handover/orchestration: cancellation is idempotent and is never revoked")
{
    SourceLab lab;
    lab.establish();
    const SourceSession session =
        ExtractSourceSession(*lab.entry, SourceIdentity(), CgiOf(SourceIdentity()), lab.mux.associationEpoch());

    HandoverCoordinator coordinator{ExecutionMode::ISOLATED_SIMULATOR};
    CoordinationRecord record;
    REQUIRE(coordinator.openTransaction(session, TargetBinding(), MmeUeS1apId, 1, 1, std::chrono::seconds{30},
                                        &record, nullptr));
    const HandoverTransactionId id = record.transaction;

    CoordinationRefusalRecord failure;
    REQUIRE(coordinator.cancel(id, &failure));
    REQUIRE(coordinator.cancel(id, &failure));
    CHECK(coordinator.find(id) == nullptr);
    CHECK(coordinator.findByMmeUeS1apId(MmeUeS1apId) == nullptr);

    // Nothing moves a cancelled record again: not an advance, not a binding
    // and not a command gate.
    CHECK_FALSE(coordinator.advance(id, OrchestrationState::HANDOVER_PREPARING, &failure));
    CHECK(failure.refusal == CoordinationRefusal::TRANSACTION_CANCELLED);
    CHECK_FALSE(coordinator.bindPreparation(id, 4321, &failure));
    CHECK(failure.refusal == CoordinationRefusal::TRANSACTION_CANCELLED);
}

TEST_CASE("lte/handover/orchestration: expiry stops a record authorizing anything and releases nothing")
{
    SourceLab lab;
    lab.establish();
    const uint32_t teidBefore = lab.entry->bearer.parameters().localTeid;
    const SourceSession session =
        ExtractSourceSession(*lab.entry, SourceIdentity(), CgiOf(SourceIdentity()), lab.mux.associationEpoch());

    HandoverCoordinator coordinator{ExecutionMode::ISOLATED_SIMULATOR};
    CoordinationRecord record;
    REQUIRE(coordinator.openTransaction(session, TargetBinding(), MmeUeS1apId, 1, 1, std::chrono::milliseconds{1},
                                        &record, nullptr));
    const HandoverTransactionId id = record.transaction;
    std::this_thread::sleep_for(std::chrono::milliseconds{5});

    // A record whose deadline has passed is unusable whether or not anything
    // has swept it yet.
    CoordinationRefusalRecord failure;
    CHECK_FALSE(coordinator.advance(id, OrchestrationState::HANDOVER_PREPARING, &failure));
    CHECK(failure.refusal == CoordinationRefusal::TRANSACTION_EXPIRED);

    CHECK(coordinator.expireDue(std::chrono::steady_clock::now()) == 1);
    CHECK(coordinator.find(id) == nullptr);
    CHECK_FALSE(coordinator.advance(id, OrchestrationState::HANDOVER_PREPARING, &failure));
    CHECK(failure.refusal == CoordinationRefusal::TRANSACTION_CANCELLED);

    // Expiry is not an authorization and never has been: it is how a record
    // stops being usable, and it releases nothing on either eNB.
    CHECK(lab.entry->s1 == UeS1State::BEARER_ACTIVE);
    CHECK(lab.entry->bearer.active());
    CHECK(lab.entry->bearer.parameters().localTeid == teidBefore);
}

TEST_CASE("lte/handover/orchestration: the preparation binding is where the arrival token enters")
{
    SourceLab lab;
    lab.establish();
    const SourceSession session =
        ExtractSourceSession(*lab.entry, SourceIdentity(), CgiOf(SourceIdentity()), lab.mux.associationEpoch());

    // The target runs under an association epoch of its own, so the
    // coordinator's provisional transaction identity is not the one the rest
    // of the system holds once the preparation is bound.
    HandoverCoordinator coordinator{ExecutionMode::ISOLATED_SIMULATOR};
    CoordinationRecord record;
    REQUIRE(coordinator.openTransaction(session, TargetBinding(5), MmeUeS1apId, lab.mux.associationEpoch(), 5,
                                        std::chrono::seconds{30}, &record, nullptr));
    const HandoverTransactionId provisional = record.transaction;

    CoordinationRefusalRecord failure;
    CHECK_FALSE(coordinator.bindPreparation(provisional, 9, &failure));
    CHECK(failure.refusal == CoordinationRefusal::STALE_ASSOCIATION_EPOCH);

    const HandoverTransactionId targetSide{MmeUeS1apId, 5, 42};
    CHECK_FALSE(coordinator.bindPreparation(targetSide, 0, &failure));
    CHECK(failure.refusal == CoordinationRefusal::INCOMPLETE_COORDINATION_RECORD);

    REQUIRE(coordinator.bindPreparation(targetSide, 0x12345678u, &failure));
    CHECK(coordinator.find(provisional) == nullptr);
    const CoordinationRecord *bound = coordinator.find(targetSide);
    REQUIRE(bound != nullptr);
    CHECK(bound->arrivalToken == 0x12345678u);
    CHECK(bound->complete());

    // A second binding that disagrees is a conflicting preparation, not a
    // second token for the same transaction.
    CHECK_FALSE(coordinator.bindPreparation(targetSide, 0x99, &failure));
    CHECK(failure.refusal == CoordinationRefusal::CONFLICTING_HANDOVER_PENDING);
    CHECK(coordinator.find(targetSide)->arrivalToken == 0x12345678u);
}

TEST_CASE("lte/handover/orchestration: target selection names a target explicitly and never discovers one")
{
    SourceLab lab;
    lab.establish();
    const SourceSession session =
        ExtractSourceSession(*lab.entry, SourceIdentity(), CgiOf(SourceIdentity()), lab.mux.associationEpoch());

    const std::vector<HandoverTargetBinding> inventory{TargetBinding()};
    const HandoverTargetBinding *selected = nullptr;
    CoordinationRefusalRecord failure;

    // No target is selected by default, and none is taken because it came
    // first in the inventory.
    CHECK_FALSE(HandoverCoordinator::SelectTarget(session, inventory, 0, selected, &failure));
    CHECK(failure.refusal == CoordinationRefusal::NO_AUTHORIZED_TARGET);
    CHECK_FALSE(HandoverCoordinator::SelectTarget(session, inventory, 0x1234, selected, &failure));
    CHECK(failure.refusal == CoordinationRefusal::NO_AUTHORIZED_TARGET);
    CHECK(selected == nullptr);

    REQUIRE(HandoverCoordinator::SelectTarget(session, inventory, TargetEnbId, selected, &failure));
    REQUIRE(selected != nullptr);
    CHECK(selected->identity.enbId == TargetEnbId);

    SUBCASE("a target that names two networks is refused")
    {
        std::vector<HandoverTargetBinding> incoherent{TargetBinding()};
        incoherent[0].tai = Tai{Plmn{"001", "01"}, TargetIdentity().tac};
        CHECK_FALSE(HandoverCoordinator::SelectTarget(session, incoherent, TargetEnbId, selected, &failure));
        CHECK(failure.refusal == CoordinationRefusal::NO_AUTHORIZED_TARGET);

        incoherent[0] = TargetBinding();
        incoherent[0].cgi = EutranCgi{TestPlmn(), 0};
        CHECK_FALSE(HandoverCoordinator::SelectTarget(session, incoherent, TargetEnbId, selected, &failure));
        CHECK(failure.refusal == CoordinationRefusal::NO_AUTHORIZED_TARGET);
    }

    SUBCASE("an incomplete binding directs nobody anywhere")
    {
        std::vector<HandoverTargetBinding> incomplete{TargetBinding()};
        incomplete[0].radioEndpoint = InetAddress{};
        CHECK_FALSE(HandoverCoordinator::SelectTarget(session, incomplete, TargetEnbId, selected, &failure));
        CHECK(failure.refusal == CoordinationRefusal::NO_AUTHORIZED_TARGET);

        incomplete[0] = TargetBinding();
        incomplete[0].associationEpoch = 0;
        CHECK_FALSE(HandoverCoordinator::SelectTarget(session, incomplete, TargetEnbId, selected, &failure));
        CHECK(failure.refusal == CoordinationRefusal::NO_AUTHORIZED_TARGET);
    }

    SUBCASE("a source may not be handed over to itself")
    {
        std::vector<HandoverTargetBinding> self{TargetBinding()};
        self[0].identity = SourceIdentity();
        self[0].cgi = CgiOf(SourceIdentity());
        self[0].tai = Tai{SourceIdentity().plmn, SourceIdentity().tac};
        CHECK_FALSE(HandoverCoordinator::SelectTarget(session, self, SourceEnbId, selected, &failure));
        CHECK(failure.refusal == CoordinationRefusal::TARGET_NOT_PERMITTED);
    }
}

TEST_CASE("lte/handover/orchestration: the orchestration state machine refuses out-of-order events")
{
    // A duplicate of the state a transaction is already in changes nothing.
    CHECK(ApplyOrchestrationEvent(OrchestrationState::SOURCE_CONNECTED, OrchestrationState::SOURCE_CONNECTED) ==
          OrchestrationState::SOURCE_CONNECTED);
    CHECK(ApplyOrchestrationEvent(OrchestrationState::UE_RELOCATION_PENDING,
                                  OrchestrationState::UE_RELOCATION_PENDING) ==
          OrchestrationState::UE_RELOCATION_PENDING);

    // One authoritative event per state, in order.
    CHECK(ApplyOrchestrationEvent(OrchestrationState::SOURCE_CONNECTED, OrchestrationState::HANDOVER_PREPARING) ==
          OrchestrationState::HANDOVER_PREPARING);
    CHECK(ApplyOrchestrationEvent(OrchestrationState::HANDOVER_PREPARING, OrchestrationState::TARGET_PREPARED) ==
          OrchestrationState::TARGET_PREPARED);
    CHECK(ApplyOrchestrationEvent(OrchestrationState::TARGET_PREPARED, OrchestrationState::SOURCE_COMMAND_PENDING) ==
          OrchestrationState::SOURCE_COMMAND_PENDING);
    CHECK(ApplyOrchestrationEvent(OrchestrationState::SOURCE_COMMAND_PENDING,
                                  OrchestrationState::UE_RELOCATION_PENDING) ==
          OrchestrationState::UE_RELOCATION_PENDING);
    CHECK(ApplyOrchestrationEvent(OrchestrationState::UE_RELOCATION_PENDING,
                                  OrchestrationState::TARGET_ARRIVAL_CONFIRMED) ==
          OrchestrationState::TARGET_ARRIVAL_CONFIRMED);
    CHECK(ApplyOrchestrationEvent(OrchestrationState::TARGET_ARRIVAL_CONFIRMED,
                                  OrchestrationState::HANDOVER_NOTIFY_SENT) ==
          OrchestrationState::HANDOVER_NOTIFY_SENT);
    CHECK(ApplyOrchestrationEvent(OrchestrationState::HANDOVER_NOTIFY_SENT,
                                  OrchestrationState::AWAITING_CORE_PATH_UPDATE) ==
          OrchestrationState::AWAITING_CORE_PATH_UPDATE);

    // Skipping a step is refused rather than silently taken.
    CHECK_FALSE(ApplyOrchestrationEvent(OrchestrationState::SOURCE_CONNECTED, OrchestrationState::TARGET_PREPARED)
                    .has_value());
    CHECK_FALSE(ApplyOrchestrationEvent(OrchestrationState::SOURCE_CONNECTED,
                                        OrchestrationState::AWAITING_CORE_PATH_UPDATE)
                    .has_value());
    CHECK_FALSE(ApplyOrchestrationEvent(OrchestrationState::HANDOVER_PREPARING,
                                        OrchestrationState::UE_RELOCATION_PENDING)
                    .has_value());

    // A terminal state never moves again. AWAITING_CORE_PATH_UPDATE is the
    // deliberate end of this phase: it is not a completed handover, and
    // nothing reopens it to start one.
    for (const OrchestrationState terminal :
         {OrchestrationState::AWAITING_CORE_PATH_UPDATE, OrchestrationState::PREPARATION_FAILED,
          OrchestrationState::EXECUTION_FAILED, OrchestrationState::CANCELLED})
    {
        CHECK(IsTerminal(terminal));
        CHECK_FALSE(ApplyOrchestrationEvent(terminal, OrchestrationState::SOURCE_CONNECTED).has_value());
        CHECK_FALSE(ApplyOrchestrationEvent(terminal, OrchestrationState::HANDOVER_NOTIFY_SENT).has_value());
        CHECK(ApplyOrchestrationEvent(terminal, terminal) == terminal);
    }
    CHECK_FALSE(IsTerminal(OrchestrationState::HANDOVER_NOTIFY_SENT));

    // A failure or a cancellation is reachable from every non-terminal state,
    // so an attempt that cannot continue is recorded rather than left
    // half-alive waiting for an event that will not come.
    for (const OrchestrationState live :
         {OrchestrationState::SOURCE_CONNECTED, OrchestrationState::HANDOVER_PREPARING,
          OrchestrationState::TARGET_PREPARED, OrchestrationState::SOURCE_COMMAND_PENDING,
          OrchestrationState::UE_RELOCATION_PENDING, OrchestrationState::TARGET_ARRIVAL_CONFIRMED,
          OrchestrationState::HANDOVER_NOTIFY_SENT})
    {
        CHECK(ApplyOrchestrationEvent(live, OrchestrationState::PREPARATION_FAILED) ==
              OrchestrationState::PREPARATION_FAILED);
        CHECK(ApplyOrchestrationEvent(live, OrchestrationState::EXECUTION_FAILED) ==
              OrchestrationState::EXECUTION_FAILED);
        CHECK(ApplyOrchestrationEvent(live, OrchestrationState::CANCELLED) == OrchestrationState::CANCELLED);
    }
}

// --- C: source Handover Command ---------------------------------------------

namespace
{

// Opens a coordination record for the lab's UE and moves it to the one state
// the command gate accepts: the target has admitted and committed real
// resources and nothing has been sent to the UE yet.
struct Prepared
{
    HandoverCoordinator coordinator{ExecutionMode::ISOLATED_SIMULATOR};
    HandoverTransactionId transaction{};
    uint32_t arrivalToken{};
};

Prepared PrepareFor(SourceLab &lab, uint32_t arrivalToken = 0x0BADF00Du)
{
    Prepared prepared;
    const SourceSession session =
        ExtractSourceSession(*lab.entry, SourceIdentity(), CgiOf(SourceIdentity()), lab.mux.associationEpoch());
    REQUIRE(prepared.coordinator.openTransaction(session, TargetBinding(), MmeUeS1apId, lab.mux.associationEpoch(),
                                                 TargetBinding().associationEpoch, std::chrono::seconds{30},
                                                 nullptr, nullptr));
    prepared.transaction = HandoverTransactionId{MmeUeS1apId, TargetBinding().associationEpoch, 42};
    REQUIRE(prepared.coordinator.bindPreparation(prepared.transaction, arrivalToken, nullptr));
    prepared.arrivalToken = arrivalToken;
    REQUIRE(prepared.coordinator.advance(prepared.transaction, OrchestrationState::HANDOVER_PREPARING, nullptr));
    REQUIRE(prepared.coordinator.advance(prepared.transaction, OrchestrationState::TARGET_PREPARED, nullptr));
    return prepared;
}

HandoverCommand CommandFor(SourceLab &lab)
{
    HandoverCommand command;
    command.mmeUeS1apId = lab.entry->mmeUeS1apId;
    command.enbUeS1apId = lab.entry->enbUeS1apId;
    command.handoverType = HandoverType::INTRA_LTE;
    command.targetToSource = std::vector<uint8_t>{'S', 'I', 'M', '-', 'H', 'O', 'v', '1', 0x00};
    return command;
}

bool DetailNames(const CommandDelivery &outcome, const std::string &name)
{
    return outcome.refusal.has_value() && outcome.refusal->detail.find(name) != std::string::npos;
}

// Everything about a source UE a refusal is forbidden to move. It is compared
// across the call rather than against a fixed expectation, so a subcase that
// deliberately breaks one precondition does not have to defend the value it
// broke.
struct SourceSnapshot
{
    UeS1State s1;
    uint32_t enbUeS1apId, mmeUeS1apId, accessGeneration, radioUeId;
    bool bearerActive, dedicatedActive;
    uint32_t defaultTeid, dedicatedTeid;
    bool hasAmbr;
    uint64_t ambrDownlink, ambrUplink;
    InetAddress peer;
};

SourceSnapshot Take(const EnbUeEntry &entry)
{
    SourceSnapshot snapshot;
    snapshot.s1 = entry.s1;
    snapshot.enbUeS1apId = entry.enbUeS1apId;
    snapshot.mmeUeS1apId = entry.mmeUeS1apId;
    snapshot.accessGeneration = entry.accessGeneration;
    snapshot.radioUeId = entry.radioUeId;
    snapshot.bearerActive = entry.bearer.active();
    snapshot.defaultTeid = entry.bearer.parameters().localTeid;
    snapshot.dedicatedActive = !entry.dedicatedBearers.empty() && entry.dedicatedBearers[0].active();
    snapshot.dedicatedTeid =
        entry.dedicatedBearers.empty() ? 0 : entry.dedicatedBearers[0].parameters().localTeid;
    snapshot.hasAmbr = entry.ueAmbr.has_value();
    snapshot.ambrDownlink = entry.ueAmbr.has_value() ? entry.ueAmbr->downlink : 0;
    snapshot.ambrUplink = entry.ueAmbr.has_value() ? entry.ueAmbr->uplink : 0;
    snapshot.peer = entry.peer;
    return snapshot;
}

bool Same(const SourceSnapshot &a, const SourceSnapshot &b)
{
    return a.s1 == b.s1 && a.enbUeS1apId == b.enbUeS1apId && a.mmeUeS1apId == b.mmeUeS1apId &&
           a.accessGeneration == b.accessGeneration && a.radioUeId == b.radioUeId &&
           a.bearerActive == b.bearerActive && a.dedicatedActive == b.dedicatedActive &&
           a.defaultTeid == b.defaultTeid && a.dedicatedTeid == b.dedicatedTeid && a.hasAmbr == b.hasAmbr &&
           a.ambrDownlink == b.ambrDownlink && a.ambrUplink == b.ambrUplink && a.peer == b.peer;
}

} // namespace

TEST_CASE("lte/handover/orchestration: a connected source ue receives the simulated handover command")
{
    SourceLab lab;
    lab.establish({6});
    Prepared prepared = PrepareFor(lab);

    const CommandDelivery outcome = DeliverHandoverCommand(lab.mux, *lab.entry, prepared.coordinator,
                                                           prepared.transaction, CommandFor(lab), TargetBinding());
    REQUIRE(outcome.delivered);
    CHECK_FALSE(outcome.refusal.has_value());

    // The frame is what the source's production radio sender wrote. It names
    // the authorized target and this transaction's arrival token and carries
    // no address, because no frame is ever authority to direct a UE anywhere.
    const std::vector<link::Message> frames = DrainRadio(lab.ue);
    REQUIRE(frames.size() == 1);
    CHECK(frames[0].type == link::MessageType::SIMULATED_HANDOVER_COMMAND);
    CHECK(frames[0].ueId == lab.ue.ueId);
    const link::SimulatedHandoverCommand command =
        link::DecodeSimulatedHandoverCommand(frames[0].payload.data(), frames[0].payload.size());
    CHECK(command.targetPlmn == EncodePlmn(TargetIdentity().plmn));
    CHECK(command.targetEnbId == TargetEnbId);
    CHECK(command.targetTac == TargetIdentity().tac);
    CHECK(command.arrivalToken == prepared.arrivalToken);
    CHECK(command.mmeUeS1apId == MmeUeS1apId);
    CHECK(command.ueIpv4 == PdnAddress(lab.ue.ueId));
    CHECK(outcome.command.arrivalToken == prepared.arrivalToken);

    // The command has been handed over and the UE is relocating. Nothing here
    // reports a finished handover.
    const CoordinationRecord *record = prepared.coordinator.find(prepared.transaction);
    REQUIRE(record != nullptr);
    CHECK(record->state == OrchestrationState::UE_RELOCATION_PENDING);

    // A second command is refused: the UE is already executing one.
    const CommandDelivery again = DeliverHandoverCommand(lab.mux, *lab.entry, prepared.coordinator,
                                                         prepared.transaction, CommandFor(lab), TargetBinding());
    CHECK_FALSE(again.delivered);
    CHECK(DetailNames(again, "HANDOVER_ALREADY_EXECUTING"));
    CHECK(DrainRadio(lab.ue).empty());
}

TEST_CASE("lte/handover/orchestration: a command delivery moves no source bearer or teid")
{
    SourceLab lab;
    lab.establish({6});
    Prepared prepared = PrepareFor(lab);
    const uint32_t defaultTeid = lab.entry->bearer.parameters().localTeid;
    const uint32_t dedicatedTeid = lab.entry->dedicatedBearers[0].parameters().localTeid;

    REQUIRE(DeliverHandoverCommand(lab.mux, *lab.entry, prepared.coordinator, prepared.transaction, CommandFor(lab),
                                   TargetBinding())
                .delivered);

    // The source keeps its context, its bearers and its transport until the
    // MME releases it. Sending a command is not a release and never has been.
    CHECK(lab.entry->s1 == UeS1State::BEARER_ACTIVE);
    CHECK(lab.entry->bearer.active());
    CHECK(lab.entry->dedicatedBearers[0].active());
    CHECK(lab.entry->bearer.parameters().localTeid == defaultTeid);
    CHECK(lab.entry->dedicatedBearers[0].parameters().localTeid == dedicatedTeid);
    CHECK(lab.entry->enbUeS1apId != 0);
    CHECK(lab.entry->mmeUeS1apId == MmeUeS1apId);
    CHECK(lab.mux.registry().findByLocalTeid(defaultTeid) == lab.entry);
    CHECK(lab.mux.registry().findByLocalTeid(dedicatedTeid) == lab.entry);
}

TEST_CASE("lte/handover/orchestration: the command gate refuses before anything is delivered")
{
    SourceLab lab;
    lab.establish({6});
    Prepared prepared = PrepareFor(lab);
    // The command the MME would have sent is captured before any subcase
    // changes the entry it is read off, so a subcase that breaks one
    // precondition does not accidentally break the command with it.
    const HandoverCommand command = CommandFor(lab);

    // One refusal, one check that it named the reason and one check that it
    // moved nothing: not the source entry, not its bearers, not its transport
    // and not the radio endpoint. A refusal is a refusal to move the UE and
    // nothing more.
    auto refuses = [&](EnbUeEntry &target, HandoverCoordinator &coordinator,
                       const HandoverTransactionId &transaction, const HandoverCommand &attempted,
                       const HandoverTargetBinding &binding, const std::string &expected) {
        const SourceSnapshot before = Take(*lab.entry);
        const CommandDelivery outcome =
            DeliverHandoverCommand(lab.mux, target, coordinator, transaction, attempted, binding);
        CHECK_FALSE(outcome.delivered);
        CHECK(DetailNames(outcome, expected));
        CHECK(Same(Take(*lab.entry), before));
        CHECK(DrainRadio(lab.ue).empty());
    };

    SUBCASE("a provisional context is never commanded")
    {
        EnbUeEntry &provisional = lab.mux.registry().allocateProvisional();
        refuses(provisional, prepared.coordinator, prepared.transaction, command, TargetBinding(),
                "NOT_A_REACHED_UE");
    }

    SUBCASE("a source ue with no s1 connection is refused")
    {
        lab.entry->s1 = UeS1State::NO_S1;
        refuses(*lab.entry, prepared.coordinator, prepared.transaction, command, TargetBinding(),
                "UE_NOT_CONNECTED");
    }

    SUBCASE("a command naming another ue is refused")
    {
        HandoverCommand wrong = command;
        wrong.mmeUeS1apId = MmeUeS1apId + 1;
        refuses(*lab.entry, prepared.coordinator, prepared.transaction, wrong, TargetBinding(),
                "WRONG_COMMAND_UE_IDENTITY");
    }

    SUBCASE("a source whose s1ap identifiers moved is refused")
    {
        lab.entry->enbUeS1apId = lab.entry->enbUeS1apId + 1;
        refuses(*lab.entry, prepared.coordinator, prepared.transaction, command, TargetBinding(),
                "S1AP_IDENTITY_CHANGED");
    }

    SUBCASE("a source whose access epoch moved is refused")
    {
        lab.entry->accessGeneration = lab.entry->accessGeneration + 1;
        refuses(*lab.entry, prepared.coordinator, prepared.transaction, command, TargetBinding(),
                "SESSION_CHANGED");
    }

    SUBCASE("a source association that is no longer the recorded one is refused")
    {
        // A new S1-MME association is a new transport epoch. A handover that
        // began under the old one may not be executed through this one.
        lab.mux.unbindAssociation();
        const uint32_t epoch = lab.mux.bindAssociation(lab.wire, 1);
        CHECK(epoch != 0);
        refuses(*lab.entry, prepared.coordinator, prepared.transaction, command, TargetBinding(),
                "ASSOCIATION_EPOCH_CHANGED");
    }

    SUBCASE("a target that is no longer approved is refused")
    {
        HandoverTargetBinding changed = TargetBinding();
        changed.identity = EnbIdentity{TestPlmn(), 0x00FFFFFEu, 2};
        refuses(*lab.entry, prepared.coordinator, prepared.transaction, command, changed, "TARGET_NOT_APPROVED");
    }

    SUBCASE("a target with no radio endpoint is refused")
    {
        CoordinationRecord *record = prepared.coordinator.findMutable(prepared.transaction);
        REQUIRE(record != nullptr);
        record->targetRadioEndpoint = InetAddress{};
        refuses(*lab.entry, prepared.coordinator, prepared.transaction, command, TargetBinding(),
                "TARGET_ENDPOINT_UNAVAILABLE");
    }

    SUBCASE("a record with no arrival token is refused")
    {
        CoordinationRecord *record = prepared.coordinator.findMutable(prepared.transaction);
        REQUIRE(record != nullptr);
        record->arrivalToken = 0;
        refuses(*lab.entry, prepared.coordinator, prepared.transaction, command, TargetBinding(),
                "ARRIVAL_TOKEN_MISSING");
    }

    SUBCASE("a cancelled transaction is refused")
    {
        REQUIRE(prepared.coordinator.cancel(prepared.transaction, nullptr));
        refuses(*lab.entry, prepared.coordinator, prepared.transaction, command, TargetBinding(),
                "TRANSACTION_CANCELLED");
    }

    SUBCASE("a transaction that is still only preparing has no committed resources")
    {
        HandoverCoordinator earlier{ExecutionMode::ISOLATED_SIMULATOR};
        const SourceSession session =
            ExtractSourceSession(*lab.entry, SourceIdentity(), CgiOf(SourceIdentity()), lab.mux.associationEpoch());
        REQUIRE(earlier.openTransaction(session, TargetBinding(), MmeUeS1apId, lab.mux.associationEpoch(),
                                        TargetBinding().associationEpoch, std::chrono::seconds{30}, nullptr,
                                        nullptr));
        const HandoverTransactionId id{MmeUeS1apId, TargetBinding().associationEpoch, 7};
        REQUIRE(earlier.bindPreparation(id, 5, nullptr));
        REQUIRE(earlier.advance(id, OrchestrationState::HANDOVER_PREPARING, nullptr));
        refuses(*lab.entry, earlier, id, command, TargetBinding(), "NO_COMMITTED_RESOURCES");
    }

    SUBCASE("a live epc process never commands a ue")
    {
        HandoverCoordinator live{ExecutionMode::LIVE_EPC};
        refuses(*lab.entry, live, prepared.transaction, command, TargetBinding(), "LIVE_MODE_DISABLED");
    }
}

// --- E: the isolated MME relay ---------------------------------------------

namespace
{

// The security material the isolated MME states for the UE. It is fixture data
// and not a UE security key; nothing here derives one and the relay carries
// these bytes through without ever reading the key itself.
IsolatedUeSecurity TestSecurity()
{
    IsolatedUeSecurity security;
    security.encryptionAlgorithms = {0x80, 0x00};
    security.integrityAlgorithms = {0x40, 0x00};
    security.context.nextHopChainingCount = 3;
    for (size_t i = 0; i < security.context.nextHopParameter.size(); ++i)
        security.context.nextHopParameter[i] = static_cast<uint8_t>(0xA0 + i);
    return security;
}

// One source eNB serving a real UE, one target eNB that can really admit and
// commit a Handover Request, and the isolated MME between them. Nothing in
// here calls a codec-free path: every message that crosses the relay is
// encoded by the accepted production codec and read back with it.
struct RelayLab
{
    SourceLab source;
    CaptureSender targetWire;
    EnbConfig targetConfig{TestEnbConfig(TargetEnbId, "127.0.0.3", 2)};
    EnbMultiplexer target{targetConfig, targetWire};
    HandoverCoordinator coordinator{ExecutionMode::ISOLATED_SIMULATOR};
    IsolatedMmeRelay relay{coordinator};
    HandoverTransactionId transaction{};
    uint32_t arrivalToken{};

    SourceSession session() const
    {
        return ExtractSourceSession(*source.entry, SourceIdentity(), CgiOf(SourceIdentity()),
                                    source.mux.associationEpoch());
    }

    void open()
    {
        REQUIRE(coordinator.openTransaction(session(), TargetBinding(), MmeUeS1apId, source.mux.associationEpoch(),
                                            TargetBinding().associationEpoch, std::chrono::seconds{30}, nullptr,
                                            nullptr));
        const CoordinationRecord *record = coordinator.findByMmeUeS1apId(MmeUeS1apId);
        REQUIRE(record != nullptr);
        // The provisional identity carries the source association epoch, which
        // is the association this handover is being made under.
        transaction = record->transaction;
        REQUIRE(transaction.associationEpoch == source.mux.associationEpoch());
    }

    // The Handover Required the source's own production codec builds.
    std::vector<uint8_t> requiredPdu(const EnbIdentity &targetCell = TargetIdentity(),
                                     uint32_t mmeId = MmeUeS1apId)
    {
        SourceSession copy = session();
        copy.mmeUeS1apId = mmeId;
        HandoverRequired required;
        CoordinationRefusalRecord failure;
        REQUIRE(BuildHandoverRequired(copy, targetCell, "radioNetwork", CauseHandoverDesirableForRadioReasons,
                                      &required, &failure));
        return EncodeHandoverRequired(required);
    }

    PreparationHop runPreparation(const IsolatedUeSecurity &security = TestSecurity(),
                                  const HandoverTargetBinding &binding = TargetBinding())
    {
        const PreparationHop hop =
            relay.relayPreparation(requiredPdu(), transaction, binding, security, target,
                                   binding.associationEpoch);
        if (hop.delivered)
        {
            transaction = hop.transaction;
            arrivalToken = hop.arrivalToken;
        }
        return hop;
    }
};

// The arrival the UE sends the target it reached, repeating what the source
// authorized and naming both cells. It is a simulator control frame and not
// 3GPP RRC.
link::SimulatedHandoverAccess AccessFor(uint32_t arrivalToken)
{
    link::SimulatedHandoverAccess access;
    access.arrivalToken = arrivalToken;
    access.sourcePlmn = EncodePlmn(TestPlmn());
    access.sourceEnbId = SourceEnbId;
    access.sourceTac = SourceIdentity().tac;
    access.targetPlmn = EncodePlmn(TestPlmn());
    access.targetEnbId = TargetEnbId;
    access.targetTac = TargetIdentity().tac;
    access.mmeUeS1apId = MmeUeS1apId;
    access.ueIpv4 = PdnAddress(1);
    return access;
}

} // namespace

TEST_CASE("lte/handover/orchestration: a simulated handover container is labelled and is never rrc")
{
    // The label is ASCII and deliberately not anything a real RRC message
    // starts with, so a container carrying it cannot be mistaken for one.
    CHECK(SimulatedContainerLabel.size() == 8);

    const auto container = BuildSimulatedSourceToTarget(MmeUeS1apId, 0x0012345u, PdnAddress(1));
    REQUIRE(container.size() == 20);
    CHECK(IsSimulatedContainer(container));
    CHECK(std::equal(SimulatedContainerLabel.begin(), SimulatedContainerLabel.end(), container.begin()));

    // It names the session and the PDN address and nothing else. An opaque
    // container is not authority to invent security or RRC content, so there
    // is none in here and nothing parses past the label.
    CHECK(container[8] == 0x00);
    CHECK(container[9] == 0x00);
    CHECK(container[10] == 0x00);
    CHECK(container[11] == static_cast<uint8_t>(MmeUeS1apId));
    CHECK(container[12] == 0x00);
    CHECK(container[13] == 0x01);
    CHECK(container[14] == 0x23);
    CHECK(container[15] == 0x45);
    CHECK(container[16] == 10);
    CHECK(container[17] == 45);
    CHECK(container[18] == 0);
    CHECK(container[19] == 1);

    // A container that names no session is refused rather than built.
    CHECK_THROWS_AS(BuildSimulatedSourceToTarget(0, 0x0012345u, PdnAddress(1)), std::invalid_argument);
    CHECK_THROWS_AS(BuildSimulatedSourceToTarget(MmeUeS1apId, 0, PdnAddress(1)), std::invalid_argument);
    CHECK_THROWS_AS(BuildSimulatedSourceToTarget(MmeUeS1apId, 0x0012345u, Ip(0, 0, 0, 0)), std::invalid_argument);

    // A container that does not carry the label is not one of these, whatever
    // it is.
    CHECK_FALSE(IsSimulatedContainer({}));
    CHECK_FALSE(IsSimulatedContainer({0x00, 0x01, 0x02, 0x03}));
    CHECK_FALSE(IsSimulatedContainer({'S', 'I', 'M', '-', 'H', 'O', 'v'}));
}

TEST_CASE("lte/handover/orchestration: a handover required is built from the verified session and one named target")
{
    SourceLab lab;
    lab.establish({6});
    const SourceSession session =
        ExtractSourceSession(*lab.entry, SourceIdentity(), CgiOf(SourceIdentity()), lab.mux.associationEpoch());

    HandoverRequired required;
    CoordinationRefusalRecord failure;
    REQUIRE(BuildHandoverRequired(session, TargetIdentity(), "radioNetwork", CauseHandoverDesirableForRadioReasons,
                                  &required, &failure));

    // The identities are the source's own and the one target the coordinator
    // authorized. The cause is stated by the caller: a reason for a handover is
    // a decision and is never filled in silently.
    CHECK(required.mmeUeS1apId == MmeUeS1apId);
    CHECK(required.enbUeS1apId == session.enbUeS1apId);
    CHECK(required.handoverType == HandoverType::INTRA_LTE);
    CHECK(required.causeCategory == "radioNetwork");
    CHECK(required.causeValue == CauseHandoverDesirableForRadioReasons);
    CHECK(required.target.enbId == TargetIdentity().enbId);
    CHECK(required.target.tac == TargetIdentity().tac);
    CHECK(required.target.plmn.mcc == TestPlmn().mcc);
    CHECK(required.target.plmn.mnc == TestPlmn().mnc);

    // Indirect GTP-U forwarding is not implemented, so the message never
    // promises the source a transport this system does not have.
    CHECK_FALSE(required.directForwardingPathAvailable);

    // The container is the simulator's own and is labelled as one.
    REQUIRE(IsSimulatedContainer(required.sourceToTarget));
    CHECK(required.sourceToTarget == BuildSimulatedSourceToTarget(MmeUeS1apId, session.enbUeS1apId, session.ueIpv4));

    // It survives the codec unchanged, which is what the relay carries.
    const auto pdu = EncodeHandoverRequired(required);
    const HandoverRequired decoded = DecodeHandoverRequired(pdu.data(), pdu.size());
    CHECK(decoded.mmeUeS1apId == required.mmeUeS1apId);
    CHECK(decoded.enbUeS1apId == required.enbUeS1apId);
    CHECK(decoded.causeCategory == required.causeCategory);
    CHECK(decoded.causeValue == required.causeValue);
    CHECK(decoded.target.enbId == required.target.enbId);
    CHECK(decoded.target.tac == required.target.tac);
    CHECK(decoded.sourceToTarget == required.sourceToTarget);

    SUBCASE("an unverified session builds nothing")
    {
        // A default-constructed `CoordinationRecord` is the only session
        // reachable without the extractor, and its source is not verified.
        CoordinationRecord blank;
        HandoverRequired built;
        CHECK_FALSE(BuildHandoverRequired(blank.source, TargetIdentity(), "radioNetwork", 1, &built, &failure));
        CHECK(failure.refusal == CoordinationRefusal::SOURCE_PROVENANCE_NOT_ESTABLISHED);
    }

    SUBCASE("the source cell cannot hand a ue over to itself")
    {
        HandoverRequired built;
        CHECK_FALSE(BuildHandoverRequired(session, SourceIdentity(), "radioNetwork", 1, &built, &failure));
        CHECK(failure.refusal == CoordinationRefusal::TARGET_NOT_PERMITTED);
    }

    SUBCASE("an incomplete target identity is refused")
    {
        HandoverRequired built;
        CHECK_FALSE(BuildHandoverRequired(session, EnbIdentity{TestPlmn(), 0, 2}, "radioNetwork", 1, &built,
                                          &failure));
        CHECK(failure.refusal == CoordinationRefusal::NO_AUTHORIZED_TARGET);
    }

    SUBCASE("a cause that names no reason is refused")
    {
        HandoverRequired built;
        CHECK_FALSE(BuildHandoverRequired(session, TargetIdentity(), "", 1, &built, &failure));
        CHECK(failure.refusal == CoordinationRefusal::INCOMPLETE_COORDINATION_RECORD);
        CHECK_FALSE(BuildHandoverRequired(session, TargetIdentity(), "radioNetwork", -1, &built, &failure));
        CHECK(failure.refusal == CoordinationRefusal::INCOMPLETE_COORDINATION_RECORD);
    }
}

TEST_CASE("lte/handover/orchestration: a relayed preparation carries real s1ap bytes across every hop")
{
    RelayLab lab;
    lab.source.establish({6});
    lab.open();

    const SourceSession session = lab.session();
    const PreparationHop hop = lab.runPreparation();
    REQUIRE(hop.delivered);
    REQUIRE(hop.coordinationFailure == std::nullopt);
    REQUIRE(hop.targetFailure == std::nullopt);

    // Every hop carried real encoded S1AP produced and read back by the
    // accepted production codec, so this exchange is a relay and not a set of
    // method calls standing in for one.
    CHECK_FALSE(hop.requiredPdu.empty());
    CHECK_FALSE(hop.requestPdu.empty());
    CHECK_FALSE(hop.acknowledgePdu.empty());
    CHECK_FALSE(hop.commandPdu.empty());
    CHECK(hop.failurePdu.empty());

    // The Handover Request the target really received.
    const HandoverRequest request = DecodeHandoverRequest(hop.requestPdu.data(), hop.requestPdu.size());
    CHECK(request.mmeUeS1apId == MmeUeS1apId);
    CHECK(request.handoverType == HandoverType::INTRA_LTE);
    CHECK(request.causeCategory == "radioNetwork");
    CHECK(request.causeValue == CauseHandoverDesirableForRadioReasons);
    CHECK(request.ueAmbr.downlink == session.ueAmbr.downlink);
    CHECK(request.ueAmbr.uplink == session.ueAmbr.uplink);

    // The bearer inventory is the verified source session's, in its canonical
    // order, and the roles the target was given are the network's own statement
    // of the session rather than anything inferred from the list.
    REQUIRE(request.erabs.size() == 2);
    CHECK(request.erabs[0].erabId == 5);
    CHECK(request.erabs[1].erabId == 6);
    CHECK(session.roles.size() == 2);
    CHECK(session.roles[0].role == BearerRole::DEFAULT);
    CHECK(session.roles[1].role == BearerRole::DEDICATED);
    CHECK(session.roles[1].linkedDefaultErabId == 5);

    // The handover security material is carried through and never generated,
    // defaulted or derived by the relay.
    CHECK(request.encryptionAlgorithms == TestSecurity().encryptionAlgorithms);
    CHECK(request.integrityAlgorithms == TestSecurity().integrityAlgorithms);
    CHECK(request.securityContext.nextHopChainingCount == 3);
    CHECK(request.securityContext.nextHopParameter == TestSecurity().context.nextHopParameter);

    // The container is the simulator's own and is preserved byte for byte.
    REQUIRE(IsSimulatedContainer(request.sourceToTarget));
    const HandoverRequired required = DecodeHandoverRequired(hop.requiredPdu.data(), hop.requiredPdu.size());
    CHECK(request.sourceToTarget == required.sourceToTarget);

    // The Acknowledge reports real committed target transport, and the
    // Handover Command carries its container unchanged with no forwarding
    // offered for bearers this system cannot forward.
    const HandoverRequestAcknowledge acknowledge =
        DecodeHandoverRequestAcknowledge(hop.acknowledgePdu.data(), hop.acknowledgePdu.size());
    CHECK(acknowledge.mmeUeS1apId == MmeUeS1apId);
    REQUIRE(acknowledge.admitted.size() == 2);
    CHECK(acknowledge.failed.empty());
    CHECK(acknowledge.admitted[0].erabId == 5);
    CHECK(acknowledge.admitted[1].erabId == 6);
    CHECK(acknowledge.admitted[0].transportLayerAddress != Ip(0, 0, 0, 0));
    CHECK(acknowledge.admitted[1].transportLayerAddress != Ip(0, 0, 0, 0));

    const HandoverCommand command = DecodeHandoverCommand(hop.commandPdu.data(), hop.commandPdu.size());
    CHECK(command.mmeUeS1apId == MmeUeS1apId);
    CHECK(command.enbUeS1apId == session.enbUeS1apId);
    CHECK(command.handoverType == HandoverType::INTRA_LTE);
    CHECK(command.dataForwarding.empty());
    CHECK(command.targetToSource == acknowledge.targetToSource);

    // The target's transaction identity and its arrival token are bound into
    // the record here, by the component that actually learned them.
    CHECK(hop.arrivalToken != 0);
    CHECK(hop.transaction.associationEpoch == TargetBinding().associationEpoch);
    const CoordinationRecord *record = lab.coordinator.find(hop.transaction);
    REQUIRE(record != nullptr);
    CHECK(record->arrivalToken == hop.arrivalToken);
    CHECK(record->state == OrchestrationState::TARGET_PREPARED);
    CHECK(record->complete());

    // The target really owns a provisional context for this UE. It is not a
    // reached UE and it is not one the source could have been sent to.
    const EnbUeEntry *provisional = lab.target.registry().findByMmeUeS1apId(MmeUeS1apId);
    REQUIRE(provisional != nullptr);
    CHECK(UeRegistry::isProvisional(*provisional));
    CHECK(provisional->radioUeId == 0);
}

TEST_CASE("lte/handover/orchestration: a relayed preparation refuses before it reaches a target")
{
    RelayLab lab;
    lab.source.establish({6});
    lab.open();
    const auto goodPdu = lab.requiredPdu();

    auto refuses = [&](const std::vector<uint8_t> &pdu, const HandoverTransactionId &txn,
                       const HandoverTargetBinding &binding, uint64_t epoch, const std::string &name) {
        const PreparationHop hop =
            lab.relay.relayPreparation(pdu, txn, binding, TestSecurity(), lab.target, epoch);
        CHECK_FALSE(hop.delivered);
        CHECK(hop.commandPdu.empty());
        CHECK(hop.acknowledgePdu.empty());
        CHECK(hop.requestPdu.empty());
        REQUIRE(hop.coordinationFailure.has_value());
        CHECK(hop.coordinationFailure->detail.find(name) != std::string::npos);
    };

    SUBCASE("a live epc process relays nothing")
    {
        HandoverCoordinator live{ExecutionMode::LIVE_EPC};
        IsolatedMmeRelay relay{live};
        const PreparationHop hop =
            relay.relayPreparation(goodPdu, lab.transaction, TargetBinding(), TestSecurity(), lab.target,
                                   TargetBinding().associationEpoch);
        CHECK_FALSE(hop.delivered);
        REQUIRE(hop.coordinationFailure.has_value());
        CHECK(hop.coordinationFailure->refusal == CoordinationRefusal::LIVE_MODE_DISABLED);
    }

    SUBCASE("an unknown transaction names no record")
    {
        refuses(goodPdu, HandoverTransactionId{MmeUeS1apId, TargetBinding().associationEpoch, 999},
                TargetBinding(), TargetBinding().associationEpoch, "no live coordination record");
    }

    SUBCASE("a stale target association epoch is refused")
    {
        refuses(goodPdu, lab.transaction, TargetBinding(), TargetBinding().associationEpoch + 1,
                "the target association epoch");
    }

    SUBCASE("a target that is not the authorized one is refused")
    {
        HandoverTargetBinding other = TargetBinding();
        other.identity = EnbIdentity{TestPlmn(), 0x00FFFFFEu, 2};
        refuses(goodPdu, lab.transaction, other, other.associationEpoch, "is not the one this record names");
    }

    SUBCASE("a handover required that cannot be decoded is refused")
    {
        refuses({0x00, 0x01, 0x02}, lab.transaction, TargetBinding(), TargetBinding().associationEpoch,
                "could not be decoded");
    }

    SUBCASE("a handover required naming another ue is refused")
    {
        refuses(lab.requiredPdu(TargetIdentity(), MmeUeS1apId + 1), lab.transaction, TargetBinding(),
                TargetBinding().associationEpoch, "names a different UE");
    }

    SUBCASE("a handover required naming another target is refused")
    {
        refuses(lab.requiredPdu(EnbIdentity{TestPlmn(), 0x00FFFFFEu, 2}), lab.transaction, TargetBinding(),
                TargetBinding().associationEpoch, "names a target this coordinator did not authorize");
    }

    // Nothing a refusal did may have moved the record or the source.
    const CoordinationRecord *record = lab.coordinator.findByMmeUeS1apId(MmeUeS1apId);
    REQUIRE(record != nullptr);
    CHECK(record->state == OrchestrationState::SOURCE_CONNECTED);
    CHECK(record->arrivalToken == 0);
    CHECK_FALSE(record->complete());
    CHECK(lab.source.entry->s1 == UeS1State::BEARER_ACTIVE);
}

TEST_CASE("lte/handover/orchestration: a refused target preparation is reported as a failure and never as a command")
{
    RelayLab lab;
    lab.source.establish({6});
    lab.open();

    // No mutually supported encryption algorithm, so the target's admission
    // refuses with the standard Cause it would put on the wire. That Cause is
    // what makes a Handover Preparation Failure conformant to send.
    IsolatedUeSecurity unsupported = TestSecurity();
    unsupported.encryptionAlgorithms = {0x00, 0x00};
    const PreparationHop hop = lab.runPreparation(unsupported);

    CHECK_FALSE(hop.delivered);
    CHECK(hop.commandPdu.empty());
    CHECK(hop.acknowledgePdu.empty());
    REQUIRE(hop.targetFailure.has_value());
    CHECK_FALSE(hop.coordinationFailure.has_value());

    // The failure is the message the standard names for this outcome and it
    // carries the target's own Cause rather than an invented one.
    REQUIRE_FALSE(hop.failurePdu.empty());
    const HandoverPreparationFailure failure =
        DecodeHandoverPreparationFailure(hop.failurePdu.data(), hop.failurePdu.size());
    CHECK(failure.mmeUeS1apId == MmeUeS1apId);
    CHECK(failure.enbUeS1apId == lab.session().enbUeS1apId);
    CHECK(failure.causeCategory == hop.targetFailure->causeCategory);
    CHECK(failure.causeValue == hop.targetFailure->causeValue);
    CHECK(failure.causeValue >= 0);

    // The preparation started and did not finish, and it is recorded as one
    // rather than left in HANDOVER_PREPARING waiting for an event that will
    // never arrive. Nothing was committed at the target and nothing was told
    // to the UE.
    const CoordinationRecord *record = lab.coordinator.findByMmeUeS1apId(MmeUeS1apId);
    REQUIRE(record != nullptr);
    CHECK(record->state == OrchestrationState::PREPARATION_FAILED);
    CHECK(record->arrivalToken == 0);
    CHECK(IsTerminal(record->state));
    CHECK(lab.target.registry().findByMmeUeS1apId(MmeUeS1apId) == nullptr);
    CHECK(DrainRadio(lab.source.ue).empty());
    CHECK(lab.source.entry->bearer.parameters().localTeid != 0);
}

TEST_CASE("lte/handover/orchestration: a target refusal with no wire cause sends no failure message")
{
    RelayLab lab;
    lab.source.establish({6});
    lab.open();

    // With no association bound the target cannot even admit, and the refusal
    // is purely internal. There is no conformant Cause to report it under, so
    // nothing is invented: the refusal is reported and no message goes out.
    lab.target.unbindAssociation();

    IsolatedUeSecurity unsupported = TestSecurity();
    unsupported.encryptionAlgorithms = {0x00, 0x00};
    const PreparationHop hop = lab.runPreparation(unsupported);

    CHECK_FALSE(hop.delivered);
    CHECK(hop.commandPdu.empty());
    CHECK(hop.failurePdu.empty());
    REQUIRE(hop.targetFailure.has_value());
    CHECK(hop.targetFailure->causeValue < 0);

    const CoordinationRecord *record = lab.coordinator.findByMmeUeS1apId(MmeUeS1apId);
    REQUIRE(record != nullptr);
    CHECK(record->state == OrchestrationState::PREPARATION_FAILED);
}


TEST_CASE("lte/handover/orchestration: a target arrival is confirmed only from the arrival the target accepted")
{
    RelayLab lab;
    lab.source.establish({6});
    lab.open();
    CoordinationRefusalRecord failure;

    // Nothing has arrived anywhere yet, so there is no arrival to report and
    // nothing may be confirmed. The evidence is read out of the target and a
    // caller has no way to hand one over.
    REQUIRE(lab.target.lastVerifiedArrival() == std::nullopt);
    CHECK_FALSE(lab.relay.confirmTargetArrival(lab.target, &failure));
    CHECK(failure.refusal == CoordinationRefusal::WRONG_TRANSACTION_STATE);
    CHECK(failure.detail.find("has not accepted a handover arrival") != std::string::npos);

    const PreparationHop hop = lab.runPreparation();
    REQUIRE(hop.delivered);

    // A prepared target owns transport for a UE that has not arrived. The
    // preparation is not arrival evidence and the relay will not take one.
    REQUIRE(lab.target.lastVerifiedArrival() == std::nullopt);
    CHECK_FALSE(lab.relay.confirmTargetArrival(lab.target, &failure));
    CHECK(failure.refusal == CoordinationRefusal::WRONG_TRANSACTION_STATE);

    const HandoverCommand command = DecodeHandoverCommand(hop.commandPdu.data(), hop.commandPdu.size());
    REQUIRE(DeliverHandoverCommand(lab.source.mux, *lab.source.entry, lab.coordinator, lab.transaction, command,
                                   TargetBinding())
                .delivered);
    DrainRadio(lab.source.ue);

    // The command was delivered and the UE is relocating. It has still not
    // arrived, so there is still nothing to confirm.
    REQUIRE(lab.target.lastVerifiedArrival() == std::nullopt);
    CHECK_FALSE(lab.relay.confirmTargetArrival(lab.target, &failure));
    CHECK(failure.refusal == CoordinationRefusal::WRONG_TRANSACTION_STATE);

    // The arrival goes through the production radio receive path of the
    // target. That is the whole of the evidence, and it is what the target
    // reports afterwards.
    const auto frame = link::Encode({link::MessageType::SIMULATED_HANDOVER_ACCESS, 1,
                                     link::EncodeSimulatedHandoverAccess(AccessFor(hop.arrivalToken))});
    lab.target.handleRadioFrame(frame.data(), frame.size(), lab.source.ue.radio.LocalAddress());
    REQUIRE(lab.target.lastVerifiedArrival().has_value());

    REQUIRE(lab.relay.confirmTargetArrival(lab.target, &failure));
    const CoordinationRecord *record = lab.coordinator.find(lab.transaction);
    REQUIRE(record != nullptr);
    CHECK(record->state == OrchestrationState::TARGET_ARRIVAL_CONFIRMED);

    // A repeat of the same confirmation is the same event rather than a second
    // one: it changes nothing and does not move the transaction on.
    CHECK(lab.relay.confirmTargetArrival(lab.target, &failure));
    CHECK(record->state == OrchestrationState::TARGET_ARRIVAL_CONFIRMED);
}

TEST_CASE("lte/handover/orchestration: an arrival that disagrees with the record confirms nothing")
{
    // The target's arrival gate is not the end of the check. What it accepted
    // still has to agree with what this transaction already binds, so a UE
    // cannot be confirmed by restating a session it is not part of.
    auto run = [&](const std::string &name, const std::function<void(RelayLab &)> &breakIt) {
        RelayLab lab;
        lab.source.establish({6});
        lab.open();
        const PreparationHop hop = lab.runPreparation();
        REQUIRE(hop.delivered);
        const HandoverCommand command = DecodeHandoverCommand(hop.commandPdu.data(), hop.commandPdu.size());
        REQUIRE(DeliverHandoverCommand(lab.source.mux, *lab.source.entry, lab.coordinator, lab.transaction, command,
                                       TargetBinding())
                    .delivered);
        DrainRadio(lab.source.ue);
        const auto frame = link::Encode({link::MessageType::SIMULATED_HANDOVER_ACCESS, 1,
                                         link::EncodeSimulatedHandoverAccess(AccessFor(hop.arrivalToken))});
        lab.target.handleRadioFrame(frame.data(), frame.size(), lab.source.ue.radio.LocalAddress());
        REQUIRE(lab.target.lastVerifiedArrival().has_value());

        // Break the agreement between the accepted arrival and the record.
        const s1ap::VerifiedTargetArrival before = *lab.target.lastVerifiedArrival();
        breakIt(lab);

        CoordinationRefusalRecord failure;
        CHECK_FALSE(lab.relay.confirmTargetArrival(lab.target, &failure));
        REQUIRE(failure.detail.find(name) != std::string::npos);

        // The refusal moved nothing.
        const CoordinationRecord *record = lab.coordinator.find(lab.transaction);
        REQUIRE(record != nullptr);
        CHECK(record->state == OrchestrationState::UE_RELOCATION_PENDING);
        CHECK(before.arrivalToken != 0);
    };

    run("does not present the token", [](RelayLab &lab) {
        lab.coordinator.findMutable(lab.transaction)->arrivalToken ^= 0x5A5A5A5Au;
    });
    run("names another source cell", [](RelayLab &lab) {
        lab.coordinator.findMutable(lab.transaction)->source.sourceCell.enbId ^= 0x0000FF00u;
    });
    run("names another target cell", [](RelayLab &lab) {
        lab.coordinator.findMutable(lab.transaction)->target.enbId ^= 0x0000FF00u;
    });
    run("names another PDN address", [](RelayLab &lab) {
        lab.coordinator.findMutable(lab.transaction)->pdnAddress[3] ^= 0xFFu;
    });
}

TEST_CASE("lte/handover/orchestration: the handover notify the target really sent is accepted once and then is idempotent")
{
    RelayLab lab;
    lab.source.establish({6});
    lab.open();

    const PreparationHop hop = lab.runPreparation();
    REQUIRE(hop.delivered);
    const HandoverCommand command = DecodeHandoverCommand(hop.commandPdu.data(), hop.commandPdu.size());
    REQUIRE(DeliverHandoverCommand(lab.source.mux, *lab.source.entry, lab.coordinator, lab.transaction, command,
                                   TargetBinding())
                .delivered);
    DrainRadio(lab.source.ue);

    const auto frame = link::Encode({link::MessageType::SIMULATED_HANDOVER_ACCESS, 1,
                                     link::EncodeSimulatedHandoverAccess(AccessFor(hop.arrivalToken))});
    lab.target.handleRadioFrame(frame.data(), frame.size(), lab.source.ue.radio.LocalAddress());
    REQUIRE(lab.relay.confirmTargetArrival(lab.target, nullptr));

    // The target builds its Handover Notify from the proven arrival and sends
    // it through the real association. What the relay accepts is the bytes that
    // actually left, not a message the test assembled.
    const HandoverNotifyOutcome outcome = lab.target.notifyHandover(lab.transaction);
    REQUIRE(outcome.sent);
    REQUIRE(outcome.message.has_value());
    REQUIRE(lab.targetWire.sent.size() == 1);
    const std::vector<uint8_t> &notifyPdu = lab.targetWire.sent.front().second;

    CoordinationRefusalRecord failure;
    REQUIRE(lab.relay.acceptHandoverNotify(notifyPdu, lab.transaction, &failure));

    // The transaction stops at AWAITING_CORE_PATH_UPDATE. That state is named
    // for what has not happened: the MME-controlled downlink bearer path update
    // and the source context release are later work and nothing here performs
    // or reports them.
    const CoordinationRecord *record = lab.coordinator.find(lab.transaction);
    REQUIRE(record != nullptr);
    CHECK(record->state == OrchestrationState::AWAITING_CORE_PATH_UPDATE);
    CHECK(IsTerminal(record->state));

    // The message agrees with what the coordinator holds.
    const HandoverNotify decoded = DecodeHandoverNotify(notifyPdu.data(), notifyPdu.size());
    CHECK(decoded.mmeUeS1apId == MmeUeS1apId);
    CHECK(decoded.cgi.plmn.mcc == TestPlmn().mcc);
    CHECK(decoded.cgi.plmn.mnc == TestPlmn().mnc);
    CHECK(decoded.cgi.cellId == CgiOf(TargetIdentity()).cellId);
    CHECK(decoded.tai.tac == TargetIdentity().tac);

    // A repeat notification is the same event, not a second one.
    CHECK(lab.relay.acceptHandoverNotify(notifyPdu, lab.transaction, &failure));
    CHECK(record->state == OrchestrationState::AWAITING_CORE_PATH_UPDATE);
    CHECK(lab.targetWire.sent.size() == 1);

    // A Handover Notify from anywhere but the target is refused, and one that
    // names another cell than this transaction moved to is refused even though
    // the transaction is already notified.
    CoordinationRefusalRecord uplinkFailure;
    lab.relay.onUplink(false, notifyPdu, &uplinkFailure);
    REQUIRE(lab.relay.lastRefusal().has_value());

    HandoverNotify wrongCell = decoded;
    wrongCell.cgi.cellId = 0x00FFFFF0;
    const auto wrongPdu = EncodeHandoverNotify(wrongCell);
    CHECK_FALSE(lab.relay.acceptHandoverNotify(wrongPdu, lab.transaction, &failure));
    CHECK(failure.refusal == CoordinationRefusal::TARGET_NOT_PERMITTED);

    // Nothing about a refused message moved the transaction.
    CHECK(record->state == OrchestrationState::AWAITING_CORE_PATH_UPDATE);
}
