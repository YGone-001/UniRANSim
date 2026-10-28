//
// This file is a part of UERANSIM project.
// Copyright (c) 2027 ALİ GÜNGÖR.
//
// https://github.com/aligungr/UERANSIM/
// See README, LICENSE, and CONTRIBUTING files for licensing details.
//

#include <ext/doctest/doctest.h>

#include <lte/enb/codec.hpp>
#include <lte/enb/failure_injection.hpp>
#include <lte/enb/config.hpp>
#include <lte/enb/multiplexer.hpp>
#include <lte/enb/recovery.hpp>
#include <lte/enb/types.hpp>
#include <lte/enb/ue_registry.hpp>
#include <lte/ue/config.hpp>
#include <lte/ue/lifecycle.hpp>
#include <lte/ue/radio_link.hpp>

#include <atomic>
#include <chrono>
#include <cstdio>
#include <fstream>
#include <set>
#include <string>
#include <thread>
#include <vector>

namespace
{

using namespace lte;
using namespace lte::enb;
namespace link = lte::ue::link;

class Sender : public IS1apSender
{
  public:
    void sendS1ap(uint16_t, const std::vector<uint8_t> &pdu) override
    {
        sent.push_back(pdu);
    }

    [[nodiscard]] size_t initiating(uint8_t procedureCode) const
    {
        size_t total = 0;
        for (const auto &pdu : sent)
        {
            const auto probe = s1ap::ProbeS1apPdu(pdu.data(), pdu.size());
            if (probe.kind == s1ap::S1apPdu::Kind::INITIATING && probe.procedureCode == procedureCode)
                ++total;
        }
        return total;
    }

    std::vector<std::vector<uint8_t>> sent;
};

EnbConfig Config()
{
    EnbConfig c;
    c.plmn = {"460", "02"};
    c.enbId = c.tac = 1;
    c.s1uAddress = c.ueLinkAddress = "127.0.0.1";
    c.s1uPort = c.ueLinkPort = 0;
    c.maxUes = 8;
    c.allowLoopbackS1u = true;
    return c;
}

// One simulated radio peer bound to an ephemeral loopback port.
struct FakeUe
{
    udp::UdpServer radio{"127.0.0.1", 0};
    uint32_t ueId;
    explicit FakeUe(uint32_t id) : ueId(id) {}
};

// One long-lived multiplexer plus the association senders the recovery loop
// rebinds between.
struct Lab
{
    EnbConfig config{Config()};
    EnbMultiplexer mux{config};
    Sender first;
    Sender second;
    uint32_t epoch1{};
    uint32_t epoch2{};

    Lab()
    {
        epoch1 = mux.bindAssociation(first, 4);
    }

    // Simulates the successful S1 Setup of a replacement association: the old
    // one is torn down first, exactly as invalidateAccess() does on a loss.
    uint32_t reconnect()
    {
        mux.unbindAssociation();
        epoch2 = mux.bindAssociation(second, 4);
        return epoch2;
    }

    void uplink(const FakeUe &ue, link::MessageType type, std::vector<uint8_t> payload)
    {
        const auto frame = link::Encode({type, ue.ueId, std::move(payload)});
        mux.handleRadioFrame(frame.data(), frame.size(), ue.radio.LocalAddress());
    }

    void ready(const FakeUe &ue, uint8_t ebi, uint32_t generation)
    {
        uplink(ue, link::MessageType::BEARER_TRANSPORT_READY, link::EncodeBearerRestoration(ebi, generation));
    }

    void request(const s1ap::InitialContextSetupRequest &value)
    {
        const auto wire = s1ap::EncodeInitialContextSetupRequest(value);
        mux.handleS1ap(wire.data(), wire.size(), 1);
    }

    void erabSetup(const s1ap::ErabSetupRequest &value)
    {
        const auto wire = s1ap::EncodeErabSetupRequest(value);
        mux.handleS1ap(wire.data(), wire.size(), 1);
    }

    void erabModify(const s1ap::ErabModifyRequest &value)
    {
        const auto wire = s1ap::EncodeErabModifyRequest(value);
        mux.handleS1ap(wire.data(), wire.size(), 1);
    }

    std::vector<link::Message> drain(const FakeUe &ue)
    {
        std::vector<link::Message> messages;
        uint8_t buffer[4096];
        InetAddress peer;
        for (int i = 0; i < 32; ++i)
        {
            const int n = ue.radio.Receive(buffer, sizeof(buffer), 0, peer);
            if (n <= 0)
                break;
            messages.push_back(link::Decode(buffer, static_cast<size_t>(n)));
        }
        return messages;
    }
};

// A fully confirmed EPS session: default EBI 5 plus dedicated EBIs 6 and 7,
// all with live access transport, exactly as a running eNB would hold it.
void Establish(Lab &lab, FakeUe &ue, uint32_t mmeId, uint32_t sgwTeidBase, std::array<uint8_t, 4> ueIpv4)
{
    auto &registry = lab.mux.registry();
    auto &entry = registry.registerPeer(ue.ueId, ue.radio.LocalAddress());
    registry.bindEnbUeS1apId(entry, registry.allocateEnbUeS1apId());
    registry.setMmeUeS1apId(entry, mmeId);
    entry.s1 = UeS1State::BEARER_ACTIVE;

    auto parameters = [&](uint8_t ebi, uint8_t qci) {
        return BearerParameters{ebi,
                                qci,
                                ue.ueId,
                                {127, 0, 0, 9},
                                sgwTeidBase + ebi,
                                registry.allocateLocalTeid(),
                                static_cast<uint8_t>(ebi == 5 ? 0 : 5),
                                {qci, static_cast<uint8_t>(ebi == 5 ? 15 : 8), false, false, {}}};
    };
    entry.bearer.establish(parameters(5, 9));
    entry.bearer.activateUe(ue.ueId, 5, ueIpv4);
    registry.bindLocalTeid(entry, entry.bearer.parameters().localTeid);
    for (uint8_t ebi : {6, 7})
    {
        auto &bearer = registry.addDedicatedBearer(entry, parameters(ebi, 7));
        bearer.activateUe(ue.ueId, ebi, ueIpv4);
        registry.bindLocalTeid(entry, bearer, bearer.parameters().localTeid);
    }
}

// A multi-E-RAB Initial Context Setup Request that re-establishes EBI 5/6/7
// against a fresh SGW transport, as the MME would after a Service Request.
s1ap::InitialContextSetupRequest MultiErab(uint32_t mmeId, uint32_t enbId, uint32_t sgwTeidBase)
{
    s1ap::InitialContextSetupRequest request{};
    request.mmeUeS1apId = mmeId;
    request.enbUeS1apId = enbId;
    request.ueAmbrDl = 1;
    request.ueAmbrUl = 1;
    request.encryptionAlgorithms = {0x80, 0x00};
    request.integrityAlgorithms = {0x00, 0x20};
    for (uint8_t ebi : {5, 6, 7})
    {
        s1ap::ErabToBeSetupItem erab{};
        erab.erabId = ebi;
        erab.qci = (ebi == 5) ? 9 : 7;
        erab.transportLayerAddress = {127, 0, 0, 9};
        erab.gtpTeid = TeidToBytes(sgwTeidBase + ebi);
        erab.nasPduPresent = true;
        erab.nasPdu = {0x77, 0x27};
        request.erabs.push_back(erab);
    }
    return request;
}

// Compact Service Request uplink as the simulated radio sends it after an
// unexpected access loss: S-TMSI followed by the protected NAS PDU.
std::vector<uint8_t> ServiceRequestPayload()
{
    return {1, 0x12, 0x34, 0x56, 0x78, 0xC7, 0x00, 0x01, 0x02};
}

// A temporary fault-injection control file. Created empty and removed on scope
// exit so a test can never leave a command behind for a later one. The poll
// interval is kept at the configured minimum because the injector paces its
// own reads; a test that polls twice sleeps past it.
struct ControlFile
{
    std::string path;

    explicit ControlFile(const std::string &name) : path("/tmp/uniransim-injection-" + name + "-" + Next())
    {
        Write("");
    }

    ~ControlFile() { std::remove(path.c_str()); }

    void Write(const std::string &line) const
    {
        std::ofstream out(path, std::ios::trunc);
        out << line;
    }

    [[nodiscard]] FailureInjectionConfig Config() const
    {
        FailureInjectionConfig config;
        config.controlFile = path;
        config.pollIntervalMs = 10;
        return config;
    }

  private:
    static std::string Next()
    {
        static unsigned long sequence = 0;
        return std::to_string(++sequence);
    }
};

ue::MobilityContext Mobility()
{
    ue::MobilityContext m;
    m.emm = ue::EmmState::REGISTERED;
    m.ecm = ue::EcmState::CONNECTED;
    m.bearer = ue::EpsBearerState::USER_PLANE_READY;
    m.securityContextValid = true;
    m.defaultEbi = 5;
    m.assignedIpv4 = {10, 45, 0, 2};
    m.guti = std::array<uint8_t, 11>{0xF6, 0x64, 0xF0, 0x20, 0, 1, 1, 0x12, 0x34, 0x56, 0x78};
    return m;
}

} // namespace

// ---------------------------------------------------------------------------
// Association epoch and sender rebinding
// ---------------------------------------------------------------------------

TEST_CASE("recovery/binding: a stale epoch cannot transmit through a rebound sender")
{
    S1apSenderBinding binding;
    Sender oldSender;
    Sender newSender;

    CHECK_FALSE(binding.bound());
    CHECK_FALSE(binding.send(1, 1, {0x01}));
    CHECK(binding.unboundRejects() == 1);
    CHECK(binding.staleRejects() == 0);

    binding.bind(oldSender, 1);
    CHECK(binding.bound());
    CHECK(binding.epoch() == 1);
    CHECK(binding.send(1, 1, {0x02}));
    CHECK(oldSender.sent.size() == 1);

    // A handler left over from a previous association is counted, never sent.
    CHECK_FALSE(binding.send(2, 1, {0x03}));
    CHECK(binding.staleRejects() == 1);
    CHECK(oldSender.sent.size() == 1);

    binding.unbind(1);
    binding.bind(newSender, 2);
    CHECK_FALSE(binding.send(1, 1, {0x04}));
    CHECK(binding.staleRejects() == 2);
    CHECK(oldSender.sent.size() == 1);
    CHECK(newSender.sent.empty());
    CHECK(binding.send(2, 1, {0x05}));
    CHECK(newSender.sent.size() == 1);

    // A late teardown of the old association cannot detach the new one.
    binding.unbind(1);
    CHECK(binding.bound());
    CHECK(binding.epoch() == 2);
    CHECK(binding.send(2, 1, {0x06}));
    CHECK(newSender.sent.size() == 2);
    binding.unbind(2);
    CHECK_FALSE(binding.bound());
    CHECK_FALSE(binding.send(2, 1, {0x07}));
    CHECK(binding.unboundRejects() == 2);
}

TEST_CASE("recovery/binding: epochs are never reused and a late teardown cannot detach the new association")
{
    Lab lab;
    Sender other;

    CHECK(lab.epoch1 == 1);
    CHECK(lab.mux.associationBound());
    CHECK(lab.mux.associationEpoch() == 1);
    CHECK_THROWS(lab.mux.bindAssociation(other, 4)); // already bound

    // The replacement association allocates a brand-new epoch.
    const uint32_t replacement = lab.reconnect();
    CHECK(replacement != lab.epoch1);
    CHECK(replacement != 0);
    CHECK(lab.mux.associationBound());
    CHECK(lab.mux.associationEpoch() == replacement);
    CHECK(lab.mux.recoveryCounters().associationsEstablished == 2);

    lab.mux.unbindAssociation();
    CHECK_FALSE(lab.mux.associationBound());
    CHECK(lab.mux.associationEpoch() == 0);

    const uint32_t third = lab.mux.bindAssociation(other, 4);
    CHECK(third == replacement + 1);
    CHECK(third != lab.epoch1);
    CHECK(third != replacement);
    CHECK(lab.mux.nextAssociationEpoch() == third + 1);
    CHECK(lab.mux.recoveryCounters().associationsEstablished == 3);
}

TEST_CASE("recovery/binding: association epoch zero is never allocated")
{
    S1apSenderBinding binding;
    Sender sender;
    CHECK_THROWS(binding.bind(sender, 0));
    CHECK_FALSE(binding.bound());
}

// ---------------------------------------------------------------------------
// Access invalidation after an unexpected association loss
// ---------------------------------------------------------------------------

TEST_CASE("recovery/loss: access transport and S1AP identities die while logical EPS state is retained")
{
    Lab lab;
    FakeUe ue(1);
    Establish(lab, ue, 0x100, 0x2000, {10, 45, 0, 2});
    auto *entry = lab.mux.registry().find(1);
    REQUIRE(entry != nullptr);
    const uint32_t enbId = entry->enbUeS1apId;
    const uint32_t mmeId = entry->mmeUeS1apId;
    const uint32_t defaultTeid = entry->bearer.parameters().localTeid;
    const uint32_t dedicatedTeid = entry->dedicatedBearers[0].parameters().localTeid;
    REQUIRE(defaultTeid != 0);
    REQUIRE(dedicatedTeid != 0);
    const size_t before = lab.first.sent.size();

    CHECK(lab.mux.invalidateAccess() == 1);

    // Nothing is fabricated for the MME: an unexpected loss is not a 3GPP
    // UE Context Release procedure.
    CHECK(lab.first.sent.size() == before);
    CHECK_FALSE(lab.mux.associationBound());

    CHECK(lab.mux.registry().findByEnbUeS1apId(enbId) == nullptr);
    CHECK(lab.mux.registry().findByMmeUeS1apId(mmeId) == nullptr);
    CHECK(lab.mux.registry().findByLocalTeid(defaultTeid) == nullptr);
    CHECK(lab.mux.registry().findByLocalTeid(dedicatedTeid) == nullptr);
    CHECK(entry->enbUeS1apId == 0);
    CHECK(entry->mmeUeS1apId == 0);
    CHECK(entry->s1 == UeS1State::IDLE_RETAINED);

    CHECK(entry->bearer.logicalExists());
    CHECK(entry->bearer.logicalConfirmed());
    CHECK_FALSE(entry->bearer.signalingEstablished());
    CHECK(entry->bearer.parameters().localTeid == 0);
    CHECK(entry->bearer.parameters().sgwTeid == 0);
    for (const auto &bearer : entry->dedicatedBearers)
    {
        CHECK(bearer.logicalExists());
        CHECK(bearer.logicalConfirmed());
        CHECK(bearer.parameters().localTeid == 0);
    }

    const auto &recovery = lab.mux.recoveryCounters();
    CHECK(recovery.accessInvalidations == 1);
    CHECK(recovery.activeUesAffectedByLoss == 1);
    CHECK(recovery.logicalBearersRetained == 3);
    CHECK(recovery.localTeidsInvalidated == 3);
}

TEST_CASE("recovery/loss: the access-loss indication is an internal generation-bound notification")
{
    Lab lab;
    FakeUe ue(1);
    Establish(lab, ue, 0x100, 0x2000, {10, 45, 0, 2});
    const uint32_t generation = lab.mux.registry().find(1)->accessGeneration;

    lab.drain(ue);
    CHECK(lab.mux.invalidateAccess() == 1);
    const auto messages = lab.drain(ue);
    REQUIRE(messages.size() == 1);
    const auto &message = messages.front();
    CHECK(message.type == link::MessageType::S1_ACCESS_LOST);
    CHECK(link::IsDownlink(message.type));
    CHECK_FALSE(link::IsUplink(message.type));
    const auto lost = link::DecodeBearerRestoration(message.payload);
    CHECK(lost.first == 5);                   // the default EBI names the session
    CHECK(lost.second == generation + 1);     // the generation releaseS1 just allocated
    // It is not a UE Context Release Command/Complete, not NAS and not RRC.
    CHECK(message.type != link::MessageType::S1_CONTEXT_RELEASED);
    CHECK(message.type != link::MessageType::S1_CONTEXT_RESTORED);
}

TEST_CASE("recovery/loss: an idle UE is not touched and keeps its access generation")
{
    Lab lab;
    FakeUe ue(1);
    auto &entry = lab.mux.registry().registerPeer(1, ue.radio.LocalAddress());
    const uint32_t generation = entry.accessGeneration;

    CHECK(lab.mux.invalidateAccess() == 0);
    CHECK(entry.accessGeneration == generation);
    CHECK(entry.s1 == UeS1State::NO_S1);
    CHECK(lab.drain(ue).empty());
    CHECK(lab.mux.recoveryCounters().activeUesAffectedByLoss == 0);
}

TEST_CASE("recovery/loss: a duplicated access-loss indication is rejected as stale")
{
    auto mobility = Mobility();
    mobility.acceptAccessRelease(5, 1);
    CHECK(mobility.accessGeneration == 1);
    CHECK(mobility.ecm == ue::EcmState::IDLE);
    CHECK_THROWS(mobility.acceptAccessRelease(5, 1)); // duplicate
    CHECK_THROWS(mobility.acceptAccessRelease(5, 0)); // previous generation
    CHECK_THROWS(mobility.acceptAccessRelease(5, 3)); // skipped generation
    CHECK_THROWS(mobility.acceptAccessRelease(6, 2)); // wrong EBI
    CHECK(mobility.accessGeneration == 1);
}

// ---------------------------------------------------------------------------
// Restoration through a genuine Service Request
// ---------------------------------------------------------------------------

TEST_CASE("recovery/restore: Service Request yields a fresh S1 identity and fresh TEIDs on every bearer")
{
    Lab lab;
    FakeUe ue(1);
    Establish(lab, ue, 0x100, 0x2000, {10, 45, 0, 2});
    auto *entry = lab.mux.registry().find(1);
    const uint32_t oldEnbId = entry->enbUeS1apId;
    const uint32_t oldDefaultTeid = entry->bearer.parameters().localTeid;
    const uint32_t oldDedicatedTeid = entry->dedicatedBearers[0].parameters().localTeid;

    lab.mux.invalidateAccess();
    lab.drain(ue);
    lab.reconnect();

    lab.uplink(ue, link::MessageType::SERVICE_REQUEST, ServiceRequestPayload());
    REQUIRE(entry->s1 == UeS1State::CONTEXT_PENDING);
    REQUIRE(entry->enbUeS1apId != 0);
    CHECK(entry->enbUeS1apId != oldEnbId);
    CHECK(lab.second.initiating(12) == 1); // Initial UE Message

    // A second Service Request cannot replace the pending context.
    const uint32_t pendingEnbId = entry->enbUeS1apId;
    const uint64_t rejectedBefore = lab.mux.recoveryCounters().staleMessagesRejected;
    lab.uplink(ue, link::MessageType::SERVICE_REQUEST, ServiceRequestPayload());
    CHECK(lab.mux.recoveryCounters().staleMessagesRejected == rejectedBefore + 1);
    CHECK(entry->enbUeS1apId == pendingEnbId);

    lab.request(MultiErab(0x100, entry->enbUeS1apId, 0x3000));
    CHECK(entry->s1 == UeS1State::CONTEXT_ESTABLISHED);
    const uint32_t freshDefault = entry->bearer.parameters().localTeid;
    const uint32_t freshDedicated = entry->dedicatedBearers[0].parameters().localTeid;
    CHECK(freshDefault != 0);
    CHECK(freshDedicated != 0);
    CHECK(freshDefault != oldDefaultTeid);
    CHECK(freshDedicated != oldDedicatedTeid);
    CHECK(lab.mux.registry().findByLocalTeid(freshDefault) == entry);
    CHECK(lab.mux.registry().findByLocalTeid(oldDefaultTeid) == nullptr);

    const uint32_t generation = entry->accessGeneration;
    lab.ready(ue, 5, generation);
    CHECK(entry->bearer.active());
    CHECK(entry->s1 == UeS1State::BEARER_ACTIVE);
    lab.ready(ue, 6, generation);
    lab.ready(ue, 7, generation);
    CHECK(entry->dedicatedBearers[0].active());
    CHECK(entry->dedicatedBearers[1].active());
    CHECK(lab.mux.recoveryCounters().successfulUeRestorations == 1);
}

TEST_CASE("recovery/restore: multi-E-RAB Initial Context Setup restores default and dedicated bearers together")
{
    Lab lab;
    FakeUe ue(1);
    Establish(lab, ue, 0x100, 0x2000, {10, 45, 0, 2});
    lab.mux.invalidateAccess();
    lab.drain(ue);
    lab.reconnect();
    lab.uplink(ue, link::MessageType::SERVICE_REQUEST, ServiceRequestPayload());
    auto *entry = lab.mux.registry().find(1);

    lab.request(MultiErab(0x100, entry->enbUeS1apId, 0x3000));
    const uint32_t generation = entry->accessGeneration;

    // The default must come first: a dedicated confirmation before the default
    // is ready is rejected and leaves that bearer unconfirmed.
    const uint64_t rejectedBefore = lab.mux.recoveryCounters().staleMessagesRejected;
    lab.ready(ue, 6, generation);
    CHECK_FALSE(entry->dedicatedBearers[0].active());
    CHECK(lab.mux.recoveryCounters().staleMessagesRejected == rejectedBefore + 1);

    lab.ready(ue, 5, generation);
    lab.ready(ue, 6, generation);
    lab.ready(ue, 7, generation);
    CHECK(entry->bearer.active());
    CHECK(entry->dedicatedBearers[0].active());
    CHECK(entry->dedicatedBearers[1].active());
}

TEST_CASE("recovery/restore: stale generation and unknown EBI confirmations cannot activate a bearer")
{
    Lab lab;
    FakeUe ue(1);
    Establish(lab, ue, 0x100, 0x2000, {10, 45, 0, 2});
    lab.mux.invalidateAccess();
    lab.reconnect();
    lab.uplink(ue, link::MessageType::SERVICE_REQUEST, ServiceRequestPayload());
    auto *entry = lab.mux.registry().find(1);
    lab.request(MultiErab(0x100, entry->enbUeS1apId, 0x3000));
    const uint32_t generation = entry->accessGeneration;

    const uint64_t rejectedBefore = lab.mux.recoveryCounters().staleMessagesRejected;
    lab.ready(ue, 5, generation - 1);
    lab.ready(ue, 5, generation + 1);
    lab.ready(ue, 5, 0);
    lab.ready(ue, 9, generation);
    CHECK_FALSE(entry->bearer.active());
    CHECK(lab.mux.recoveryCounters().staleMessagesRejected == rejectedBefore + 4);

    lab.ready(ue, 5, generation);
    CHECK(entry->bearer.active());
}

TEST_CASE("recovery/stale: an Initial Context Setup from the previous epoch is rejected")
{
    Lab lab;
    FakeUe ue(1);
    Establish(lab, ue, 0x100, 0x2000, {10, 45, 0, 2});
    auto *entry = lab.mux.registry().find(1);
    const uint32_t staleEnbId = entry->enbUeS1apId;

    lab.mux.invalidateAccess();
    lab.reconnect();
    lab.request(MultiErab(0x100, staleEnbId, 0x3000));

    CHECK(lab.mux.recoveryCounters().staleMessagesRejected >= 1);
    CHECK_FALSE(entry->bearer.signalingEstablished());
    CHECK(entry->s1 == UeS1State::IDLE_RETAINED);
    CHECK(lab.second.sent.empty());
}

// ---------------------------------------------------------------------------
// Failure injection and rollback
// ---------------------------------------------------------------------------

TEST_CASE("recovery/injection: the armed send drops exactly one PDU and reports the interruption")
{
    Lab lab;
    FakeUe ue(1);
    Establish(lab, ue, 0x100, 0x2000, {10, 45, 0, 2});
    lab.mux.invalidateAccess();
    lab.reconnect();
    auto *entry = lab.mux.registry().find(1);
    REQUIRE(entry != nullptr);
    REQUIRE(entry->s1 == UeS1State::IDLE_RETAINED);
    const size_t before = lab.second.sent.size();

    lab.mux.armLossBeforeNextS1apSend();
    CHECK_FALSE(lab.mux.injectionTriggered());
    lab.uplink(ue, link::MessageType::SERVICE_REQUEST, ServiceRequestPayload());

    CHECK(lab.mux.injectionTriggered());
    CHECK(lab.mux.recoveryCounters().injectedAssociationLosses == 1);
    CHECK(lab.second.sent.size() == before); // nothing was transmitted
    // The provisional context was discarded rather than left half-open.
    CHECK(entry->s1 == UeS1State::IDLE_RETAINED);
    CHECK(entry->enbUeS1apId == 0);
    CHECK(entry->bearer.logicalConfirmed());

    // The one-shot injection does not block the next legitimate attempt.
    lab.mux.clearInjection();
    CHECK_FALSE(lab.mux.injectionTriggered());
    lab.uplink(ue, link::MessageType::SERVICE_REQUEST, ServiceRequestPayload());
    CHECK(entry->s1 == UeS1State::CONTEXT_PENDING);
    CHECK(lab.second.sent.size() == before + 1);
}

TEST_CASE("recovery/rollback: a lost Initial Context Setup publishes no half-committed bearer")
{
    Lab lab;
    FakeUe ue(1);
    Establish(lab, ue, 0x100, 0x2000, {10, 45, 0, 2});
    lab.mux.invalidateAccess();
    lab.drain(ue); // the S1_ACCESS_LOST indication is not under test here
    lab.reconnect();
    lab.uplink(ue, link::MessageType::SERVICE_REQUEST, ServiceRequestPayload());
    auto *entry = lab.mux.registry().find(1);
    REQUIRE(entry->s1 == UeS1State::CONTEXT_PENDING);

    lab.mux.armLossBeforeNextS1apSend();
    lab.request(MultiErab(0x100, entry->enbUeS1apId, 0x3000));
    CHECK(lab.mux.injectionTriggered());

    CHECK(entry->s1 == UeS1State::CONTEXT_PENDING);
    CHECK_FALSE(entry->bearer.signalingEstablished());
    CHECK(entry->bearer.parameters().localTeid == 0);
    CHECK(entry->mmeUeS1apId == 0);
    for (const auto &bearer : entry->dedicatedBearers)
    {
        CHECK_FALSE(bearer.signalingEstablished());
        CHECK(bearer.parameters().localTeid == 0);
    }
    CHECK(lab.drain(ue).empty());

    // The rollback left a clean slate: a retry on a usable association succeeds.
    lab.mux.clearInjection();
    lab.request(MultiErab(0x100, entry->enbUeS1apId, 0x3000));
    CHECK(entry->s1 == UeS1State::CONTEXT_ESTABLISHED);
    CHECK(entry->mmeUeS1apId == 0x100);
    CHECK(entry->bearer.signalingEstablished());
    CHECK(entry->bearer.parameters().localTeid != 0);
}

TEST_CASE("recovery/rollback: a lost dedicated E-RAB Setup leaves the new bearer unconfirmed")
{
    Lab lab;
    FakeUe ue(1);
    Establish(lab, ue, 0x100, 0x2000, {10, 45, 0, 2});
    auto *entry = lab.mux.registry().find(1);
    REQUIRE(entry->dedicatedBearers.size() == 2);

    s1ap::ErabSetupRequest setup{};
    setup.mmeUeS1apId = entry->mmeUeS1apId;
    setup.enbUeS1apId = entry->enbUeS1apId;
    s1ap::ErabToBeSetupItem erab{};
    erab.erabId = 8;
    erab.qci = 7;
    erab.transportLayerAddress = {127, 0, 0, 9};
    erab.gtpTeid = TeidToBytes(0x4000);
    erab.nasPduPresent = true;
    erab.nasPdu = {0x62, 0x00};
    setup.erabs.push_back(erab);

    lab.mux.armLossBeforeNextS1apSend();
    lab.erabSetup(setup);
    CHECK(lab.mux.injectionTriggered());
    CHECK(entry->dedicatedBearers.size() == 2);
    CHECK(lab.mux.registry().findBearer(*entry, 8) == nullptr);
    CHECK(lab.drain(ue).empty());

    // The two pre-existing dedicated bearers are untouched by the failure.
    CHECK(entry->dedicatedBearers[0].active());
    CHECK(entry->dedicatedBearers[1].active());
}

TEST_CASE("recovery/rollback: a lost E-RAB Modify publishes no partial QoS or transport state")
{
    Lab lab;
    FakeUe ue(1);
    Establish(lab, ue, 0x100, 0x2000, {10, 45, 0, 2});
    auto *entry = lab.mux.registry().find(1);
    auto *bearer = lab.mux.registry().findBearer(*entry, 6);
    REQUIRE(bearer != nullptr);
    const auto before = bearer->parameters();

    s1ap::ErabModifyRequest modify{};
    modify.mmeUeS1apId = entry->mmeUeS1apId;
    modify.enbUeS1apId = entry->enbUeS1apId;
    s1ap::ErabToBeModifiedItem item{};
    item.erabId = 6;
    item.qos = ErabQos{3, 2, false, false, {}};
    item.nasPdu = {0x62, 0x00, 0xC9, 0x5B};
    modify.erabs.push_back(item);

    lab.mux.armLossBeforeNextS1apSend();
    lab.erabModify(modify);
    CHECK(lab.mux.injectionTriggered());

    const auto after = bearer->parameters();
    CHECK(after.qos.qci == before.qos.qci);
    CHECK(after.qos.priorityLevel == before.qos.priorityLevel);
    CHECK(after.sgwTeid == before.sgwTeid);
    CHECK(after.localTeid == before.localTeid);
    CHECK(lab.drain(ue).empty());
}

// ---------------------------------------------------------------------------
// Concurrent UE isolation and resource lifetime
// ---------------------------------------------------------------------------

TEST_CASE("recovery/concurrent: two UEs lose access together and recover independently")
{
    Lab lab;
    FakeUe a(1);
    FakeUe b(2);
    Establish(lab, a, 0x100, 0x2000, {10, 45, 0, 2});
    Establish(lab, b, 0x200, 0x5000, {10, 45, 0, 3});
    auto *entryA = lab.mux.registry().find(1);
    auto *entryB = lab.mux.registry().find(2);
    const uint32_t teidA = entryA->bearer.parameters().localTeid;
    const uint32_t teidB = entryB->bearer.parameters().localTeid;

    CHECK(lab.mux.invalidateAccess() == 2);
    CHECK(entryA->s1 == UeS1State::IDLE_RETAINED);
    CHECK(entryB->s1 == UeS1State::IDLE_RETAINED);
    CHECK(lab.mux.registry().findByLocalTeid(teidA) == nullptr);
    CHECK(lab.mux.registry().findByLocalTeid(teidB) == nullptr);
    CHECK(lab.mux.recoveryCounters().activeUesAffectedByLoss == 2);
    CHECK(lab.mux.recoveryCounters().logicalBearersRetained == 6);

    lab.reconnect();
    lab.uplink(a, link::MessageType::SERVICE_REQUEST, ServiceRequestPayload());
    lab.uplink(b, link::MessageType::SERVICE_REQUEST, ServiceRequestPayload());
    REQUIRE(entryA->s1 == UeS1State::CONTEXT_PENDING);
    REQUIRE(entryB->s1 == UeS1State::CONTEXT_PENDING);
    REQUIRE(entryA->enbUeS1apId != entryB->enbUeS1apId);

    lab.request(MultiErab(0x100, entryA->enbUeS1apId, 0x3000));
    lab.request(MultiErab(0x200, entryB->enbUeS1apId, 0x6000));
    const uint32_t genA = entryA->accessGeneration;
    const uint32_t genB = entryB->accessGeneration;
    lab.ready(a, 5, genA);
    lab.ready(b, 5, genB);
    lab.ready(a, 6, genA);
    lab.ready(a, 7, genA);
    lab.ready(b, 6, genB);
    lab.ready(b, 7, genB);

    CHECK(entryA->bearer.active());
    CHECK(entryB->bearer.active());
    CHECK(entryA->bearer.parameters().localTeid != entryB->bearer.parameters().localTeid);
    CHECK(entryA->bearer.ueIpv4() == std::array<uint8_t, 4>{10, 45, 0, 2});
    CHECK(entryB->bearer.ueIpv4() == std::array<uint8_t, 4>{10, 45, 0, 3});
    CHECK(lab.mux.recoveryCounters().successfulUeRestorations == 2);
}

TEST_CASE("recovery/concurrent: one UE's failed restoration leaves the other UE's session intact")
{
    Lab lab;
    FakeUe a(1);
    FakeUe b(2);
    Establish(lab, a, 0x100, 0x2000, {10, 45, 0, 2});
    Establish(lab, b, 0x200, 0x5000, {10, 45, 0, 3});
    lab.mux.invalidateAccess();
    lab.reconnect();

    lab.uplink(a, link::MessageType::SERVICE_REQUEST, ServiceRequestPayload());
    lab.uplink(b, link::MessageType::SERVICE_REQUEST, ServiceRequestPayload());
    auto *entryA = lab.mux.registry().find(1);
    auto *entryB = lab.mux.registry().find(2);

    // UE A restores normally.
    lab.request(MultiErab(0x100, entryA->enbUeS1apId, 0x3000));
    const uint32_t genA = entryA->accessGeneration;
    lab.ready(a, 5, genA);
    lab.ready(a, 6, genA);
    lab.ready(a, 7, genA);
    CHECK(entryA->bearer.active());

    // UE B's restoration is refused: the request names no default E-RAB role,
    // so the whole context setup fails without publishing any transport.
    s1ap::InitialContextSetupRequest broken = MultiErab(0x200, entryB->enbUeS1apId, 0x6000);
    broken.erabs.erase(broken.erabs.begin()); // drop EBI 5, leaving only dedicated
    lab.request(broken);
    CHECK_FALSE(entryB->bearer.signalingEstablished());
    CHECK(entryB->s1 == UeS1State::CONTEXT_PENDING);
    CHECK(entryB->bearer.parameters().localTeid == 0);

    // UE A's live session is untouched by UE B's failure.
    CHECK(entryA->bearer.active());
    CHECK(entryA->s1 == UeS1State::BEARER_ACTIVE);
    CHECK(lab.mux.registry().findBearer(*entryA, 6)->active());
    CHECK(lab.mux.registry().findBearer(*entryA, 7)->active());
}

TEST_CASE("recovery/lifetime: repeated association flapping reuses no identifier and leaks no context")
{
    Lab lab;
    FakeUe ue(1);
    Establish(lab, ue, 0x100, 0x2000, {10, 45, 0, 2});

    std::vector<uint32_t> teids;
    std::vector<uint32_t> enbIds;
    for (int round = 0; round < 5; ++round)
    {
        lab.mux.invalidateAccess();
        lab.reconnect();
        lab.uplink(ue, link::MessageType::SERVICE_REQUEST, ServiceRequestPayload());
        auto *entry = lab.mux.registry().find(1);
        REQUIRE(entry != nullptr);
        REQUIRE(entry->s1 == UeS1State::CONTEXT_PENDING);
        enbIds.push_back(entry->enbUeS1apId);
        lab.request(MultiErab(0x100, entry->enbUeS1apId, 0x3000 + static_cast<uint32_t>(round) * 0x10));
        const uint32_t generation = entry->accessGeneration;
        lab.ready(ue, 5, generation);
        lab.ready(ue, 6, generation);
        lab.ready(ue, 7, generation);
        CHECK(entry->bearer.active());
        teids.push_back(entry->bearer.parameters().localTeid);
    }

    CHECK(lab.mux.registry().size() == 1);
    const std::set<uint32_t> uniqueTeids(teids.begin(), teids.end());
    const std::set<uint32_t> uniqueIds(enbIds.begin(), enbIds.end());
    CHECK(uniqueTeids.size() == teids.size());
    CHECK(uniqueIds.size() == enbIds.size());
    CHECK(lab.mux.recoveryCounters().successfulUeRestorations == 5);
    CHECK(lab.mux.recoveryCounters().accessInvalidations == 5);
}

TEST_CASE("recovery/lifetime: a new Attach on a reused registry entry restarts the access generation")
{
    Lab lab;
    FakeUe ue(1);
    Establish(lab, ue, 0x100, 0x2000, {10, 45, 0, 2});
    auto *entry = lab.mux.registry().find(1);
    REQUIRE(entry != nullptr);

    // The first legitimate ECM-IDLE transition moves the shared counter to 1.
    lab.mux.registry().releaseS1(*entry);
    REQUIRE(entry->accessGeneration == 1);
    auto previous = Mobility();
    CHECK_NOTHROW(previous.acceptAccessRelease(5, 1));
    CHECK(previous.accessGeneration == 1);

    // The UE restarts on the same radio endpoint and sends a fresh Attach
    // Request. The eNB reuses the registry entry but restarts the shared
    // counter together with the new mobility context of the restarted UE.
    lab.drain(ue);
    lab.uplink(ue, link::MessageType::NAS_UPLINK, {0x41, 0x01, 0x02, 0x03});
    REQUIRE(lab.mux.registry().find(1) == entry);
    CHECK(entry->accessGeneration == 0);
    CHECK(entry->s1 == UeS1State::CONTEXT_PENDING);
    CHECK_FALSE(entry->bearer.logicalConfirmed());

    // The next legitimate S1 release is in step with the restarted UE.
    entry->s1 = UeS1State::BEARER_ACTIVE;
    lab.mux.registry().releaseS1(*entry);
    CHECK(entry->accessGeneration == 1);
    auto restarted = Mobility();
    CHECK_NOTHROW(restarted.acceptAccessRelease(5, 1));
    CHECK(restarted.accessGeneration == 1);
}

TEST_CASE("recovery/lifetime: a carried access generation is what desynchronises a restarted UE")
{
    // The failure the restart above prevents: a fresh mobility context starts
    // at generation zero, so a release the eNB numbered from a carried counter
    // arrives one step ahead and is rejected instead of being honoured.
    auto restarted = Mobility();
    CHECK(restarted.accessGeneration == 0);
    CHECK_THROWS(restarted.acceptAccessRelease(5, 2));
    CHECK(restarted.accessGeneration == 0);
    CHECK_NOTHROW(restarted.acceptAccessRelease(5, 1));
    CHECK(restarted.accessGeneration == 1);
}

TEST_CASE("recovery/lifetime: repeated association loss leaves a retained idle UE reachable and pageable")
{
    Lab lab;
    FakeUe ue(1);
    Establish(lab, ue, 0x100, 0x2000, {10, 45, 0, 2});
    auto *entry = lab.mux.registry().find(1);
    REQUIRE(entry != nullptr);

    // Legitimate ECM-IDLE before the first outage.
    lab.mux.registry().releaseS1(*entry);
    const uint32_t idleGeneration = entry->accessGeneration;
    REQUIRE(idleGeneration == 1);

    for (int round = 0; round < 4; ++round)
    {
        // An already idle UE is not touched by an association loss: no access
        // notification is sent and the shared generation does not move.
        lab.drain(ue);
        CHECK(lab.mux.invalidateAccess() == 0);
        CHECK(entry->s1 == UeS1State::IDLE_RETAINED);
        CHECK(entry->accessGeneration == idleGeneration);
        CHECK(lab.drain(ue).empty());

        // Reconnection allocates a fresh association epoch every time.
        CHECK(lab.reconnect() > 1);

        // A genuine page after the epoch change still reaches the retained
        // idle radio peer.
        s1ap::PagingMessage page{};
        page.ueIdentityIndexValue = 1;
        page.identity = s1ap::PagingMessage::Identity::S_TMSI;
        page.sTmsi = {1, 0xC0000104u};
        page.cnDomain = 0;
        page.taiList = {{{"460", "02"}, 1}};
        const auto pdu = s1ap::EncodePaging(page);
        lab.mux.handleS1ap(pdu.data(), pdu.size(), 0);
        const auto messages = lab.drain(ue);
        REQUIRE(messages.size() == 1);
        CHECK(messages.front().type == link::MessageType::PAGING_INDICATION);
    }

    CHECK(entry->s1 == UeS1State::IDLE_RETAINED);
    CHECK(entry->accessGeneration == idleGeneration);
    CHECK(lab.mux.recoveryCounters().activeUesAffectedByLoss == 0);
}

// ---------------------------------------------------------------------------
// Retry policy, state machine and configuration
// ---------------------------------------------------------------------------

TEST_CASE("recovery/backoff: delays grow, stay bounded and honour a TimeToWait floor")
{
    RecoveryConfig recovery;
    recovery.delayMs = 200;
    recovery.delayMaxMs = 1000;

    CHECK(RecoveryBackoffMs(recovery, 0, 0) == 200);
    CHECK(RecoveryBackoffMs(recovery, 1, 0) == 200);
    CHECK(RecoveryBackoffMs(recovery, 2, 0) == 400);
    CHECK(RecoveryBackoffMs(recovery, 3, 0) == 800);
    CHECK(RecoveryBackoffMs(recovery, 4, 0) == 1000);
    CHECK(RecoveryBackoffMs(recovery, 50, 0) == 1000);
    // A TimeToWait floor from an S1 Setup Failure raises the delay.
    CHECK(RecoveryBackoffMs(recovery, 1, 700) == 700);
    CHECK(RecoveryBackoffMs(recovery, 1, 5000) == 1000); // still bounded
    CHECK(RecoveryBackoffMs(recovery, -3, 0) == 200);
}

TEST_CASE("recovery/backoff: an interruptible delay returns early once shutdown is requested")
{
    std::atomic_bool shutdown{false};
    std::thread canceller([&shutdown] {
        std::this_thread::sleep_for(std::chrono::milliseconds(40));
        shutdown = true;
    });
    const auto started = std::chrono::steady_clock::now();
    const bool completed = InterruptibleDelay(400, shutdown);
    const auto elapsed =
        std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::steady_clock::now() - started);
    canceller.join();
    CHECK_FALSE(completed);
    CHECK(elapsed.count() < 400);

    std::atomic_bool idle{false};
    CHECK(InterruptibleDelay(1, idle)); // a short wait completes normally
    std::atomic_bool already{true};
    CHECK_FALSE(InterruptibleDelay(1000, already)); // already requested
}

TEST_CASE("recovery/state: RECOVERING and STOPPING extend the connection state machine")
{
    ConnectionStateMachine machine;
    CHECK(machine.state() == ConnectionState::DISCONNECTED);
    CHECK(machine.transition(ConnectionEvent::CONNECT_STARTED));
    CHECK(machine.state() == ConnectionState::SCTP_CONNECTING);
    CHECK(machine.transition(ConnectionEvent::SCTP_CONNECTED));
    CHECK(machine.transition(ConnectionEvent::SETUP_REQUEST_SENT));
    CHECK(machine.transition(ConnectionEvent::SETUP_ACCEPTED));
    CHECK(machine.state() == ConnectionState::S1_SETUP_ESTABLISHED);

    CHECK(machine.transition(ConnectionEvent::CONNECTION_LOST));
    CHECK(machine.state() == ConnectionState::DISCONNECTED);
    CHECK(machine.transition(ConnectionEvent::RECOVERY_STARTED));
    CHECK(machine.state() == ConnectionState::RECOVERING);
    // A reconnect must re-enter SCTP_CONNECTING first. The runtime may not
    // jump straight from RECOVERING to SCTP_CONNECTED once connect() returns.
    CHECK_FALSE(machine.transition(ConnectionEvent::SCTP_CONNECTED));
    CHECK(machine.state() == ConnectionState::RECOVERING);
    CHECK(machine.transition(ConnectionEvent::CONNECT_STARTED));
    CHECK(machine.state() == ConnectionState::SCTP_CONNECTING);
    CHECK(machine.transition(ConnectionEvent::SCTP_CONNECTED));
    CHECK(machine.transition(ConnectionEvent::SETUP_REQUEST_SENT));
    CHECK(machine.transition(ConnectionEvent::SETUP_REJECTED));
    CHECK(machine.state() == ConnectionState::S1_SETUP_FAILED);
    CHECK(machine.transition(ConnectionEvent::RECOVERY_STARTED));
    CHECK(machine.state() == ConnectionState::RECOVERING);

    CHECK(machine.transition(ConnectionEvent::SHUTDOWN_REQUESTED));
    CHECK(machine.state() == ConnectionState::STOPPING);
    CHECK_FALSE(machine.transition(ConnectionEvent::CONNECT_STARTED));
    CHECK(machine.state() == ConnectionState::STOPPING);
    CHECK(std::string(ToString(ConnectionState::RECOVERING)) == "RECOVERING");
    CHECK(std::string(ToString(ConnectionState::STOPPING)) == "STOPPING");
}

TEST_CASE("recovery/config: retry and failure-injection settings are parsed and validated")
{
    const std::string base = R"(
mcc: '460'
mnc: '02'
enbId: 0x19B
tac: 1
enbName: UERANSIM-lte-enb
s1apIp: 127.0.0.1
pagingDrx: 128
mme:
  address: 127.0.0.2
  port: 36412
)";
    const auto defaults = lte::enb::ParseConfig(base);
    CHECK(defaults.recovery.maxAttempts == 0);
    CHECK(defaults.recovery.delayMs == 2000);
    CHECK(defaults.recovery.delayMaxMs == 15000);
    CHECK(defaults.failureInjection.controlFile.empty());

    std::string configured = base;
    configured += "\nrecovery:\n  maxAttempts: 7\n  delayMs: 250\n  delayMaxMs: 4000\n";
    configured += "failureInjection:\n  controlFile: /tmp/does-not-exist\n  pollIntervalMs: 25\n";
    const auto value = lte::enb::ParseConfig(configured);
    CHECK(value.recovery.maxAttempts == 7);
    CHECK(value.recovery.delayMs == 250);
    CHECK(value.recovery.delayMaxMs == 4000);
    CHECK(value.failureInjection.controlFile == "/tmp/does-not-exist");
    CHECK(value.failureInjection.pollIntervalMs == 25);

    std::string inverted = base;
    inverted += "\nrecovery:\n  delayMs: 5000\n  delayMaxMs: 100\n";
    CHECK_THROWS(lte::enb::ParseConfig(inverted));
    std::string tooMany = base;
    tooMany += "\nrecovery:\n  maxAttempts: -1\n";
    CHECK_THROWS(lte::enb::ParseConfig(tooMany));
    std::string emptyFile = base;
    emptyFile += "\nfailureInjection:\n  controlFile: ''\n";
    CHECK_THROWS(lte::enb::ParseConfig(emptyFile));
    std::string fastPoll = base;
    fastPoll += "\nfailureInjection:\n  controlFile: /tmp/x\n  pollIntervalMs: 1\n";
    CHECK_THROWS(lte::enb::ParseConfig(fastPoll));
}

TEST_CASE("recovery/config: the UE recovery trigger is optional and bounded")
{
    const std::string base = R"(
imsi: '460020123456789'
mcc: '460'
mnc: '02'
k: '465B5CE8B199B49FAA5F0A2EE238A6BC'
opc: 'CD63CB71954A9F4E48A5994E37A02BAF'
amf: 'B9B9'
initialSqn: 'FF9BB4D0B607'
pdnType: IPv4
networkCapability: 'E0E0'
enbLink:
  localAddress: 127.0.0.1
  localPort: 4999
  address: 127.0.0.1
  port: 4998
)";
    const auto defaults = lte::ue::ParseConfig(base);
    CHECK(defaults.lifecycle.recoveryDelayMs == 6000);
    CHECK(defaults.lifecycle.recoveryRetryMs == 5000);
    CHECK(defaults.lifecycle.recoveryMaxAttempts == 3);

    std::string disabled = base;
    disabled += "\nlifecycle:\n  recoveryDelayMs: 0\n  recoveryMaxAttempts: 0\n";
    const auto off = lte::ue::ParseConfig(disabled);
    CHECK(off.lifecycle.recoveryDelayMs == 0);
    CHECK(off.lifecycle.recoveryMaxAttempts == 0);

    std::string invalid = base;
    invalid += "\nlifecycle:\n  recoveryRetryMs: 50\n";
    CHECK_THROWS(lte::ue::ParseConfig(invalid));
    std::string unbounded = base;
    unbounded += "\nlifecycle:\n  recoveryMaxAttempts: 11\n";
    CHECK_THROWS(lte::ue::ParseConfig(unbounded));
}

// ---------------------------------------------------------------------------
// Injected-loss versus unexpected-loss accounting
//
// A consumed injection command and the association-loss event it causes are one
// event. The command is counted as injected when it executes, the ensuing
// teardown is then classified as injected rather than unexpected, and a
// graceful shutdown or a never-established association counts as neither. Real
// transport failures stay separately observable.
// ---------------------------------------------------------------------------

TEST_CASE("recovery/counters: a consumed loss command is counted as injected and not also unexpected")
{
    Lab lab;
    ControlFile control("loss-command");
    control.Write("loss");
    FailureInjector injector(control.Config());

    REQUIRE(injector.poll() == FailureInjector::Command::LOSS);
    // Exactly what the serve loop does once the command has been consumed.
    lab.mux.noteInjectedAssociationLoss();
    lab.mux.classifyAssociationLoss(/*stopping=*/false, /*established=*/true);

    CHECK(lab.mux.recoveryCounters().injectedAssociationLosses == 1);
    CHECK(lab.mux.recoveryCounters().unexpectedAssociationLosses == 0);

    // A later and unrelated transport failure is a separate event and is still
    // observable as unexpected.
    lab.mux.classifyAssociationLoss(false, true);
    CHECK(lab.mux.recoveryCounters().injectedAssociationLosses == 1);
    CHECK(lab.mux.recoveryCounters().unexpectedAssociationLosses == 1);
}

TEST_CASE("recovery/counters: an executed loss-before-s1ap-response counts as injected exactly once")
{
    Lab lab;
    FakeUe ue(1);
    Establish(lab, ue, 0x100, 0x2000, {10, 45, 0, 2});
    lab.mux.invalidateAccess();
    lab.reconnect();

    ControlFile control("loss-before-response");
    control.Write("loss-before-s1ap-response");
    FailureInjector injector(control.Config());
    REQUIRE(injector.poll() == FailureInjector::Command::LOSS_BEFORE_S1AP_RESPONSE);
    lab.mux.armLossBeforeNextS1apSend();
    CHECK(lab.mux.injectionArmed());

    // The interruption happens inside the production send path, which is where
    // the injected loss is marked.
    lab.uplink(ue, link::MessageType::SERVICE_REQUEST, ServiceRequestPayload());
    REQUIRE(lab.mux.injectionTriggered());
    CHECK(lab.mux.recoveryCounters().injectedAssociationLosses == 1);

    lab.mux.classifyAssociationLoss(false, true);
    CHECK(lab.mux.recoveryCounters().injectedAssociationLosses == 1);
    CHECK(lab.mux.recoveryCounters().unexpectedAssociationLosses == 0);
}

TEST_CASE("recovery/counters: an armed injection that never fires counts nothing")
{
    Lab lab;
    ControlFile control("loss-never-fired");
    control.Write("loss-before-s1ap-response");
    FailureInjector injector(control.Config());
    REQUIRE(injector.poll() == FailureInjector::Command::LOSS_BEFORE_S1AP_RESPONSE);
    lab.mux.armLossBeforeNextS1apSend();

    // No send happens, so nothing is interrupted and nothing is marked. The
    // armed state alone is not a loss.
    CHECK(lab.mux.injectionArmed());
    CHECK_FALSE(lab.mux.injectionTriggered());
    CHECK(lab.mux.recoveryCounters().injectedAssociationLosses == 0);
    CHECK(lab.mux.recoveryCounters().unexpectedAssociationLosses == 0);
    CHECK_FALSE(lab.mux.takeInjectedAssociationLoss());

    // A teardown of a never-established association counts as neither.
    lab.mux.classifyAssociationLoss(false, false);
    CHECK(lab.mux.recoveryCounters().injectedAssociationLosses == 0);
    CHECK(lab.mux.recoveryCounters().unexpectedAssociationLosses == 0);
}

TEST_CASE("recovery/counters: an unknown control command is ignored and counts nothing")
{
    Lab lab;
    ControlFile control("unknown-command");
    control.Write("reboot-the-core");
    FailureInjector injector(control.Config());

    REQUIRE(injector.poll() == FailureInjector::Command::UNKNOWN);
    CHECK(injector.lastCommand() == "reboot-the-core");

    // The serve loop only logs an unknown command; it neither marks an injected
    // loss nor tears the association down.
    CHECK(lab.mux.recoveryCounters().injectedAssociationLosses == 0);
    CHECK_FALSE(lab.mux.takeInjectedAssociationLoss());

    // A genuine loss that follows is therefore still classified as unexpected.
    lab.mux.classifyAssociationLoss(false, true);
    CHECK(lab.mux.recoveryCounters().injectedAssociationLosses == 0);
    CHECK(lab.mux.recoveryCounters().unexpectedAssociationLosses == 1);
}

TEST_CASE("recovery/counters: a graceful shutdown counts as neither")
{
    Lab lab;
    CHECK(lab.mux.recoveryCounters().injectedAssociationLosses == 0);

    lab.mux.classifyAssociationLoss(/*stopping=*/true, /*established=*/true);
    CHECK(lab.mux.recoveryCounters().injectedAssociationLosses == 0);
    CHECK(lab.mux.recoveryCounters().unexpectedAssociationLosses == 0);

    // A shutdown that follows a consumed injection still carries exactly the one
    // count the command earned, and the stop adds nothing of its own.
    lab.mux.noteInjectedAssociationLoss();
    lab.mux.classifyAssociationLoss(true, true);
    CHECK(lab.mux.recoveryCounters().injectedAssociationLosses == 1);
    CHECK(lab.mux.recoveryCounters().unexpectedAssociationLosses == 0);
}

TEST_CASE("recovery/counters: a real transport failure is counted as unexpected and separately observable")
{
    Lab lab;
    lab.mux.classifyAssociationLoss(false, true);
    lab.mux.classifyAssociationLoss(false, true);
    lab.mux.classifyAssociationLoss(false, true);

    CHECK(lab.mux.recoveryCounters().unexpectedAssociationLosses == 3);
    CHECK(lab.mux.recoveryCounters().injectedAssociationLosses == 0);

    // A mark that is never paired with a teardown does not leak into a later
    // unrelated failure.
    lab.mux.noteInjectedAssociationLoss();
    lab.mux.takeInjectedAssociationLoss();
    lab.mux.classifyAssociationLoss(false, true);
    CHECK(lab.mux.recoveryCounters().unexpectedAssociationLosses == 4);
    CHECK(lab.mux.recoveryCounters().injectedAssociationLosses == 1);
}

TEST_CASE("recovery/counters: association flapping counts one loss per consumed executed command")
{
    Lab lab;
    ControlFile control("flapping");
    FailureInjector injector(control.Config());

    for (int i = 0; i < 4; ++i)
    {
        control.Write("loss");
        // The injector paces its own reads; a flapping loop always exceeds the
        // interval in practice.
        std::this_thread::sleep_for(std::chrono::milliseconds(15));
        REQUIRE(injector.poll() == FailureInjector::Command::LOSS);
        lab.mux.noteInjectedAssociationLoss();
        lab.mux.classifyAssociationLoss(false, true);
    }
    CHECK(lab.mux.recoveryCounters().injectedAssociationLosses == 4);
    CHECK(lab.mux.recoveryCounters().unexpectedAssociationLosses == 0);

    // A genuine failure in the middle of the flapping is still its own event.
    lab.mux.classifyAssociationLoss(false, true);
    CHECK(lab.mux.recoveryCounters().injectedAssociationLosses == 4);
    CHECK(lab.mux.recoveryCounters().unexpectedAssociationLosses == 1);
}

TEST_CASE("recovery/counters: a control command is consumed once and cannot fire twice")
{
    ControlFile control("one-shot");
    control.Write("loss");
    FailureInjector injector(control.Config());

    REQUIRE(injector.poll() == FailureInjector::Command::LOSS);
    // Consumption is by truncation, so the command is gone from the control
    // file rather than merely remembered as already seen.
    std::ifstream remaining(control.path);
    std::string leftover;
    std::getline(remaining, leftover);
    CHECK(leftover.empty());

    std::this_thread::sleep_for(std::chrono::milliseconds(15));
    CHECK(injector.poll() == FailureInjector::Command::NONE);

    // A genuinely new command is still picked up.
    control.Write("loss-before-s1ap-response");
    std::this_thread::sleep_for(std::chrono::milliseconds(15));
    CHECK(injector.poll() == FailureInjector::Command::LOSS_BEFORE_S1AP_RESPONSE);
    std::this_thread::sleep_for(std::chrono::milliseconds(15));
    CHECK(injector.poll() == FailureInjector::Command::NONE);
}
