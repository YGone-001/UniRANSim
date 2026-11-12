//
// This file is a part of UERANSIM project.
// Copyright (c) 2027 ALİ GÜNGÖR.
//
// https://github.com/aligungr/UERANSIM/
// See README, LICENSE, and CONTRIBUTING files for licensing details.
//

// Phase 18-E: the isolated MME's core path update and the source release that
// follows it.
//
// Every case here drives the production pipeline: two real EnbMultiplexer
// instances, the isolated MME relay carrying real encoded S1AP, a real encoded
// radio arrival on the target's receive path, and the isolated SGW's own
// forwarding map. A transaction is brought to AWAITING_CORE_PATH_UPDATE exactly
// as Phase 18-D leaves it, and the phase's steps are then applied to it.

#include <ext/doctest/doctest.h>

#include <algorithm>
#include <array>
#include <chrono>
#include <cstdint>
#include <optional>
#include <string>
#include <thread>
#include <vector>

#include <lib/udp/server.hpp>
#include <lte/enb/codec.hpp>
#include <lte/enb/gtpu.hpp>
#include <lte/enb/handover_admission.hpp>
#include <lte/enb/handover_core_path.hpp>
#include <lte/enb/handover_orchestration.hpp>
#include <lte/enb/handover_preparation.hpp>
#include <lte/enb/handover_source_release.hpp>
#include <lte/enb/multiplexer.hpp>
#include <lte/enb/s1u_endpoint.hpp>
#include <lte/enb/ue_registry.hpp>
#include <lte/ue/radio_link.hpp>

namespace
{

using namespace lte::enb;
using namespace lte::enb::s1ap;
namespace link = lte::ue::link;
using Clock = std::chrono::steady_clock;

constexpr uint32_t SourceEnbId = 0x0012345u;
constexpr uint32_t TargetEnbId = 0x00ABCDEu;
constexpr uint32_t MmeUeS1apId = 201;
constexpr uint32_t SecondMmeUeS1apId = 202;
constexpr uint32_t UeRadioId = 7;
constexpr uint32_t SecondRadioId = 8;

constexpr uint8_t DefaultEbi = 5;
constexpr uint8_t DedicatedEbi = 6;
constexpr uint8_t DefaultQci = 9;
constexpr uint8_t DedicatedQci = 7;
constexpr uint32_t SgwDefaultTeid = 30;
constexpr uint32_t SgwDedicatedTeid = 36;
constexpr uint16_t SgwPort = 2152;
const std::array<uint8_t, 4> SgwIp{127, 0, 0, 2};
constexpr std::array<uint8_t, 4> PdnIpv4{10, 0, 0, 1};

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

EnbConfig Config(uint32_t enbId, const std::string &address, uint16_t tac)
{
    EnbConfig config{};
    config.plmn = TestPlmn();
    config.enbId = enbId;
    config.tac = tac;
    config.localAddress = "127.0.0.1";
    config.mmeAddress = "127.0.0.1";
    config.ueLinkAddress = address;
    config.ueLinkPort = 0;
    config.s1uAddress = address;
    config.s1uPort = 0;
    config.allowLoopbackS1u = true;
    config.maxUes = 8;
    return config;
}

struct FakeUe
{
    explicit FakeUe(uint32_t id) : radio("127.0.0.1", 0), radioUeId(id) {}
    udp::UdpServer radio;
    uint32_t radioUeId;
};

void SendRadio(EnbMultiplexer &mux, const FakeUe &ue, link::MessageType type, std::vector<uint8_t> payload)
{
    const auto frame = link::Encode({type, ue.radioUeId, std::move(payload)});
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

s1ap::ErabToBeSetupItem Item(uint8_t ebi, uint8_t qci, uint32_t sgwTeid, std::vector<uint8_t> nasPdu = {})
{
    s1ap::ErabToBeSetupItem item{};
    item.erabId = ebi;
    item.qci = qci;
    item.priorityLevel = 5;
    item.transportLayerAddress = SgwIp;
    item.gtpTeid = TeidToBytes(sgwTeid);
    item.nasPduPresent = !nasPdu.empty();
    item.nasPdu = std::move(nasPdu);
    return item;
}

// The whole isolated two-eNB pipeline, and the transaction it brought to the
// Phase 18-D boundary.
struct PhaseLab
{
    HandoverCoordinator coordinator{ExecutionMode::ISOLATED_SIMULATOR};
    IsolatedMmeRelay relay{coordinator};
    IsolatedMmeRelay::Endpoint sourceMme{relay, false};
    IsolatedMmeRelay::Endpoint targetMme{relay, true};
    EnbMultiplexer source{Config(SourceEnbId, "127.0.0.1", 1), sourceMme};
    EnbMultiplexer target{Config(TargetEnbId, "127.0.0.3", 2), targetMme};
    IsolatedSgw sgw{ExecutionMode::ISOLATED_SIMULATOR, Ipv4ToString(SgwIp), SgwPort};
    FakeUe ue{UeRadioId};
    FakeUe second{SecondRadioId};

    HandoverTransactionId transaction{};
    uint32_t arrivalToken{};
    HandoverTargetBinding binding{};
    uint32_t sourceDefaultTeid{};
    uint32_t sourceDedicatedTeid{};

    // One UE's EPS session, established through the production radio and S1AP
    // entry points only.
    EnbUeEntry &establish(FakeUe &who, uint32_t mmeUeS1apId, const std::array<uint8_t, 4> &address)
    {
        SendRadio(source, who, link::MessageType::NAS_UPLINK, {0x41, 0x01, 0x02, 0x03});
        EnbUeEntry *entry = source.registry().find(who.radioUeId);
        REQUIRE(entry != nullptr);

        s1ap::InitialContextSetupRequest request{};
        request.mmeUeS1apId = mmeUeS1apId;
        request.enbUeS1apId = entry->enbUeS1apId;
        request.ueAmbrUl = 1000;
        request.ueAmbrDl = 2000;
        request.erabs = {Item(DefaultEbi, DefaultQci, SgwDefaultTeid)};
        const auto pdu = s1ap::EncodeInitialContextSetupRequest(request);
        source.handleS1ap(pdu.data(), pdu.size(), 1);
        REQUIRE(entry->bearer.signalingEstablished());

        SendRadio(source, who, link::MessageType::BEARER_READY,
                  {DefaultEbi, address[0], address[1], address[2], address[3]});
        REQUIRE(entry->bearer.active());

        s1ap::ErabSetupRequest setup{};
        setup.mmeUeS1apId = mmeUeS1apId;
        setup.enbUeS1apId = entry->enbUeS1apId;
        setup.erabs = {Item(DedicatedEbi, DedicatedQci, SgwDedicatedTeid, {0x2E, 0x01})};
        const auto frame = s1ap::EncodeErabSetupRequest(setup);
        source.handleS1ap(frame.data(), frame.size(), 1);
        SendRadio(source, who, link::MessageType::BEARER_ACTIVATED, {DedicatedEbi});
        REQUIRE(entry->dedicatedBearers.size() == 1);

        DrainRadio(who);
        return *entry;
    }

    HandoverTargetBinding TargetBinding() const
    {
        HandoverTargetBinding binding;
        binding.identity = TargetIdentity();
        binding.cgi = CgiOf(TargetIdentity());
        binding.tai = Tai{TestPlmn(), TargetIdentity().tac};
        binding.radioEndpoint = target.ueLinkAddress();
        binding.s1uAddress = SgwIp;
        binding.encryptionAlgorithms = {0x80, 0x00};
        binding.integrityAlgorithms = {0x40, 0x00};
        binding.associationEpoch = target.associationEpoch();
        binding.permittedSource = SourceIdentity();
        binding.ready = true;
        return binding;
    }

    static IsolatedUeSecurity Security()
    {
        IsolatedUeSecurity security;
        security.encryptionAlgorithms = {0x80, 0x00};
        security.integrityAlgorithms = {0x40, 0x00};
        security.context.nextHopChainingCount = 3;
        for (size_t i = 0; i < security.context.nextHopParameter.size(); ++i)
            security.context.nextHopParameter[i] = static_cast<uint8_t>(0xA0 + i);
        return security;
    }

    // Drives the accepted Phase 18-D sequence up to AWAITING_CORE_PATH_UPDATE
    // for a UE that is already established on this source. It is the same
    // production path the privileged acceptance runs; only the UE is a socket
    // this file owns instead of the running runtime.
    void handOver(EnbUeEntry &entry, FakeUe &who, uint32_t mmeUeS1apId, bool serveDedicated)
    {
        sourceDefaultTeid = entry.bearer.parameters().localTeid;
        REQUIRE(serveDedicated == (entry.dedicatedBearers.size() == 1));
        if (serveDedicated)
            sourceDedicatedTeid = entry.dedicatedBearers.front().parameters().localTeid;

        const SourceSession session =
            ExtractSourceSession(entry, SourceIdentity(), CgiOf(SourceIdentity()), source.associationEpoch());
        REQUIRE(session.isVerified());

        binding = TargetBinding();
        const std::vector<HandoverTargetBinding> inventory{binding};
        const HandoverTargetBinding *selected = nullptr;
        CoordinationRefusalRecord selectFailure;
        REQUIRE(HandoverCoordinator::SelectTarget(session, inventory, TargetEnbId, selected, &selectFailure));

        CoordinationRecord opened;
        CoordinationRefusalRecord openFailure;
        REQUIRE(coordinator.openTransaction(session, *selected, mmeUeS1apId, source.associationEpoch(),
                                             binding.associationEpoch, std::chrono::seconds{30}, &opened,
                                             &openFailure));
        transaction = opened.transaction;

        HandoverRequired required;
        CoordinationRefusalRecord requiredFailure;
        REQUIRE(BuildHandoverRequired(session, TargetIdentity(), "radioNetwork",
                                      CauseHandoverDesirableForRadioReasons, &required, &requiredFailure));
        const auto requiredPdu = EncodeHandoverRequired(required);

        const PreparationHop hop =
            relay.relayPreparation(requiredPdu, transaction, binding, Security(), target, binding.associationEpoch);
        REQUIRE(hop.delivered);
        arrivalToken = hop.arrivalToken;
        const auto command = DecodeHandoverCommand(hop.commandPdu.data(), hop.commandPdu.size());

        CommandDelivery delivery = DeliverHandoverCommand(source, entry, coordinator, hop.transaction, command, binding);
        REQUIRE(delivery.delivered);
        DrainRadio(who);

        // The arrival, from the UE's own socket to the target's radio endpoint.
        link::SimulatedHandoverAccess access;
        access.arrivalToken = arrivalToken;
        access.sourcePlmn = EncodePlmn(TestPlmn());
        access.sourceEnbId = SourceEnbId;
        access.sourceTac = SourceIdentity().tac;
        access.targetPlmn = EncodePlmn(TestPlmn());
        access.targetEnbId = TargetEnbId;
        access.targetTac = TargetIdentity().tac;
        access.mmeUeS1apId = mmeUeS1apId;
        access.ueIpv4 = entry.bearer.ueIpv4();
        const auto payload = link::EncodeSimulatedHandoverAccess(access);
        const auto frame = link::Encode({link::MessageType::SIMULATED_HANDOVER_ACCESS, who.radioUeId, payload});
        who.radio.Send(target.ueLinkAddress(), frame.data(), frame.size());

        const auto deadline = Clock::now() + std::chrono::seconds{5};
        while (Clock::now() < deadline && !target.lastVerifiedArrival().has_value())
        {
            target.poll(64, 64);
            std::this_thread::sleep_for(std::chrono::milliseconds(2));
        }
        REQUIRE(target.lastVerifiedArrival().has_value());

        CoordinationRefusalRecord arrivalFailure;
        REQUIRE(relay.confirmTargetArrival(target, &arrivalFailure));
        REQUIRE(target.notifyHandover(transaction).sent);

        const CoordinationRecord *record = coordinator.find(transaction);
        REQUIRE(record != nullptr);
        REQUIRE(record->state == OrchestrationState::AWAITING_CORE_PATH_UPDATE);
    }

    // Establish one UE and hand it over through the whole pipeline.
    void reachNotify()
    {
        EnbUeEntry &entry = establish(ue, MmeUeS1apId, PdnIpv4);
        handOver(entry, ue, MmeUeS1apId, true);
    }

    // The source-side mapping the isolated SGW holds before any handover.
    IsolatedSessionKey Session() const
    {
        return IsolatedSessionKey{MmeUeS1apId, PdnIpv4};
    }

    std::vector<AcceptedTargetEndpoint> SourceEndpoints()
    {
        const auto address = ParseIpv4([](const InetAddress &a) {
            const auto text = a.toString();
            return text.substr(0, text.rfind(':'));
        }(source.s1uAddress()));
        const uint16_t port = source.s1uAddress().getPort();

        AcceptedTargetEndpoint defaultBearer;
        defaultBearer.ebi = DefaultEbi;
        defaultBearer.role = BearerRole::DEFAULT;
        defaultBearer.sgwTeid = SgwDefaultTeid;
        defaultBearer.endpoint = IsolatedDownlinkEndpoint{address, sourceDefaultTeid, port};

        AcceptedTargetEndpoint dedicated;
        dedicated.ebi = DedicatedEbi;
        dedicated.role = BearerRole::DEDICATED;
        dedicated.linkedDefaultEbi = DefaultEbi;
        dedicated.sgwTeid = SgwDedicatedTeid;
        dedicated.endpoint = IsolatedDownlinkEndpoint{address, sourceDedicatedTeid, port};
        return {defaultBearer, dedicated};
    }

    bool InstallSourcePath()
    {
        CorePathRefusalRecord failure;
        return sgw.installSession(Session(), source.associationEpoch(), SourceEndpoints(), &failure);
    }
};

} // namespace

TEST_CASE("lte/handover/core-phase: the mme-controlled core path migrates both bearers and the source release completes")
{
    PhaseLab lab;
    lab.reachNotify();
    REQUIRE(lab.InstallSourcePath());
    REQUIRE(*lab.sgw.generationOf(lab.Session()) == 1);

    // The MME validates the whole precondition set, records the request and
    // applies it; only a read-back of the SGW's installed map is a success.
    const CorePathOutcome update = lab.relay.requestCorePathUpdate(lab.sgw, lab.target, lab.transaction);
    REQUIRE(update.committed);
    REQUIRE(update.confirmed);
    CHECK_FALSE(update.indeterminate);
    REQUIRE(update.state.has_value());
    CHECK(*update.state == OrchestrationState::CORE_PATH_UPDATED);
    CHECK(update.pathGeneration == 2);

    // Both bearers moved, and each names the target's own local TEID.
    const auto *targetEntry = lab.target.registry().find(UeRadioId);
    REQUIRE(targetEntry != nullptr);
    const uint32_t targetDefaultTeid = targetEntry->bearer.parameters().localTeid;
    const uint32_t targetDedicatedTeid = targetEntry->dedicatedBearers.front().parameters().localTeid;
    CHECK(lab.sgw.installed(lab.Session(), DefaultEbi)->endpoint.teid == targetDefaultTeid);
    CHECK(lab.sgw.installed(lab.Session(), DedicatedEbi)->endpoint.teid == targetDedicatedTeid);
    CHECK(lab.sgw.installed(lab.Session(), DefaultEbi)->originalSource.teid == lab.sourceDefaultTeid);
    CHECK(lab.sgw.installed(lab.Session(), DedicatedEbi)->originalSource.teid == lab.sourceDedicatedTeid);

    // The source is untouched by the core update: it still holds its context
    // and its transport until the MME decides to release it.
    const auto *sourceEntry = lab.source.registry().find(UeRadioId);
    REQUIRE(sourceEntry != nullptr);
    CHECK(sourceEntry->bearer.parameters().localTeid == lab.sourceDefaultTeid);
    CHECK_FALSE(lab.source.registry().isRetiredTeid(lab.sourceDefaultTeid));

    // The guard is a bounded event, and it is not satisfied before its bound.
    SourceReleaseRefusalRecord guardFailure;
    REQUIRE(lab.relay.armSourceRelease(lab.transaction, Clock::now(), std::chrono::milliseconds{50}, &guardFailure));

    SourceReleaseStepOutcome early = lab.relay.releaseSource(lab.source, lab.transaction, Clock::now());
    CHECK_FALSE(early.sent);
    REQUIRE(early.refusal.has_value());
    CHECK(early.refusal->refusal == SourceReleaseRefusal::RELEASE_GUARD_NOT_SATISFIED);
    CHECK(lab.source.registry().find(UeRadioId) != nullptr);
    CHECK_FALSE(lab.source.registry().isRetiredTeid(lab.sourceDefaultTeid));

    // After the bound, the MME sends a real encoded command; the source
    // releases and answers with a real encoded Complete, which the MME decodes.
    const SourceReleaseStepOutcome released =
        lab.relay.releaseSource(lab.source, lab.transaction, Clock::now() + std::chrono::milliseconds{100});
    CHECK(released.sent);
    REQUIRE(released.confirmed);
    REQUIRE(released.state.has_value());
    CHECK(*released.state == OrchestrationState::ISOLATED_HANDOVER_COMPLETE);

    const CoordinationRecord *record = lab.coordinator.find(lab.transaction);
    REQUIRE(record != nullptr);
    CHECK(record->state == OrchestrationState::ISOLATED_HANDOVER_COMPLETE);
    CHECK(record->sourceRelease.evidence == SourceReleaseEvidence::RELEASE_COMPLETE);
    CHECK_FALSE(record->sourceRelease.completePdu.empty());
    CHECK_FALSE(record->sourceRelease.commandPdu.empty());
    // The command really is an S1AP UE Context Release Command with the
    // successful-handover cause.
    const auto command = DecodeUeContextReleaseCommand(record->sourceRelease.commandPdu.data(),
                                                       record->sourceRelease.commandPdu.size());
    CHECK(command.mmeUeS1apId == MmeUeS1apId);
    CHECK(command.enbUeS1apId.has_value());
    CHECK(*command.enbUeS1apId == record->source.enbUeS1apId);
    CHECK(command.causeCategory == "radioNetwork");
    CHECK(command.causeValue == CauseSuccessfulHandover);
    const auto complete = DecodeUeContextReleaseComplete(record->sourceRelease.completePdu.data(),
                                                         record->sourceRelease.completePdu.size());
    CHECK(complete.mmeUeS1apId == MmeUeS1apId);
    CHECK(complete.enbUeS1apId == record->source.enbUeS1apId);

    // The source context is gone, its transport is retired and nothing told the
    // UE that an access it is no longer on had ended.
    CHECK(lab.source.registry().find(UeRadioId) == nullptr);
    CHECK(lab.source.registry().findByMmeUeS1apId(MmeUeS1apId) == nullptr);
    CHECK(lab.source.registry().findByLocalTeid(lab.sourceDefaultTeid) == nullptr);
    CHECK(lab.source.registry().isRetiredTeid(lab.sourceDefaultTeid));
    CHECK(lab.source.registry().isRetiredTeid(lab.sourceDedicatedTeid));
    for (const auto &frame : DrainRadio(lab.ue))
        CHECK(frame.type != link::MessageType::S1_CONTEXT_RELEASED);

    // The target kept everything it owned.
    const auto *kept = lab.target.registry().find(UeRadioId);
    REQUIRE(kept != nullptr);
    CHECK(kept->bearer.parameters().localTeid == targetDefaultTeid);
    CHECK(kept->dedicatedBearers.front().parameters().localTeid == targetDedicatedTeid);
    CHECK(kept->bearer.active());
    CHECK(kept->dedicatedBearers.front().active());
    CHECK(kept->bearer.ueIpv4() == PdnIpv4);
    CHECK(kept->mmeUeS1apId == MmeUeS1apId);
    CHECK_FALSE(lab.target.registry().isRetiredTeid(targetDefaultTeid));
    CHECK_FALSE(lab.target.registry().isRetiredTeid(targetDedicatedTeid));

    // A delayed G-PDU on an old source TEID is classified as retired and moves
    // no counter of the reached UE.
    const uint64_t retiredBefore = lab.source.s1uCounters().retiredTeidDrops;
    const uint64_t targetDownlinkBefore = kept->counters.s1uDownlinkPackets;
    const uint8_t payload[] = {0x45, 0x00, 0x00, 0x14, 0x00, 0x00, 0x00, 0x00};
    const auto datagram = gtpu::EncodeTPdu(lab.sourceDefaultTeid, payload, sizeof(payload));
    udp::UdpServer sender{Ipv4ToString(SgwIp), SgwPort + 1};
    sender.Send(lab.source.s1uAddress(), datagram.data(), datagram.size());
    lab.source.poll(0, 8);
    CHECK(lab.source.s1uCounters().retiredTeidDrops == retiredBefore + 1);
    CHECK(lab.target.registry().find(UeRadioId)->counters.s1uDownlinkPackets == targetDownlinkBefore);
}

TEST_CASE("lte/handover/core-phase: a core update is refused before the handover notify")
{
    PhaseLab lab;
    EnbUeEntry &entry = lab.establish(lab.ue, MmeUeS1apId, PdnIpv4);
    lab.sourceDefaultTeid = entry.bearer.parameters().localTeid;
    lab.sourceDedicatedTeid = entry.dedicatedBearers.front().parameters().localTeid;
    REQUIRE(lab.InstallSourcePath());

    const SourceSession session =
        ExtractSourceSession(entry, SourceIdentity(), CgiOf(SourceIdentity()), lab.source.associationEpoch());
    lab.binding = lab.TargetBinding();
    const std::vector<HandoverTargetBinding> inventory{lab.binding};
    const HandoverTargetBinding *selected = nullptr;
    CoordinationRefusalRecord selectFailure;
    REQUIRE(HandoverCoordinator::SelectTarget(session, inventory, TargetEnbId, selected, &selectFailure));

    CoordinationRecord opened;
    CoordinationRefusalRecord openFailure;
    REQUIRE(lab.coordinator.openTransaction(session, *selected, MmeUeS1apId, lab.source.associationEpoch(),
                                            lab.binding.associationEpoch, std::chrono::seconds{30}, &opened,
                                            &openFailure));

    const CorePathOutcome outcome = lab.relay.requestCorePathUpdate(lab.sgw, lab.target, opened.transaction);
    CHECK_FALSE(outcome.committed);
    CHECK_FALSE(outcome.confirmed);
    REQUIRE(outcome.refusal.has_value());
    CHECK(outcome.refusal->refusal == CorePathRefusal::WRONG_STATE);
    // Nothing was dispatched and nothing moved.
    const CoordinationRecord *record = lab.coordinator.find(opened.transaction);
    REQUIRE(record != nullptr);
    CHECK(record->state == OrchestrationState::SOURCE_CONNECTED);
    CHECK_FALSE(record->corePath.dispatched);
    CHECK(*lab.sgw.generationOf(lab.Session()) == 1);
    CHECK(lab.sgw.installed(lab.Session(), DefaultEbi)->endpoint.teid == lab.sourceDefaultTeid);
}

TEST_CASE("lte/handover/core-phase: a core update needs a reached target context")
{
    PhaseLab lab;
    lab.reachNotify();
    REQUIRE(lab.InstallSourcePath());

    // The target no longer holds the reached UE, so there is no accepted
    // endpoint set to migrate to.
    EnbUeEntry *reached = lab.target.registry().find(UeRadioId);
    REQUIRE(reached != nullptr);
    lab.target.registry().remove(*reached);

    const CorePathOutcome outcome = lab.relay.requestCorePathUpdate(lab.sgw, lab.target, lab.transaction);
    CHECK_FALSE(outcome.committed);
    REQUIRE(outcome.refusal.has_value());
    CHECK(outcome.refusal->refusal == CorePathRefusal::TARGET_CONTEXT_LOST);
    CHECK(*lab.sgw.generationOf(lab.Session()) == 1);
    const CoordinationRecord *record = lab.coordinator.find(lab.transaction);
    REQUIRE(record != nullptr);
    CHECK(record->state == OrchestrationState::AWAITING_CORE_PATH_UPDATE);
}

TEST_CASE("lte/handover/core-phase: a lost answer is reconciled from the installed map and never re-applied")
{
    PhaseLab lab;
    lab.reachNotify();
    REQUIRE(lab.InstallSourcePath());

    CoordinationRecord *record = lab.coordinator.findMutable(lab.transaction);
    REQUIRE(record != nullptr);
    CorePathRefusalRecord beginFailure;
    REQUIRE(BeginIsolatedCorePathUpdate(lab.coordinator, lab.target, lab.sgw, lab.transaction, &beginFailure));

    // The MME hands the request to the SGW and the answer is lost: the
    // publication happens, the observation does not.
    CoordinationRefusalRecord step;
    REQUIRE(lab.coordinator.advance(lab.transaction, OrchestrationState::CORE_UPDATE_COMMITTING, &step));
    REQUIRE(lab.sgw.apply(record->corePath.request).committed);
    CHECK(*lab.sgw.generationOf(lab.Session()) == 2);
    CHECK(record->state == OrchestrationState::CORE_UPDATE_COMMITTING);

    // Reconciliation reads the map; it never applies a second update.
    const CorePathOutcome reconciled = ReconcileIsolatedPathUpdate(lab.sgw, lab.coordinator, lab.transaction);
    REQUIRE(reconciled.confirmed);
    CHECK_FALSE(reconciled.indeterminate);
    REQUIRE(reconciled.state.has_value());
    CHECK(*reconciled.state == OrchestrationState::CORE_PATH_UPDATED);
    CHECK(reconciled.pathGeneration == 2);
    // Two publications, not three: the replay of the same request would have
    // been a duplicate, and no second request was made.
    CHECK(*lab.sgw.generationOf(lab.Session()) == 2);
    CHECK(record->corePath.pathGeneration == 2);
}

TEST_CASE("lte/handover/core-phase: an unreadable installation stays indeterminate rather than succeeding")
{
    PhaseLab lab;
    lab.reachNotify();
    REQUIRE(lab.InstallSourcePath());

    CoordinationRecord *record = lab.coordinator.findMutable(lab.transaction);
    REQUIRE(record != nullptr);
    CorePathRefusalRecord beginFailure;
    REQUIRE(BeginIsolatedCorePathUpdate(lab.coordinator, lab.target, lab.sgw, lab.transaction, &beginFailure));

    CoordinationRefusalRecord step;
    REQUIRE(lab.coordinator.advance(lab.transaction, OrchestrationState::CORE_UPDATE_COMMITTING, &step));
    REQUIRE(lab.sgw.apply(record->corePath.request).committed);

    // The reading is taken from a map that no longer describes this session: a
    // request for another session is not something reconciliation can prove.
    record->corePath.request.session = IsolatedSessionKey{MmeUeS1apId, {10, 9, 9, 9}};
    const CorePathOutcome reconciled = ReconcileIsolatedPathUpdate(lab.sgw, lab.coordinator, lab.transaction);
    CHECK_FALSE(reconciled.confirmed);
    CHECK(reconciled.indeterminate);
    REQUIRE(reconciled.state.has_value());
    CHECK(*reconciled.state == OrchestrationState::CORE_UPDATE_COMMITTING);
    CHECK(IsTerminal(*reconciled.state) == false);

    // And the transaction cannot be cancelled out of an unresolved core path.
    CoordinationRefusalRecord cancelFailure;
    CHECK_FALSE(lab.coordinator.cancel(lab.transaction, &cancelFailure));
    CHECK(cancelFailure.refusal == CoordinationRefusal::WRONG_TRANSACTION_STATE);
}

TEST_CASE("lte/handover/core-phase: a second core update for a settled transaction is refused")
{
    PhaseLab lab;
    lab.reachNotify();
    REQUIRE(lab.InstallSourcePath());
    REQUIRE(lab.relay.requestCorePathUpdate(lab.sgw, lab.target, lab.transaction).confirmed);

    const CorePathOutcome again = lab.relay.requestCorePathUpdate(lab.sgw, lab.target, lab.transaction);
    CHECK_FALSE(again.committed);
    REQUIRE(again.refusal.has_value());
    CHECK(again.refusal->refusal == CorePathRefusal::WRONG_STATE);
    CHECK(*lab.sgw.generationOf(lab.Session()) == 2);
}

TEST_CASE("lte/handover/core-phase: a handover release needs a verified decision and a pending handover")
{
    PhaseLab lab;
    lab.reachNotify();
    REQUIRE(lab.InstallSourcePath());
    REQUIRE(lab.relay.requestCorePathUpdate(lab.sgw, lab.target, lab.transaction).confirmed);

    // The decision cannot be built before the core update is confirmed: here it
    // is, so this one is real, and the command it authorizes is real too.
    const CoordinationRecord *record = lab.coordinator.find(lab.transaction);
    REQUIRE(record != nullptr);
    const auto decision = BuildHandoverSourceReleaseDecision(*record, record->corePath.pathGeneration);
    CHECK(decision.isVerified());
    CHECK(decision.defaultTeid == lab.sourceDefaultTeid);
    REQUIRE(decision.dedicatedTeids.size() == 1);
    CHECK(decision.dedicatedTeids.front() == lab.sourceDedicatedTeid);

    // A command with the handover cause from a cell that never commanded this
    // UE reaches the same release decision only if it also holds the record.
    // The source refuses it, and nothing is retired.
    EnbUeEntry *entry = lab.source.registry().find(UeRadioId);
    REQUIRE(entry != nullptr);
    s1ap::UeContextReleaseCommand command{};
    command.mmeUeS1apId = MmeUeS1apId;
    command.enbUeS1apId = entry->enbUeS1apId;
    command.causeCategory = "radioNetwork";
    command.causeValue = CauseSuccessfulHandover;

    HandoverSourceReleaseDecision accepted;
    SourceReleaseRefusalRecord failure;
    const bool verified = VerifyHandoverSourceRelease(*entry, lab.source.associationEpoch(), command,
                                                      {}, {}, &accepted, &failure);
    CHECK_FALSE(verified);
    CHECK(failure.refusal == SourceReleaseRefusal::NO_PENDING_HANDOVER);

    // With the MME's decision but without the source's own record the answer is
    // the same: the cause is not an authorization.
    const bool verified2 = VerifyHandoverSourceRelease(*entry, lab.source.associationEpoch(), command, {},
                                                       {decision}, &accepted, &failure);
    CHECK_FALSE(verified2);
    CHECK(failure.refusal == SourceReleaseRefusal::NO_PENDING_HANDOVER);
    CHECK(lab.source.registry().find(UeRadioId) != nullptr);
    CHECK_FALSE(lab.source.registry().isRetiredTeid(lab.sourceDefaultTeid));
}

TEST_CASE("lte/handover/core-phase: an ordinary release still retains the session and tells the ue")
{
    PhaseLab lab;
    EnbUeEntry &entry = lab.establish(lab.ue, MmeUeS1apId, PdnIpv4);
    const uint32_t defaultTeid = entry.bearer.parameters().localTeid;
    const uint32_t enbUeS1apId = entry.enbUeS1apId;

    const auto command = EncodeUeContextReleaseCommand(MmeUeS1apId, enbUeS1apId, "radioNetwork", 20);
    lab.source.handleS1ap(command.data(), command.size(), 1);

    // The accepted ECM-IDLE behaviour is unchanged: the entry stays, the
    // logical bearers stay, and the UE is told its access ended.
    EnbUeEntry *released = lab.source.registry().find(UeRadioId);
    REQUIRE(released != nullptr);
    CHECK(released->s1 == UeS1State::IDLE_RETAINED);
    CHECK(released->sessionRetained);
    CHECK(released->bearer.logicalExists());
    CHECK_FALSE(released->bearer.signalingEstablished());
    CHECK(released->enbUeS1apId == 0);
    CHECK(lab.source.registry().isRetiredTeid(defaultTeid));

    bool told = false;
    for (const auto &frame : DrainRadio(lab.ue))
        told = told || frame.type == link::MessageType::S1_CONTEXT_RELEASED;
    CHECK(told);
}

TEST_CASE("lte/handover/core-phase: a duplicate release command cannot reach a released context")
{
    PhaseLab lab;
    lab.reachNotify();
    REQUIRE(lab.InstallSourcePath());
    REQUIRE(lab.relay.requestCorePathUpdate(lab.sgw, lab.target, lab.transaction).confirmed);
    REQUIRE(lab.relay.armSourceRelease(lab.transaction, Clock::now(), std::chrono::milliseconds{0}, nullptr));

    const SourceReleaseStepOutcome released =
        lab.relay.releaseSource(lab.source, lab.transaction, Clock::now());
    REQUIRE(released.confirmed);

    // The same bytes again: the context they name is gone, so the source
    // refuses the command rather than re-running a cleanup against whatever
    // holds that identifier now. The dispatcher counts the rejection and sends
    // nothing back.
    const CoordinationRecord *record = lab.coordinator.find(lab.transaction);
    REQUIRE(record != nullptr);
    const uint64_t rejectedBefore = lab.source.recoveryCounters().staleMessagesRejected;
    const size_t wireBefore = lab.sourceMme.received().size();
    lab.source.handleS1ap(record->sourceRelease.commandPdu.data(), record->sourceRelease.commandPdu.size(), 1);
    CHECK(lab.source.recoveryCounters().staleMessagesRejected == rejectedBefore + 1);
    CHECK(lab.sourceMme.received().size() == wireBefore);
    CHECK(lab.source.registry().find(UeRadioId) == nullptr);
    CHECK(lab.source.registry().isRetiredTeid(lab.sourceDefaultTeid));
    // The target is untouched.
    CHECK(lab.target.registry().find(UeRadioId) != nullptr);
}

TEST_CASE("lte/handover/core-phase: a handover of one ue leaves another ue on the source alone")
{
    PhaseLab lab;
    EnbUeEntry &first = lab.establish(lab.ue, MmeUeS1apId, PdnIpv4);

    // A second UE on the same source cell, with its own S1 context and its own
    // transport. Its identifiers are the ones that must not move.
    EnbUeEntry &second = lab.establish(lab.second, SecondMmeUeS1apId, {10, 0, 0, 2});
    const uint32_t secondDefaultTeid = second.bearer.parameters().localTeid;
    const uint32_t secondDedicatedTeid = second.dedicatedBearers.front().parameters().localTeid;
    const uint32_t secondGeneration = second.accessGeneration;
    const uint32_t secondEnbUeS1apId = second.enbUeS1apId;

    // The first UE is handed over and its source context is released, through
    // the same production steps as the positive case.
    lab.handOver(first, lab.ue, MmeUeS1apId, true);
    REQUIRE(lab.InstallSourcePath());
    REQUIRE(lab.relay.requestCorePathUpdate(lab.sgw, lab.target, lab.transaction).confirmed);
    REQUIRE(lab.relay.armSourceRelease(lab.transaction, Clock::now(), std::chrono::milliseconds{0}, nullptr));
    REQUIRE(lab.relay.releaseSource(lab.source, lab.transaction, Clock::now()).confirmed);

    // The other UE is exactly where it was: same entry, same S1 identity, same
    // access epoch, same transport, still forwarding, nothing retired.
    EnbUeEntry *other = lab.source.registry().find(SecondRadioId);
    REQUIRE(other != nullptr);
    CHECK(other->enbUeS1apId == secondEnbUeS1apId);
    CHECK(other->mmeUeS1apId == SecondMmeUeS1apId);
    CHECK(other->accessGeneration == secondGeneration);
    CHECK(other->bearer.active());
    CHECK(other->bearer.parameters().localTeid == secondDefaultTeid);
    CHECK(other->dedicatedBearers.front().parameters().localTeid == secondDedicatedTeid);
    CHECK(other->s1 == UeS1State::BEARER_ACTIVE);
    CHECK(lab.source.registry().findByLocalTeid(secondDefaultTeid) != nullptr);
    CHECK(lab.source.registry().findByLocalTeid(secondDedicatedTeid) != nullptr);
    CHECK_FALSE(lab.source.registry().isRetiredTeid(secondDefaultTeid));
    CHECK_FALSE(lab.source.registry().isRetiredTeid(secondDedicatedTeid));
    CHECK(lab.source.registry().findByMmeUeS1apId(SecondMmeUeS1apId) == other);

    // And the first UE's context is the one that went.
    CHECK(lab.source.registry().find(UeRadioId) == nullptr);
    CHECK(lab.source.registry().findByMmeUeS1apId(MmeUeS1apId) == nullptr);
}
