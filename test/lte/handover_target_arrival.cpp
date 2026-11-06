//
// Phase 18-C: verified target arrival, atomic provisional promotion and the
// Handover Notify gate.
//
// These cases drive a prepared target eNB from the moment its resources are
// committed to the moment a Handover Notify leaves the real S1AP association.
// The arrival is never a flag: it is a handover-specific simulated radio frame
// delivered to `EnbMultiplexer::handleRadioFrame`, which is the same entry
// point every other simulated radio message uses, and every identifier these
// cases observe was bound by the production allocator on the production path.
//
// Where a case needs a specific TEID on the wire it queues that value *for the
// allocator to return*, which is the documented test seam and not an
// assignment to a bearer. Where a case needs a failure inside the promotion it
// uses the deterministic fault injectors, which are arguments and never
// production switches.

#include <ext/doctest/doctest.h>

#include <lte/enb/codec.hpp>
#include <lte/enb/gtpu.hpp>
#include <lte/enb/handover_admission.hpp>
#include <lte/enb/handover_preparation.hpp>
#include <lte/enb/multiplexer.hpp>
#include <lte/enb/s1u_endpoint.hpp>
#include <lte/enb/ue_registry.hpp>
#include <lte/enb/user_plane.hpp>
#include <lte/ue/radio_link.hpp>
#include <lib/udp/server.hpp>

#include <array>
#include <cstdint>
#include <deque>
#include <string>
#include <vector>

namespace
{

using namespace lte::enb;
using namespace lte::enb::s1ap;
using lte::ErabQos;
using lte::UeAmbr;
using lte::ue::link::MessageType;

std::array<uint8_t, 4> Ip(uint8_t a, uint8_t b, uint8_t c, uint8_t d)
{
    return {a, b, c, d};
}

std::array<uint8_t, 4> TeidBytes(uint32_t value)
{
    return {static_cast<uint8_t>(value >> 24), static_cast<uint8_t>(value >> 16),
            static_cast<uint8_t>(value >> 8), static_cast<uint8_t>(value)};
}

ErabQos Qos(uint8_t qci, uint8_t priorityLevel, bool preemptionCapability = false,
            bool preemptionVulnerability = false)
{
    return ErabQos{qci, priorityLevel, preemptionCapability, preemptionVulnerability, {}};
}

// Test fixture data only. This is not a UE security key and no real key is ever
// present in this repository's tests.
std::array<uint8_t, 32> TestNextHopParameter()
{
    std::array<uint8_t, 32> key{};
    for (size_t i = 0; i < key.size(); ++i)
        key[i] = static_cast<uint8_t>(0xA0 + i);
    return key;
}

// The SGW endpoint every prepared bearer carries across unchanged, and the
// peer the shared S1-U endpoint accepts a downlink from.
constexpr std::array<uint8_t, 4> SgwAddress{127, 0, 0, 9};
constexpr uint32_t SgwTeid5 = 0x0A0B0C0Du;
constexpr uint32_t SgwTeid6 = 0x0E0F1011u;
constexpr uint32_t SgwTeid7 = 0x12131415u;

// The PDN address the UE's own NAS assigned it. A source eNB states it in the
// simulated handover command from the bearer it has been serving, and the
// arriving UE repeats it, so a target is not asked to take an address from a
// stranger.
std::array<uint8_t, 4> PdnAddress(uint32_t radioUeId)
{
    return {10, 45, 0, static_cast<uint8_t>(radioUeId)};
}

EnbIdentity IdentityOf(const EnbConfig &config)
{
    return EnbIdentity{config.plmn, config.enbId, config.tac};
}

EutranCgi CgiOf(const EnbConfig &config)
{
    return EutranCgi{config.plmn, (config.enbId & 0xFFFFFU) << 8U};
}

// One target eNB and, when a case needs one, its source. Two eNB instances
// never share an S1-U IP/UDP pair or a simulated-radio endpoint.
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

constexpr uint32_t TargetEnbId = 0x00ABCDEu;
constexpr uint32_t SourceEnbId = 0x0012345u;

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

    std::vector<CapturedS1ap> sent;
};

struct FakeUe
{
    explicit FakeUe(uint32_t id) : ueId(id)
    {
    }
    udp::UdpServer radio{"127.0.0.1", 0};
    uint32_t ueId;
};

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

ErabToBeSetupItemHoReq RequestBearer(uint8_t erabId, uint8_t qci, uint8_t priorityLevel, bool preemptionCapability,
                                     bool preemptionVulnerability, uint32_t sgwTeid)
{
    ErabToBeSetupItemHoReq item;
    item.erabId = erabId;
    item.sgwAddress = SgwAddress;
    item.sgwTeid = TeidBytes(sgwTeid);
    item.qos = Qos(qci, priorityLevel, preemptionCapability, preemptionVulnerability);
    return item;
}

BearerRoleBinding RoleDefault(uint8_t erabId, uint8_t qci, uint8_t priorityLevel)
{
    BearerRoleBinding binding;
    binding.erabId = erabId;
    binding.role = BearerRole::DEFAULT;
    binding.qci = qci;
    binding.priorityLevel = priorityLevel;
    return binding;
}

BearerRoleBinding RoleDedicated(uint8_t erabId, uint8_t linkedDefault, uint8_t qci, uint8_t priorityLevel,
                                bool preemptionCapability, bool preemptionVulnerability)
{
    BearerRoleBinding binding;
    binding.erabId = erabId;
    binding.role = BearerRole::DEDICATED;
    binding.linkedDefaultErabId = linkedDefault;
    binding.qci = qci;
    binding.priorityLevel = priorityLevel;
    binding.preemptionCapability = preemptionCapability;
    binding.preemptionVulnerability = preemptionVulnerability;
    return binding;
}

// One default bearer (E-RAB 5) and one dedicated bearer (E-RAB 6 linked to
// it). The roles are the network's own statement of the session and are never
// derived from the QCI or from the order the E-RABs are listed in.
HandoverRequest SampleRequest(uint32_t mmeUeS1apId = 7)
{
    HandoverRequest message;
    message.mmeUeS1apId = mmeUeS1apId;
    message.handoverType = HandoverType::INTRA_LTE;
    message.causeCategory = "radioNetwork";
    message.causeValue = 16;
    message.ueAmbr = UeAmbr{150000000ULL, 75000000ULL};
    message.erabs = {RequestBearer(5, 5, 15, false, false, SgwTeid5), RequestBearer(6, 6, 3, false, true, SgwTeid6)};
    message.sourceToTarget = {0x01, 0x02, 0x03, 0x04};
    message.encryptionAlgorithms = {0x80, 0x00};
    message.integrityAlgorithms = {0x40, 0x00};
    message.securityContext.nextHopChainingCount = 3;
    message.securityContext.nextHopParameter = TestNextHopParameter();
    return message;
}

std::vector<BearerRoleBinding> SampleRoles()
{
    return {RoleDefault(5, 5, 15), RoleDedicated(6, 5, 6, 3, false, true)};
}

HandoverTransactionId Transaction(uint32_t mmeUeS1apId, uint64_t epoch, uint32_t sequence = 0)
{
    return HandoverTransactionId{mmeUeS1apId, epoch, sequence};
}

// The simulated handover command a source eNB sends the UE it serves. Nothing
// in this repository puts one into a transparent container or sends one to an
// MME; it is a simulator control frame and not 3GPP RRC.
lte::ue::link::SimulatedHandoverCommand CommandFor(const EnbConfig &target, uint32_t arrivalToken,
                                                   uint32_t mmeUeS1apId, uint32_t radioUeId)
{
    lte::ue::link::SimulatedHandoverCommand command;
    command.targetPlmn = EncodePlmn(target.plmn);
    command.targetEnbId = target.enbId;
    command.targetTac = target.tac;
    command.arrivalToken = arrivalToken;
    command.mmeUeS1apId = mmeUeS1apId;
    command.ueIpv4 = PdnAddress(radioUeId);
    return command;
}

// The arrival the UE sends the target it reached, repeating what the source
// authorised and naming both cells.
lte::ue::link::SimulatedHandoverAccess AccessFor(const EnbConfig &source, const EnbConfig &target,
                                                 uint32_t arrivalToken, uint32_t mmeUeS1apId, uint32_t radioUeId)
{
    lte::ue::link::SimulatedHandoverAccess access;
    access.arrivalToken = arrivalToken;
    access.sourcePlmn = EncodePlmn(source.plmn);
    access.sourceEnbId = source.enbId;
    access.sourceTac = source.tac;
    access.targetPlmn = EncodePlmn(target.plmn);
    access.targetEnbId = target.enbId;
    access.targetTac = target.tac;
    access.mmeUeS1apId = mmeUeS1apId;
    access.ueIpv4 = PdnAddress(radioUeId);
    return access;
}

std::vector<uint8_t> AccessFrame(uint32_t radioUeId, const lte::ue::link::SimulatedHandoverAccess &access)
{
    return lte::ue::link::Encode({MessageType::SIMULATED_HANDOVER_ACCESS, radioUeId,
                                  lte::ue::link::EncodeSimulatedHandoverAccess(access)});
}

// One downlink IPv4 packet. The shared S1-U endpoint validates the
// destination against the address the bearer was activated with, so a case
// that wants delivery has to name the UE it is delivering to.
std::vector<uint8_t> Payload(const std::array<uint8_t, 4> &destination)
{
    return {0x45, 0x00, 0x00, 0x14, 0x00, 0x00, 0x00, 0x00,
            0x40, 0x01, 0x00, 0x00, 0x7F, 0x00, 0x00, 0x01,
            destination[0], destination[1], destination[2], destination[3]};
}

std::vector<uint8_t> GPduWire(uint32_t teid, const std::vector<uint8_t> &payload)
{
    return gtpu::EncodeTPdu(teid, payload.data(), payload.size());
}

// --- one target eNB driven through the production multiplexer -------------

struct TargetLab
{
    CaptureSender wire;
    EnbConfig config{TestEnbConfig(TargetEnbId, "127.0.0.3")};
    EnbMultiplexer mux{config, wire};
    FakeUe ue{1};

    // The eNB-side view of the source. Supplied by the caller of
    // `prepareHandover` and explicitly test-harness-verified provenance: this
    // repository has no runtime path that establishes it, which is exactly why
    // the live S1AP dispatcher never starts a preparation.
    SourceContext source{EnbIdentity{Plmn{"460", "02"}, SourceEnbId, 1}, true};

    TargetContext targetContext() const
    {
        TargetContext target;
        target.identity = IdentityOf(config);
        target.s1uAddress = Ip(127, 0, 0, 3);
        target.encryptionAlgorithms = {0x80, 0x00};
        target.integrityAlgorithms = {0x40, 0x00};
        return target;
    }

    // Admit, commit and mark the preparation awaiting the UE's access, through
    // the multiplexer's own entry point.
    bool prepare(EnbMultiplexer::PreparedHandover *prepared, uint32_t mmeUeS1apId = 7,
                 const std::vector<BearerRoleBinding> &roles = SampleRoles())
    {
        return mux.prepareHandover(Transaction(mmeUeS1apId, mux.associationEpoch()), SampleRequest(mmeUeS1apId),
                                   source, targetContext(), roles, prepared);
    }

    // Drives the encoded arrival through the production radio receive path.
    void arrive(uint32_t radioUeId, uint32_t arrivalToken, uint32_t mmeUeS1apId, FakeUe &at,
                const EnbConfig &from = TestEnbConfig(SourceEnbId, "127.0.0.1"))
    {
        const auto frame = AccessFrame(radioUeId, AccessFor(from, config, arrivalToken, mmeUeS1apId, radioUeId));
        mux.handleRadioFrame(frame.data(), frame.size(), at.radio.LocalAddress());
    }

    void sendGPdu(uint32_t teid, uint32_t radioUeId = 1)
    {
        udp::UdpServer sgw("127.0.0.9", 2152);
        const auto packet = Payload(PdnAddress(radioUeId));
        const auto wire = GPduWire(teid, packet);
        sgw.Send(mux.s1uAddress(), wire.data(), wire.size());
        mux.poll(0, 16);
    }
};

// The reached entry a completed arrival produced, looked up the way production
// looks it up: by the radio identity the UE announced itself under.
EnbUeEntry *Reached(TargetLab &lab)
{
    return lab.mux.registry().find(lab.ue.ueId);
}

} // namespace

// --- A: a prepared context is not a reached UE ----------------------------

TEST_CASE("lte/handover/arrival: a prepared context is not a reached ue and cannot forward a g-pdu")
{
    TargetLab lab;
    EnbMultiplexer::PreparedHandover prepared;
    REQUIRE(lab.prepare(&prepared));
    REQUIRE(prepared.arrivalToken != 0);

    // The transaction committed real resources and owns a provisional context.
    EnbUeEntry *provisional = lab.mux.registry().findByMmeUeS1apId(7);
    REQUIRE(provisional != nullptr);
    CHECK(UeRegistry::isProvisional(*provisional));
    CHECK(provisional->radioUeId == 0);
    CHECK(lab.mux.registry().holdsProvisional(*provisional));

    // It has no registered radio peer and no registered radio identity, so
    // nothing can address it as a UE.
    CHECK(lab.mux.registry().find(lab.ue.ueId) == nullptr);
    CHECK(lab.mux.registry().findByPeer(lab.ue.radio.LocalAddress()) == nullptr);
    CHECK(lab.mux.registry().size() == 0);

    // Its bearers are established and deliberately not ready, which is the
    // whole forwarding restriction.
    REQUIRE(provisional->bearer.signalingEstablished());
    CHECK_FALSE(provisional->bearer.active());
    CHECK(PreparedBearersNonForwardable(*provisional));

    // A real downlink G-PDU at the real shared endpoint, for the TEID the
    // commit bound. Nothing reaches a UE that has not arrived, and the drop is
    // classified as an inactive bearer rather than as an unknown or retired
    // tunnel.
    lab.sendGPdu(provisional->bearer.parameters().localTeid);
    CHECK(DrainRadio(lab.ue).empty());
    CHECK(provisional->counters.bearerInactiveDrops == 1);
    CHECK(provisional->counters.s1uDownlinkPackets == 0);
    CHECK(lab.mux.registry().size() == 0);
}

// --- B: verified target arrival ------------------------------------------

TEST_CASE("lte/handover/arrival: an access frame through the production receive path correlates to the prepared transaction")
{
    TargetLab lab;
    EnbMultiplexer::PreparedHandover prepared;
    REQUIRE(lab.prepare(&prepared));

    EnbUeEntry *before = lab.mux.registry().findByMmeUeS1apId(7);
    REQUIRE(before != nullptr);

    // The frame is the production encoder's output and is delivered to the
    // production radio handler. There is no `arrivalVerified` flag anywhere in
    // this case.
    lab.arrive(lab.ue.ueId, prepared.arrivalToken, 7, lab.ue);

    // Full correlation: the reached UE holds exactly what the transaction
    // bound — the same S1AP identities and the same target TEIDs — under the
    // radio identity and the radio peer the arrival presented.
    EnbUeEntry *reached = Reached(lab);
    REQUIRE(reached != nullptr);
    CHECK(reached == before);
    CHECK_FALSE(UeRegistry::isProvisional(*reached));
    CHECK(reached->enbUeS1apId == prepared.acknowledge.enbUeS1apId);
    CHECK(reached->mmeUeS1apId == 7);
    CHECK(reached->peer == lab.ue.radio.LocalAddress());
    CHECK(lab.mux.registry().findByPeer(lab.ue.radio.LocalAddress()) == reached);

    // The preparation record agrees: the arrival was consumed, ownership moved
    // and the record retained only what it cannot act on.
    const PreparationRecord *record = lab.mux.preparations()->findByArrivalToken(prepared.arrivalToken);
    REQUIRE(record != nullptr);
    CHECK(record->state == PreparationState::TARGET_REACHED);
    CHECK(IsReached(record->state));
    CHECK(record->ownershipTransferred);
    CHECK(record->entry == nullptr);
    CHECK(record->ownedTeids.empty());
    CHECK(record->reachedRadioUeId == lab.ue.ueId);
    CHECK(record->reachedEnbUeS1apId == prepared.acknowledge.enbUeS1apId);
    CHECK(record->reachedUeIpv4 == PdnAddress(lab.ue.ueId));
}

// --- C: atomic promotion -------------------------------------------------

TEST_CASE("lte/handover/arrival: promotion moves the same entry and preserves every prepared identifier")
{
    TargetLab lab;
    EnbMultiplexer::PreparedHandover prepared;
    REQUIRE(lab.prepare(&prepared));

    EnbUeEntry *before = lab.mux.registry().findByMmeUeS1apId(7);
    REQUIRE(before != nullptr);
    const uint32_t defaultTeid = before->bearer.parameters().localTeid;
    const uint32_t dedicatedTeid = before->dedicatedBearers.front().parameters().localTeid;
    const uint32_t enbUeS1apId = before->enbUeS1apId;
    const size_t reachedBefore = lab.mux.registry().size();
    REQUIRE(defaultTeid != 0);
    REQUIRE(dedicatedTeid != 0);
    REQUIRE(defaultTeid != dedicatedTeid);

    lab.arrive(lab.ue.ueId, prepared.arrivalToken, 7, lab.ue);

    EnbUeEntry *after = Reached(lab);
    REQUIRE(after != nullptr);

    // Same underlying entry: the promotion is a move of the provisional
    // context, not a fresh registration that copied its contents.
    CHECK(after == before);

    // Same target TEIDs and the same S1AP identifiers.
    CHECK(after->bearer.parameters().localTeid == defaultTeid);
    CHECK(after->dedicatedBearers.front().parameters().localTeid == dedicatedTeid);
    CHECK(after->enbUeS1apId == enbUeS1apId);
    CHECK(after->mmeUeS1apId == 7);
    CHECK(lab.mux.registry().findByLocalTeid(defaultTeid) == after);
    CHECK(lab.mux.registry().findByLocalTeid(dedicatedTeid) == after);
    CHECK(lab.mux.registry().findByEnbUeS1apId(enbUeS1apId) == after);

    // Correct radio and peer indexes.
    CHECK(lab.mux.registry().find(lab.ue.ueId) == after);
    CHECK(lab.mux.registry().findByPeer(lab.ue.radio.LocalAddress()) == after);

    // No duplicated capacity consumption: the provisional slot became the
    // reached slot rather than a second one being taken.
    CHECK(lab.mux.registry().size() == reachedBefore + 1);
    CHECK(lab.mux.registry().capacity() == 8);

    // Provisional ownership is gone.
    CHECK_FALSE(UeRegistry::isProvisional(*after));
    CHECK_FALSE(lab.mux.registry().holdsProvisional(*after));
}

// --- D: default and dedicated bearer readiness ---------------------------

TEST_CASE("lte/handover/arrival: default and dedicated bearers activate with their prepared identity")
{
    TargetLab lab;
    EnbMultiplexer::PreparedHandover prepared;
    REQUIRE(lab.prepare(&prepared));

    EnbUeEntry *before = lab.mux.registry().findByMmeUeS1apId(7);
    REQUIRE(before != nullptr);
    REQUIRE(before->dedicatedBearers.size() == 1);

    lab.arrive(lab.ue.ueId, prepared.arrivalToken, 7, lab.ue);

    EnbUeEntry *reached = Reached(lab);
    REQUIRE(reached != nullptr);

    // The default bearer is ready, and so is the dedicated one that is linked
    // to it. A dedicated bearer is never made ready ahead of its default: the
    // activation runs default first, and the readiness check refuses the whole
    // arrival unless every prepared bearer can be made ready.
    CHECK(reached->bearer.active());
    REQUIRE(reached->dedicatedBearers.size() == 1);
    const BearerContext &dedicated = reached->dedicatedBearers.front();
    CHECK(dedicated.active());

    // The dedicated bearer keeps the network-assigned identity it was given:
    // its E-RAB identity, its linked default EBI, its QCI and its ARP.
    CHECK(dedicated.kind() == BearerKind::DEDICATED);
    CHECK(dedicated.parameters().erabId == 6);
    CHECK(dedicated.parameters().linkedDefaultEbi == 5);
    CHECK(dedicated.parameters().qci == 6);
    CHECK(dedicated.parameters().qos.qci == 6);
    CHECK(dedicated.parameters().qos.priorityLevel == 3);
    CHECK_FALSE(dedicated.parameters().qos.preemptionCapability);
    CHECK(dedicated.parameters().qos.preemptionVulnerability);
    CHECK(dedicated.parameters().ueId == lab.ue.ueId);
    CHECK(reached->bearer.kind() == BearerKind::DEFAULT);
    CHECK(reached->bearer.parameters().erabId == 5);
    CHECK(reached->bearer.parameters().linkedDefaultEbi == 0);
    CHECK(reached->bearer.parameters().qci == 5);
    CHECK(reached->bearer.parameters().qos.priorityLevel == 15);

    // And its target transport is the one the commit bound.
    CHECK(dedicated.parameters().localTeid == before->dedicatedBearers.front().parameters().localTeid);
    CHECK(dedicated.parameters().sgwTeid == SgwTeid6);
    CHECK(dedicated.parameters().sgwAddress == SgwAddress);
    CHECK(reached->bearer.parameters().sgwTeid == SgwTeid5);

    // The reached context is a served UE with an active S1 context.
    CHECK(reached->s1 == UeS1State::BEARER_ACTIVE);
}

// --- E: target S1-U positive control -------------------------------------

TEST_CASE("lte/handover/arrival: the same prepared teid refuses forwarding before arrival and delivers after it")
{
    TargetLab lab;
    EnbMultiplexer::PreparedHandover prepared;
    REQUIRE(lab.prepare(&prepared));

    EnbUeEntry *entry = lab.mux.registry().findByMmeUeS1apId(7);
    REQUIRE(entry != nullptr);
    const uint32_t defaultTeid = entry->bearer.parameters().localTeid;
    const uint32_t dedicatedTeid = entry->dedicatedBearers.front().parameters().localTeid;

    // Before arrival the identical bearer refuses to forward.
    lab.sendGPdu(defaultTeid);
    CHECK(DrainRadio(lab.ue).empty());
    CHECK(entry->counters.bearerInactiveDrops == 1);

    lab.arrive(lab.ue.ueId, prepared.arrivalToken, 7, lab.ue);
    EnbUeEntry *reached = Reached(lab);
    REQUIRE(reached != nullptr);

    // After target readiness the same TEID is a legitimate downlink and is
    // delivered over the simulated radio to the peer that arrived.
    lab.sendGPdu(defaultTeid);
    auto frames = DrainRadio(lab.ue);
    REQUIRE(frames.size() == 1);
    CHECK(frames.front().type == MessageType::DATA_DOWNLINK);
    CHECK(reached->bearer.counters().downlinkPackets == 1);
    CHECK(reached->counters.s1uDownlinkPackets == 1);

    // The dedicated bearer forwards on its own TEID and is reported as such.
    lab.sendGPdu(dedicatedTeid);
    frames = DrainRadio(lab.ue);
    REQUIRE(frames.size() == 1);
    CHECK(frames.front().type == MessageType::DATA_DOWNLINK_BEARER);
    CHECK(frames.front().payload[0] == 6);
    CHECK(reached->dedicatedBearers.front().counters().downlinkPackets == 1);

    // The pre-arrival drop was counted once and is not re-credited to the
    // fresh access.
    CHECK(reached->counters.bearerInactiveDrops == 1);
}

// --- F: Handover Notify from proven arrival ------------------------------

TEST_CASE("lte/handover/arrival: a handover notify is built from a proven arrival and sent through the real association")
{
    TargetLab lab;
    EnbMultiplexer::PreparedHandover prepared;
    REQUIRE(lab.prepare(&prepared));
    lab.arrive(lab.ue.ueId, prepared.arrivalToken, 7, lab.ue);
    REQUIRE(Reached(lab) != nullptr);

    const HandoverNotifyOutcome outcome = lab.mux.notifyHandover(prepared.transaction);
    REQUIRE(outcome.sent);
    REQUIRE(outcome.message.has_value());
    CHECK(outcome.refusal == std::nullopt);

    // The identities come from what the transaction bound, and the cell from
    // this eNB's own configuration.
    CHECK(outcome.message->mmeUeS1apId == 7);
    CHECK(outcome.message->enbUeS1apId == prepared.acknowledge.enbUeS1apId);
    CHECK(outcome.message->cgi.plmn.mcc == "460");
    CHECK(outcome.message->cgi.plmn.mnc == "02");
    CHECK(outcome.message->cgi.cellId == ((TargetEnbId & 0xFFFFFU) << 8U));
    CHECK(outcome.message->tai.plmn.mcc == "460");
    CHECK(outcome.message->tai.tac == 1);

    // One PDU left through the real sender, on the UE-associated stream.
    REQUIRE(lab.wire.sent.size() == 1);
    CHECK(lab.wire.sent.front().stream == SctpStreamForUe(1, prepared.acknowledge.enbUeS1apId));

    // Wire shape: Handover Notification is procedure 2 and an initiating
    // message, and the payload decodes back to exactly what was built.
    const auto probe = ProbeS1apPdu(lab.wire.sent.front().pdu.data(), lab.wire.sent.front().pdu.size());
    CHECK(probe.kind == S1apPdu::Kind::INITIATING);
    CHECK(probe.procedureCode == 2);
    const HandoverNotify decoded =
        DecodeHandoverNotify(lab.wire.sent.front().pdu.data(), lab.wire.sent.front().pdu.size());
    CHECK(decoded.mmeUeS1apId == outcome.message->mmeUeS1apId);
    CHECK(decoded.enbUeS1apId == outcome.message->enbUeS1apId);
    CHECK(decoded.cgi.cellId == outcome.message->cgi.cellId);
    CHECK(decoded.tai.tac == outcome.message->tai.tac);

    // The record agrees that a Notify went out, and a second attempt is a
    // duplicate rather than a second notification.
    const PreparationRecord *record = lab.mux.preparations()->findByArrivalToken(prepared.arrivalToken);
    REQUIRE(record != nullptr);
    CHECK(record->state == PreparationState::NOTIFY_SENT);
    CHECK(record->notifySent);
    const HandoverNotifyOutcome again = lab.mux.notifyHandover(prepared.transaction);
    CHECK_FALSE(again.sent);
    REQUIRE(again.refusal.has_value());
    CHECK(again.refusal->refusal == NotifyRefusal::ALREADY_NOTIFIED);
    CHECK(lab.wire.sent.size() == 1);
}

// --- G: early Notify rejection -------------------------------------------

TEST_CASE("lte/handover/arrival: a notify attempted before the arrival gate is refused without sending")
{
    // Before commitment: an admitted plan owns nothing and proves nothing.
    {
        TargetLab lab;
        const auto request = SampleRequest();
        REQUIRE(lab.mux.preparations() != nullptr);
        PreparationRecord *record = lab.mux.preparations()->admit(Transaction(7, lab.mux.associationEpoch()), request,
                                                                 lab.source, lab.targetContext(), SampleRoles());
        REQUIRE(record != nullptr);
        CHECK(record->state == PreparationState::ADMITTED);

        const HandoverNotifyOutcome outcome = lab.mux.notifyHandover(record->id);
        CHECK_FALSE(outcome.sent);
        REQUIRE(outcome.refusal.has_value());
        CHECK(outcome.refusal->refusal == NotifyRefusal::NOT_COMMITTED);
        CHECK(lab.wire.sent.empty());
    }

    // Before arrival: committed resources are not an arrival.
    {
        TargetLab lab;
        EnbMultiplexer::PreparedHandover prepared;
        REQUIRE(lab.prepare(&prepared));
        const HandoverNotifyOutcome outcome = lab.mux.notifyHandover(prepared.transaction);
        CHECK_FALSE(outcome.sent);
        REQUIRE(outcome.refusal.has_value());
        CHECK(outcome.refusal->refusal == NotifyRefusal::NOT_REACHED);
        CHECK(lab.wire.sent.empty());
    }

    // During an incomplete promotion: the arrival did not complete, so there
    // is nothing to notify and the prepared context is still the target's.
    {
        TargetLab lab;
        EnbMultiplexer::PreparedHandover prepared;
        REQUIRE(lab.prepare(&prepared));
        TargetArrivalEvidence evidence;
        evidence.access = AccessFor(TestEnbConfig(SourceEnbId, "127.0.0.1"), lab.config, prepared.arrivalToken, 7,
                                    lab.ue.ueId);
        evidence.radioUeId = lab.ue.ueId;
        evidence.peer = lab.ue.radio.LocalAddress();
        evidence.target = IdentityOf(lab.config);
        evidence.targetCgi = CgiOf(lab.config);
        evidence.associationEpoch = lab.mux.associationEpoch();
        ArrivalRefusalRecord failure;
        CHECK_FALSE(lab.mux.preparations()->acceptArrival(evidence, nullptr, &failure,
                                                          ArrivalFaultInjector{ArrivalFaultInjector::Fault::
                                                                                   BEARER_READINESS}));
        CHECK(failure.refusal == ArrivalRefusal::BEARER_READINESS_FAILED);
        CHECK(lab.mux.registry().holdsProvisional(*lab.mux.registry().findByMmeUeS1apId(7)));

        const HandoverNotifyOutcome outcome = lab.mux.notifyHandover(prepared.transaction);
        CHECK_FALSE(outcome.sent);
        REQUIRE(outcome.refusal.has_value());
        CHECK(outcome.refusal->refusal == NotifyRefusal::NOT_REACHED);
        CHECK(lab.wire.sent.empty());
    }

    // With an inactive bearer: a bearer the network added to the reached UE
    // and the UE has not confirmed is not ready, and the gate reads the real
    // contexts rather than the record's description of them.
    {
        TargetLab lab;
        EnbMultiplexer::PreparedHandover prepared;
        REQUIRE(lab.prepare(&prepared));
        lab.arrive(lab.ue.ueId, prepared.arrivalToken, 7, lab.ue);
        EnbUeEntry *reached = Reached(lab);
        REQUIRE(reached != nullptr);
        REQUIRE(reached->bearer.active());

        // The production path an E-RAB Setup Request takes. The bearer is
        // established and deliberately not made UE-ready.
        const uint32_t lateTeid = lab.mux.registry().allocateLocalTeid();
        BearerContext &late = lab.mux.registry().addDedicatedBearer(
            *reached, BearerParameters{7, 7, lab.ue.ueId, SgwAddress, SgwTeid7, lateTeid, 5, Qos(7, 1, false, false)},
            false);
        CHECK_FALSE(late.active());

        const HandoverNotifyOutcome outcome = lab.mux.notifyHandover(prepared.transaction);
        CHECK_FALSE(outcome.sent);
        REQUIRE(outcome.refusal.has_value());
        CHECK(outcome.refusal->refusal == NotifyRefusal::BEARERS_NOT_READY);
        CHECK(lab.wire.sent.empty());

        // Once the UE confirms it, the gate passes.
        late.activateUe(lab.ue.ueId, 7, PdnAddress(lab.ue.ueId));
        CHECK(lab.mux.notifyHandover(prepared.transaction).sent);
    }

    // Under a stale association: a transaction begun under an association that
    // is no longer bound is not notified through a later one.
    {
        TargetLab lab;
        EnbMultiplexer::PreparedHandover prepared;
        REQUIRE(lab.prepare(&prepared));
        lab.arrive(lab.ue.ueId, prepared.arrivalToken, 7, lab.ue);
        HandoverTransactionId stale = prepared.transaction;
        stale.associationEpoch = prepared.transaction.associationEpoch + 100;
        const HandoverNotifyOutcome outcome = lab.mux.notifyHandover(stale);
        CHECK_FALSE(outcome.sent);
        REQUIRE(outcome.refusal.has_value());
        CHECK(outcome.refusal->refusal == NotifyRefusal::NO_PREPARATION);
        CHECK(lab.wire.sent.empty());
    }

    // A cell that is not the one the transaction was admitted for is refused,
    // and nothing is sent.
    {
        TargetLab lab;
        EnbMultiplexer::PreparedHandover prepared;
        REQUIRE(lab.prepare(&prepared));
        lab.arrive(lab.ue.ueId, prepared.arrivalToken, 7, lab.ue);
        CaptureSender other;
        const HandoverNotifyOutcome outcome =
            lab.mux.preparations()->notify(prepared.transaction, EnbIdentity{Plmn{"460", "02"}, 0x1234u, 1}, other, 1);
        CHECK_FALSE(outcome.sent);
        REQUIRE(outcome.refusal.has_value());
        CHECK(outcome.refusal->refusal == NotifyRefusal::TARGET_CELL_MISMATCH);
        CHECK(other.sent.empty());
        CHECK(lab.wire.sent.empty());
    }
}

// --- H: replay and collision protection ----------------------------------

TEST_CASE("lte/handover/arrival: replayed, conflicting and wrong-target arrivals disturb nothing")
{
    TargetLab lab;
    EnbMultiplexer::PreparedHandover prepared;
    REQUIRE(lab.prepare(&prepared));

    // A refusal on this path is not an exception: the production radio handler
    // classifies a rejected datagram, counts it and leaves every context alone.
    // So the evidence a refusal happened is that nothing moved.
    auto attempt = [&](const lte::ue::link::SimulatedHandoverAccess &access, uint32_t radioUeId, FakeUe &at) {
        const auto frame = AccessFrame(radioUeId, access);
        lab.mux.handleRadioFrame(frame.data(), frame.size(), at.radio.LocalAddress());
    };

    auto access = AccessFor(TestEnbConfig(SourceEnbId, "127.0.0.1"), lab.config, prepared.arrivalToken, 7, lab.ue.ueId);

    // A binding nothing ever issued is refused and allocates nothing.
    {
        auto unknown = access;
        unknown.arrivalToken = 0x0BADF00Du;
        attempt(unknown, lab.ue.ueId, lab.ue);
    }
    // A different MME UE identity than the one the transaction bound.
    {
        auto wrongUe = access;
        wrongUe.mmeUeS1apId = 99;
        attempt(wrongUe, lab.ue.ueId, lab.ue);
    }
    // A source cell the admission did not record.
    {
        auto wrongSource = access;
        wrongSource.sourceEnbId = 0x77777u;
        attempt(wrongSource, lab.ue.ueId, lab.ue);
    }
    // A target cell other than this one.
    {
        auto wrongTarget = access;
        wrongTarget.targetEnbId = 0x77777u;
        attempt(wrongTarget, lab.ue.ueId, lab.ue);
    }
    // A PDN address other than the one the source authorised. The target only
    // has the source's word for that address, so this disagreement is only
    // detectable where the caller has seen the source's command — which is
    // exactly the corroboration `sourceCommand` exists for.
    {
        TargetArrivalEvidence evidence;
        evidence.access = access;
        evidence.access.ueIpv4 = Ip(10, 9, 9, 9);
        evidence.radioUeId = lab.ue.ueId;
        evidence.peer = lab.ue.radio.LocalAddress();
        evidence.target = IdentityOf(lab.config);
        evidence.targetCgi = CgiOf(lab.config);
        evidence.associationEpoch = lab.mux.associationEpoch();
        evidence.sourceCommand = CommandFor(lab.config, prepared.arrivalToken, 7, lab.ue.ueId);
        ArrivalRefusalRecord failure;
        CHECK_FALSE(lab.mux.preparations()->acceptArrival(evidence, nullptr, &failure));
        CHECK(failure.refusal == ArrivalRefusal::SOURCE_COMMAND_MISMATCH);
    }

    // None of that moved the transaction or consumed the binding.
    const PreparationRecord *record = lab.mux.preparations()->findByArrivalToken(prepared.arrivalToken);
    REQUIRE(record != nullptr);
    CHECK(record->state == PreparationState::TARGET_PREPARED);
    CHECK_FALSE(record->ownershipTransferred);
    CHECK(lab.mux.registry().findByMmeUeS1apId(7) != nullptr);
    CHECK(UeRegistry::isProvisional(*lab.mux.registry().findByMmeUeS1apId(7)));
    CHECK(lab.mux.registry().size() == 0);

    // The real arrival succeeds, and a replay of the same frame is then a
    // spent binding rather than a second promotion.
    lab.arrive(lab.ue.ueId, prepared.arrivalToken, 7, lab.ue);
    REQUIRE(Reached(lab) != nullptr);
    const size_t before = lab.mux.registry().size();
    attempt(access, lab.ue.ueId, lab.ue);
    CHECK(lab.mux.registry().size() == before);
    CHECK(Reached(lab) != nullptr);

    // A second UE arriving under an identity that is already taken is refused,
    // and the first UE's context is untouched.
    FakeUe second{2};
    {
        auto collision = AccessFor(TestEnbConfig(SourceEnbId, "127.0.0.1"), lab.config, prepared.arrivalToken, 7,
                                   second.ueId);
        attempt(collision, lab.ue.ueId, second);
    }
    CHECK(Reached(lab)->mmeUeS1apId == 7);
    CHECK(lab.mux.registry().find(second.ueId) == nullptr);
    CHECK(lab.mux.registry().findByPeer(second.radio.LocalAddress()) == nullptr);
}

// --- I: promotion rollback -----------------------------------------------

TEST_CASE("lte/handover/arrival: a promotion that cannot complete leaves no half-promoted context")
{
    // Registry-index publication: the registry rolls its own move back and the
    // arrival never sees a reached context.
    {
        TargetLab lab;
        EnbMultiplexer::PreparedHandover prepared;
        REQUIRE(lab.prepare(&prepared));
        EnbUeEntry *entry = lab.mux.registry().findByMmeUeS1apId(7);
        REQUIRE(entry != nullptr);
        const uint32_t defaultTeid = entry->bearer.parameters().localTeid;

        TargetArrivalEvidence evidence;
        evidence.access = AccessFor(TestEnbConfig(SourceEnbId, "127.0.0.1"), lab.config, prepared.arrivalToken, 7,
                                    lab.ue.ueId);
        evidence.radioUeId = lab.ue.ueId;
        evidence.peer = lab.ue.radio.LocalAddress();
        evidence.target = IdentityOf(lab.config);
        evidence.targetCgi = CgiOf(lab.config);
        evidence.associationEpoch = lab.mux.associationEpoch();

        ArrivalRefusalRecord failure;
        CHECK_FALSE(lab.mux.preparations()->acceptArrival(evidence, nullptr, &failure,
                                                          ArrivalFaultInjector{ArrivalFaultInjector::Fault::
                                                                                   REGISTRY_PUBLICATION}));
        CHECK(failure.refusal == ArrivalRefusal::PROMOTION_FAILED);

        // No half-promoted context: nothing is in the reached indexes, the
        // prepared context is still provisional and still owns its transport,
        // and nothing forwards.
        CHECK(lab.mux.registry().find(lab.ue.ueId) == nullptr);
        CHECK(lab.mux.registry().findByPeer(lab.ue.radio.LocalAddress()) == nullptr);
        CHECK(lab.mux.registry().holdsProvisional(*entry));
        CHECK(lab.mux.registry().findByLocalTeid(defaultTeid) == entry);
        CHECK_FALSE(entry->bearer.active());

        lab.sendGPdu(defaultTeid);
        CHECK(DrainRadio(lab.ue).empty());
        CHECK(entry->counters.bearerInactiveDrops == 1);

        // The binding is still live, so a later attempt can still arrive.
        CHECK(lab.mux.preparations()->findByArrivalToken(prepared.arrivalToken)->state ==
              PreparationState::TARGET_PREPARED);
    }

    // Bearer-readiness boundary: the promotion happened and was undone, and
    // still nothing forwards.
    {
        TargetLab lab;
        EnbMultiplexer::PreparedHandover prepared;
        REQUIRE(lab.prepare(&prepared));
        EnbUeEntry *entry = lab.mux.registry().findByMmeUeS1apId(7);
        REQUIRE(entry != nullptr);
        const uint32_t defaultTeid = entry->bearer.parameters().localTeid;

        TargetArrivalEvidence evidence;
        evidence.access = AccessFor(TestEnbConfig(SourceEnbId, "127.0.0.1"), lab.config, prepared.arrivalToken, 7,
                                    lab.ue.ueId);
        evidence.radioUeId = lab.ue.ueId;
        evidence.peer = lab.ue.radio.LocalAddress();
        evidence.target = IdentityOf(lab.config);
        evidence.targetCgi = CgiOf(lab.config);
        evidence.associationEpoch = lab.mux.associationEpoch();

        ArrivalRefusalRecord failure;
        CHECK_FALSE(lab.mux.preparations()->acceptArrival(evidence, nullptr, &failure,
                                                          ArrivalFaultInjector{ArrivalFaultInjector::Fault::
                                                                                   BEARER_READINESS}));
        CHECK(failure.refusal == ArrivalRefusal::BEARER_READINESS_FAILED);

        CHECK(lab.mux.registry().find(lab.ue.ueId) == nullptr);
        CHECK(lab.mux.registry().findByPeer(lab.ue.radio.LocalAddress()) == nullptr);
        CHECK(lab.mux.registry().holdsProvisional(*entry));
        CHECK_FALSE(entry->bearer.active());
        for (const BearerContext &bearer : entry->dedicatedBearers)
            CHECK_FALSE(bearer.active());

        lab.sendGPdu(defaultTeid);
        CHECK(DrainRadio(lab.ue).empty());
        CHECK(entry->counters.bearerInactiveDrops == 1);
    }
}

// --- J: preparation owner destruction ------------------------------------

TEST_CASE("lte/handover/arrival: destroying the preparation owner leaves a reached ue alone")
{
    TargetLab lab;
    EnbMultiplexer::PreparedHandover prepared;
    REQUIRE(lab.prepare(&prepared));
    lab.arrive(lab.ue.ueId, prepared.arrivalToken, 7, lab.ue);

    EnbUeEntry *reached = Reached(lab);
    REQUIRE(reached != nullptr);
    const uint32_t defaultTeid = reached->bearer.parameters().localTeid;
    const uint32_t dedicatedTeid = reached->dedicatedBearers.front().parameters().localTeid;

    // Unbinding the association destroys the preparation owner. That is
    // ordinary association teardown and is the strictest cleanup this phase
    // has.
    lab.mux.unbindAssociation();

    // The reached UE still exists and still owns its transport.
    EnbUeEntry *still = lab.mux.registry().find(lab.ue.ueId);
    REQUIRE(still != nullptr);
    CHECK(still == reached);
    CHECK(still->mmeUeS1apId == 7);
    CHECK(still->enbUeS1apId == prepared.acknowledge.enbUeS1apId);
    CHECK(still->bearer.active());
    CHECK(still->dedicatedBearers.front().active());
    CHECK(lab.mux.registry().findByLocalTeid(defaultTeid) == still);
    CHECK(lab.mux.registry().findByLocalTeid(dedicatedTeid) == still);
    CHECK(lab.mux.registry().findByPeer(lab.ue.radio.LocalAddress()) == still);

    // Nothing was retired behind it: a fresh downlink still resolves and is
    // delivered, so the TEIDs are live rather than merely remembered.
    lab.sendGPdu(defaultTeid);
    auto frames = DrainRadio(lab.ue);
    REQUIRE(frames.size() == 1);
    CHECK(frames.front().type == MessageType::DATA_DOWNLINK);
}

// --- K: source and multi-UE isolation ------------------------------------

TEST_CASE("lte/handover/arrival: a failed arrival leaves the source and another ue untouched")
{
    // Two eNBs and two UEs. The source holds one UE's established session; the
    // target prepares a handover for it and a second one for another UE.
    CaptureSender sourceWire, targetWire;
    EnbConfig sourceConfig = TestEnbConfig(SourceEnbId, "127.0.0.1");
    EnbConfig targetConfig = TestEnbConfig(TargetEnbId, "127.0.0.3");
    EnbMultiplexer source{sourceConfig, sourceWire};
    EnbMultiplexer target{targetConfig, targetWire};
    FakeUe first{1}, second{2};

    // A reached UE on the source, built through the production registration
    // path, holding its own live TEIDs.
    EnbUeEntry &sourceEntry = source.registry().registerPeer(first.ueId, first.radio.LocalAddress());
    source.registry().bindEnbUeS1apId(sourceEntry, source.registry().allocateEnbUeS1apId());
    source.registry().setMmeUeS1apId(sourceEntry, 7);
    const uint32_t sourceTeid = source.registry().allocateLocalTeid();
    sourceEntry.bearer.establish(BearerParameters{5, 5, first.ueId, SgwAddress, SgwTeid5, sourceTeid, 0, Qos(5, 15)},
                                 false);
    sourceEntry.bearer.activateUe(first.ueId, 5, PdnAddress(first.ueId));
    source.registry().bindLocalTeid(sourceEntry, sourceTeid);
    sourceEntry.s1 = UeS1State::BEARER_ACTIVE;

    SourceContext sourceContext{EnbIdentity{Plmn{"460", "02"}, SourceEnbId, 1}, true};
    auto targetContext = [&] {
        TargetContext t;
        t.identity = IdentityOf(targetConfig);
        t.s1uAddress = Ip(127, 0, 0, 3);
        t.encryptionAlgorithms = {0x80, 0x00};
        t.integrityAlgorithms = {0x40, 0x00};
        return t;
    };

    EnbMultiplexer::PreparedHandover one, two;
    REQUIRE(target.prepareHandover(Transaction(7, target.associationEpoch()), SampleRequest(7), sourceContext,
                                   targetContext(), SampleRoles(), &one));
    REQUIRE(target.prepareHandover(Transaction(8, target.associationEpoch()), SampleRequest(8), sourceContext,
                                   targetContext(), SampleRoles(), &two));
    REQUIRE(one.arrivalToken != 0);
    REQUIRE(two.arrivalToken != 0);
    REQUIRE(one.arrivalToken != two.arrivalToken);

    EnbUeEntry *twoProvisional = target.registry().findByMmeUeS1apId(8);
    REQUIRE(twoProvisional != nullptr);
    const uint32_t twoTeid = twoProvisional->bearer.parameters().localTeid;

    // The first arrival fails: it names a source cell this admission did not
    // record. The production radio handler classifies the refusal and moves
    // nothing, so the evidence is that nothing moved.
    lte::ue::link::SimulatedHandoverAccess wrong = AccessFor(sourceConfig, targetConfig, one.arrivalToken, 7, first.ueId);
    wrong.sourceEnbId = 0x55555u;
    const auto badFrame = AccessFrame(first.ueId, wrong);
    target.handleRadioFrame(badFrame.data(), badFrame.size(), first.radio.LocalAddress());
    CHECK(target.registry().find(first.ueId) == nullptr);
    CHECK(target.registry().findByMmeUeS1apId(7) != nullptr);
    CHECK(UeRegistry::isProvisional(*target.registry().findByMmeUeS1apId(7)));

    // The source is untouched: same TEID, still resolvable, still active.
    EnbUeEntry *sourceAfter = source.registry().find(first.ueId);
    REQUIRE(sourceAfter != nullptr);
    CHECK(sourceAfter == &sourceEntry);
    CHECK(sourceAfter->bearer.parameters().localTeid == sourceTeid);
    CHECK(sourceAfter->bearer.active());
    CHECK(source.registry().findByLocalTeid(sourceTeid) == sourceAfter);

    // The other UE's target resources are untouched and still prepared.
    EnbUeEntry *twoAfter = target.registry().findByMmeUeS1apId(8);
    REQUIRE(twoAfter != nullptr);
    CHECK(twoAfter == twoProvisional);
    CHECK(UeRegistry::isProvisional(*twoAfter));
    CHECK(twoAfter->bearer.parameters().localTeid == twoTeid);
    CHECK(target.registry().findByLocalTeid(twoTeid) == twoAfter);
    CHECK_FALSE(twoAfter->bearer.active());

    // The first arrival then succeeds on its own binding and leaves the second
    // preparation exactly as it was.
    const auto goodFrame =
        AccessFrame(first.ueId, AccessFor(sourceConfig, targetConfig, one.arrivalToken, 7, first.ueId));
    target.handleRadioFrame(goodFrame.data(), goodFrame.size(), first.radio.LocalAddress());
    EnbUeEntry *firstReached = target.registry().find(first.ueId);
    REQUIRE(firstReached != nullptr);
    CHECK(firstReached->mmeUeS1apId == 7);
    CHECK(firstReached->bearer.active());
    CHECK(target.registry().findByMmeUeS1apId(8) == twoProvisional);
    CHECK(UeRegistry::isProvisional(*target.registry().findByMmeUeS1apId(8)));
    CHECK(target.registry().findByLocalTeid(twoTeid) == twoProvisional);
}

// --- L: accepted production contracts are unchanged ----------------------

TEST_CASE("lte/handover/arrival: the accepted gtpu and teid contracts are unchanged")
{
    // The GTP-U dispatch whitelist is still exactly four message types, and an
    // End Marker is still recorded and nothing else moves. Phase 18-C touched
    // the registry and the bearer context, so this pins the boundary it must
    // not have widened.
    {
        TargetLab lab;
        EnbMultiplexer::PreparedHandover prepared;
        REQUIRE(lab.prepare(&prepared));
        lab.arrive(lab.ue.ueId, prepared.arrivalToken, 7, lab.ue);
        EnbUeEntry *reached = Reached(lab);
        REQUIRE(reached != nullptr);
        const uint32_t teid = reached->bearer.parameters().localTeid;

        udp::UdpServer sgw("127.0.0.9", 2152);
        // A bare End Marker: version 1, protocol type 1, no optional fields,
        // length zero, naming the tunnel whose payload stream is ending.
        std::vector<uint8_t> marker{0x30, gtpu::EndMarker, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00};
        marker[4] = static_cast<uint8_t>(teid >> 24);
        marker[5] = static_cast<uint8_t>(teid >> 16);
        marker[6] = static_cast<uint8_t>(teid >> 8);
        marker[7] = static_cast<uint8_t>(teid);
        REQUIRE(gtpu::Decode(marker.data(), marker.size()).messageType == gtpu::EndMarker);
        sgw.Send(lab.mux.s1uAddress(), marker.data(), marker.size());
        lab.mux.poll(0, 16);
        CHECK(DrainRadio(lab.ue).empty());
        CHECK(lab.mux.registry().findByLocalTeid(teid) == reached);
        CHECK(reached->bearer.active());
        CHECK(reached->bearer.counters().downlinkPackets == 0);
    }

    // There is no revival: a retired identifier is still unusable and the
    // allocator never reissues one. Phase 18-C moved ownership between two
    // owners and must not have moved it here.
    {
        TeidSequence sequence(0x00004000u, 64);
        UeRegistry registry(8, [&sequence] { return sequence.next(); });
        EnbUeEntry &entry = registry.registerPeer(1, InetAddress("127.0.0.1", 41001));
        registry.bindEnbUeS1apId(entry, registry.allocateEnbUeS1apId());
        const uint32_t teid = registry.allocateLocalTeid();
        entry.bearer.establish(BearerParameters{5, 5, 1, SgwAddress, SgwTeid5, teid, 0, Qos(5, 15)}, false);
        entry.bearer.activateUe(1, 5, PdnAddress(1));
        registry.bindLocalTeid(entry, teid);
        CHECK(registry.findByLocalTeid(teid) == &entry);

        // A release is the production path that stops a tunnel resolving, and
        // it goes through retirement rather than through a bare erase.
        registry.releaseS1(entry);
        CHECK(registry.findByLocalTeid(teid) == nullptr);
        CHECK(registry.isRetiredTeid(teid));

        // The identifier is not reserved, so it cannot be bound again, and a
        // monotonic allocator has already spent its step.
        EnbUeEntry &other = registry.registerPeer(2, InetAddress("127.0.0.1", 41002));
        CHECK_THROWS(registry.bindLocalTeid(other, teid));
        for (int i = 0; i < 8; ++i)
            CHECK(registry.allocateLocalTeid() != teid);
    }
}
