//
// Phase 18-B: atomic target-eNB handover resource commitment.
//
// These cases drive the bridge between `EvaluateHandoverAdmission` and
// `BuildHandoverRequestAcknowledge`. Every transport identifier they observe
// comes out of the registry's allocator on the same path a production bearer
// establishment runs, so nothing here can be closed by a value a test chose and
// then attached. Where a case needs a specific value on the wire it queues that
// value *for the allocator to return*, which is the documented test seam and not
// an assignment to a bearer.
//
// The non-forwarding case sends a real G-PDU at the real shared S1-U endpoint
// and reads the endpoint's own counters, rather than asserting on a bearer flag
// the test could have set itself.

#include <ext/doctest/doctest.h>

#include <lte/enb/gtpu.hpp>
#include <lte/enb/handover_admission.hpp>
#include <lte/enb/handover_preparation.hpp>
#include <lte/enb/s1u_endpoint.hpp>
#include <lte/enb/ue_registry.hpp>

#include <array>
#include <chrono>
#include <cstdint>
#include <deque>
#include <functional>
#include <set>
#include <string>
#include <utility>
#include <vector>

namespace
{

using namespace lte::enb;
using namespace lte::enb::s1ap;
using lte::ErabQos;
using lte::UeAmbr;

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

EnbIdentity SourceIdentity()
{
    return EnbIdentity{Plmn{"001", "01"}, 0x0012345u, 1};
}

EnbIdentity TargetIdentity()
{
    return EnbIdentity{Plmn{"001", "01"}, 0x00ABCDEu, 2};
}

// The SGW endpoint every prepared bearer carries across unchanged, and the
// peer the shared S1-U endpoint will accept a downlink from.
constexpr std::array<uint8_t, 4> SgwAddress{127, 0, 0, 9};
constexpr uint32_t SgwTeid5 = 0x0A0B0C0Du;
constexpr uint32_t SgwTeid6 = 0x0E0F1011u;
constexpr uint32_t SgwTeid7 = 0x12131415u;

const InetAddress &SgwPeer()
{
    static const InetAddress peer{"127.0.0.9", 2152};
    return peer;
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

// One default bearer (E-RAB 5) and one dedicated bearer (E-RAB 6 linked to it).
// The list order is the request's; the roles are the network's own statement of
// the session and are never derived from the QCI or from that order.
HandoverRequest SampleRequest()
{
    HandoverRequest message;
    message.mmeUeS1apId = 7;
    message.handoverType = HandoverType::INTRA_LTE;
    message.causeCategory = "radioNetwork";
    message.causeValue = 16;
    message.ueAmbr = UeAmbr{150000000ULL, 75000000ULL};
    message.erabs = {RequestBearer(5, 5, 15, false, false, SgwTeid5),
                     RequestBearer(6, 6, 3, false, true, SgwTeid6)};
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

SourceContext SampleSource()
{
    return SourceContext{SourceIdentity(), true};
}

TargetContext SampleTargetContext()
{
    TargetContext target;
    target.identity = TargetIdentity();
    target.s1uAddress = Ip(198, 51, 100, 1);
    target.encryptionAlgorithms = {0x80, 0x00};
    target.integrityAlgorithms = {0x40, 0x00};
    return target;
}

HandoverTransactionId Transaction(uint32_t mmeUeS1apId, uint64_t epoch, uint32_t sequence = 0)
{
    return HandoverTransactionId{mmeUeS1apId, epoch, sequence};
}

constexpr uint64_t Epoch = 41;

// --- one target eNB, real production resource management ------------------

// A target whose local TEIDs come from a `TeidSequence`, which is "of exactly
// the form production uses". Nothing in these cases assigns a TEID to a bearer.
struct TargetLab
{
    explicit TargetLab(uint32_t seed = 0x00001000u, size_t maxUes = 8)
        : sequence(seed, 64), registry(maxUes, [this] { return sequence.next(); })
    {
    }

    TeidSequence sequence;
    UeRegistry registry;
};

// --- one target eNB whose identifiers are chosen by the case ---------------

// The same thing with a queue instead of a monotonic sequence, for the cases
// that must put an exact identifier on the wire. The value still reaches the
// bearer only through the allocator's reservation and the binder's validation.
struct WireLab
{
    udp::UdpServer ueLink{"127.0.0.1", 0};
    std::deque<uint32_t> teidQueue;
    UeRegistry registry;
    S1uEndpoint s1u{"127.0.0.1", 0, true, registry, ueLink};

    WireLab() : registry(8, [this] {
        if (teidQueue.empty())
            throw TeidExhausted("the test TEID queue is empty");
        const uint32_t value = teidQueue.front();
        teidQueue.pop_front();
        return value;
    })
    {
    }

    static bool received(udp::UdpServer &socket)
    {
        std::array<uint8_t, 512> buffer{};
        InetAddress peer;
        return socket.Receive(buffer.data(), buffer.size(), 0, peer) > 0;
    }
};

const std::vector<uint8_t> kPayload{0x45, 0x00, 0x00, 0x14, 0x00, 0x00, 0x00, 0x00,
                                    0x40, 0x01, 0x00, 0x00, 0x7F, 0x00, 0x00, 0x01,
                                    0x7F, 0x00, 0x00, 0x02};

// A G-PDU on the wire, from the SGW peer this preparation named.
std::vector<uint8_t> GPduWire(uint32_t teid, const std::vector<uint8_t> &payload)
{
    return gtpu::EncodeTPdu(teid, payload.data(), payload.size());
}

// --- a reached UE at a source eNB, built through the production path -------

// The source side of the two-eNB fixture. Everything here goes through
// `registerPeer`, `establish`, `activateUe` and `bindLocalTeid`, which is the
// same sequence the eNB runtime runs. Nothing is set by hand behind the APIs.
struct SourceUe
{
    TeidSequence sequence;
    UeRegistry registry;
    EnbUeEntry *entry{};
    uint32_t defaultTeid{};
    uint32_t dedicatedTeid{};

    explicit SourceUe(uint32_t radioUeId, uint32_t mmeUeS1apId)
        : sequence(0x00002000u, 64), registry(8, [this] { return sequence.next(); })
    {
        entry = &registry.registerPeer(radioUeId, InetAddress("127.0.0.1", static_cast<uint16_t>(40000 + radioUeId)));
        registry.bindEnbUeS1apId(*entry, registry.allocateEnbUeS1apId());
        registry.setMmeUeS1apId(*entry, mmeUeS1apId);

        defaultTeid = registry.allocateLocalTeid();
        entry->bearer.establish(
            BearerParameters{5, 5, radioUeId, SgwAddress, SgwTeid5, defaultTeid, 0, Qos(5, 15)}, false);
        entry->bearer.activateUe(radioUeId, 5, {10, 45, 0, static_cast<uint8_t>(radioUeId)});
        registry.bindLocalTeid(*entry, defaultTeid);

        dedicatedTeid = registry.allocateLocalTeid();
        auto &dedicated = registry.addDedicatedBearer(
            *entry,
            BearerParameters{6, 6, radioUeId, SgwAddress, SgwTeid6, dedicatedTeid, 5, Qos(6, 3, false, true)}, false);
        dedicated.activateUe(radioUeId, 6, entry->bearer.ueIpv4());
        registry.bindLocalTeid(*entry, dedicated, dedicatedTeid);

        entry->s1 = UeS1State::BEARER_ACTIVE;
    }
};

} // namespace

// --- A: real target resources ---------------------------------------------

TEST_CASE("lte/handover/preparation: a commit binds real allocator teids and owns a provisional context")
{
    TargetLab lab;
    HandoverAdmission admission =
        EvaluateHandoverAdmission(SampleRequest(), SampleSource(), SampleTargetContext(), SampleRoles());
    REQUIRE(admission.admitted);
    REQUIRE_FALSE(admission.holdsTransportResources());

    const uint64_t issuedBefore = lab.sequence.issued();
    TargetResourceCommit commit =
        CommitHandoverResources(admission, SampleTargetContext(), lab.registry, Transaction(7, Epoch));

    REQUIRE(commit.committed);
    CHECK(commit.refusal == std::nullopt);
    CHECK(commit.outstandingTeids.empty());
    CHECK(commit.prepared.bearers.size() == 2);
    CHECK(commit.prepared.committed.size() == 2);
    CHECK(commit.prepared.state == PreparationState::TARGET_PREPARED);
    CHECK(commit.prepared.resourceState == ResourceState::RESOURCES_COMMITTED_PREPARED);

    // Every identifier came out of the allocator, and exactly one per bearer.
    CHECK(lab.sequence.issued() == issuedBefore + 2);
    CHECK(commit.prepared.bearers[0].localTeid != 0);
    CHECK(commit.prepared.bearers[1].localTeid != 0);
    CHECK(commit.prepared.bearers[0].localTeid != commit.prepared.bearers[1].localTeid);

    // The values are owned by the registry: they resolve, and they resolve to
    // the context this commit created.
    EnbUeEntry *entry = commit.ownedEntry;
    REQUIRE(entry != nullptr);
    for (const auto &bearer : commit.prepared.bearers)
        CHECK(lab.registry.findByLocalTeid(bearer.localTeid) == entry);

    // It is a provisional target context, not a reached UE and not a session.
    CHECK(UeRegistry::isProvisional(*entry));
    CHECK(entry->radioUeId == 0);
    CHECK(lab.registry.find(entry->radioUeId) == nullptr);
    CHECK(lab.registry.findByPeer(InetAddress("127.0.0.1", 0)) == nullptr);

    // The S1AP identity is the registry's too.
    CHECK(commit.prepared.enbUeS1apId != 0);
    CHECK(lab.registry.findByEnbUeS1apId(commit.prepared.enbUeS1apId) == entry);
    CHECK(lab.registry.findByMmeUeS1apId(7) == entry);

    // The network's own statement of each bearer is carried across unchanged,
    // and the target adds only its own transport.
    const PreparedBearer &def = commit.prepared.bearers[0];
    const PreparedBearer &ded = commit.prepared.bearers[1];
    CHECK(def.role == BearerRole::DEFAULT);
    CHECK(def.erabId == 5);
    CHECK(def.qci == 5);
    CHECK(def.priorityLevel == 15);
    CHECK(def.sgwAddress == SgwAddress);
    CHECK(def.sgwTeid == TeidBytes(SgwTeid5));
    CHECK(def.targetAddress == SampleTargetContext().s1uAddress);
    CHECK_FALSE(def.linkedDefaultErabId.has_value());
    CHECK(ded.role == BearerRole::DEDICATED);
    CHECK(ded.erabId == 6);
    CHECK(ded.qci == 6);
    CHECK(ded.priorityLevel == 3);
    CHECK(ded.preemptionVulnerability);
    CHECK_FALSE(ded.preemptionCapability);
    CHECK(ded.linkedDefaultErabId == std::optional<uint8_t>{5});
    CHECK(ded.sgwAddress == SgwAddress);
    CHECK(ded.sgwTeid == TeidBytes(SgwTeid6));
    CHECK(ded.targetAddress == SampleTargetContext().s1uAddress);

    // The committed set is exactly the two endpoints, in readiness order.
    CHECK(commit.prepared.committed[0].erabId == 5);
    CHECK(commit.prepared.committed[0].address == SampleTargetContext().s1uAddress);
    CHECK(commit.prepared.committed[0].teid == TeidBytes(def.localTeid));
    CHECK(commit.prepared.committed[1].erabId == 6);
    CHECK(commit.prepared.committed[1].teid == TeidBytes(ded.localTeid));
}

TEST_CASE("lte/handover/preparation: a prepared bearer is established and not ready for the ue")
{
    TargetLab lab;
    HandoverAdmission admission =
        EvaluateHandoverAdmission(SampleRequest(), SampleSource(), SampleTargetContext(), SampleRoles());
    REQUIRE(admission.admitted);
    TargetResourceCommit commit =
        CommitHandoverResources(admission, SampleTargetContext(), lab.registry, Transaction(7, Epoch));
    REQUIRE(commit.committed);
    EnbUeEntry *entry = commit.ownedEntry;
    REQUIRE(entry != nullptr);

    // The prepared state is the bearer's own: established so the transport is
    // real, not UE-ready so nothing may be delivered to a UE that has not
    // arrived. Nothing in this phase calls `activateUe`, so it cannot become
    // ready by accident.
    REQUIRE(entry->bearer.signalingEstablished());
    CHECK_FALSE(entry->bearer.active());
    REQUIRE(entry->dedicatedBearers.size() == 1);
    REQUIRE(entry->dedicatedBearers[0].signalingEstablished());
    CHECK_FALSE(entry->dedicatedBearers[0].active());
    CHECK(PreparedBearersNonForwardable(*entry));

    // A reached UE is not in this state and the predicate says so, before the
    // bearer exists and after it does.
    UeRegistry reached(8);
    auto &ue = reached.registerPeer(1, InetAddress("127.0.0.1", 40001));
    CHECK_FALSE(PreparedBearersNonForwardable(ue));
    const uint32_t teid = reached.allocateLocalTeid();
    ue.bearer.establish(BearerParameters{5, 5, 1, SgwAddress, SgwTeid5, teid, 0, Qos(5, 15)}, false);
    reached.bindLocalTeid(ue, teid);
    CHECK_FALSE(PreparedBearersNonForwardable(ue));
    ue.bearer.activateUe(1, 5, {10, 45, 0, 1});
    CHECK_FALSE(PreparedBearersNonForwardable(ue));
}

// --- B: the acknowledge comes from what was committed ----------------------

TEST_CASE("lte/handover/preparation: the acknowledge names exactly the transport the commit bound")
{
    TargetLab lab;
    HandoverAdmission admission =
        EvaluateHandoverAdmission(SampleRequest(), SampleSource(), SampleTargetContext(), SampleRoles());
    REQUIRE(admission.admitted);
    HandoverPreparationOwner owner(lab.registry, Epoch);
    PreparationRecord *record =
        owner.admit(Transaction(7, Epoch), SampleRequest(), SampleSource(), SampleTargetContext(), SampleRoles());
    REQUIRE(record != nullptr);
    REQUIRE(record->state == PreparationState::ADMITTED);

    TargetResourceCommit commit = owner.commit(record->id, SampleTargetContext());
    REQUIRE(commit.committed);

    HandoverRequestAcknowledge message = owner.acknowledge(record->id);
    CHECK(message.mmeUeS1apId == 7);
    CHECK(message.enbUeS1apId == commit.prepared.enbUeS1apId);
    REQUIRE(message.admitted.size() == 2);

    // One committed endpoint per admitted bearer, and the wire form is the one
    // the encoder produces for the values the commit actually bound.
    HandoverRequestAcknowledge expected;
    expected.mmeUeS1apId = 7;
    expected.enbUeS1apId = commit.prepared.enbUeS1apId;
    for (const auto &bearer : commit.prepared.bearers)
    {
        ErabAdmittedItem item;
        item.erabId = bearer.erabId;
        item.transportLayerAddress = bearer.targetAddress;
        item.gtpTeid = TeidBytes(bearer.localTeid);
        expected.admitted.push_back(item);
    }
    expected.targetToSource = admission.sourceToTarget;
    CHECK(EncodeHandoverRequestAcknowledge(message) == EncodeHandoverRequestAcknowledge(expected));

    // The committed set is the input `BuildHandoverRequestAcknowledge`
    // validates, so the two must agree exactly; nothing is filled in here.
    HandoverRequestAcknowledge direct = BuildHandoverRequestAcknowledge(
        admission, 7, commit.prepared.enbUeS1apId, commit.prepared.committed);
    CHECK(EncodeHandoverRequestAcknowledge(direct) == EncodeHandoverRequestAcknowledge(message));

    // Repeating it produces the same message and gains no resource.
    const uint64_t issued = lab.sequence.issued();
    CHECK(EncodeHandoverRequestAcknowledge(owner.acknowledge(record->id)) ==
          EncodeHandoverRequestAcknowledge(message));
    CHECK(lab.sequence.issued() == issued);

    // The container is the accepted Phase 18-A echo of the admission's
    // source-to-target container. It is pinned rather than changed.
    CHECK(message.targetToSource == admission.sourceToTarget);
    CHECK(message.targetToSource == std::vector<uint8_t>{0x01, 0x02, 0x03, 0x04});
}

TEST_CASE("lte/handover/preparation: a refused commit reports a failure that names no surviving identifier")
{
    TargetLab lab;
    HandoverAdmission admission =
        EvaluateHandoverAdmission(SampleRequest(), SampleSource(), SampleTargetContext(), SampleRoles());
    REQUIRE(admission.admitted);
    TargetResourceCommit commit =
        CommitHandoverResources(admission, SampleTargetContext(), lab.registry, Transaction(7, Epoch),
                                CommitFaultInjector(CommitFaultInjector::Fault::CAPACITY_EXHAUSTED));
    REQUIRE_FALSE(commit.committed);
    REQUIRE(commit.refusal.has_value());
    CHECK(commit.refusal->refusal == CommitRefusal::CAPACITY_EXHAUSTED);

    HandoverFailure failure = CommitRefusalAsHandoverFailure(*commit.refusal, 7);
    CHECK(failure.mmeUeS1apId == 7);
    CHECK(failure.causeCategory == "radioNetwork");
    CHECK(failure.causeValue == 20);

    // Nothing may be acknowledged from it.
    HandoverPreparationOwner owner(lab.registry, Epoch);
    CHECK_THROWS_AS(owner.acknowledge(Transaction(7, Epoch)), HandoverRefused);
}

// --- C: readiness order is not the wire order ------------------------------

TEST_CASE("lte/handover/preparation: a reversed e-rab list still commits default first")
{
    // The same session as `SampleRequest`, deliberately listed dedicated first.
    HandoverRequest request = SampleRequest();
    std::swap(request.erabs[0], request.erabs[1]);

    TargetLab lab;
    HandoverAdmission admission =
        EvaluateHandoverAdmission(request, SampleSource(), SampleTargetContext(), SampleRoles());
    REQUIRE(admission.admitted);

    TargetResourceCommit commit =
        CommitHandoverResources(admission, SampleTargetContext(), lab.registry, Transaction(7, Epoch));
    REQUIRE(commit.committed);
    REQUIRE(commit.prepared.bearers.size() == 2);
    // The order is derived from the roles, never from the position in the list.
    CHECK(commit.prepared.bearers[0].role == BearerRole::DEFAULT);
    CHECK(commit.prepared.bearers[0].erabId == 5);
    CHECK(commit.prepared.bearers[1].role == BearerRole::DEDICATED);
    CHECK(commit.prepared.bearers[1].erabId == 6);
    CHECK(commit.prepared.committed[0].erabId == 5);
    CHECK(commit.prepared.committed[1].erabId == 6);
    // The default really is the default context, so a dedicated bearer's link
    // resolves against it.
    REQUIRE(commit.ownedEntry != nullptr);
    CHECK(commit.ownedEntry->bearer.parameters().erabId == 5);
    REQUIRE(commit.ownedEntry->dedicatedBearers.size() == 1);
    CHECK(commit.ownedEntry->dedicatedBearers[0].parameters().linkedDefaultEbi == 5);
}

TEST_CASE("lte/handover/preparation: three bearers listed in a scrambled order commit in readiness order")
{
    HandoverRequest request;
    request.mmeUeS1apId = 7;
    request.handoverType = HandoverType::INTRA_LTE;
    request.causeCategory = "radioNetwork";
    request.causeValue = 16;
    request.ueAmbr = UeAmbr{150000000ULL, 75000000ULL};
    request.erabs = {RequestBearer(7, 7, 4, true, false, SgwTeid7), RequestBearer(5, 5, 15, false, false, SgwTeid5),
                     RequestBearer(6, 6, 3, false, true, SgwTeid6)};
    request.sourceToTarget = {0x01, 0x02, 0x03, 0x04};
    request.encryptionAlgorithms = {0x80, 0x00};
    request.integrityAlgorithms = {0x40, 0x00};
    request.securityContext.nextHopChainingCount = 3;
    request.securityContext.nextHopParameter = TestNextHopParameter();

    std::vector<BearerRoleBinding> roles = {
        RoleDedicated(7, 5, 7, 4, true, false), RoleDefault(5, 5, 15), RoleDedicated(6, 5, 6, 3, false, true)};

    TargetLab lab;
    HandoverAdmission admission = EvaluateHandoverAdmission(request, SampleSource(), SampleTargetContext(), roles);
    REQUIRE(admission.admitted);
    TargetResourceCommit commit =
        CommitHandoverResources(admission, SampleTargetContext(), lab.registry, Transaction(7, Epoch));
    REQUIRE(commit.committed);
    REQUIRE(commit.prepared.bearers.size() == 3);

    std::vector<uint8_t> order;
    for (const auto &bearer : commit.prepared.bearers)
        order.push_back(bearer.erabId);
    // The single default is first whatever the wire order was, and the
    // dedicated bearers follow it in the order the request listed them: the
    // only readiness constraint is that a dedicated bearer follows the default
    // it links to, and both of these link to E-RAB 5.
    CHECK(order == std::vector<uint8_t>{5, 7, 6});
    CHECK(commit.prepared.bearers[0].role == BearerRole::DEFAULT);
    CHECK(commit.prepared.bearers[1].role == BearerRole::DEDICATED);
    CHECK(commit.prepared.bearers[2].role == BearerRole::DEDICATED);
    CHECK(commit.prepared.bearers[1].linkedDefaultErabId == std::optional<uint8_t>{5});
    CHECK(commit.prepared.bearers[2].linkedDefaultErabId == std::optional<uint8_t>{5});
    // The network's own QoS is per bearer and cannot blur together.
    CHECK(commit.prepared.bearers[1].qci == 7);
    CHECK(commit.prepared.bearers[2].qci == 6);
    CHECK(commit.prepared.bearers[1].preemptionCapability);
    CHECK_FALSE(commit.prepared.bearers[2].preemptionCapability);
    // And each dedicated bearer's link resolves against the single default.
    REQUIRE(commit.ownedEntry != nullptr);
    REQUIRE(commit.ownedEntry->dedicatedBearers.size() == 2);
    CHECK(commit.ownedEntry->dedicatedBearers[0].parameters().linkedDefaultEbi == 5);
    CHECK(commit.ownedEntry->dedicatedBearers[1].parameters().linkedDefaultEbi == 5);
}

// --- D: atomicity and the two kinds of rollback ---------------------------

TEST_CASE("lte/handover/preparation: a failure on the second bearer leaves nothing of the first")
{
    TargetLab lab;
    HandoverAdmission admission =
        EvaluateHandoverAdmission(SampleRequest(), SampleSource(), SampleTargetContext(), SampleRoles());
    REQUIRE(admission.admitted);
    REQUIRE(admission.bearers.size() == 2);

    const uint64_t issuedBefore = lab.sequence.issued();
    TargetResourceCommit commit = CommitHandoverResources(
        admission, SampleTargetContext(), lab.registry, Transaction(7, Epoch),
        CommitFaultInjector(CommitFaultInjector::Fault::DEDICATED_BEARER_PREPARATION));

    REQUIRE_FALSE(commit.committed);
    REQUIRE(commit.refusal.has_value());
    CHECK(commit.refusal->refusal == CommitRefusal::DEDICATED_BEARER_PREPARATION_FAILED);
    CHECK_FALSE(commit.holdsTransportResources());
    CHECK(commit.prepared.bearers.empty());
    CHECK(commit.prepared.committed.empty());
    CHECK(commit.prepared.enbUeS1apId == 0);
    CHECK(commit.ownedEntry == nullptr);
    CHECK(commit.outstandingTeids.empty());

    // Both identifiers were spent, because both were reserved before the
    // failure. The rollback never rewinds the allocator.
    CHECK(lab.sequence.issued() == issuedBefore + 2);
    const uint32_t defaultTeid = 0x00001001u;
    const uint32_t dedicatedTeid = 0x00001002u;

    // The default bearer had been bound, so its identifier stops resolving and
    // is identifiable as retired: its tunnel existed and ended.
    CHECK(lab.registry.findByLocalTeid(defaultTeid) == nullptr);
    CHECK(lab.registry.isRetiredTeid(defaultTeid));

    // The dedicated bearer's identifier had only been reserved. It must not be
    // recorded as retired, because no tunnel of this registry ever existed to
    // retire; it is simply not there.
    CHECK(lab.registry.findByLocalTeid(dedicatedTeid) == nullptr);
    CHECK_FALSE(lab.registry.isRetiredTeid(dedicatedTeid));

    // And the provisional context is gone: no prepared ownership survives a
    // refusal, so no partial acknowledge can be built from it.
    CHECK(lab.registry.findByMmeUeS1apId(7) == nullptr);
    CHECK(lab.registry.findByEnbUeS1apId(commit.prepared.enbUeS1apId) == nullptr);
}

TEST_CASE("lte/handover/preparation: a failure on the first bearer reserves one identifier and drops it")
{
    TargetLab lab;
    HandoverAdmission admission =
        EvaluateHandoverAdmission(SampleRequest(), SampleSource(), SampleTargetContext(), SampleRoles());
    REQUIRE(admission.admitted);

    const uint64_t issuedBefore = lab.sequence.issued();
    TargetResourceCommit commit = CommitHandoverResources(
        admission, SampleTargetContext(), lab.registry, Transaction(7, Epoch),
        CommitFaultInjector(CommitFaultInjector::Fault::DEFAULT_BEARER_PREPARATION));
    REQUIRE_FALSE(commit.committed);
    REQUIRE(commit.refusal.has_value());
    CHECK(commit.refusal->refusal == CommitRefusal::DEFAULT_BEARER_PREPARATION_FAILED);

    CHECK(lab.sequence.issued() == issuedBefore + 1);
    const uint32_t teid = 0x00001001u;
    CHECK(lab.registry.findByLocalTeid(teid) == nullptr);
    // Nothing was ever bound, so nothing is retired. The reservation is
    // dropped and the identifier is spent.
    CHECK_FALSE(lab.registry.isRetiredTeid(teid));
    CHECK_FALSE(commit.holdsTransportResources());
    CHECK(commit.ownedEntry == nullptr);
    CHECK(commit.outstandingTeids.empty());
}

TEST_CASE("lte/handover/preparation: a rollback that cannot complete is surfaced, never reported as success")
{
    TargetLab lab;
    HandoverAdmission admission =
        EvaluateHandoverAdmission(SampleRequest(), SampleSource(), SampleTargetContext(), SampleRoles());
    REQUIRE(admission.admitted);

    // A dedicated bearer's preparation fails, and the rollback of what that
    // leaves behind does not complete. Both faults are needed: without the
    // first there is no rollback to fail.
    TargetResourceCommit commit = CommitHandoverResources(
        admission, SampleTargetContext(), lab.registry, Transaction(7, Epoch),
        CommitFaultInjector(CommitFaultInjector::Fault::DEDICATED_BEARER_PREPARATION,
                            CommitFaultInjector::Fault::CLEANUP_FAILURE));

    REQUIRE_FALSE(commit.committed);
    REQUIRE(commit.refusal.has_value());
    CHECK(commit.refusal->refusal == CommitRefusal::CLEANUP_FAILED);
    // It is not a committed success either.
    CHECK(commit.prepared.state == PreparationState::COMMIT_FAILED);
    CHECK(commit.prepared.enbUeS1apId == 0);

    // What is still outstanding is visible rather than quietly lost. The whole
    // reserved set is named, including the identifier that was only reserved:
    // a retry that could not see that one would leak it.
    REQUIRE(commit.ownedEntry != nullptr);
    REQUIRE(commit.outstandingTeids.size() == 2);
    CHECK(commit.outstandingTeids[0] == 0x00001001u);
    CHECK(commit.outstandingTeids[1] == 0x00001002u);
    CHECK(commit.holdsTransportResources());
    REQUIRE(commit.prepared.bearers.size() == 1);
    CHECK(commit.prepared.bearers[0].localTeid == 0x00001001u);
    CHECK(lab.registry.findByLocalTeid(0x00001001u) == commit.ownedEntry);
    // The reserved one does not resolve and is not retired: it is outstanding.
    CHECK(lab.registry.findByLocalTeid(0x00001002u) == nullptr);
    CHECK_FALSE(lab.registry.isRetiredTeid(0x00001002u));

    // A single `CLEANUP_FAILURE` alone is not a failure at all: a commit that
    // would succeed attempts no rollback, so there is no cleanup to fail.
    TargetLab clean;
    HandoverAdmission other =
        EvaluateHandoverAdmission(SampleRequest(), SampleSource(), SampleTargetContext(), SampleRoles());
    REQUIRE(other.admitted);
    TargetResourceCommit untouched = CommitHandoverResources(
        other, SampleTargetContext(), clean.registry, Transaction(7, Epoch),
        CommitFaultInjector(CommitFaultInjector::Fault::CLEANUP_FAILURE));
    CHECK(untouched.committed);

    // The owner keeps what is outstanding and a later cancellation releases it.
    // That is the difference between a failure that was surfaced and one that
    // was quietly swallowed.
    HandoverPreparationOwner owner(lab.registry, Epoch);
    PreparationRecord *record =
        owner.admit(Transaction(7, Epoch), SampleRequest(), SampleSource(), SampleTargetContext(), SampleRoles());
    REQUIRE(record != nullptr);
    TargetResourceCommit second = owner.commit(
        record->id, SampleTargetContext(),
        CommitFaultInjector(CommitFaultInjector::Fault::DEDICATED_BEARER_PREPARATION,
                            CommitFaultInjector::Fault::CLEANUP_FAILURE));
    REQUIRE_FALSE(second.committed);
    REQUIRE(second.refusal.has_value());
    CHECK(second.refusal->refusal == CommitRefusal::CLEANUP_FAILED);
    REQUIRE(record->entry != nullptr);
    CHECK(record->state == PreparationState::COMMIT_FAILED);
    REQUIRE(record->ownedTeids.size() == 2);

    CommitRefusalRecord failure;
    CHECK(owner.cancel(record->id, &failure));
    CHECK(record->entry == nullptr);
    CHECK(record->ownedTeids.empty());
    CHECK(lab.registry.findByLocalTeid(second.outstandingTeids[0]) == nullptr);
    CHECK(lab.registry.findByLocalTeid(second.outstandingTeids[1]) == nullptr);
    CHECK(lab.registry.isRetiredTeid(second.outstandingTeids[0]));
    CHECK_FALSE(lab.registry.isRetiredTeid(second.outstandingTeids[1]));
}

TEST_CASE("lte/handover/preparation: capacity exhaustion is a refusal and not a half-built context")
{
    // A registry that is already full refuses the provisional context and
    // allocates nothing.
    UeRegistry full(1);
    auto &ue = full.registerPeer(1, InetAddress("127.0.0.1", 40001));
    REQUIRE(full.find(1) == &ue);

    HandoverAdmission admission =
        EvaluateHandoverAdmission(SampleRequest(), SampleSource(), SampleTargetContext(), SampleRoles());
    REQUIRE(admission.admitted);
    TargetResourceCommit commit = CommitHandoverResources(admission, SampleTargetContext(), full, Transaction(7, Epoch));
    REQUIRE_FALSE(commit.committed);
    REQUIRE(commit.refusal.has_value());
    CHECK(commit.refusal->refusal == CommitRefusal::CAPACITY_EXHAUSTED);
    CHECK(commit.ownedEntry == nullptr);
    CHECK_FALSE(commit.holdsTransportResources());
    CHECK(commit.outstandingTeids.empty());
    // The reached UE is untouched and the registry still holds exactly it.
    CHECK(full.size() == 1);
    CHECK(full.find(1) == &ue);
    CHECK_FALSE(ue.bearer.signalingEstablished());
}

// --- E: prepared is not forwardable ---------------------------------------

TEST_CASE("lte/handover/preparation: a g-pdu for a prepared teid is dropped as inactive, not as unknown or retired")
{
    WireLab lab;
    lab.teidQueue.push_back(0x0000C001u);
    lab.teidQueue.push_back(0x0000C002u);

    HandoverAdmission admission =
        EvaluateHandoverAdmission(SampleRequest(), SampleSource(), SampleTargetContext(), SampleRoles());
    REQUIRE(admission.admitted);
    TargetResourceCommit commit =
        CommitHandoverResources(admission, SampleTargetContext(), lab.registry, Transaction(7, Epoch));
    REQUIRE(commit.committed);
    EnbUeEntry *entry = commit.ownedEntry;
    REQUIRE(entry != nullptr);
    REQUIRE(commit.prepared.bearers[0].localTeid == 0x0000C001u);
    REQUIRE(commit.prepared.bearers[1].localTeid == 0x0000C002u);

    // A real downlink G-PDU at the real shared endpoint, from the peer the
    // preparation named, for the TEID the commit bound.
    std::vector<uint8_t> wire = GPduWire(0x0000C001u, kPayload);
    lab.s1u.handleDatagram(wire.data(), wire.size(), SgwPeer());

    // Nothing is delivered to a UE that has not arrived.
    CHECK_FALSE(WireLab::received(lab.ueLink));
    // And the drop is classified for what it is. The identifier resolves, so it
    // is neither a retired tunnel's traffic nor a packet that never had one.
    // The inactive-drop classification is the receiving entry's own counter;
    // the endpoint's counters answer for the packets it refuses without a
    // bearer at all.
    CHECK(entry->counters.bearerInactiveDrops == 1);
    CHECK(entry->counters.unexpectedPeerDrops == 0);
    CHECK(entry->counters.malformedDrops == 0);
    CHECK(lab.s1u.counters().unknownTeidDrops == 0);
    CHECK(lab.s1u.counters().retiredTeidDrops == 0);
    CHECK(lab.s1u.counters().malformedDrops == 0);
    CHECK(lab.s1u.counters().endMarkers == 0);
    // No user-plane credit is given to a bearer that carried nothing.
    CHECK(entry->counters.s1uDownlinkPackets == 0);
    CHECK(entry->counters.s1uDownlinkBytes == 0);
    CHECK(entry->bearer.counters().downlinkPackets == 0);

    // The dedicated bearer behaves the same way, on its own TEID.
    std::vector<uint8_t> dedicatedWire = GPduWire(0x0000C002u, kPayload);
    lab.s1u.handleDatagram(dedicatedWire.data(), dedicatedWire.size(), SgwPeer());
    CHECK_FALSE(WireLab::received(lab.ueLink));
    CHECK(entry->counters.bearerInactiveDrops == 2);
    CHECK(lab.s1u.counters().unknownTeidDrops == 0);
    CHECK(lab.s1u.counters().retiredTeidDrops == 0);

    // The three classifications stay distinguishable from one another, which is
    // what makes the inactive drop above meaningful.
    std::vector<uint8_t> unknownWire = GPduWire(0x0000DEADu, kPayload);
    lab.s1u.handleDatagram(unknownWire.data(), unknownWire.size(), SgwPeer());
    CHECK(lab.s1u.counters().unknownTeidDrops == 1);
    CHECK(entry->counters.bearerInactiveDrops == 2);
    CHECK(lab.s1u.counters().retiredTeidDrops == 0);
}

TEST_CASE("lte/handover/preparation: an old teid stops resolving when the preparation is cancelled")
{
    WireLab lab;
    lab.teidQueue.push_back(0x0000D001u);
    lab.teidQueue.push_back(0x0000D002u);

    HandoverAdmission admission =
        EvaluateHandoverAdmission(SampleRequest(), SampleSource(), SampleTargetContext(), SampleRoles());
    REQUIRE(admission.admitted);
    HandoverPreparationOwner owner(lab.registry, Epoch);
    PreparationRecord *record =
        owner.admit(Transaction(7, Epoch), SampleRequest(), SampleSource(), SampleTargetContext(), SampleRoles());
    REQUIRE(record != nullptr);
    TargetResourceCommit commit = owner.commit(record->id, SampleTargetContext());
    REQUIRE(commit.committed);

    // While prepared, the identifiers resolve and are classified inactive.
    std::vector<uint8_t> wire = GPduWire(0x0000D001u, kPayload);
    lab.s1u.handleDatagram(wire.data(), wire.size(), SgwPeer());
    REQUIRE(commit.ownedEntry != nullptr);
    CHECK(commit.ownedEntry->counters.bearerInactiveDrops == 1);
    CHECK(lab.s1u.counters().retiredTeidDrops == 0);
    CHECK(lab.s1u.counters().unknownTeidDrops == 0);

    // Cancellation is idempotent and releases exactly what the record owned.
    CommitRefusalRecord failure;
    CHECK(owner.cancel(record->id, &failure));
    CHECK(record->state == PreparationState::PREPARATION_CANCELLED);
    CHECK(record->entry == nullptr);
    CHECK(record->ownedTeids.empty());
    CHECK(lab.registry.isRetiredTeid(0x0000D001u));
    CHECK(lab.registry.isRetiredTeid(0x0000D002u));
    CHECK(lab.registry.findByLocalTeid(0x0000D001u) == nullptr);

    const size_t retiredAfterFirst = lab.registry.retiredTeids().size();
    CHECK(owner.cancel(record->id, &failure));
    CHECK(lab.registry.retiredTeids().size() == retiredAfterFirst);
    CHECK(record->state == PreparationState::PREPARATION_CANCELLED);

    // A late packet for the old tunnel is now reported as having outlived it,
    // not as inactive and not as unknown. The entry that recorded the earlier
    // inactive drop is gone, so this is the endpoint's own classification and
    // it is not the one the prepared bearer produced.
    std::vector<uint8_t> late = GPduWire(0x0000D001u, kPayload);
    lab.s1u.handleDatagram(late.data(), late.size(), SgwPeer());
    CHECK(lab.s1u.counters().retiredTeidDrops == 1);
    CHECK(lab.s1u.counters().unknownTeidDrops == 0);
    CHECK_FALSE(WireLab::received(lab.ueLink));
}

// --- F: the source is not disturbed ---------------------------------------

TEST_CASE("lte/handover/preparation: preparing at a target leaves the source e-nb untouched")
{
    // The source's UE is a real reached UE on the production bearer path, not a
    // flag saying the source is ready.
    SourceUe source(3, 203);
    REQUIRE(source.entry != nullptr);
    REQUIRE(source.entry->bearer.active());
    REQUIRE(source.registry.findByLocalTeid(source.defaultTeid) == source.entry);
    REQUIRE(source.registry.findByLocalTeid(source.dedicatedTeid) == source.entry);

    const UeS1State sourceS1 = source.entry->s1;
    const uint32_t sourceGeneration = source.entry->accessGeneration;
    const uint32_t sourceEnbUeS1apId = source.entry->enbUeS1apId;
    const uint32_t sourceMmeUeS1apId = source.entry->mmeUeS1apId;
    const UserPlaneCounters sourceCounters = source.entry->counters;
    const uint64_t sourceDefaultUplink = source.entry->bearer.counters().uplinkPackets;
    const bool sourceSessionRetained = source.entry->sessionRetained;

    // A separate target eNB prepares the same UE's bearers.
    TargetLab target;
    HandoverRequest request;
    request.mmeUeS1apId = sourceMmeUeS1apId;
    request.handoverType = HandoverType::INTRA_LTE;
    request.causeCategory = "radioNetwork";
    request.causeValue = 16;
    request.ueAmbr = UeAmbr{150000000ULL, 75000000ULL};
    request.erabs = {RequestBearer(5, 5, 15, false, false, SgwTeid5), RequestBearer(6, 6, 3, false, true, SgwTeid6)};
    request.sourceToTarget = {0x01, 0x02, 0x03, 0x04};
    request.encryptionAlgorithms = {0x80, 0x00};
    request.integrityAlgorithms = {0x40, 0x00};
    request.securityContext.nextHopChainingCount = 3;
    request.securityContext.nextHopParameter = TestNextHopParameter();

    HandoverAdmission admission = EvaluateHandoverAdmission(request, SourceContext{SourceIdentity(), true},
                                                            SampleTargetContext(), SampleRoles());
    REQUIRE(admission.admitted);
    HandoverPreparationOwner owner(target.registry, Epoch);
    PreparationRecord *record =
        owner.admit(Transaction(sourceMmeUeS1apId, Epoch), request, SourceContext{SourceIdentity(), true},
                    SampleTargetContext(), SampleRoles());
    REQUIRE(record != nullptr);
    TargetResourceCommit commit = owner.commit(record->id, SampleTargetContext());
    REQUIRE(commit.committed);

    // The source's context is exactly what it was. Nothing was released, no
    // generation advanced, no S1 connection was detached and no bearer changed.
    CHECK(source.entry->s1 == sourceS1);
    CHECK(source.entry->accessGeneration == sourceGeneration);
    CHECK(source.entry->enbUeS1apId == sourceEnbUeS1apId);
    CHECK(source.entry->mmeUeS1apId == sourceMmeUeS1apId);
    CHECK(source.entry->sessionRetained == sourceSessionRetained);
    CHECK(source.entry->counters.s1uUplinkPackets == sourceCounters.s1uUplinkPackets);
    CHECK(source.entry->bearer.counters().uplinkPackets == sourceDefaultUplink);
    CHECK(source.entry->bearer.active());

    // No source TEID was retired and both still resolve at the source.
    CHECK_FALSE(source.registry.isRetiredTeid(source.defaultTeid));
    CHECK_FALSE(source.registry.isRetiredTeid(source.dedicatedTeid));
    CHECK(source.registry.findByLocalTeid(source.defaultTeid) == source.entry);
    CHECK(source.registry.findByLocalTeid(source.dedicatedTeid) == source.entry);
    CHECK(source.registry.findByMmeUeS1apId(sourceMmeUeS1apId) == source.entry);

    // The target's identifiers are a fresh pair and are not the source's.
    REQUIRE(commit.prepared.bearers.size() == 2);
    CHECK(commit.prepared.bearers[0].localTeid != source.defaultTeid);
    CHECK(commit.prepared.bearers[1].localTeid != source.dedicatedTeid);
    CHECK(target.registry.findByLocalTeid(source.defaultTeid) == nullptr);
    CHECK(source.registry.findByLocalTeid(commit.prepared.bearers[0].localTeid) == nullptr);

    // The target keeps the network's own statement of the bearers.
    CHECK(commit.prepared.bearers[0].qci == 5);
    CHECK(commit.prepared.bearers[1].qci == 6);
    CHECK(commit.prepared.bearers[1].linkedDefaultErabId == std::optional<uint8_t>{5});
    CHECK(commit.prepared.bearers[0].sgwAddress == SgwAddress);
    CHECK(commit.prepared.bearers[1].sgwAddress == SgwAddress);

    // Cancelling the preparation changes nothing at the source either.
    CommitRefusalRecord failure;
    CHECK(owner.cancel(record->id, &failure));
    CHECK(source.entry->bearer.active());
    CHECK(source.registry.findByLocalTeid(source.defaultTeid) == source.entry);
    CHECK_FALSE(source.registry.isRetiredTeid(source.defaultTeid));
}

// --- G: duplicates, staleness and expiry ----------------------------------

TEST_CASE("lte/handover/preparation: a repeated request is one transaction and allocates nothing twice")
{
    TargetLab lab;
    HandoverPreparationOwner owner(lab.registry, Epoch);
    HandoverRequest request = SampleRequest();
    SourceContext source = SampleSource();
    TargetContext target = SampleTargetContext();

    PreparationRecord *first = owner.admit(Transaction(7, Epoch), request, source, target, SampleRoles());
    REQUIRE(first != nullptr);
    CHECK(first->state == PreparationState::ADMITTED);
    CHECK(first->id.sequence == 1);
    CHECK(owner.size() == 1);

    // The same request again, with the identity sequence absent or stale: it
    // resolves to the same transaction and starts nothing new.
    PreparationRecord *again = owner.admit(Transaction(7, Epoch), request, source, target, SampleRoles());
    CHECK(again == first);
    CHECK(owner.size() == 1);
    CHECK(again->id.sequence == 1);

    TargetResourceCommit commit = owner.commit(first->id, target);
    REQUIRE(commit.committed);
    const uint64_t issued = lab.sequence.issued();

    // A second commit is refused and allocates no further TEID set.
    TargetResourceCommit repeat = owner.commit(first->id, target);
    REQUIRE_FALSE(repeat.committed);
    REQUIRE(repeat.refusal.has_value());
    CHECK(repeat.refusal->refusal == CommitRefusal::ALREADY_COMMITTED);
    CHECK(lab.sequence.issued() == issued);
    CHECK(lab.registry.findByLocalTeid(commit.prepared.bearers[0].localTeid) == commit.ownedEntry);

    // So is a second admission after the commit: it is the same live
    // transaction and its plan is unchanged.
    PreparationRecord *afterCommit = owner.admit(Transaction(7, Epoch), request, source, target, SampleRoles());
    CHECK(afterCommit == first);
    CHECK(owner.size() == 1);
    CHECK(lab.sequence.issued() == issued);
}

TEST_CASE("lte/handover/preparation: a conflicting duplicate is refused and starts nothing")
{
    TargetLab lab;
    HandoverPreparationOwner owner(lab.registry, Epoch);
    HandoverRequest request = SampleRequest();

    PreparationRecord *first =
        owner.admit(Transaction(7, Epoch), request, SampleSource(), SampleTargetContext(), SampleRoles());
    REQUIRE(first != nullptr);
    CHECK(first->state == PreparationState::ADMITTED);

    // The same identity, a different plan: a different transaction pretending
    // to be this one. The roles and the request are changed together, so the
    // new plan is internally consistent and only its QoS differs.
    HandoverRequest changed = SampleRequest();
    changed.erabs[0].qos.priorityLevel = 14;
    std::vector<BearerRoleBinding> changedRoles = {RoleDefault(5, 5, 14), RoleDedicated(6, 5, 6, 3, false, true)};
    CommitRefusalRecord failure;
    PreparationRecord *conflict =
        owner.admit(Transaction(7, Epoch), changed, SampleSource(), SampleTargetContext(), changedRoles, &failure);
    CHECK(conflict == nullptr);
    CHECK(failure.refusal == CommitRefusal::CONFLICTING_TRANSACTION);
    CHECK(owner.size() == 1);
    CHECK(first->state == PreparationState::ADMITTED);
    CHECK(first->entry == nullptr);
    CHECK(first->ownedTeids.empty());

    // The refused admission itself is recorded and owns nothing, so a repeat of
    // it cannot allocate anything either.
    HandoverRequest bad = SampleRequest();
    bad.erabs = {};
    PreparationRecord *refused =
        owner.admit(Transaction(9, Epoch), bad, SampleSource(), SampleTargetContext(), SampleRoles());
    REQUIRE(refused != nullptr);
    CHECK(refused->state == PreparationState::ADMISSION_REFUSED);
    REQUIRE(refused->refusal.has_value());
    CHECK(refused->refusal->refusal == CommitRefusal::ADMISSION_NOT_ADMITTED);
    CHECK(refused->ownedTeids.empty());
    CHECK(refused->entry == nullptr);

    const uint64_t issued = lab.sequence.issued();
    PreparationRecord *refusedAgain =
        owner.admit(Transaction(9, Epoch), bad, SampleSource(), SampleTargetContext(), SampleRoles());
    CHECK(refusedAgain == refused);
    CHECK(lab.sequence.issued() == issued);
}

TEST_CASE("lte/handover/preparation: a new request after a finished preparation is a new transaction")
{
    TargetLab lab;
    HandoverPreparationOwner owner(lab.registry, Epoch);
    HandoverRequest request = SampleRequest();

    PreparationRecord *first =
        owner.admit(Transaction(7, Epoch), request, SampleSource(), SampleTargetContext(), SampleRoles());
    REQUIRE(first != nullptr);
    TargetResourceCommit commit = owner.commit(first->id, SampleTargetContext());
    REQUIRE(commit.committed);
    CHECK(owner.cancel(first->id, nullptr));
    CHECK(first->state == PreparationState::PREPARATION_CANCELLED);

    // A different plan for the same UE is a genuinely new preparation: the
    // finished one does not stand in its way, and the identity resolves to the
    // newest of them so a later operation cannot reach back into the old one.
    HandoverRequest changed = SampleRequest();
    changed.erabs[0].qos.priorityLevel = 14;
    std::vector<BearerRoleBinding> changedRoles = {RoleDefault(5, 5, 14), RoleDedicated(6, 5, 6, 3, false, true)};
    PreparationRecord *second =
        owner.admit(Transaction(7, Epoch), changed, SampleSource(), SampleTargetContext(), changedRoles);
    REQUIRE(second != nullptr);
    CHECK(second != first);
    CHECK(second->state == PreparationState::ADMITTED);
    CHECK(second->id.sequence == 2);
    CHECK(owner.find(Transaction(7, Epoch)) == second);
    CHECK(owner.size() == 2);

    // The new one allocates its own fresh identifier pair; the old one's are
    // already retired and are never handed out again.
    TargetResourceCommit fresh = owner.commit(second->id, SampleTargetContext());
    REQUIRE(fresh.committed);
    CHECK(lab.registry.isRetiredTeid(commit.prepared.bearers[0].localTeid));
    CHECK(lab.registry.isRetiredTeid(commit.prepared.bearers[1].localTeid));
    CHECK(fresh.prepared.bearers[0].localTeid != commit.prepared.bearers[0].localTeid);
    CHECK(fresh.prepared.bearers[1].localTeid != commit.prepared.bearers[1].localTeid);
    CHECK(fresh.prepared.bearers[0].priorityLevel == 14);
    CHECK(lab.registry.findByLocalTeid(fresh.prepared.bearers[0].localTeid) == fresh.ownedEntry);

    // The finished preparation stays finished and owns nothing.
    CHECK(first->state == PreparationState::PREPARATION_CANCELLED);
    CHECK(first->entry == nullptr);
    CHECK(first->ownedTeids.empty());
}

TEST_CASE("lte/handover/preparation: work begun under a stale association epoch is refused")
{
    TargetLab lab;
    HandoverPreparationOwner owner(lab.registry, Epoch);
    HandoverRequest request = SampleRequest();

    CommitRefusalRecord failure;
    PreparationRecord *stale =
        owner.admit(Transaction(7, Epoch - 1), request, SampleSource(), SampleTargetContext(), SampleRoles(), &failure);
    CHECK(stale == nullptr);
    CHECK(failure.refusal == CommitRefusal::STALE_ASSOCIATION);
    CHECK(owner.size() == 0);

    PreparationRecord *live =
        owner.admit(Transaction(7, Epoch), request, SampleSource(), SampleTargetContext(), SampleRoles());
    REQUIRE(live != nullptr);

    // The same identity under an epoch that is no longer bound cannot advance
    // the transaction either.
    TargetResourceCommit commit = owner.commit(Transaction(7, Epoch - 1), SampleTargetContext());
    REQUIRE_FALSE(commit.committed);
    REQUIRE(commit.refusal.has_value());
    CHECK(commit.refusal->refusal == CommitRefusal::STALE_ASSOCIATION);
    CHECK(live->state == PreparationState::ADMITTED);
    CHECK(lab.sequence.issued() == 0);

    // And a completion under a stale epoch never gets as far as changing the
    // record: the transaction it names is not one this owner holds.
    CHECK_FALSE(owner.awaitUeAccess(Transaction(7, Epoch - 1), &failure));
    CHECK(failure.refusal == CommitRefusal::WRONG_STATE);
    CHECK(live->state == PreparationState::ADMITTED);
}

TEST_CASE("lte/handover/preparation: an expired preparation releases what it owned")
{
    TargetLab lab;
    // Expiry is driven by an explicit clock, so the lifetime here can be far
    // longer than the case takes to run: the sweep is handed a `now` that is
    // past the deadline and nothing has to wait for wall-clock time.
    HandoverPreparationOwner owner(lab.registry, Epoch, std::chrono::seconds(60));
    HandoverRequest request = SampleRequest();

    PreparationRecord *record =
        owner.admit(Transaction(7, Epoch), request, SampleSource(), SampleTargetContext(), SampleRoles());
    REQUIRE(record != nullptr);
    TargetResourceCommit commit = owner.commit(record->id, SampleTargetContext());
    REQUIRE(commit.committed);
    REQUIRE(lab.registry.findByLocalTeid(commit.prepared.bearers[0].localTeid) != nullptr);

    const auto future = std::chrono::steady_clock::now() + std::chrono::seconds(120);
    const size_t expired = owner.expireDue(future);
    CHECK(expired == 1);
    CHECK(record->state == PreparationState::PREPARATION_EXPIRED);
    REQUIRE(record->refusal.has_value());
    CHECK(record->refusal->refusal == CommitRefusal::EXPIRED);
    CHECK(record->entry == nullptr);
    CHECK(record->ownedTeids.empty());
    CHECK(lab.registry.findByLocalTeid(commit.prepared.bearers[0].localTeid) == nullptr);
    CHECK(lab.registry.isRetiredTeid(commit.prepared.bearers[0].localTeid));
    CHECK(lab.registry.findByMmeUeS1apId(7) == nullptr);

    // A second sweep finds nothing outstanding and changes nothing.
    CHECK(owner.expireDue(future) == 0);

    // A completion arriving after the cleanup is refused, so a stale callback
    // cannot turn a released preparation back into a live one.
    CommitRefusalRecord failure;
    CHECK_FALSE(owner.awaitUeAccess(record->id, &failure));
    CHECK(failure.refusal == CommitRefusal::WRONG_STATE);
    CHECK(record->state == PreparationState::PREPARATION_EXPIRED);
}

TEST_CASE("lte/handover/preparation: a commit after the deadline expires the transaction instead")
{
    TargetLab lab;
    HandoverPreparationOwner owner(lab.registry, Epoch, std::chrono::milliseconds(0));
    PreparationRecord *record =
        owner.admit(Transaction(7, Epoch), SampleRequest(), SampleSource(), SampleTargetContext(), SampleRoles());
    REQUIRE(record != nullptr);

    TargetResourceCommit commit = owner.commit(record->id, SampleTargetContext());
    REQUIRE_FALSE(commit.committed);
    REQUIRE(commit.refusal.has_value());
    CHECK(commit.refusal->refusal == CommitRefusal::EXPIRED);
    CHECK(record->state == PreparationState::PREPARATION_EXPIRED);
    CHECK(lab.sequence.issued() == 0);
    CHECK(commit.ownedEntry == nullptr);
}

TEST_CASE("lte/handover/preparation: a completion after cancellation fails closed")
{
    TargetLab lab;
    HandoverPreparationOwner owner(lab.registry, Epoch);
    PreparationRecord *record =
        owner.admit(Transaction(7, Epoch), SampleRequest(), SampleSource(), SampleTargetContext(), SampleRoles());
    REQUIRE(record != nullptr);
    TargetResourceCommit commit = owner.commit(record->id, SampleTargetContext());
    REQUIRE(commit.committed);

    // While prepared, the completion is accepted and says where the target is:
    // ready, and waiting for a UE that has not arrived.
    CommitRefusalRecord failure;
    CHECK(owner.awaitUeAccess(record->id, &failure));
    CHECK(record->resources.resourceState == ResourceState::AWAITING_UE_TARGET_ACCESS);
    // Still not forwardable: awaiting the UE is not the UE having arrived.
    REQUIRE(record->entry != nullptr);
    CHECK(PreparedBearersNonForwardable(*record->entry));

    CHECK(owner.cancel(record->id, &failure));
    CHECK(record->state == PreparationState::PREPARATION_CANCELLED);
    CHECK_FALSE(owner.awaitUeAccess(record->id, &failure));
    CHECK(failure.refusal == CommitRefusal::WRONG_STATE);
    CHECK(record->state == PreparationState::PREPARATION_CANCELLED);
    CHECK(lab.registry.findByLocalTeid(commit.prepared.bearers[0].localTeid) == nullptr);

    // An acknowledge for a cleaned-up preparation is refused too.
    CHECK_THROWS_AS(owner.acknowledge(record->id), HandoverRefused);
}

// --- H: one preparation cannot disturb another -----------------------------

TEST_CASE("lte/handover/preparation: two ues prepared together stay independent")
{
    TargetLab lab;
    HandoverPreparationOwner owner(lab.registry, Epoch);
    HandoverRequest first = SampleRequest();
    HandoverRequest second = SampleRequest();
    second.mmeUeS1apId = 8;
    second.erabs = {RequestBearer(5, 9, 8, false, false, SgwTeid5), RequestBearer(6, 8, 7, true, false, SgwTeid6)};

    PreparationRecord *a =
        owner.admit(Transaction(7, Epoch), first, SampleSource(), SampleTargetContext(), SampleRoles());
    PreparationRecord *b = owner.admit(Transaction(8, Epoch), second, SampleSource(), SampleTargetContext(),
                                       {RoleDefault(5, 9, 8), RoleDedicated(6, 5, 8, 7, true, false)});
    REQUIRE(a != nullptr);
    REQUIRE(b != nullptr);
    REQUIRE(a != b);

    TargetResourceCommit commitA = owner.commit(a->id, SampleTargetContext());
    TargetResourceCommit commitB = owner.commit(b->id, SampleTargetContext());
    REQUIRE(commitA.committed);
    REQUIRE(commitB.committed);
    REQUIRE(commitA.ownedEntry != nullptr);
    REQUIRE(commitB.ownedEntry != nullptr);
    CHECK(commitA.ownedEntry != commitB.ownedEntry);

    // Four identifiers, four distinct owners. A UE's transport resolves to that
    // UE's context and to no other.
    std::set<uint32_t> ids;
    for (uint32_t teid : {commitA.prepared.bearers[0].localTeid, commitA.prepared.bearers[1].localTeid,
                          commitB.prepared.bearers[0].localTeid, commitB.prepared.bearers[1].localTeid})
        REQUIRE(ids.insert(teid).second);
    CHECK(lab.registry.findByLocalTeid(commitA.prepared.bearers[0].localTeid) == commitA.ownedEntry);
    CHECK(lab.registry.findByLocalTeid(commitA.prepared.bearers[1].localTeid) == commitA.ownedEntry);
    CHECK(lab.registry.findByLocalTeid(commitB.prepared.bearers[0].localTeid) == commitB.ownedEntry);
    CHECK(lab.registry.findByLocalTeid(commitB.prepared.bearers[1].localTeid) == commitB.ownedEntry);
    CHECK(lab.registry.findByMmeUeS1apId(7) == commitA.ownedEntry);
    CHECK(lab.registry.findByMmeUeS1apId(8) == commitB.ownedEntry);

    // Their QoS is their own and cannot blur together.
    CHECK(commitB.prepared.bearers[0].qci == 9);
    CHECK(commitA.prepared.bearers[0].qci == 5);
    CHECK(commitB.prepared.bearers[1].qci == 8);
    CHECK(commitA.prepared.bearers[1].qci == 6);
    CHECK(commitB.prepared.bearers[1].preemptionCapability);
    CHECK_FALSE(commitA.prepared.bearers[1].preemptionCapability);

    // Cancelling one leaves the other exactly as it was.
    CommitRefusalRecord failure;
    CHECK(owner.cancel(a->id, &failure));
    CHECK(a->state == PreparationState::PREPARATION_CANCELLED);
    CHECK(b->state == PreparationState::TARGET_PREPARED);
    CHECK(lab.registry.findByLocalTeid(commitA.prepared.bearers[0].localTeid) == nullptr);
    CHECK(lab.registry.isRetiredTeid(commitA.prepared.bearers[0].localTeid));
    CHECK(lab.registry.findByLocalTeid(commitB.prepared.bearers[0].localTeid) == commitB.ownedEntry);
    CHECK(lab.registry.findByLocalTeid(commitB.prepared.bearers[1].localTeid) == commitB.ownedEntry);
    CHECK_FALSE(lab.registry.isRetiredTeid(commitB.prepared.bearers[0].localTeid));
    CHECK(lab.registry.findByMmeUeS1apId(8) == commitB.ownedEntry);

    HandoverRequestAcknowledge still = owner.acknowledge(b->id);
    CHECK(still.mmeUeS1apId == 8);
    CHECK(still.admitted.size() == 2);
}

TEST_CASE("lte/handover/preparation: a preparation leaves a reached ue in the same registry alone")
{
    TargetLab lab;
    auto &ue = lab.registry.registerPeer(1, InetAddress("127.0.0.1", 40001));
    const uint32_t ueTeid = lab.registry.allocateLocalTeid();
    ue.bearer.establish(BearerParameters{5, 5, 1, SgwAddress, SgwTeid5, ueTeid, 0, Qos(5, 15)}, false);
    ue.bearer.activateUe(1, 5, {10, 45, 0, 1});
    lab.registry.bindLocalTeid(ue, ueTeid);
    ue.s1 = UeS1State::BEARER_ACTIVE;

    HandoverPreparationOwner owner(lab.registry, Epoch);
    PreparationRecord *record =
        owner.admit(Transaction(7, Epoch), SampleRequest(), SampleSource(), SampleTargetContext(), SampleRoles());
    REQUIRE(record != nullptr);
    TargetResourceCommit commit = owner.commit(record->id, SampleTargetContext());
    REQUIRE(commit.committed);

    // The reached UE keeps its identity, its transport and its readiness.
    CHECK(lab.registry.find(1) == &ue);
    CHECK(lab.registry.findByLocalTeid(ueTeid) == &ue);
    CHECK(ue.bearer.active());
    CHECK(ue.s1 == UeS1State::BEARER_ACTIVE);
    CHECK(ue.accessGeneration == 0);
    CHECK_FALSE(lab.registry.isRetiredTeid(ueTeid));
    // And the provisional context is not findable as a UE.
    CHECK(lab.registry.find(commit.ownedEntry->radioUeId) == nullptr);

    CommitRefusalRecord failure;
    CHECK(owner.cancel(record->id, &failure));
    CHECK(lab.registry.findByLocalTeid(ueTeid) == &ue);
    CHECK_FALSE(lab.registry.isRetiredTeid(ueTeid));
}

// --- the refusal surface and the accepted contracts ------------------------

TEST_CASE("lte/handover/preparation: a plan that cannot be committed whole is refused before anything is allocated")
{
    TargetLab lab;
    HandoverAdmission good =
        EvaluateHandoverAdmission(SampleRequest(), SampleSource(), SampleTargetContext(), SampleRoles());
    REQUIRE(good.admitted);

    auto commitWith = [&](HandoverAdmission admission, TargetContext target, HandoverTransactionId id) {
        return CommitHandoverResources(admission, target, lab.registry, id);
    };

    // Each entry mutates the admitted plan in one named way and expects one
    // named refusal. Nothing is allocated for any of them.
    struct Named
    {
        const char *name;
        CommitRefusal expected;
        std::function<TargetResourceCommit()> run;
    };
    std::vector<Named> cases;

    auto add = [&cases](const char *name, CommitRefusal expected, std::function<TargetResourceCommit()> run) {
        cases.push_back(Named{name, expected, std::move(run)});
    };

    add("a refused admission", CommitRefusal::ADMISSION_NOT_ADMITTED, [&] {
        HandoverAdmission refused = good;
        refused.admitted = false;
        return commitWith(refused, SampleTargetContext(), Transaction(7, Epoch));
    });
    add("an empty bearer set", CommitRefusal::EMPTY_BEARER_SET, [&] {
        HandoverAdmission empty = good;
        empty.bearers.clear();
        return commitWith(empty, SampleTargetContext(), Transaction(7, Epoch));
    });
    add("a plan that already holds transport", CommitRefusal::ADMISSION_NOT_ADMITTED, [&] {
        HandoverAdmission bound = good;
        bound.bearers[0].targetTransport.bound = true;
        return commitWith(bound, SampleTargetContext(), Transaction(7, Epoch));
    });
    add("a transaction naming no ue", CommitRefusal::TRANSACTION_IDENTITY_ABSENT,
        [&] { return commitWith(good, SampleTargetContext(), Transaction(0, Epoch)); });
    add("a target that is not the admitted one", CommitRefusal::TARGET_IDENTITY_MISMATCH, [&] {
        TargetContext other = SampleTargetContext();
        other.identity.enbId = 0x00ABCDFFu;
        return commitWith(good, other, Transaction(7, Epoch));
    });
    add("a target with no s1-u address", CommitRefusal::TARGET_TRANSPORT_ADDRESS_ABSENT, [&] {
        TargetContext none = SampleTargetContext();
        none.s1uAddress = Ip(0, 0, 0, 0);
        return commitWith(good, none, Transaction(7, Epoch));
    });
    add("a duplicated e-rab identity", CommitRefusal::DUPLICATE_ERAB_ID, [&] {
        HandoverAdmission twice = good;
        twice.bearers.push_back(twice.bearers[0]);
        return commitWith(twice, SampleTargetContext(), Transaction(7, Epoch));
    });
    add("an e-rab identity outside the bearer range", CommitRefusal::BEARER_PARAMETERS_INVALID, [&] {
        HandoverAdmission low = good;
        low.bearers[0].erabId = 4;
        return commitWith(low, SampleTargetContext(), Transaction(7, Epoch));
    });
    add("a bearer carrying qci zero", CommitRefusal::BEARER_PARAMETERS_INVALID, [&] {
        HandoverAdmission zero = good;
        zero.bearers[0].qci = 0;
        return commitWith(zero, SampleTargetContext(), Transaction(7, Epoch));
    });
    add("a bearer naming a zero sgw teid", CommitRefusal::BEARER_PARAMETERS_INVALID, [&] {
        HandoverAdmission none = good;
        none.bearers[0].sgwTeid = TeidBytes(0);
        return commitWith(none, SampleTargetContext(), Transaction(7, Epoch));
    });
    add("a dedicated bearer with no link", CommitRefusal::LINKED_DEFAULT_MISSING, [&] {
        HandoverAdmission loose = good;
        loose.bearers[1].linkedDefaultErabId.reset();
        return commitWith(loose, SampleTargetContext(), Transaction(7, Epoch));
    });
    add("a dedicated bearer linked to something that is not a default of this set",
        CommitRefusal::LINKED_DEFAULT_MISSING, [&] {
            HandoverAdmission loose = good;
            loose.bearers[1].linkedDefaultErabId = 7;
            return commitWith(loose, SampleTargetContext(), Transaction(7, Epoch));
        });
    add("a set with no default bearer", CommitRefusal::LINKED_DEFAULT_MISSING, [&] {
        HandoverAdmission onlyDedicated = good;
        onlyDedicated.bearers[0].role = BearerRole::DEDICATED;
        onlyDedicated.bearers[0].linkedDefaultErabId = 6;
        return commitWith(onlyDedicated, SampleTargetContext(), Transaction(7, Epoch));
    });
    add("two default bearers", CommitRefusal::MULTIPLE_DEFAULT_BEARERS, [&] {
        HandoverAdmission twoDefaults = good;
        twoDefaults.bearers[1].role = BearerRole::DEFAULT;
        twoDefaults.bearers[1].linkedDefaultErabId.reset();
        return commitWith(twoDefaults, SampleTargetContext(), Transaction(7, Epoch));
    });

    for (const auto &item : cases)
    {
        CAPTURE(item.name);
        const uint64_t issued = lab.sequence.issued();
        TargetResourceCommit commit = item.run();
        CHECK_FALSE(commit.committed);
        REQUIRE(commit.refusal.has_value());
        CHECK(commit.refusal->refusal == item.expected);
        CHECK(commit.ownedEntry == nullptr);
        CHECK_FALSE(commit.holdsTransportResources());
        CHECK(commit.outstandingTeids.empty());
        // A refusal that was reached before allocation spends nothing at all.
        CHECK(lab.sequence.issued() == issued);
    }
}

TEST_CASE("lte/handover/preparation: the accepted phase 18-a contracts are unchanged")
{
    // Admission is still a plan and still holds nothing, whatever this phase
    // adds on top of it.
    HandoverAdmission admission =
        EvaluateHandoverAdmission(SampleRequest(), SampleSource(), SampleTargetContext(), SampleRoles());
    REQUIRE(admission.admitted);
    CHECK_FALSE(admission.holdsTransportResources());
    CHECK(admission.bearers.size() == 2);
    CHECK(admission.bearers[0].role == BearerRole::DEFAULT);
    CHECK(admission.bearers[1].role == BearerRole::DEDICATED);

    // The acknowledge still echoes the source-to-target container, and a
    // Handover Failure still carries no eNB-UE-S1AP-ID: the wire shape is the
    // Phase 18-A one and neither is this phase's to change.
    CHECK(admission.sourceToTarget == std::vector<uint8_t>{0x01, 0x02, 0x03, 0x04});
    HandoverAdmission refused = admission;
    refused.admitted = false;
    refused.refusal = AdmissionRefusalRecord{AdmissionRefusal::EMPTY_BEARER_SET, "the admitted bearer set is empty",
                                             "radioNetwork", 47};
    HandoverFailure failure = RefusalAsHandoverFailure(refused, 7);
    CHECK(failure.mmeUeS1apId == 7);
    CHECK(failure.causeCategory == "radioNetwork");
    CHECK(failure.causeValue == 47);
    // A refused admission has a Handover Failure; an admitted one does not.
    CHECK_THROWS_AS(RefusalAsHandoverFailure(admission, 7), HandoverRefused);

    // And an acknowledge built from transport no commit bound is still refused,
    // so this phase cannot be bypassed to reach one.
    CHECK_THROWS_AS(BuildHandoverRequestAcknowledge(admission, 7, 11, {}), HandoverRefused);
    CHECK_THROWS_AS(BuildHandoverRequestAcknowledge(admission, 7, 11,
                                                    {CommittedTransport{5, Ip(198, 51, 100, 1), TeidBytes(1)}}),
                    HandoverRefused);
}
