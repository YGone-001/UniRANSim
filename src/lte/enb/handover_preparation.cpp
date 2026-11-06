// Phase 18-B: atomic target-eNB handover resource commitment.
//
// See the header for the contract. The two rules that shape every line here:
// nothing is fabricated, and nothing is left behind.

#include "handover_preparation.hpp"

#include <algorithm>
#include <set>
#include <sstream>
#include <stdexcept>

namespace lte::enb::s1ap
{

namespace
{

bool SameEnbIdentity(const EnbIdentity &a, const EnbIdentity &b)
{
    return a.enbId == b.enbId && a.tac == b.tac && a.plmn.mcc == b.plmn.mcc && a.plmn.mnc == b.plmn.mnc;
}

bool SameAddress(const std::array<uint8_t, 4> &a, const std::array<uint8_t, 4> &b)
{
    return a == b;
}

// Whether two evaluations of the same request describe the same plan. A repeat
// that agrees is the same transaction and must not allocate anything; one that
// disagrees is a conflicting duplicate and is refused whole.
bool SamePlan(const HandoverAdmission &a, const HandoverAdmission &b)
{
    if (a.admitted != b.admitted || a.handoverType != b.handoverType)
        return false;
    if (a.refusal.has_value() != b.refusal.has_value())
        return false;
    if (a.refusal.has_value() && a.refusal->refusal != b.refusal->refusal)
        return false;
    if (!SameEnbIdentity(a.source, b.source) || !SameEnbIdentity(a.target, b.target))
        return false;
    if (a.bearers.size() != b.bearers.size())
        return false;
    for (size_t i = 0; i < a.bearers.size(); ++i)
    {
        const AdmittedBearer &x = a.bearers[i];
        const AdmittedBearer &y = b.bearers[i];
        if (x.erabId != y.erabId || x.role != y.role || x.linkedDefaultErabId != y.linkedDefaultErabId ||
            x.qci != y.qci || x.priorityLevel != y.priorityLevel ||
            x.preemptionCapability != y.preemptionCapability || x.preemptionVulnerability != y.preemptionVulnerability)
            return false;
        if (!SameAddress(x.sgwAddress, y.sgwAddress) || !SameAddress(x.sgwTeid, y.sgwTeid))
            return false;
        if (!SameAddress(x.targetTransport.address, y.targetTransport.address))
            return false;
    }
    return true;
}

// A commit refusal carries the Cause the refusal would be reported under, so a
// Handover Failure can be built from it without inventing one. The categories
// and values are the standard's, not this file's.
CommitRefusalRecord Refuse(CommitRefusal refusal, std::string detail, std::string causeCategory = "radioNetwork",
                           int causeValue = -1)
{
    return CommitRefusalRecord{refusal, std::move(detail), std::move(causeCategory), causeValue};
}

// TS 36.413 causes that fit a refused target commitment. `noRadioResourcesAvailable`
// is the standard's answer to a target that cannot take the bearers; transport
// resource unavailable is `transportResourceUnavailable`.
const char *const CauseCategoryTransport = "transport";
constexpr int CauseNoRadioResourcesAvailable = 20; // radioNetwork, TS 36.413 9.2.1.3
constexpr int CauseTransportResourceUnavailable = 13; // transport, TS 36.413 9.2.1.4

// The EPS bearer identity range `DefaultBearerContext::establish` accepts. EBI
// 1 to 4 are reserved by the standard and this implementation will not create
// one, so a plan naming one is refused before anything is allocated rather
// than half way through a commit.
constexpr uint8_t MinBearerIdentity = 5;
constexpr uint8_t MaxBearerIdentity = 15;

bool BearerIdentityUsable(uint8_t erabId)
{
    return erabId >= MinBearerIdentity && erabId <= MaxBearerIdentity;
}

} // namespace

// --- Naming ---------------------------------------------------------------

const char *ToString(PreparationState state)
{
    switch (state)
    {
    case PreparationState::NEW:
        return "NEW";
    case PreparationState::ADMITTED:
        return "ADMITTED";
    case PreparationState::COMMITTING:
        return "COMMITTING";
    case PreparationState::TARGET_PREPARED:
        return "TARGET_PREPARED";
    case PreparationState::ADMISSION_REFUSED:
        return "ADMISSION_REFUSED";
    case PreparationState::COMMIT_FAILED:
        return "COMMIT_FAILED";
    case PreparationState::PREPARATION_CANCELLED:
        return "PREPARATION_CANCELLED";
    case PreparationState::PREPARATION_EXPIRED:
        return "PREPARATION_EXPIRED";
    }
    return "UNKNOWN";
}

bool IsTerminal(PreparationState state)
{
    switch (state)
    {
    case PreparationState::ADMISSION_REFUSED:
    case PreparationState::COMMIT_FAILED:
    case PreparationState::PREPARATION_CANCELLED:
    case PreparationState::PREPARATION_EXPIRED:
        return true;
    case PreparationState::NEW:
    case PreparationState::ADMITTED:
    case PreparationState::COMMITTING:
    case PreparationState::TARGET_PREPARED:
        return false;
    }
    return true;
}

const char *ToString(ResourceState state)
{
    switch (state)
    {
    case ResourceState::ADMISSION_EVALUATED:
        return "ADMISSION_EVALUATED";
    case ResourceState::RESOURCES_RESERVED:
        return "RESOURCES_RESERVED";
    case ResourceState::RESOURCES_COMMITTED_PREPARED:
        return "RESOURCES_COMMITTED_PREPARED";
    case ResourceState::AWAITING_UE_TARGET_ACCESS:
        return "AWAITING_UE_TARGET_ACCESS";
    }
    return "UNKNOWN";
}

const char *ToString(CommitRefusal refusal)
{
    switch (refusal)
    {
    case CommitRefusal::ADMISSION_NOT_ADMITTED:
        return "ADMISSION_NOT_ADMITTED";
    case CommitRefusal::EMPTY_BEARER_SET:
        return "EMPTY_BEARER_SET";
    case CommitRefusal::TARGET_IDENTITY_MISMATCH:
        return "TARGET_IDENTITY_MISMATCH";
    case CommitRefusal::TARGET_TRANSPORT_ADDRESS_ABSENT:
        return "TARGET_TRANSPORT_ADDRESS_ABSENT";
    case CommitRefusal::DUPLICATE_ERAB_ID:
        return "DUPLICATE_ERAB_ID";
    case CommitRefusal::LINKED_DEFAULT_MISSING:
        return "LINKED_DEFAULT_MISSING";
    case CommitRefusal::BEARER_PARAMETERS_INVALID:
        return "BEARER_PARAMETERS_INVALID";
    case CommitRefusal::MULTIPLE_DEFAULT_BEARERS:
        return "MULTIPLE_DEFAULT_BEARERS";
    case CommitRefusal::TRANSACTION_IDENTITY_ABSENT:
        return "TRANSACTION_IDENTITY_ABSENT";
    case CommitRefusal::CAPACITY_EXHAUSTED:
        return "CAPACITY_EXHAUSTED";
    case CommitRefusal::TEID_ALLOCATION_FAILED:
        return "TEID_ALLOCATION_FAILED";
    case CommitRefusal::DEFAULT_BEARER_PREPARATION_FAILED:
        return "DEFAULT_BEARER_PREPARATION_FAILED";
    case CommitRefusal::DEDICATED_BEARER_PREPARATION_FAILED:
        return "DEDICATED_BEARER_PREPARATION_FAILED";
    case CommitRefusal::CONFLICTING_TRANSACTION:
        return "CONFLICTING_TRANSACTION";
    case CommitRefusal::STALE_ASSOCIATION:
        return "STALE_ASSOCIATION";
    case CommitRefusal::ALREADY_COMMITTED:
        return "ALREADY_COMMITTED";
    case CommitRefusal::WRONG_STATE:
        return "WRONG_STATE";
    case CommitRefusal::EXPIRED:
        return "EXPIRED";
    case CommitRefusal::CLEANUP_FAILED:
        return "CLEANUP_FAILED";
    }
    return "UNKNOWN";
}

bool operator==(const HandoverTransactionId &a, const HandoverTransactionId &b)
{
    return a.mmeUeS1apId == b.mmeUeS1apId && a.associationEpoch == b.associationEpoch && a.sequence == b.sequence;
}

bool operator!=(const HandoverTransactionId &a, const HandoverTransactionId &b)
{
    return !(a == b);
}

bool operator<(const HandoverTransactionId &a, const HandoverTransactionId &b)
{
    if (a.mmeUeS1apId != b.mmeUeS1apId)
        return a.mmeUeS1apId < b.mmeUeS1apId;
    if (a.associationEpoch != b.associationEpoch)
        return a.associationEpoch < b.associationEpoch;
    return a.sequence < b.sequence;
}

std::string ToString(const HandoverTransactionId &id)
{
    std::ostringstream out;
    out << "mmeUeS1apId=" << id.mmeUeS1apId << " epoch=" << id.associationEpoch << " sequence=" << id.sequence;
    return out.str();
}

// --- Prepared state -------------------------------------------------------

bool PreparedBearersNonForwardable(const EnbUeEntry &entry)
{
    // Only a provisional context can be in this state at all, and only if its
    // bearers were really established. A description of a bearer is not a
    // bearer: an entry that never had one answers false here, so the predicate
    // cannot be satisfied by a hand-built success state.
    if (!UeRegistry::isProvisional(entry) || !entry.bearer.signalingEstablished())
        return false;
    if (entry.bearer.active())
        return false;
    for (const auto &bearer : entry.dedicatedBearers)
    {
        if (!bearer.signalingEstablished() || bearer.active())
            return false;
    }
    return true;
}

bool TargetResourceCommit::holdsTransportResources() const
{
    return !prepared.committed.empty();
}

// --- Commitment -----------------------------------------------------------

TargetResourceCommit CommitHandoverResources(const HandoverAdmission &admission, const TargetContext &target,
                                             UeRegistry &registry, const HandoverTransactionId &transaction,
                                             const CommitFaultInjector &faults)
{
    TargetResourceCommit result;
    result.prepared.transaction = transaction;
    result.prepared.target = target.identity;
    result.prepared.mmeUeS1apId = transaction.mmeUeS1apId;
    result.prepared.state = PreparationState::COMMITTING;

    // A refusal that left nothing behind. Everything the attempt produced is
    // dropped, so the caller cannot build a partial acknowledge from it.
    auto fail = [&result](CommitRefusal refusal, std::string detail, std::string causeCategory = "radioNetwork",
                          int causeValue = -1) {
        result.committed = false;
        result.prepared.bearers.clear();
        result.prepared.committed.clear();
        result.prepared.enbUeS1apId = 0;
        result.prepared.resourceState = ResourceState::ADMISSION_EVALUATED;
        result.prepared.state = PreparationState::COMMIT_FAILED;
        result.ownedEntry = nullptr;
        result.outstandingTeids.clear();
        result.refusal = Refuse(refusal, std::move(detail), std::move(causeCategory), causeValue);
        return result;
    };

    // 1. Validate the entire set. Nothing is allocated before this point, so a
    // set that cannot be committed whole costs nothing.
    if (!admission.admitted)
        return fail(CommitRefusal::ADMISSION_NOT_ADMITTED, "the admission was refused");
    if (admission.bearers.empty())
        return fail(CommitRefusal::EMPTY_BEARER_SET, "the admitted bearer set is empty");
    if (admission.holdsTransportResources())
        return fail(CommitRefusal::ADMISSION_NOT_ADMITTED, "the admission already holds transport resources");
    if (transaction.mmeUeS1apId == 0)
        return fail(CommitRefusal::TRANSACTION_IDENTITY_ABSENT, "the transaction names no MME-UE-S1AP-ID");
    if (!SameEnbIdentity(admission.target, target.identity))
        return fail(CommitRefusal::TARGET_IDENTITY_MISMATCH, "the target context does not name the admitted target");
    if (target.s1uAddress == std::array<uint8_t, 4>{})
        return fail(CommitRefusal::TARGET_TRANSPORT_ADDRESS_ABSENT, "the target has no S1-U address to serve on");

    std::set<uint8_t> seen;
    std::set<uint8_t> defaultIdentities;
    for (const auto &bearer : admission.bearers)
    {
        if (!BearerIdentityUsable(bearer.erabId))
            return fail(CommitRefusal::BEARER_PARAMETERS_INVALID,
                        "E-RAB " + std::to_string(bearer.erabId) + " is outside the EPS bearer identity range");
        if (bearer.qci == 0)
            return fail(CommitRefusal::BEARER_PARAMETERS_INVALID,
                        "E-RAB " + std::to_string(bearer.erabId) + " carries QCI zero");
        if (TeidFromBytes(bearer.sgwTeid) == 0)
            return fail(CommitRefusal::BEARER_PARAMETERS_INVALID,
                        "E-RAB " + std::to_string(bearer.erabId) + " names a zero SGW TEID");
        if (!SameAddress(bearer.targetTransport.address, target.s1uAddress))
            return fail(CommitRefusal::TARGET_IDENTITY_MISMATCH,
                        "E-RAB " + std::to_string(bearer.erabId) + " is not planned on the target's S1-U address");
        if (!seen.insert(bearer.erabId).second)
            return fail(CommitRefusal::DUPLICATE_ERAB_ID, "E-RAB " + std::to_string(bearer.erabId) + " appears twice");
        if (bearer.role == BearerRole::DEFAULT)
        {
            if (bearer.linkedDefaultErabId.has_value())
                return fail(CommitRefusal::LINKED_DEFAULT_MISSING,
                            "default E-RAB " + std::to_string(bearer.erabId) + " names a linked default");
            defaultIdentities.insert(bearer.erabId);
        }
    }
    for (const auto &bearer : admission.bearers)
    {
        if (bearer.role != BearerRole::DEDICATED)
            continue;
        if (!bearer.linkedDefaultErabId.has_value())
            return fail(CommitRefusal::LINKED_DEFAULT_MISSING,
                        "dedicated E-RAB " + std::to_string(bearer.erabId) + " names no linked default");
        if (*bearer.linkedDefaultErabId == bearer.erabId ||
            defaultIdentities.count(*bearer.linkedDefaultErabId) == 0)
            return fail(CommitRefusal::LINKED_DEFAULT_MISSING,
                        "dedicated E-RAB " + std::to_string(bearer.erabId) + " links to E-RAB " +
                            std::to_string(*bearer.linkedDefaultErabId) + ", which is not a default of this set");
    }
    if (defaultIdentities.empty())
        return fail(CommitRefusal::LINKED_DEFAULT_MISSING, "the set names no default bearer");
    if (defaultIdentities.size() > 1)
        return fail(CommitRefusal::MULTIPLE_DEFAULT_BEARERS,
                    "a target-side context owns one default bearer and the set names " +
                        std::to_string(defaultIdentities.size()));

    // 2. Verify target resource capacity. The registry is the authority: it
    // refuses a provisional context when the per-UE bound is reached and
    // allocates nothing. The fault point reaches that refusal deterministically
    // without having to fill a registry first.
    if (faults.firesAt(CommitFaultInjector::Fault::CAPACITY_EXHAUSTED))
        return fail(CommitRefusal::CAPACITY_EXHAUSTED, "injected: the target has no room for another context",
                    "radioNetwork", CauseNoRadioResourcesAvailable);
    if (faults.firesAt(CommitFaultInjector::Fault::CONFLICTING_TRANSACTION))
        return fail(CommitRefusal::CONFLICTING_TRANSACTION, "injected: another live preparation owns these resources");
    if (faults.firesAt(CommitFaultInjector::Fault::STALE_ASSOCIATION))
        return fail(CommitRefusal::STALE_ASSOCIATION, "injected: the association epoch is no longer bound");

    // The readiness order: every default bearer before any dedicated one, each
    // group keeping the order the admission planned it in. A request whose E-RAB
    // list is deliberately reordered produces the same order here, because the
    // order is derived from the roles and never from the wire position.
    std::vector<const AdmittedBearer *> plan;
    plan.reserve(admission.bearers.size());
    for (const auto &bearer : admission.bearers)
        if (bearer.role == BearerRole::DEFAULT)
            plan.push_back(&bearer);
    for (const auto &bearer : admission.bearers)
        if (bearer.role == BearerRole::DEDICATED)
            plan.push_back(&bearer);

    // 3. Reserve a provisional target context. This is real resource ownership
    // and not a UE session: it has no radio identity and no peer, and
    // `registerPeer` is never called, so nothing here can manufacture an
    // arrival.
    EnbUeEntry *entry = nullptr;
    try
    {
        entry = &registry.allocateProvisional();
    }
    catch (const std::exception &e)
    {
        return fail(CommitRefusal::CAPACITY_EXHAUSTED, e.what(), "radioNetwork", CauseNoRadioResourcesAvailable);
    }
    result.ownedEntry = entry;

    // Everything the attempt reserved or bound, in allocation order. Rollback
    // walks it backwards: a value that was bound is retired through the normal
    // lifecycle and one that was only reserved is dropped, which is exactly the
    // distinction `unbindLocalTeid` already draws.
    std::vector<uint32_t> allocated;
    std::vector<PreparedBearer> prepared;
    std::vector<CommittedTransport> committed;
    prepared.reserve(plan.size());
    committed.reserve(plan.size());
    allocated.reserve(plan.size());

    // When this is false the rollback could not complete. The failure is
    // surfaced rather than reported as a successful cleanup, and the resources
    // are deliberately left where the caller can still see them.
    bool cleaned = true;
    auto rollback = [&]() -> bool {
        if (entry == nullptr)
            return true;
        if (faults.firesAt(CommitFaultInjector::Fault::CLEANUP_FAILURE))
            return false;
        for (auto it = allocated.rbegin(); it != allocated.rend(); ++it)
            registry.unbindLocalTeid(*entry, *it);
        registry.removeProvisional(*entry);
        entry = nullptr;
        result.ownedEntry = nullptr;
        return true;
    };

    // The only identity the target holds for a UE that has not arrived is the
    // MME's. `BearerParameters::ueId` must be non-zero and is the identity the
    // bearer is bound to for user-plane validation, so it is this and not a
    // radio identity: there is no radio identity yet, and inventing one would
    // be inventing the arrival. Whatever later promotes this context to a
    // reached UE must carry this value forward or re-establish the bearers; the
    // radio identity is not interchangeable with it.
    const uint32_t bearerUeId = transaction.mmeUeS1apId;

    // 4, 5 and 6. Reserve, prepare and bind each bearer. A default is prepared
    // first whatever the wire order was, and a dedicated bearer is prepared
    // only after the default it links to is ready.
    for (const AdmittedBearer *bearer : plan)
    {
        const bool isDefault = bearer->role == BearerRole::DEFAULT;
        const auto failure = isDefault ? CommitRefusal::DEFAULT_BEARER_PREPARATION_FAILED
                                       : CommitRefusal::DEDICATED_BEARER_PREPARATION_FAILED;

        // 3. Reserve the local transport identifier. It comes from this
        // registry's allocator and from nowhere else.
        uint32_t localTeid = 0;
        try
        {
            localTeid = registry.allocateLocalTeid();
        }
        catch (const std::exception &e)
        {
            if (!rollback())
            {
                cleaned = false;
                break;
            }
            return fail(CommitRefusal::TEID_ALLOCATION_FAILED, e.what(), CauseCategoryTransport,
                        CauseTransportResourceUnavailable);
        }
        allocated.push_back(localTeid);
        result.prepared.resourceState = ResourceState::RESOURCES_RESERVED;

        // A preparation failure after the identifier is reserved and before it
        // is bound is the delicate one: the value exists and no tunnel does, so
        // the rollback must drop the reservation and must not retire it.
        const auto faultPoint = isDefault ? CommitFaultInjector::Fault::DEFAULT_BEARER_PREPARATION
                                          : CommitFaultInjector::Fault::DEDICATED_BEARER_PREPARATION;
        if (faults.firesAt(faultPoint))
        {
            if (!rollback())
            {
                cleaned = false;
                break;
            }
            return fail(failure, "injected: the bearer's preparation failed after its identifier was reserved");
        }

        BearerParameters parameters{};
        parameters.erabId = bearer->erabId;
        parameters.qci = bearer->qci;
        parameters.ueId = bearerUeId;
        parameters.sgwAddress = bearer->sgwAddress;
        parameters.sgwTeid = TeidFromBytes(bearer->sgwTeid);
        parameters.localTeid = localTeid;
        parameters.linkedDefaultEbi = isDefault ? 0 : *bearer->linkedDefaultErabId;
        parameters.qos = ErabQos{bearer->qci, bearer->priorityLevel, bearer->preemptionCapability,
                                 bearer->preemptionVulnerability, bearer->gbr};

        BearerContext *context = nullptr;
        try
        {
            if (isDefault)
            {
                entry->bearer.establish(parameters, false);
                context = &entry->bearer;
            }
            else
            {
                context = &registry.addDedicatedBearer(*entry, parameters, false);
            }
            // The order is fixed by the registry's contract: the identifier is
            // bound to a bearer that already owns exactly that value, so a
            // caller cannot attach one of its own choosing.
            registry.bindLocalTeid(*entry, *context, localTeid);
        }
        catch (const std::exception &e)
        {
            if (!rollback())
            {
                cleaned = false;
                break;
            }
            return fail(failure, e.what());
        }

        PreparedBearer owned{};
        owned.erabId = bearer->erabId;
        owned.role = bearer->role;
        owned.linkedDefaultErabId = bearer->linkedDefaultErabId;
        owned.qci = bearer->qci;
        owned.priorityLevel = bearer->priorityLevel;
        owned.preemptionCapability = bearer->preemptionCapability;
        owned.preemptionVulnerability = bearer->preemptionVulnerability;
        owned.sgwAddress = bearer->sgwAddress;
        owned.sgwTeid = bearer->sgwTeid;
        owned.targetAddress = target.s1uAddress;
        owned.localTeid = localTeid;
        prepared.push_back(owned);

        committed.push_back(CommittedTransport{bearer->erabId, target.s1uAddress, TeidToBytes(localTeid)});
    }

    if (!cleaned)
    {
        // The rollback itself failed. Say so. What is still outstanding stays
        // visible in the result so the caller can retry, and this is never
        // reported as a committed success. `outstandingTeids` is the whole
        // reserved set rather than only the bound part, because the rollback
        // that did not happen left the reserved one outstanding too and a retry
        // that cannot see it would leak it.
        result.committed = false;
        result.prepared.bearers = prepared;
        result.prepared.committed = committed;
        result.prepared.enbUeS1apId = 0;
        result.prepared.resourceState = ResourceState::RESOURCES_RESERVED;
        result.prepared.state = PreparationState::COMMIT_FAILED;
        result.outstandingTeids = allocated;
        result.refusal = Refuse(CommitRefusal::CLEANUP_FAILED,
                                "the rollback of a refused commit did not complete; resources remain outstanding");
        return result;
    }

    // 6. Own the S1 connection identity as well. A target binds an
    // eNB-UE-S1AP-ID when it takes a context on, and this is the registry's
    // allocator producing it, not a value chosen here. The MME identity is the
    // one the transaction names and is bound so that a second preparation
    // cannot be given the same UE identity.
    try
    {
        const uint32_t enbUeS1apId = registry.allocateEnbUeS1apId();
        registry.bindEnbUeS1apId(*entry, enbUeS1apId);
        registry.setMmeUeS1apId(*entry, transaction.mmeUeS1apId);
        result.prepared.enbUeS1apId = enbUeS1apId;
    }
    catch (const std::exception &e)
    {
        if (!rollback())
        {
            result.committed = false;
            result.prepared.bearers = prepared;
            result.prepared.committed = committed;
            result.prepared.enbUeS1apId = 0;
            result.prepared.resourceState = ResourceState::RESOURCES_RESERVED;
            result.prepared.state = PreparationState::COMMIT_FAILED;
            result.outstandingTeids = allocated;
            result.refusal = Refuse(CommitRefusal::CLEANUP_FAILED,
                                    "the rollback of a refused commit did not complete; resources remain outstanding");
            return result;
        }
        return fail(CommitRefusal::CAPACITY_EXHAUSTED, e.what(), "radioNetwork", CauseNoRadioResourcesAvailable);
    }

    // 7. Publish the complete set only now that every required operation has
    // succeeded. Nothing above could have been mistaken for a half-finished
    // commit, because the caller sees only this result.
    result.committed = true;
    result.prepared.bearers = std::move(prepared);
    result.prepared.committed = std::move(committed);
    result.prepared.resourceState = ResourceState::RESOURCES_COMMITTED_PREPARED;
    result.prepared.state = PreparationState::TARGET_PREPARED;
    result.refusal.reset();
    return result;
}

HandoverFailure CommitRefusalAsHandoverFailure(const CommitRefusalRecord &refusal, uint32_t mmeUeS1apId)
{
    HandoverFailure failure{};
    failure.mmeUeS1apId = mmeUeS1apId;
    failure.causeCategory = refusal.causeCategory;
    failure.causeValue = refusal.causeValue;
    return failure;
}

// --- Preparation transactions --------------------------------------------

HandoverPreparationOwner::HandoverPreparationOwner(UeRegistry &registry, uint64_t associationEpoch,
                                                   std::chrono::milliseconds lifetime)
    : m_registry(registry), m_epoch(associationEpoch), m_lifetime(lifetime)
{
}

HandoverPreparationOwner::~HandoverPreparationOwner()
{
    // A destructor cannot report a cleanup that did not complete, so it tries
    // and then stops. A caller that needs to know must cancel explicitly.
    for (auto &record : m_records)
    {
        try
        {
            releaseOwned(record, PreparationState::PREPARATION_CANCELLED, nullptr);
        }
        catch (...)
        {
        }
    }
}

const PreparationRecord *HandoverPreparationOwner::find(const HandoverTransactionId &id) const
{
    // Scanned newest first: a UE can have more than one preparation under the
    // same association when an earlier one reached a terminal state, and the
    // current transaction for that identity is the most recent of them.
    for (auto it = m_records.rbegin(); it != m_records.rend(); ++it)
        if (it->id.mmeUeS1apId == id.mmeUeS1apId && it->id.associationEpoch == id.associationEpoch)
            return &*it;
    return nullptr;
}

PreparationRecord *HandoverPreparationOwner::findMutable(const HandoverTransactionId &id)
{
    return const_cast<PreparationRecord *>(find(id));
}

PreparationRecord *HandoverPreparationOwner::admit(const HandoverTransactionId &requested,
                                                   const HandoverRequest &request, const SourceContext &source,
                                                   const TargetContext &target,
                                                   const std::vector<BearerRoleBinding> &roles,
                                                   CommitRefusalRecord *failure)
{
    // Stale work changes nothing. A caller working under an association that is
    // no longer bound is not allowed to start, advance or duplicate anything.
    if (requested.associationEpoch != m_epoch)
    {
        if (failure != nullptr)
            *failure = Refuse(CommitRefusal::STALE_ASSOCIATION, "the association epoch is no longer bound");
        return nullptr;
    }
    if (requested.mmeUeS1apId == 0)
    {
        if (failure != nullptr)
            *failure = Refuse(CommitRefusal::TRANSACTION_IDENTITY_ABSENT, "the transaction names no MME-UE-S1AP-ID");
        return nullptr;
    }

    // A repeat of a request this owner has already handled is one transaction,
    // however many times the request arrives. A repeat that agrees is answered
    // from the record that already exists and allocates nothing — including
    // when that record has already reached a terminal state, because the same
    // request under the same identity is still the same transaction and there
    // is nothing new to do about it. A repeat that disagrees with a live
    // preparation is a different transaction pretending to be this one.
    //
    // Scanned newest first, so this is the current transaction for the
    // identity. An earlier preparation that has finished does not stand in the
    // way of a genuinely new one for the same UE.
    for (auto record = m_records.rbegin(); record != m_records.rend(); ++record)
    {
        if (record->id.mmeUeS1apId != requested.mmeUeS1apId)
            continue;
        HandoverAdmission repeat = EvaluateHandoverAdmission(request, source, target, roles);
        if (SamePlan(repeat, record->admission))
            return &*record;
        if (!IsTerminal(record->state))
        {
            if (failure != nullptr)
                *failure = Refuse(CommitRefusal::CONFLICTING_TRANSACTION,
                                  "a live preparation already exists for this UE and the new request describes a "
                                  "different plan");
            return nullptr;
        }
        // The earlier preparation for this UE is finished and this request
        // describes a different one, so it is a genuinely new preparation.
        break;
    }

    // Source identity is taken from the caller, never derived from the
    // association this owner happens to hold. `EvaluateHandoverAdmission`
    // refuses an admission whose source is unknown, so an unverified source
    // produces a recorded refusal rather than a plan.
    HandoverAdmission admission = EvaluateHandoverAdmission(request, source, target, roles);

    PreparationRecord record;
    record.id = requested;
    record.id.sequence = m_nextSequence;
    if (++m_nextSequence == 0)
        m_nextSequence = 1;
    record.admission = std::move(admission);
    record.deadline = std::chrono::steady_clock::now() + m_lifetime;
    if (record.admission.admitted)
    {
        record.state = PreparationState::ADMITTED;
    }
    else
    {
        record.state = PreparationState::ADMISSION_REFUSED;
        const std::string detail = record.admission.refusal.has_value() ? record.admission.refusal->detail
                                                                        : "the admission was refused";
        const std::string category =
            record.admission.refusal.has_value() ? record.admission.refusal->causeCategory : "radioNetwork";
        const int value = record.admission.refusal.has_value() ? record.admission.refusal->causeValue : -1;
        record.refusal = Refuse(CommitRefusal::ADMISSION_NOT_ADMITTED, detail, category, value);
    }
    m_records.push_back(std::move(record));
    return &m_records.back();
}

TargetResourceCommit HandoverPreparationOwner::commit(const HandoverTransactionId &id, const TargetContext &target,
                                                      const CommitFaultInjector &faults)
{
    TargetResourceCommit refused;
    refused.prepared.transaction = id;
    refused.prepared.mmeUeS1apId = id.mmeUeS1apId;
    auto decline = [&refused](CommitRefusal refusal, std::string detail) {
        refused.committed = false;
        refused.prepared.state = PreparationState::COMMIT_FAILED;
        refused.prepared.resourceState = ResourceState::ADMISSION_EVALUATED;
        refused.refusal = Refuse(refusal, std::move(detail));
        return refused;
    };

    if (id.associationEpoch != m_epoch)
        return decline(CommitRefusal::STALE_ASSOCIATION, "the association epoch is no longer bound");

    PreparationRecord *record = findMutable(id);
    if (record == nullptr)
        return decline(CommitRefusal::WRONG_STATE, "no preparation with this identity exists");
    if (record->state == PreparationState::TARGET_PREPARED)
        return decline(CommitRefusal::ALREADY_COMMITTED, "the preparation is already committed; no further TEID set is allocated");
    if (record->state == PreparationState::COMMITTING)
        return decline(CommitRefusal::CONFLICTING_TRANSACTION, "the preparation is already being committed");
    if (IsTerminal(record->state))
        return decline(CommitRefusal::WRONG_STATE,
                       std::string("the preparation is ") + ToString(record->state) + " and owns nothing");
    if (record->state == PreparationState::ADMISSION_REFUSED)
        return decline(CommitRefusal::ADMISSION_NOT_ADMITTED, "the admission was refused");
    if (std::chrono::steady_clock::now() > record->deadline)
    {
        CommitRefusalRecord cleanup{};
        if (!releaseOwned(*record, PreparationState::PREPARATION_EXPIRED, &cleanup))
            return decline(cleanup.refusal, cleanup.detail);
        record->refusal = Refuse(CommitRefusal::EXPIRED, "the preparation lifetime elapsed");
        return decline(CommitRefusal::EXPIRED, "the preparation lifetime elapsed");
    }

    record->state = PreparationState::COMMITTING;
    record->resources.state = PreparationState::COMMITTING;

    TargetResourceCommit outcome = CommitHandoverResources(record->admission, target, m_registry, record->id, faults);
    if (outcome.committed)
    {
        record->state = PreparationState::TARGET_PREPARED;
        record->resources = outcome.prepared;
        record->resources.state = PreparationState::TARGET_PREPARED;
        record->entry = outcome.ownedEntry;
        record->ownedTeids.clear();
        for (const auto &bearer : outcome.prepared.bearers)
            record->ownedTeids.push_back(bearer.localTeid);
        record->refusal.reset();
        return outcome;
    }

    record->state = PreparationState::COMMIT_FAILED;
    record->refusal = outcome.refusal;
    if (outcome.refusal.has_value() && outcome.refusal->refusal == CommitRefusal::CLEANUP_FAILED)
    {
        // The commit could not clean up after itself. This record keeps what is
        // still outstanding so that a later `cancel` can try again, and the
        // caller is told plainly that cleanup did not happen. The list is the
        // commit's whole reserved set, not only the part it bound.
        record->entry = outcome.ownedEntry;
        record->ownedTeids = outcome.outstandingTeids;
        record->resources = outcome.prepared;
        record->resources.state = PreparationState::TARGET_PREPARED;
    }
    return outcome;
}

HandoverRequestAcknowledge HandoverPreparationOwner::acknowledge(const HandoverTransactionId &id)
{
    const PreparationRecord *record = find(id);
    if (record == nullptr)
        throw HandoverRefused(HandoverRefusal::INVALID_CONTEXT_IDENTITY, "no preparation with this identity exists");
    if (record->state != PreparationState::TARGET_PREPARED)
        throw HandoverRefused(HandoverRefusal::MISSING_MANDATORY_IE,
                              std::string("the preparation is ") + ToString(record->state) + " and cannot be acknowledged");
    if (record->resources.enbUeS1apId == 0)
        throw HandoverRefused(HandoverRefusal::INVALID_CONTEXT_IDENTITY,
                              "the preparation owns no eNB-UE-S1AP-ID to acknowledge under");
    // The eNB-UE-S1AP-ID and the transport both come from what the commit
    // actually bound. `BuildHandoverRequestAcknowledge` checks that the
    // committed set covers the admitted one and invents nothing.
    return BuildHandoverRequestAcknowledge(record->admission, record->resources.mmeUeS1apId,
                                           record->resources.enbUeS1apId, record->resources.committed);
}

bool HandoverPreparationOwner::releaseOwned(PreparationRecord &record, PreparationState terminal,
                                            CommitRefusalRecord *failure)
{
    if (record.entry != nullptr)
    {
        // Bound identifiers are retired through the normal lifecycle and
        // reserved ones are dropped, so nothing this preparation issued can
        // stop resolving without also becoming identifiable as retired or as
        // never having been a tunnel. Nothing here reaches an identifier the
        // record does not own.
        //
        // A release that throws is a cleanup that did not complete, and it is
        // reported as one rather than allowed to escape as an ordinary error
        // after some of the identifiers have already gone.
        try
        {
            for (uint32_t teid : record.ownedTeids)
                m_registry.unbindLocalTeid(*record.entry, teid);
            m_registry.removeProvisional(*record.entry);
        }
        catch (const std::exception &e)
        {
            if (failure != nullptr)
                *failure = Refuse(CommitRefusal::CLEANUP_FAILED, e.what());
            return false;
        }
        record.entry = nullptr;
    }
    record.ownedTeids.clear();
    record.resources.bearers.clear();
    record.resources.committed.clear();
    record.resources.enbUeS1apId = 0;
    record.resources.resourceState = ResourceState::ADMISSION_EVALUATED;
    // A record that already had a terminal name keeps it: a commit failure is
    // not rewritten into a cancellation.
    if (!IsTerminal(record.state))
        record.state = terminal;
    return true;
}

bool HandoverPreparationOwner::cancel(const HandoverTransactionId &id, CommitRefusalRecord *failure)
{
    PreparationRecord *record = findMutable(id);
    if (record == nullptr)
    {
        if (failure != nullptr)
            *failure = Refuse(CommitRefusal::WRONG_STATE, "no preparation with this identity exists");
        return false;
    }
    // Idempotent and safe against a second call: whatever the first released is
    // no longer owned, and whatever the record does not own is not touched.
    return releaseOwned(*record, PreparationState::PREPARATION_CANCELLED, failure);
}

size_t HandoverPreparationOwner::expireDue(std::chrono::steady_clock::time_point now)
{
    size_t expired = 0;
    for (auto &record : m_records)
    {
        if (IsTerminal(record.state) || now <= record.deadline)
            continue;
        CommitRefusalRecord cleanup{};
        if (!releaseOwned(record, PreparationState::PREPARATION_EXPIRED, &cleanup))
        {
            // Cleanup failed, so the record keeps what it owns and is not
            // counted as expired.
            record.refusal = cleanup;
            continue;
        }
        record.refusal = Refuse(CommitRefusal::EXPIRED, "the preparation lifetime elapsed");
        ++expired;
    }
    return expired;
}

bool HandoverPreparationOwner::awaitUeAccess(const HandoverTransactionId &id, CommitRefusalRecord *failure)
{
    PreparationRecord *record = findMutable(id);
    if (record == nullptr)
    {
        if (failure != nullptr)
            *failure = Refuse(CommitRefusal::WRONG_STATE, "no preparation with this identity exists");
        return false;
    }
    // This is the step a completion takes. It is refused for a transaction that
    // has already been cleaned up, which is what stops a stale completion after
    // a cancellation from turning a released preparation back into a live one.
    if (record->state != PreparationState::TARGET_PREPARED)
    {
        if (failure != nullptr)
            *failure = Refuse(CommitRefusal::WRONG_STATE,
                              std::string("the preparation is ") + ToString(record->state) + " and cannot be completed");
        return false;
    }
    record->resources.resourceState = ResourceState::AWAITING_UE_TARGET_ACCESS;
    return true;
}

} // namespace lte::enb::s1ap
