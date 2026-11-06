// Phase 18-B: atomic target-eNB handover resource commitment.
//
// This is the bridge between `EvaluateHandoverAdmission` and
// `BuildHandoverRequestAcknowledge`. Admission is a plan and allocates nothing;
// commitment turns that plan into real, owned, non-forwardable target
// resources and reports exactly what it bound. Nothing here starts a handover,
// and nothing here reports that a UE arrived.
//
// The two things this module is careful never to conflate:
//
//   admission  !=  commitment          a plan is not an owned tunnel
//   prepared   !=  arrived             an owned tunnel is not a reached UE
//
// A prepared bearer has had `establish()` called and not `activateUe()`, so
// `BearerContext::active()` is false and the shared S1-U endpoint refuses to
// forward to it. That is the whole forwarding restriction: it is the existing
// bearer readiness gate, reused rather than reimplemented.

#pragma once

#include "handover_admission.hpp"
#include "ue_registry.hpp"

#include <chrono>
#include <cstdint>
#include <deque>
#include <optional>
#include <string>
#include <vector>

namespace lte::enb::s1ap
{

// --- Transaction identity -------------------------------------------------

// What names one handover preparation at this target. The MME-UE-S1AP-ID alone
// would not do: the same MME can start a second preparation for the same UE
// after a first one failed, and the target has to be able to tell the two
// apart. The association epoch names the target's S1 association with the MME,
// so work begun under an association that has since been replaced is
// recognisable as stale. The sequence is a target-local ordinal and has no
// protocol meaning at all.
//
// Deliberately none of: EBI, TEID, a timestamp, the UE's address or a TAC.
// Every one of those is either shared with another UE, reused over time, or
// not the target's to decide.
//
// What names the transaction is the pair (mmeUeS1apId, associationEpoch). The
// sequence is this owner's own tag on it — target-local ownership bookkeeping,
// assigned when the transaction is created and carrying no protocol meaning —
// so a caller that presents the right identity with a stale or absent sequence
// is still talking about the same transaction and must not be able to start a
// second one. Every operation resolves on the pair; `operator==` compares the
// whole triple so a recorded transaction can be checked exactly.
struct HandoverTransactionId
{
    uint32_t mmeUeS1apId{};
    uint64_t associationEpoch{};
    uint32_t sequence{};
};

bool operator==(const HandoverTransactionId &a, const HandoverTransactionId &b);
bool operator!=(const HandoverTransactionId &a, const HandoverTransactionId &b);
bool operator<(const HandoverTransactionId &a, const HandoverTransactionId &b);
std::string ToString(const HandoverTransactionId &id);

// --- Preparation transaction state ---------------------------------------

// NEW -> ADMITTED -> COMMITTING -> TARGET_PREPARED, with the four terminal
// failure branches. The transitions are explicit and one-way; no failure is
// ever converted into a prepared success.
enum class PreparationState : uint8_t
{
    NEW,
    ADMITTED,
    COMMITTING,
    TARGET_PREPARED,
    ADMISSION_REFUSED,
    COMMIT_FAILED,
    PREPARATION_CANCELLED,
    PREPARATION_EXPIRED
};
const char *ToString(PreparationState state);

// Whether the state is terminal: no further transition is possible and the
// transaction owns nothing.
[[nodiscard]] bool IsTerminal(PreparationState state);

// --- Resource lifecycle state --------------------------------------------

// The target-local resource ladder of the design record. These are not the
// eight global connected-handover states; they say only how far this eNB's own
// preparation of the resources has got.
enum class ResourceState : uint8_t
{
    ADMISSION_EVALUATED,
    RESOURCES_RESERVED,
    RESOURCES_COMMITTED_PREPARED,
    AWAITING_UE_TARGET_ACCESS
};
const char *ToString(ResourceState state);

// --- Commit refusals -----------------------------------------------------

// Why the commit was refused. Every value is a condition checked before or
// during commitment, and a refusal allocates and binds nothing.
enum class CommitRefusal : uint8_t
{
    // The admission handed in was not a successful admission.
    ADMISSION_NOT_ADMITTED,
    // The admitted bearer set is empty.
    EMPTY_BEARER_SET,
    // The target identity does not name the receiving eNB.
    TARGET_IDENTITY_MISMATCH,
    // The target has no S1-U address to serve on.
    TARGET_TRANSPORT_ADDRESS_ABSENT,
    // Two admitted bearers name the same E-RAB.
    DUPLICATE_ERAB_ID,
    // A dedicated bearer names no default bearer of this set, or names one that
    // is not the default bearer this context owns.
    LINKED_DEFAULT_MISSING,
    // A bearer the target could not establish as an EPS bearer: an E-RAB
    // identity outside the range one may hold, a zero QCI, or a zero SGW TEID.
    BEARER_PARAMETERS_INVALID,
    // More than one default bearer. A target-side context owns one default
    // bearer, so a set that needs two cannot be committed here and is refused
    // whole rather than having one silently dropped.
    MULTIPLE_DEFAULT_BEARERS,
    // The transaction names no MME-UE-S1AP-ID, so it names no UE at all.
    TRANSACTION_IDENTITY_ABSENT,
    // Per-UE or registry capacity would be exceeded.
    CAPACITY_EXHAUSTED,
    // The local S1-U allocator could not produce a usable identifier.
    TEID_ALLOCATION_FAILED,
    // The default bearer could not be prepared.
    DEFAULT_BEARER_PREPARATION_FAILED,
    // A dedicated bearer could not be prepared.
    DEDICATED_BEARER_PREPARATION_FAILED,
    // Another live preparation already owns these target resources.
    CONFLICTING_TRANSACTION,
    // The caller is working under an association epoch that is no longer bound.
    STALE_ASSOCIATION,
    // This transaction has already been committed.
    ALREADY_COMMITTED,
    // The transaction is in a state this operation does not accept.
    WRONG_STATE,
    // The preparation's deadline has passed.
    EXPIRED,
    // Rollback did not complete. Reported instead of being called a success.
    CLEANUP_FAILED
};
const char *ToString(CommitRefusal refusal);

struct CommitRefusalRecord
{
    CommitRefusal refusal{};
    std::string detail;
    // The standard Cause the refusal would be reported under, so a Handover
    // Failure can be built without inventing one. -1 when the refusal is purely
    // internal and no wire Cause applies.
    std::string causeCategory{"radioNetwork"};
    int causeValue{-1};
};

// --- Deterministic fault injection --------------------------------------

// Opt-in fault points for the commitment path. It is an argument, never a
// global: production calls `CommitHandoverResources` without one and cannot be
// made to fail by anything outside its own preconditions. A test passes one to
// reach the failure branches that a working commit cannot reach on its own.
//
// TEID-allocation failure is deliberately not here. It is injected through the
// `UeRegistry` allocator seam instead, which is where the existing tests
// already reach the exhaustion and boundary cases.
class CommitFaultInjector
{
  public:
    enum class Fault : uint8_t
    {
        NONE,
        // Refuse the commit after the whole set is validated and the provisional
        // context exists, but before any identifier is reserved.
        CAPACITY_EXHAUSTED,
        // Fail the default bearer's preparation after its identifier is
        // reserved and before it is bound.
        DEFAULT_BEARER_PREPARATION,
        // Fail a dedicated bearer's preparation after the default is prepared.
        DEDICATED_BEARER_PREPARATION,
        // Refuse the commit as if another live preparation owned the resources.
        CONFLICTING_TRANSACTION,
        // Refuse the commit as if the association epoch were stale.
        STALE_ASSOCIATION,
        // Make the rollback itself fail, so the caller must surface the failure
        // explicitly instead of reporting that cleanup succeeded.
        CLEANUP_FAILURE
    };

    constexpr CommitFaultInjector() = default;
    constexpr explicit CommitFaultInjector(Fault fault) : m_first(fault)
    {
    }
    // Two faults at once. A rollback cannot fail unless something makes one be
    // attempted, so `CLEANUP_FAILURE` on its own is a no-op on a commit that
    // would otherwise succeed — there is no cleanup to fail. Reaching that
    // branch needs a preparation failure *and* a rollback that does not
    // complete, which is what the two-argument form is for.
    constexpr CommitFaultInjector(Fault first, Fault second) : m_first(first), m_second(second)
    {
    }

    [[nodiscard]] constexpr Fault fault() const
    {
        return m_first;
    }
    [[nodiscard]] constexpr bool firesAt(Fault point) const
    {
        return (m_first != Fault::NONE && m_first == point) || (m_second != Fault::NONE && m_second == point);
    }

  private:
    Fault m_first{Fault::NONE};
    Fault m_second{Fault::NONE};
};

// --- Prepared resources --------------------------------------------------

// One bearer the target has actually prepared. It carries the network's own
// statement of the bearer unchanged, and adds the target-local transport that
// the commit bound.
struct PreparedBearer
{
    uint8_t erabId{};
    BearerRole role{BearerRole::DEFAULT};
    std::optional<uint8_t> linkedDefaultErabId;
    uint8_t qci{};
    uint8_t priorityLevel{};
    bool preemptionCapability{};
    bool preemptionVulnerability{};
    // The SGW's receiving transport, carried across unchanged. The target sends
    // uplink here and never rewrites it.
    std::array<uint8_t, 4> sgwAddress{};
    std::array<uint8_t, 4> sgwTeid{};
    // The target's own S1-U address and the fresh local TEID the commit bound
    // to this bearer. The value is real: it came from `allocateLocalTeid` and
    // is owned by the registry.
    std::array<uint8_t, 4> targetAddress{};
    uint32_t localTeid{};
};

// Everything a successful commit owns. It is the input
// `BuildHandoverRequestAcknowledge` needs and nothing is invented to fill it.
struct PreparedTargetResources
{
    HandoverTransactionId transaction;
    EnbIdentity target;
    uint32_t mmeUeS1apId{};
    // Zero until one is allocated. A target binds an eNB-UE-S1AP-ID when it
    // takes the context on, and a preparation may legitimately have none yet.
    uint32_t enbUeS1apId{};
    // Default bearers first, then dedicated, each group in the order admission
    // planned them. The order is a readiness order, never the wire order.
    std::vector<PreparedBearer> bearers;
    // The complete committed transport set, one entry per admitted bearer, in
    // the same readiness order as `bearers`.
    std::vector<CommittedTransport> committed;
    ResourceState resourceState{ResourceState::ADMISSION_EVALUATED};
    PreparationState state{PreparationState::NEW};
};

// Whether the bearers a preparation actually owns are prepared and not
// forwardable. It reads the real `BearerContext::active()` of the real contexts
// through the registry entry, rather than any flag this module kept, so it
// cannot be made true by a description of a bearer that was never established:
// a bearer that was never prepared answers false here.
[[nodiscard]] bool PreparedBearersNonForwardable(const EnbUeEntry &entry);

// The result of one commitment attempt. Never a partial success: either
// `committed` is true and `prepared` describes everything that was bound, or
// `refusal` says why nothing was.
struct TargetResourceCommit
{
    bool committed{false};
    PreparedTargetResources prepared;
    std::optional<CommitRefusalRecord> refusal;
    // The provisional context this commit created and bound, or null when it
    // created none. It is the thing that owns every identifier in `prepared`,
    // and the thing a rollback releases. It is not a UE session and is never
    // one: its radio identity is zero and it has no peer.
    //
    // It is also left non-null when a rollback itself failed, so a caller can
    // see exactly what is still outstanding instead of being told cleanup
    // succeeded.
    EnbUeEntry *ownedEntry{};

    // Every identifier this attempt reserved and could not release, populated
    // only when the rollback did not complete. It is the whole set — the ones
    // that were bound and the one that was only reserved — because a rollback
    // that did not happen left both kinds outstanding, and a retry that cannot
    // see one of them would leak it. A successful commit leaves this empty: a
    // success owns nothing the caller has to clean up.
    std::vector<uint32_t> outstandingTeids;

    [[nodiscard]] bool holdsTransportResources() const;
};

// --- Commitment ----------------------------------------------------------

// Turns an admitted plan into real, owned, non-forwardable target resources.
//
// All-or-nothing across the whole bearer set. Every identifier comes from
// `UeRegistry::allocateLocalTeid` and is bound through `bindLocalTeid`; none is
// ever fabricated and none is a retired one. On any failure every reservation
// is released and every prepared mapping is revoked through the registry's own
// rollback, so nothing leaks and no partial Handover Request Acknowledge can
// be built from the result.
//
// The entry it prepares is a provisional target context: real transport
// ownership, no radio peer, no UE session. Nothing here calls `activateUe`, so
// no prepared bearer can forward.
TargetResourceCommit CommitHandoverResources(const HandoverAdmission &admission, const TargetContext &target,
                                             UeRegistry &registry, const HandoverTransactionId &transaction,
                                             const CommitFaultInjector &faults = {});

// The Handover Failure a refused commit would be sent. It preserves the MME
// transaction identity and names no eNB-UE-S1AP-ID, because a failed commit
// bound none that survives.
HandoverFailure CommitRefusalAsHandoverFailure(const CommitRefusalRecord &refusal, uint32_t mmeUeS1apId);

// --- Preparation transactions -------------------------------------------

// One preparation's record. The transaction owns the provisional context and
// every identifier bound on its behalf, and releases all of it on any terminal
// path.
struct PreparationRecord
{
    HandoverTransactionId id;
    PreparationState state{PreparationState::NEW};
    HandoverAdmission admission;
    PreparedTargetResources resources;
    // The provisional registry entry this preparation owns, if any. It is not a
    // UE session and must never be reported as one.
    EnbUeEntry *entry{};
    std::vector<uint32_t> ownedTeids;
    std::chrono::steady_clock::time_point deadline{};
    std::optional<CommitRefusalRecord> refusal;
};

// The minimal production lifecycle that stops duplicate and stale work. It
// holds no background service: expiry is a deterministic call with an explicit
// clock, so a test can drive it exactly and an ordinary run is never surprised
// by a timer.
class HandoverPreparationOwner
{
  public:
    explicit HandoverPreparationOwner(UeRegistry &registry, uint64_t associationEpoch,
                                      std::chrono::milliseconds lifetime = std::chrono::milliseconds(30000));
    // Releases anything a caller left prepared. It never throws: a cleanup that
    // cannot complete is not converted into a success here either, but a
    // destructor cannot report one, so a caller that cares must cancel
    // explicitly and read the result.
    ~HandoverPreparationOwner();

    HandoverPreparationOwner(const HandoverPreparationOwner &) = delete;
    HandoverPreparationOwner &operator=(const HandoverPreparationOwner &) = delete;

    // The association epoch this owner is bound to. A caller presenting a
    // different one is working under an association that is no longer bound and
    // every operation it asks for is refused as stale.
    [[nodiscard]] uint64_t associationEpoch() const
    {
        return m_epoch;
    }

    // Records an admission under a fresh target-local sequence. A repeat of a
    // transaction that is already known with the same plan returns the existing
    // record and allocates nothing — that holds whatever state the record has
    // reached, because the same request under the same identity is the same
    // transaction and there is nothing new to do about it. A repeat that
    // disagrees with a live preparation is a conflicting duplicate and is
    // refused. A different request after an earlier one has finished is a
    // genuinely new preparation and is recorded as one.
    //
    // Source identity is not derived here. `EvaluateHandoverAdmission` already
    // refuses an admission whose source is unknown, and this owner never fills
    // that field in from the MME association it happens to hold.
    //
    // Returns null only when no record could be made at all — a stale
    // association epoch or a transaction naming no UE — and says why in
    // `failure`. A refusal of the admission itself is not a refusal to record
    // it: the record exists in `ADMISSION_REFUSED` and owns nothing, so a
    // repeat of it cannot allocate anything either.
    PreparationRecord *admit(const HandoverTransactionId &requested, const HandoverRequest &request,
                             const SourceContext &source, const TargetContext &target,
                             const std::vector<BearerRoleBinding> &roles, CommitRefusalRecord *failure = nullptr);

    // Commits an admitted preparation. A second commit for a transaction that
    // is already prepared allocates no further TEID set and is refused.
    TargetResourceCommit commit(const HandoverTransactionId &id, const TargetContext &target,
                                const CommitFaultInjector &faults = {});

    // Builds the Handover Request Acknowledge from what the commit actually
    // bound. Repeating it produces the same message and gains no resource. The
    // eNB-UE-S1AP-ID is the one the commit bound, because that is the one the
    // registry owns; a caller cannot send an identifier this target never
    // allocated. Throws `HandoverRefused` for a transaction that is not
    // prepared.
    //
    // Note the container: `BuildHandoverRequestAcknowledge` echoes the
    // admission's `sourceToTarget` into `targetToSource`. That is accepted
    // Phase 18-A behaviour pinned by the wire vectors and is deliberately not
    // changed here, so the acknowledge carries no container of the target's own.
    // Producing a real Target-ToSource container is a later phase's work.
    HandoverRequestAcknowledge acknowledge(const HandoverTransactionId &id);

    // Explicit cancellation. Idempotent: a second call reports the same outcome
    // and cannot touch a resource the first one already released, nor one that
    // belongs to another transaction. It releases whatever the record still
    // owns — which includes a set a failed commit could not clean up — and then
    // names the transaction `PREPARATION_CANCELLED` unless it already had a
    // terminal name of its own, so a commit failure is not rewritten into a
    // cancellation.
    bool cancel(const HandoverTransactionId &id, CommitRefusalRecord *failure = nullptr);

    // Deterministic expiry. Every preparation whose deadline has passed and
    // which is not already terminal is expired and its resources released. The
    // source's bearers are never touched.
    size_t expireDue(std::chrono::steady_clock::time_point now);

    // The finalisation of a preparation: the target is ready and is awaiting the
    // UE's access. Refused for a transaction that has already been cleaned up,
    // which is what makes a stale completion after cancellation fail closed.
    bool awaitUeAccess(const HandoverTransactionId &id, CommitRefusalRecord *failure = nullptr);

    // Resolves a transaction by its identity pair (mmeUeS1apId, associationEpoch);
    // the sequence field of `id` is ignored, because it is this owner's own tag
    // and a caller that knows the identity is talking about that transaction.
    [[nodiscard]] const PreparationRecord *find(const HandoverTransactionId &id) const;
    [[nodiscard]] size_t size() const
    {
        return m_records.size();
    }

  private:
    // Resolves a transaction the same way `find` does, for the operations that
    // need to move it on.
    [[nodiscard]] PreparationRecord *findMutable(const HandoverTransactionId &id);

    // Releases everything the record owns and moves it to a terminal state.
    // Idempotent, and never reaches an identifier the record does not own. When
    // the rollback itself fails the failure is surfaced to the caller rather
    // than being reported as a successful cleanup, and the record keeps what it
    // still owns so a later call can try again.
    bool releaseOwned(PreparationRecord &record, PreparationState terminal, CommitRefusalRecord *failure);

    UeRegistry &m_registry;
    uint64_t m_epoch;
    std::chrono::milliseconds m_lifetime;
    uint32_t m_nextSequence{1};
    // A deque so that a pointer or reference to a record stays valid while the
    // owner keeps admitting, which is what makes handing a record out safe.
    std::deque<PreparationRecord> m_records;
};

} // namespace lte::enb::s1ap
