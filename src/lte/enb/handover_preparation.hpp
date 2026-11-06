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

#include <array>
#include <chrono>
#include <cstdint>
#include <deque>
#include <optional>
#include <string>
#include <vector>

namespace lte::enb
{
class IS1apSender;
}

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

// NEW -> ADMITTED -> COMMITTING -> TARGET_PREPARED -> TARGET_REACHED ->
// NOTIFY_SENT, with the four terminal failure branches. The transitions are
// explicit and one-way; no failure is ever converted into a prepared success,
// and no amount of preparation is ever converted into an arrival.
//
// TARGET_REACHED is the arrival, not the handover. It means the UE's simulated
// radio access was correlated to this transaction and its provisional context
// became a reached UE: nothing more. It does not mean the MME has switched the
// bearer path, and it does not mean the source eNB has been released.
enum class PreparationState : uint8_t
{
    NEW,
    ADMITTED,
    COMMITTING,
    TARGET_PREPARED,
    TARGET_REACHED,
    NOTIFY_SENT,
    ADMISSION_REFUSED,
    COMMIT_FAILED,
    PREPARATION_CANCELLED,
    PREPARATION_EXPIRED
};
const char *ToString(PreparationState state);

// Whether the state is terminal: no further transition is possible and the
// transaction owns nothing. A reached preparation is deliberately not terminal,
// because a Notify is still owed, but by then it owns nothing either — the
// reached registry does. `IsReached` names that pair.
[[nodiscard]] bool IsTerminal(PreparationState state);
[[nodiscard]] bool IsReached(PreparationState state);

// --- Resource lifecycle state --------------------------------------------

// The target-local resource ladder of the design record. These are not the
// eight global connected-handover states; they say only how far this eNB's own
// preparation of the resources has got.
enum class ResourceState : uint8_t
{
    ADMISSION_EVALUATED,
    RESOURCES_RESERVED,
    RESOURCES_COMMITTED_PREPARED,
    AWAITING_UE_TARGET_ACCESS,
    UE_ARRIVED,
    BEARERS_READY,
    NOTIFY_ELIGIBLE,
    NOTIFY_SENT
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

// --- Handover Notify gate -------------------------------------------------

// Why a Handover Notify may not be built or sent. Each value is one of the
// gate's conditions failing, so the refusal names the condition rather than
// reporting a generic failure.
enum class NotifyRefusal : uint8_t
{
    // No preparation with this identity exists.
    NO_PREPARATION,
    // The caller is working under an association epoch this target no longer
    // holds, so a Notify through the new association would be a Notify about a
    // transaction that does not belong to it.
    STALE_ASSOCIATION,
    // The target never committed resources for this transaction.
    NOT_COMMITTED,
    // No UE arrival has been verified for this transaction.
    NOT_REACHED,
    // The promotion did not complete, so the reached context is not real.
    PROMOTION_INCOMPLETE,
    // Not every prepared bearer is ready. A Handover Notify claims the UE has
    // arrived at a cell that can serve it.
    BEARERS_NOT_READY,
    // The MME-UE-S1AP-ID or the eNB-UE-S1AP-ID is not the one this transaction
    // bound.
    IDENTITY_MISMATCH,
    // The cell the caller names is not the one this transaction was admitted
    // against, so the CGI or the TAI the Notify would carry would not be this
    // cell's.
    TARGET_CELL_MISMATCH,
    // The transaction does not name exactly one reached UE context.
    AMBIGUOUS_CONTEXT,
    // A Handover Notify has already been sent for this transaction. A duplicate
    // arrival must not produce a second one.
    ALREADY_NOTIFIED,
    // The codec refused the message. Nothing is sent.
    ENCODE_FAILED,
    // The sender refused or threw. The attempt is reported as unsuccessful and
    // is not recorded as a notification.
    SEND_FAILED
};
const char *ToString(NotifyRefusal refusal);

struct NotifyRefusalRecord
{
    NotifyRefusal refusal{};
    std::string detail;
};

// The result of one Notify attempt. `sent` is true only when the real codec
// produced a message and a real sender accepted it; every other outcome leaves
// it false and says why, so an unsuccessful attempt is never recorded as a
// successful notification and a later one may still be attempted.
struct HandoverNotifyOutcome
{
    bool sent{false};
    std::optional<HandoverNotify> message;
    std::optional<NotifyRefusalRecord> refusal;
};

// --- Preparation transactions -------------------------------------------

// One preparation's record. The transaction owns the provisional context and
// every identifier bound on its behalf, and releases all of it on any terminal
// path — until an arrival transfers that ownership to the reached-UE registry,
// after which the record owns nothing and can release nothing.
struct PreparationRecord
{
    HandoverTransactionId id;
    PreparationState state{PreparationState::NEW};
    HandoverAdmission admission;
    PreparedTargetResources resources;
    // The provisional registry entry this preparation owns, if any. It is not a
    // UE session and must never be reported as one.
    //
    // It is cleared the moment ownership is transferred, together with
    // `ownedTeids`, so a completed record holds no pointer that could release
    // the reached UE's resources. What is kept instead is the immutable audit
    // metadata below, which describes what was reached and cannot act on it.
    EnbUeEntry *entry{};
    std::vector<uint32_t> ownedTeids;
    std::chrono::steady_clock::time_point deadline{};
    std::optional<CommitRefusalRecord> refusal;

    // The arrival binding this preparation issued. Zero until a commit produced
    // one; never reissued afterwards.
    uint32_t arrivalToken{};
    // Set when the reached-UE registry became the sole owner of the prepared
    // resources. Once it is set, cancellation, expiry and destruction are no
    // longer permitted to reach the context: a reached UE is not preparation
    // state and preparation cleanup must not destroy one.
    bool ownershipTransferred{false};
    // Immutable audit metadata about the arrival that took ownership. A value
    // here never resolves to anything: it is what was reached, not a handle to
    // it.
    uint32_t reachedRadioUeId{};
    uint32_t reachedEnbUeS1apId{};
    std::array<uint8_t, 4> reachedUeIpv4{};
    // Whether a Handover Notify has been successfully sent. An attempt that did
    // not complete leaves this false so a later one may still be made.
    bool notifySent{false};
    std::optional<NotifyRefusalRecord> notifyRefusal;
};

// --- Verified target arrival ---------------------------------------------

// The binding a committed preparation issues and an arriving UE must present.
//
// It is not a credential. Its value is not secret, it proves nothing on its own
// and no key is derived from it. What makes it usable is state at the target:
// one token per committed preparation, issued once by `AllocateArrivalToken`,
// consumed once, and bound to the transaction identity and the association
// epoch it was issued under. It has no S1AP representation either — nothing
// here puts one into a transparent container or any other information element,
// and nothing reads one out of one — so in this phase it is handed from the
// target's preparation to the source eNB's simulated handover command by a
// test harness that has verified both ends. That hand-off is explicitly
// test-harness-verified provenance and is not a production trust path.
//
// Process-lifetime monotonic, never zero and never repeated, so a token from a
// transaction that has been cleaned up cannot be reissued to another one.
uint32_t AllocateArrivalToken();

// What an arriving UE must present, and what the target independently knows.
// The two halves are deliberately separate: the frame is what the UE said, and
// the cell identity and association epoch are what this eNB is, read from its
// own configuration rather than from anything the UE claimed.
struct TargetArrivalEvidence
{
    lte::ue::link::SimulatedHandoverAccess access;
    // The simulated radio identity the UE claimed, and the UDP endpoint it
    // arrived from. The identity must be unused and the endpoint must be
    // unowned; neither is taken on the UE's word alone.
    uint32_t radioUeId{};
    InetAddress peer;
    // This eNB's own identity and the E-UTRAN CGI its cell broadcasts. Both
    // come from `EnbConfig`, never from the frame.
    EnbIdentity target;
    EutranCgi targetCgi;
    // The association epoch the target is currently bound to.
    uint64_t associationEpoch{};

    // The simulated handover command the source eNB sent this UE, when the
    // caller has seen it. It is the source's own statement of what it
    // authorised, and an arrival that disagrees with it is refused rather than
    // taken as a fresh claim.
    //
    // It is absent on the ordinary radio receive path: a target eNB does not
    // see the command the source sent, and there is no S1AP information element
    // in this repository that carries one. When it is absent the target falls
    // back to the agreement it can establish on its own — the binding resolving
    // to this transaction and the arrival naming the source cell the admission
    // recorded — and does not pretend to a corroboration it does not have. A
    // deterministic two-eNB harness that has driven both ends supplies it, and
    // that is explicitly test-harness-verified provenance, never trusted
    // production information.
    std::optional<lte::ue::link::SimulatedHandoverCommand> sourceCommand;
};

// What the target established by correlating an arrival to a prepared
// transaction. It is the evidence, and it is what promotion consumes: nothing
// downstream is asked to re-derive any of it.
struct VerifiedTargetArrival
{
    HandoverTransactionId transaction;
    uint32_t arrivalToken{};
    uint32_t radioUeId{};
    InetAddress peer;
    EnbIdentity source;
    EnbIdentity target;
    std::array<uint8_t, 4> ueIpv4{};
};

// Why a simulated target arrival was refused. Every value is a condition
// checked before anything moves, and a refusal leaves the preparation exactly
// as it was: still provisional, still non-forwardable and still owning what it
// owned.
enum class ArrivalRefusal : uint8_t
{
    // The arrival named no MME-UE-S1AP-ID, so it names no transaction at all.
    TRANSACTION_IDENTITY_ABSENT,
    // The arrival is working under an association epoch this target no longer
    // holds.
    STALE_ASSOCIATION,
    // No committed preparation issued this arrival binding.
    ARRIVAL_TOKEN_UNKNOWN,
    // The binding names a preparation that has already taken an arrival. The
    // token is spent and cannot be presented again.
    ARRIVAL_TOKEN_CONSUMED,
    // The binding belongs to a different transaction than the one the arrival
    // names.
    TRANSACTION_IDENTITY_MISMATCH,
    // The arrival names a source cell that is not the one this preparation was
    // admitted against.
    SOURCE_IDENTITY_MISMATCH,
    // The arrival names a target cell that is not this eNB.
    TARGET_IDENTITY_MISMATCH,
    // The target cell the arrival names does not produce this eNB's E-UTRAN
    // CGI.
    TARGET_CGI_MISMATCH,
    // The target cell the arrival names does not carry this eNB's tracking
    // area.
    TARGET_TAI_MISMATCH,
    // The arriving UE disagrees with the simulated handover command the source
    // eNB sent it: a different target cell, a different UE identity or a
    // different PDN address. Only checkable when the caller has seen that
    // command, which the ordinary radio receive path has not.
    SOURCE_COMMAND_MISMATCH,
    // The preparation is not a committed one awaiting its UE.
    NOT_AWAITING_ACCESS,
    // The preparation is in a state that owns nothing to arrive to: it was
    // refused, its commit failed, it was cancelled or it has expired.
    NOT_A_PREPARED_TARGET,
    // The claimed radio identity is already in use.
    RADIO_IDENTITY_CONFLICT,
    // The claimed radio endpoint already carries another UE.
    RADIO_PEER_CONFLICT,
    // The prepared bearer set is not the one the admission planned.
    BEARER_SET_INCOMPLETE,
    // The arrival carried no radio identity or no peer to correlate against.
    ARRIVAL_EVIDENCE_INCOMPLETE,
    // The registry refused the promotion. The detail says which precondition
    // failed and the context is still provisional.
    PROMOTION_FAILED,
    // The prepared bearers could not be made ready. The context has been put
    // back to provisional and nothing forwards.
    BEARER_READINESS_FAILED
};
const char *ToString(ArrivalRefusal refusal);

struct ArrivalRefusalRecord
{
    ArrivalRefusal refusal{};
    std::string detail;
};

// Opt-in fault points for the arrival path. It is an argument, never a global:
// production calls `acceptArrival` without one and cannot be made to fail by
// anything outside its own preconditions. A test passes one to reach the
// rollback a working arrival cannot reach on its own.
//
// The two seams are the two boundaries a promotion crosses: publishing the
// reached-UE indexes, and making the prepared bearers ready. They sit where
// they do on purpose. The complete bearer set is validated before the first
// `activateUe` is called and every call is therefore infallible, so the
// readiness seam is the boundary between that validation and the first
// activation rather than a point between two activations — there is no
// half-activated state for a rollback to have to reach.
class ArrivalFaultInjector
{
  public:
    enum class Fault : uint8_t
    {
        NONE,
        // Fail inside the registry promotion at the reached-index publication,
        // so the registry rolls itself back and the arrival never sees a
        // reached context.
        REGISTRY_PUBLICATION,
        // Fail after the promotion and after the whole bearer set has been
        // validated as ready, but before any bearer is activated. The arrival
        // demotes the context back to provisional and nothing forwards.
        BEARER_READINESS
    };

    constexpr ArrivalFaultInjector() = default;
    constexpr explicit ArrivalFaultInjector(Fault fault) : m_fault(fault)
    {
    }

    [[nodiscard]] constexpr Fault fault() const
    {
        return m_fault;
    }
    [[nodiscard]] constexpr bool firesAt(Fault point) const
    {
        return m_fault != Fault::NONE && m_fault == point;
    }

  private:
    Fault m_fault{Fault::NONE};
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

    // Accepts one simulated target arrival and, when every condition holds,
    // promotes the prepared context into the reached-UE registry.
    //
    // This is the only way a provisional context becomes a reached UE, and it is
    // driven by what arrived on the target's real radio receive path rather than
    // by anything a caller asserts. The correlation is the whole of the
    // evidence contract: the arrival binding resolves to exactly one committed
    // preparation of this association epoch, the source and target cells the UE
    // named are the ones that preparation was admitted between, the PDN address
    // is the one the source authorised, and the radio identity and endpoint the
    // UE arrived under are unused and unowned.
    //
    // On success the registry becomes the sole owner of the prepared bearers,
    // S1AP identifiers and local S1-U TEIDs, and the record keeps none of them.
    // On failure nothing has moved: the context is still provisional, still
    // non-forwardable and still owned here, and `failure` names the condition
    // that refused it. A failure that lands after the promotion has begun puts
    // the context back to provisional before returning, so no half-promoted
    // context is ever left behind.
    //
    // A repeat of an arrival whose binding has already been consumed is
    // refused and cannot reach a second context, a second TEID set or a second
    // Notify.
    bool acceptArrival(const TargetArrivalEvidence &evidence, VerifiedTargetArrival *verified = nullptr,
                       ArrivalRefusalRecord *failure = nullptr, const ArrivalFaultInjector &faults = {});

    // The preparation, if any, that issued this arrival binding. It answers for
    // committed preparations whether or not they have been reached, so a spent
    // binding is still recognisable as spent rather than as unknown.
    [[nodiscard]] const PreparationRecord *findByArrivalToken(uint32_t arrivalToken) const;

    // The authoritative permission to send one Handover Notify for this
    // transaction, and the send itself.
    //
    // The gate is not the codec. `EncodeHandoverNotify` remains a codec that
    // builds a message for anyone who asks; this is the only thing that says a
    // particular handover has reached the point where the target may tell the
    // MME the UE arrived. Every one of the twelve conditions is checked before
    // a byte is built, and the message's identities and cell come from what the
    // transaction actually bound rather than from what the caller passed.
    //
    // `sender` is the production S1AP send binding. A test passes an isolated
    // implementation of it; nothing here contacts a live MME on its own. A send
    // that does not complete is reported as unsuccessful and is not recorded as
    // a notification, so a later attempt is still possible and a duplicate
    // arrival still cannot produce a second successful one.
    HandoverNotifyOutcome notify(const HandoverTransactionId &id, const EnbIdentity &actualTargetCell,
                                 IS1apSender &sender, uint16_t stream);

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
    //
    // A record whose ownership has been transferred to the reached-UE registry
    // owns nothing and this does nothing to it: a reached UE is not preparation
    // state, and preparation cleanup — cancellation, expiry, a second
    // cancellation or this owner's own destruction — must never destroy one or
    // retire its current TEIDs. The record keeps its state, including a
    // `TARGET_REACHED` or `NOTIFY_SENT` name, because neither is a terminal
    // failure.
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
