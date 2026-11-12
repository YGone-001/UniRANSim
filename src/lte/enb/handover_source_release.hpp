//
// This file is a part of UERANSIM project.
// Copyright (c) 2027 ALİ GÜNGÖR.
//
// https://github.com/aligungr/UERANSIM/
// See README, LICENSE, and CONTRIBUTING files for licensing details.
//

// Phase 18-E: the handover-specific release of a source eNB's UE context.
//
// An eNB's ordinary S1 release is an ECM-IDLE transition. `UeRegistry::releaseS1`
// retires the access transport, retains the logical EPS bearer contexts, moves
// the entry to IDLE_RETAINED and tells the UE through S1_CONTEXT_RELEASED that
// the access it is on has ended. That is right for an idle release and wrong
// for a completed handover: the UE is already connected to the target, and a
// stale "your access ended" notification from the cell it left is not a fact
// about the UE's current access at all.
//
// So this module is the second semantics, and it is deliberately separate:
//
//   ordinary release     retains the session, tells the UE, keeps the entry
//   handover release     retires the transport, keeps nothing, tells the UE nothing
//
// What authorizes the second one is never a Cause field on its own. The source
// eNB must hold its own record of having commanded this UE into this handover,
// and the isolated MME must have installed a release decision it can only build
// after the SGW's installed mapping was confirmed. The cause is a corroborating
// statement, not an authorization.

#pragma once

#include <array>
#include <chrono>
#include <cstdint>
#include <optional>
#include <string>
#include <vector>

#include "codec.hpp"
#include "handover_preparation.hpp"

namespace lte::enb
{
class EnbMultiplexer;
struct EnbUeEntry;
class UeRegistry;
} // namespace lte::enb

namespace lte::enb::s1ap
{

enum class ExecutionMode : uint8_t;
enum class OrchestrationState : uint8_t;

class HandoverCoordinator;
struct CoordinationRecord;

// TS 36.413 section 9.2.1.3, radioNetwork cause 2. It is the cause an MME
// states when it releases a source context because a handover succeeded.
constexpr int CauseSuccessfulHandover = 2;

// Whether a decoded UE Context Release Command states the successful-handover
// release. It answers only what the message says; on its own it authorizes
// nothing, and the source never acts on it without its own record and the
// MME's installed decision agreeing.
bool IsSuccessfulHandoverReleaseCause(const UeContextReleaseCommand &command);

// --- What the source eNB knows about a handover it executed --------------

// The source's own record that it handed this UE to this target. It is written
// when the source's production radio sender delivers the command and by nothing
// else, so a cell that never commanded a UE holds no such record and a Release
// Command cannot invent one.
struct HandoverSourceRecord
{
    HandoverTransactionId transaction;
    uint32_t radioUeId{};
    uint32_t enbUeS1apId{};
    uint32_t mmeUeS1apId{};
    uint32_t accessGeneration{};
    uint64_t associationEpoch{};
    EnbIdentity target;
};

// What the isolated MME installs on the source when it decides the UE may be
// released. Every field is read from the live source session and the confirmed
// core path; none of it is derived from the Release Command.
//
// The constructor is private and the only factory is
// `BuildHandoverSourceReleaseDecision`, so a caller cannot assemble one out of
// fields it chose and then assert that it is verified.
class HandoverSourceReleaseDecision
{
  public:
    HandoverTransactionId transaction;
    uint32_t enbUeS1apId{};
    uint32_t mmeUeS1apId{};
    uint32_t radioUeId{};
    uint32_t accessGeneration{};
    // The source S1-MME association the handover began under.
    uint64_t associationEpoch{};
    // The generation of the isolated SGW's installed mapping that was confirmed
    // before this decision existed. Zero means no core update was confirmed and
    // the decision could not have been built.
    uint64_t corePathGeneration{};
    // The target cell the UE moved to, and that cell's own S1-U address.
    EnbIdentity target;
    std::array<uint8_t, 4> targetS1uAddress{};
    // The source's own local S1-U TEIDs at the time of the decision. They are
    // named so the release retires exactly these and a decision that names
    // another UE's transport is refused.
    uint32_t defaultTeid{};
    std::vector<uint32_t> dedicatedTeids;

    // A default-constructed decision authorizes nothing: \`m_verified\` is only
    // ever set by the factory, so an empty one is a value an out-parameter can
    // be left in, not an authorization anyone can produce by assembling fields.
    HandoverSourceReleaseDecision() = default;

    [[nodiscard]] bool isVerified() const { return m_verified; }

  private:
    bool m_verified{};

    friend HandoverSourceReleaseDecision BuildHandoverSourceReleaseDecision(const CoordinationRecord &record,
                                                                            uint64_t corePathGeneration);
};

// Builds the release decision for a transaction whose isolated core path was
// confirmed. It refuses — by throwing — when the record has not reached that
// point: a decision is only ever a statement about a UE that really moved.
HandoverSourceReleaseDecision BuildHandoverSourceReleaseDecision(const CoordinationRecord &record,
                                                                 uint64_t corePathGeneration);

// --- Refusals --------------------------------------------------------------

enum class SourceReleaseRefusal : uint8_t
{
    // The process is attached to a live EPC. Nothing here may act.
    LIVE_MODE_DISABLED,
    // The message does not state the successful-handover release.
    NOT_A_HANDOVER_RELEASE,
    // The source holds no record of having commanded this UE into a handover.
    NO_PENDING_HANDOVER,
    // The MME installed no verified release decision for this transaction.
    NO_VERIFIED_DECISION,
    // The entry the command names is not the UE the transaction moved.
    WRONG_UE_CONTEXT,
    // The identity pair the command names is not the transaction's.
    IDENTITY_MISMATCH,
    // The source's access generation moved since the handover began.
    SOURCE_GENERATION_CHANGED,
    // The source S1-MME association is no longer the one the handover began under.
    STALE_ASSOCIATION,
    // No confirmed core path update stands behind the decision.
    CORE_PATH_NOT_CONFIRMED,
    // The decision and the live context disagree on the transport to retire.
    TRANSPORT_MISMATCH,
    // The transaction is not at the point where this step may run.
    WRONG_STATE,
    // The source-release guard has not been satisfied yet.
    RELEASE_GUARD_NOT_SATISFIED,
    // The source eNB refused the command. Nothing was released.
    SOURCE_REFUSED,
    // The encode, the send or the decode failed.
    TRANSPORT_FAILED,
    // The Release Complete does not match the transaction.
    COMPLETE_MISMATCH,
    // The context was not released and no evidence says it was.
    RELEASE_NOT_CONFIRMED,
    // The source's state cannot be reconciled with the transaction.
    RECONCILIATION_FAILED
};

const char *ToString(SourceReleaseRefusal refusal);

struct SourceReleaseRefusalRecord
{
    SourceReleaseRefusal refusal{SourceReleaseRefusal::RELEASE_NOT_CONFIRMED};
    std::string detail;
};

// --- What a handover release actually did --------------------------------

struct HandoverSourceReleaseResult
{
    bool released{};
    std::vector<uint32_t> retiredTeids;
    std::optional<SourceReleaseRefusalRecord> refusal;
};

// The verified, handover-specific release of one source context.
//
// It retires the source's bound local S1-U TEIDs, erases its S1AP identifier
// mappings, releases the EPS bearer contexts and removes the radio ownership it
// held, and it sends nothing to the UE. It refuses a context that is not the one
// the decision names, a decision that is not verified, and a transport that has
// moved since the decision was made.
//
// A target context is a different registry's entry and is never reachable from
// here; two eNBs do not share a registry, and an identifier that happens to be
// equal in both is two identifiers.
HandoverSourceReleaseResult ReleaseHandoverSourceContext(const HandoverSourceReleaseDecision &decision,
                                                         UeRegistry &registry, uint64_t liveAssociationEpoch,
                                                         SourceReleaseRefusalRecord *failure = nullptr);

// Verifies that a Release Command may take the handover path at all, and returns
// the decision it relies on. It is the source's whole gate: the entry must still
// be the UE the transaction moved, the source must still hold its own record of
// the handover, and the MME's installed decision must name the same transaction,
// identity pair, access generation, association epoch and transport.
bool VerifyHandoverSourceRelease(const EnbUeEntry &entry, uint64_t liveAssociationEpoch,
                                 const UeContextReleaseCommand &command,
                                 const std::vector<HandoverSourceRecord> &records,
                                 const std::vector<HandoverSourceReleaseDecision> &decisions,
                                 HandoverSourceReleaseDecision *accepted,
                                 SourceReleaseRefusalRecord *failure);

// --- The isolated MME's release steps ------------------------------------

// How a release came to be believed. A received Complete and a reconciled
// registry state are different evidence and are never reported as one.
enum class SourceReleaseEvidence : uint8_t
{
    NONE,
    RELEASE_COMPLETE,
    RECONCILED_REGISTRY
};

// What the isolated MME holds about the release of one source context.
struct SourceReleaseTransaction
{
    bool waitArmed{};
    std::chrono::steady_clock::time_point notBefore{};
    bool commandSent{};
    std::vector<uint8_t> commandPdu;
    std::vector<uint8_t> completePdu;
    SourceReleaseEvidence evidence{SourceReleaseEvidence::NONE};
    std::vector<uint32_t> retiredTeids;
};

// What one release step produced.
struct SourceReleaseStepOutcome
{
    bool sent{};
    bool confirmed{};
    bool reconciled{};
    std::optional<OrchestrationState> state;
    std::optional<SourceReleaseRefusalRecord> refusal;
    std::string detail;
};

// Arms the bounded guard that stands between a confirmed core update and the
// source release. It is an explicit event with a deterministic deadline, not a
// timer: a caller reads the clock and says when the release becomes due.
bool EnterSourceReleaseWait(HandoverCoordinator &coordinator, const HandoverTransactionId &transaction,
                            std::chrono::steady_clock::time_point now, std::chrono::milliseconds guard,
                            SourceReleaseRefusalRecord *failure);

// Whether the guard has been satisfied. It is true only for a transaction that
// is waiting and whose deadline has passed.
bool SourceReleaseGuardSatisfied(const CoordinationRecord &record, std::chrono::steady_clock::time_point now);

// Encodes a real UE Context Release Command, installs the verified decision on
// the source, and delivers the bytes through the source's own production S1AP
// receive path. A send is not a release.
SourceReleaseStepOutcome SendSourceReleaseCommand(HandoverCoordinator &coordinator, EnbMultiplexer &source,
                                                  const HandoverTransactionId &transaction,
                                                  std::chrono::steady_clock::time_point now);

// Decodes the source's answer and, when it names exactly this transaction's
// identity pair, records the confirmation. A duplicate or mismatched Complete
// is refused rather than counted twice.
SourceReleaseStepOutcome AcceptSourceReleaseComplete(HandoverCoordinator &coordinator,
                                                     const HandoverTransactionId &transaction,
                                                     const std::vector<uint8_t> &pdu);

// Reads the source's own registry after a release whose answer was never
// observed. It confirms only when the context is gone and every TEID the
// decision named is recorded as retired; anything else stays unconfirmed and is
// reported as uncertain.
SourceReleaseStepOutcome ReconcileSourceRelease(HandoverCoordinator &coordinator, EnbMultiplexer &source,
                                                const HandoverTransactionId &transaction,
                                                std::chrono::steady_clock::time_point now);

} // namespace lte::enb::s1ap
