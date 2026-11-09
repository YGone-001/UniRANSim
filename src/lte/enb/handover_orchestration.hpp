//
// This file is a part of UERANSIM project.
// Copyright (c) 2027 ALİ GÜNGÖR.
//
// https://github.com/aligungr/UERANSIM/
// See README, LICENSE, and CONTRIBUTING files for licensing details.
//

// Phase 18-D: the trusted coordination contract between a source eNB that has
// decided to hand a UE over and the target eNB that has prepared resources for
// it. It exists because the S1AP Handover Request carries no source eNB
// identity a target could verify, and the target's MME-facing SCTP association
// names the MME and not the source. Everything this module asserts about a
// source therefore comes from the source's own live UE registry, and nothing
// here is reachable from a raw S1AP dispatcher: the live dispatcher still
// refuses to start a preparation on a guessed source.
//
// The coordination channel is an explicitly enabled, isolated, in-process
// mechanism between two components the simulator owns. It is not an
// authenticated channel. A sequential arrival token is a correlation value and
// never a credential, and nothing here is described as cryptographically
// authenticated. Live use is refused.

#pragma once

#include <array>
#include <chrono>
#include <cstdint>
#include <map>
#include <optional>
#include <stdexcept>
#include <string>
#include <vector>

#include <utils/network.hpp>

#include "codec.hpp"
#include "handover_admission.hpp"
#include "handover_preparation.hpp"
#include "multiplexer.hpp"
#include "types.hpp"
#include "user_plane.hpp"

namespace lte::enb
{
class EnbUeEntry;
class EnbMultiplexer;
}

namespace lte::enb::s1ap
{

// Which kind of network this coordination is allowed to act on. The two are
// not interchangeable and a running process never moves between them on its
// own: a handover message that cannot be decoded is a reason to refuse one,
// never a reason to fall back from the live mode to the simulator one.
enum class ExecutionMode : uint8_t
{
    // A deliberately enabled, scoped two-eNB coordinator inside the simulator.
    // This is the only mode in which anything here acts.
    ISOLATED_SIMULATOR = 0,
    // A process attached to a real EPC. Every entry point here refuses, and a
    // real target-generated RRC container is unavailable, so live S1AP handover
    // execution stays disabled.
    LIVE_EPC = 1
};

const char *ToString(ExecutionMode mode);

// Why coordination was refused. Every one of these leaves the transaction, the
// source UE and the target preparation exactly as they were.
enum class CoordinationRefusal : uint8_t
{
    // The process is attached to a live EPC. Nothing here may act.
    LIVE_MODE_DISABLED,
    // The source session could not be established from the source registry.
    SOURCE_PROVENANCE_NOT_ESTABLISHED,
    // No configured target is permitted for this source.
    NO_AUTHORIZED_TARGET,
    // The named target is not the one this source is permitted to reach.
    TARGET_NOT_PERMITTED,
    // The named target is not currently ready to be selected.
    TARGET_NOT_READY,
    // The association epochs of either side are not the current ones.
    STALE_ASSOCIATION_EPOCH,
    // A transaction already exists for this source UE.
    CONFLICTING_HANDOVER_PENDING,
    // The transaction does not exist, or is not in the state this step needs.
    WRONG_TRANSACTION_STATE,
    // The transaction has passed its expiry.
    TRANSACTION_EXPIRED,
    // The transaction has been cancelled.
    TRANSACTION_CANCELLED,
    // The coordination record does not bind what this step needs.
    INCOMPLETE_COORDINATION_RECORD
};

const char *ToString(CoordinationRefusal refusal);

// Raised when a source session cannot be established from the source's own
// registry. It is deliberately a hard failure rather than a partial record: a
// caller that cannot prove source ownership gets nothing, not a plausible
// session assembled from whatever fields happened to be set.
class SourceProvenanceError : public std::runtime_error
{
  public:
    explicit SourceProvenanceError(const std::string &why)
        : std::runtime_error(std::string("SOURCE_PROVENANCE_NOT_ESTABLISHED: ") + why)
    {
    }
};

// A refusals are recorded with the reason a caller can report without
// re-deriving it.
struct CoordinationRefusalRecord
{
    CoordinationRefusal refusal{CoordinationRefusal::INCOMPLETE_COORDINATION_RECORD};
    std::string detail;
};

// The source eNB's own statement of the session being handed over.
//
// Every field is read out of one live `EnbUeEntry` and the source's own
// configuration. Nothing here is caller-supplied, and a partially established
// session is refused rather than filled in: an identity nobody confirmed is
// worse than no identity, because a target would treat it as verified.
struct SourceSession
{
    // 1/2. The source eNB's Global eNB ID and its selected tracking area, read
    // from the source's configuration.
    EnbIdentity sourceCell;
    EutranCgi sourceCgi;
    // 3. The S1-MME association epoch this session was established under. A
    // later association never carries a handover that began under an earlier
    // one.
    uint64_t associationEpoch{};
    // 4/5. The S1AP identity pair. Both are non-zero on a session that exists.
    uint32_t mmeUeS1apId{};
    uint32_t enbUeS1apId{};
    // 6/7. The simulated radio identity and the radio endpoint this UE is
    // actually reached on. A fabricated or provisional UE has neither.
    uint32_t radioUeId{};
    InetAddress radioPeer;
    // 8/9. The EPS session identity and the network-confirmed PDN address of
    // that session. The address is the one the UE's own NAS assigned and this
    // eNB has already validated; it is never a claim a frame restated.
    uint8_t defaultEbi{};
    std::array<uint8_t, 4> ueIpv4{};
    // 13. The access epoch the source is currently serving this UE on.
    uint32_t accessGeneration{};
    // 10/11/12. The default and dedicated bearer inventory with the roles, the
    // linked-default relationships, the QoS and the SGW transport of each. The
    // roles are the network's own statement of the EPS session and are never
    // inferred from QCI or from the order an E-RAB list happens to be in.
    std::vector<BearerRoleBinding> roles;
    std::vector<ErabToBeSetupItemHoReq> erabs;
    UeAmbr ueAmbr;

    // Whether this record is complete enough to name a source at all.
    //
    // It is deliberately not writable and the constructor is deliberately not
    // public. `ExtractSourceSession` is the only way a verified session comes
    // into existence, so a caller cannot assemble one out of fields it chose
    // and then assert that it is verified — which is exactly what setting
    // `SourceContext::identityKnown` by hand would be doing to the target's
    // admission. A copy of a verified session is still verified, because
    // nothing outside this class can reach the field to un-set it either.
    [[nodiscard]] bool isVerified() const { return verified; }

  private:
    SourceSession() = default;
    bool verified{false};

    friend SourceSession ExtractSourceSession(const EnbUeEntry &entry, const EnbIdentity &sourceCell,
                                              EutranCgi sourceCgi, uint64_t associationEpoch);
    friend struct CoordinationRecord;
};

// Reads the source session out of one live source-registry entry and the
// source's own cell identity. This is the only way a `SourceSession` comes into
// existence.
//
// Throws `SourceProvenanceError` — the `SOURCE_PROVENANCE_NOT_ESTABLISHED`
// failure the contract names — whenever any of the fourteen facts cannot be
// established from the registry. It never returns a partial record, and it
// never accepts a field a caller supplied in place of one the registry holds.
SourceSession ExtractSourceSession(const EnbUeEntry &entry, const EnbIdentity &sourceCell, EutranCgi sourceCgi,
                                   uint64_t associationEpoch);

// One explicitly configured, authorized target eNB. There is no discovery
// here: a target exists because the simulator was told about it, with the
// source it may be selected from. Nothing scans for one, nothing accepts an
// address a UE named, and a PLMN or TAC match on its own never selects one.
struct HandoverTargetBinding
{
    // 1. The target's identity: Global eNB ID with the PLMN, the eNB
    // identifier and the selected tracking area.
    EnbIdentity identity;
    // 2. The target's CGI and TAI, which must agree with the identity above.
    EutranCgi cgi;
    Tai tai;
    // 3. The actual simulated-radio receive endpoint the UE must be redirected
    // to. It is the only endpoint a UE is ever sent to, and no frame names one.
    InetAddress radioEndpoint;
    // 4. The target's own S1-U endpoint, for the transport the commit binds.
    std::array<uint8_t, 4> s1uAddress{};
    // 4b. The algorithm set this target supports. It is this target's own
    // capability and is compared against the UE capabilities the MME sent, so a
    // handover is refused here rather than by a guess at what the target could
    // run. Neither side of that comparison is generated anywhere in this
    // repository.
    std::array<uint8_t, 2> encryptionAlgorithms{};
    std::array<uint8_t, 2> integrityAlgorithms{};
    // 5/6. Which simulator session this target is, and the association epoch
    // that session is currently bound under.
    uint64_t associationEpoch{};
    // 7. The explicit permitted source/target pairing. A target is only
    // selectable from a source whose identity this names.
    EnbIdentity permittedSource;
    // 8. Current readiness. An unready target is refused rather than selected
    // and then found wanting later.
    bool ready{};
};

// The transaction-level orchestration state. Each value has exactly one
// authoritative event, and nothing here advances because a timer elapsed, a
// deadline passed or a test helper set a flag.
enum class OrchestrationState : uint8_t
{
    // A verified source session exists and nothing has been asked of anyone.
    SOURCE_CONNECTED,
    // Handover Required has been produced from the verified source session and
    // delivered to the relay.
    HANDOVER_PREPARING,
    // The target has admitted and committed real resources and produced a
    // Handover Request Acknowledge. Nothing has been sent to the UE.
    TARGET_PREPARED,
    // The Handover Command has been verified against the live source session
    // and the simulated handover command is being delivered to the UE.
    SOURCE_COMMAND_PENDING,
    // The UE has been commanded and its radio transport redirected. The UE is
    // between two accesses of one ECM connection and no Attach and no Service
    // Request may be started on its behalf.
    UE_RELOCATION_PENDING,
    // The target has verified the arrival and promoted its provisional context.
    TARGET_ARRIVAL_CONFIRMED,
    // The Handover Notify has been built behind the accepted gate and handed to
    // the association. It is never a core path update.
    HANDOVER_NOTIFY_SENT,
    // The deliberately final state of this phase. The MME-controlled downlink
    // bearer path update and the source context release are later work and are
    // not performed here, so nothing in this phase ever reports an end-to-end
    // completed handover.
    AWAITING_CORE_PATH_UPDATE,
    // Preparation refused or rolled back before any UE was moved.
    PREPARATION_FAILED,
    // The UE move failed after preparation succeeded. Whatever the outcome of
    // the rollback, this is not a success.
    EXECUTION_FAILED,
    // Cancelled before the UE moved.
    CANCELLED
};

const char *ToString(OrchestrationState state);

// Whether a state is terminal. A terminal state never advances again and its
// record never authorizes anything.
bool IsTerminal(OrchestrationState state);

// What one authoritative event does to a transaction. Returns the state the
// transaction is in after the event, or nothing when the event does not apply
// to the state the transaction is in — which is the caller's signal to refuse
// rather than to advance.
//
// A duplicate event is idempotent where that is meaningful: an event that names
// the state the transaction is already in leaves it there. An event that would
// move a terminal state is refused rather than silently reopening it.
std::optional<OrchestrationState> ApplyOrchestrationEvent(OrchestrationState state, OrchestrationState event);

// Everything the coordination channel binds for one handover transaction. The
// nine bindings are all here, and a record missing any of them authorizes
// nothing.
struct CoordinationRecord
{
    // 3. The exact target preparation transaction. Its identity carries the
    // MME-UE-S1AP-ID and the association epoch.
    HandoverTransactionId transaction;
    // 1. The verified source session. Nothing may take its place.
    SourceSession source;
    // 2. The verified target identity.
    EnbIdentity target;
    // 4. The MME's identity for this UE, stated again so the two halves of the
    // binding can be compared independently.
    uint32_t mmeUeS1apId{};
    // 5. The target preparation's arrival binding. A correlation value and not
    // a credential.
    uint32_t arrivalToken{};
    // 6. The association epochs of both sides at the time the record was made.
    uint64_t sourceAssociationEpoch{};
    uint64_t targetAssociationEpoch{};
    // 7. The target radio endpoint the UE must be sent to.
    InetAddress targetRadioEndpoint;
    // 8. The verified PDN address, cross-checked against the source session and
    // again against whatever the UE's arrival restates.
    std::array<uint8_t, 4> pdnAddress{};
    // 9. Expiration and cancellation.
    std::chrono::steady_clock::time_point expiresAt{std::chrono::steady_clock::time_point::max()};
    bool cancelled{};

    OrchestrationState state{OrchestrationState::SOURCE_CONNECTED};

    // Whether this record is complete in all nine bindings. An incomplete
    // record is refused by every step rather than used with a hole in it.
    [[nodiscard]] bool complete() const;

    // Whether this record binds everything a preparation hop needs to build a
    // Handover Request, and nothing that hop produces. The arrival token and
    // the preparation's own transaction identity are deliberately absent:
    // binding them is what the hop does, so a record that already carried one
    // could not be the record a preparation is being made for. Every step
    // after the preparation still asks for `complete()`.
    [[nodiscard]] bool completeForPreparation() const;
};

// The coordinator is declared further down; the relay below only ever holds a
// reference to one.
class HandoverCoordinator;

// --- Simulator-only handover containers ------------------------------------
// The label a simulator-generated handover container starts with. It is ASCII
// and it is deliberately not anything a real RRC message begins with, so a
// container carrying it can never be mistaken for one. Nothing in this
// repository claims this is 3GPP RRC, nothing places it in a transparent
// container destined for an MME, and the target treats it as opaque bytes.
constexpr std::array<uint8_t, 8> SimulatedContainerLabel{'S', 'I', 'M', '-', 'H', 'O', 'v', '1'};

// Builds the distinctly labelled Source-To-Target container of a simulated
// handover. It names the session it belongs to and nothing else: an opaque
// container is not authority to invent security or RRC content.
TransparentContainer BuildSimulatedSourceToTarget(uint32_t mmeUeS1apId, uint32_t enbUeS1apId,
                                                  const std::array<uint8_t, 4> &ueIpv4);

// Whether a container carries the simulator label. Used to show what was built
// and what was preserved; nothing here ever parses a container past its label.
[[nodiscard]] bool IsSimulatedContainer(const TransparentContainer &container);

// --- Source-side generation -----------------------------------------------

// TS 36.413 §9.2.1.3 radio network cause values a source may state as its own
// reason for asking for a handover. Which one applies is the source's decision
// and this module never picks one.
constexpr int CauseHandoverDesirableForRadioReasons = 1;
constexpr int CauseReduceLoadInServingCell = 3;

// The Handover Required the source's own production codec builds from a
// verified session and the one target the coordinator authorized. The cause is
// stated by the caller: a reason for a handover is a decision, not a detail to
// fill in silently. The message is refused rather than built when the session
// is not verified, when the target is the serving cell, or when the cause does
// not name one the codec can put on the wire.
bool BuildHandoverRequired(const SourceSession &session, const EnbIdentity &target, const std::string &causeCategory,
                           int causeValue, HandoverRequired *required, CoordinationRefusalRecord *failure);

// --- Source-side Handover Command handling --------------------------------

// Why the source refused to hand a Handover Command to its UE. Every one of
// these leaves the source UE, its bearers and its transport exactly as they
// were, and none of them is a reason to release anything: a refusal at this
// gate is a refusal to move the UE and nothing more.
enum class CommandRefusal : uint8_t
{
    // The process is attached to a live EPC. Nothing here may act.
    LIVE_MODE_DISABLED,
    // There is no reached UE on this entry. A provisional or fabricated context
    // is never commanded.
    NOT_A_REACHED_UE,
    // The source UE is not in an S1 connection that could carry a handover.
    UE_NOT_CONNECTED,
    // The Handover Command names a different UE than the source is serving.
    WRONG_COMMAND_UE_IDENTITY,
    // The source entry no longer holds the S1AP identifiers the preparation
    // was made for.
    S1AP_IDENTITY_CHANGED,
    // The source access epoch moved on since the preparation was made.
    SESSION_CHANGED,
    // The source S1-MME association is no longer the one the record names.
    ASSOCIATION_EPOCH_CHANGED,
    // The target this record names is no longer the approved one.
    TARGET_NOT_APPROVED,
    // The record binds no arrival token, so nothing can be correlated at the
    // target.
    ARRIVAL_TOKEN_MISSING,
    // The target has not established committed resources for this transaction.
    NO_COMMITTED_RESOURCES,
    // The target has no radio endpoint the UE could be redirected to.
    TARGET_ENDPOINT_UNAVAILABLE,
    // The UE has already been commanded and is already executing a handover.
    HANDOVER_ALREADY_EXECUTING,
    // The transaction does not exist or is not in the state this step needs.
    WRONG_TRANSACTION_STATE,
    // The transaction has passed its expiry.
    TRANSACTION_EXPIRED,
    // The transaction has been cancelled.
    TRANSACTION_CANCELLED,
    // The record does not bind what this step needs.
    INCOMPLETE_COORDINATION_RECORD
};

const char *ToString(CommandRefusal refusal);

// What one delivery attempt reports. `delivered` is true only when the frame
// reached the source's production radio sender; the source's own bearer
// resources, its S1-U TEIDs and its S1 connection are untouched either way.
struct CommandDelivery
{
    bool delivered{false};
    // The frame the production radio path actually sent. Empty of meaning when
    // `delivered` is false.
    lte::ue::link::SimulatedHandoverCommand command;
    std::optional<CoordinationRefusalRecord> refusal;
};

// Verifies an authorized Handover Command against the live source session and,
// only if every check passes, hands the corresponding simulated handover
// command to the UE through the source's existing production radio sender.
//
// The checks are the source's whole gate: the UE is still the one the
// preparation was made for and is still connected; the S1AP identifiers and the
// access and association epochs have not moved; the target is still the
// approved one and still has a radio endpoint; the record binds the arrival
// token and the target has committed resources behind it; and the UE is not
// already executing another handover.
//
// A refusal moves nothing. In particular it does not release a bearer, does not
// retire a TEID, does not drop the source to ECM-IDLE and does not start an
// Attach or a Service Request.
CommandDelivery DeliverHandoverCommand(EnbMultiplexer &source, EnbUeEntry &entry, HandoverCoordinator &coordinator,
                                       const HandoverTransactionId &transaction, const HandoverCommand &command,
                                       const HandoverTargetBinding &targetBinding);

// --- The isolated MME simulator -------------------------------------------

// What the isolated MME simulator states about a UE's security. Both halves are
// MME signalling content and are carried through the relay, never generated,
// never defaulted and never logged: this simulator has no authority to derive a
// key and neither does anything else in this repository.
struct IsolatedUeSecurity
{
    // The UE's NAS security capabilities as the MME reported them. Compared
    // against the target's own supported set before admission.
    std::array<uint8_t, 2> encryptionAlgorithms{};
    std::array<uint8_t, 2> integrityAlgorithms{};
    // The handover security material carried in the Handover Request.
    SecurityContext context;
};

// Everything one relayed preparation produced. The PDU fields hold the real
// S1AP bytes in the order they crossed the relay, so a test can show the
// exchange is the accepted codec's rather than a set of method calls.
struct PreparationHop
{
    bool delivered{false};
    std::vector<uint8_t> requiredPdu;
    std::vector<uint8_t> requestPdu;
    std::vector<uint8_t> acknowledgePdu;
    // The Handover Command for the source. Empty when the hop refused.
    std::vector<uint8_t> commandPdu;
    // The Handover Preparation Failure for the source instead, when it refused.
    std::vector<uint8_t> failurePdu;
    HandoverTransactionId transaction;
    uint32_t arrivalToken{};
    std::optional<CoordinationRefusalRecord> coordinationFailure;
    std::optional<CommitRefusalRecord> targetFailure;
};

// The isolated, deterministic MME simulator of this stage.
//
// It is a transport between two eNBs the simulator owns and nothing more. Every
// message that crosses it is a real encoded S1AP PDU produced and consumed by
// the accepted production codec, so nothing here turns a message into a method
// call to get around the codec. What it is not is an MME: it holds no
// subscriber state, it derives nothing, it never tells a real core network
// anything, and it refuses to run at all outside the isolated simulator mode.
//
// The one place it speaks to a target's production entry point directly is the
// Handover Request, because that message is exactly where the trust contract
// does not permit the raw S1AP dispatcher to act: a Handover Request arriving
// over S1AP still fails closed there. This relay can start a preparation only
// because the coordinator has already established the source provenance that
// dispatcher has no way to establish.
class IsolatedMmeRelay
{
  public:
    explicit IsolatedMmeRelay(HandoverCoordinator &coordinator);

    [[nodiscard]] HandoverCoordinator &coordinator() { return m_coordinator; }
    [[nodiscard]] const HandoverCoordinator &coordinator() const { return m_coordinator; }

    // One complete preparation hop.
    //
    // `requiredPdu` is the encoded Handover Required the source's production
    // codec produced, `transaction` names the coordinator record that already
    // holds the verified source session and the authorized target, and
    // `targetBinding` is that same authorized target. The relay decodes the
    // Required, checks that it names exactly that target and that UE, builds
    // the Handover Request out of the record and the message, encodes it and
    // decodes it again on the way into the target's real preparation entry
    // point. The Acknowledge that comes back is encoded and decoded the same
    // way before it becomes the Handover Command for the source.
    //
    // The target's arrival token is bound into the coordinator record here, by
    // the component that actually learned it, and is reported so the source can
    // put it in the simulated handover command.
    PreparationHop relayPreparation(const std::vector<uint8_t> &requiredPdu, const HandoverTransactionId &transaction,
                                    const HandoverTargetBinding &targetBinding, const IsolatedUeSecurity &security,
                                    EnbMultiplexer &target, uint64_t targetAssociationEpoch);

    // Records that the target's verified arrival gate accepted the UE.
    //
    // The evidence is read out of the target itself: the arrival its
    // production radio receive path accepted and nothing else. A caller has no
    // way to supply one, so nothing but a real accepted arrival — the one
    // `HandoverPreparationOwner::acceptArrival` produces — moves a transaction
    // to TARGET_ARRIVAL_CONFIRMED. Not a decoded Handover Request, not a
    // committed resource set, not a datagram on a socket and not a Boolean.
    //
    // The evidence is then checked against what this record already binds: the
    // arrival token, both cell identities and the PDN address must agree, so a
    // UE cannot be confirmed by restating a session it is not part of and an
    // address mismatch stops the confirmation rather than becoming the
    // authority for a forwardable bearer. A transaction that has not been
    // commanded and relocated is refused as well, so this cannot skip a step.
    // A repeat of the same confirmation is the same event and moves nothing.
    bool confirmTargetArrival(EnbMultiplexer &target, CoordinationRefusalRecord *failure);

    // Records the target's Handover Notify and moves the transaction to
    // AWAITING_CORE_PATH_UPDATE. That state is the deliberate end of this
    // phase: the MME-controlled downlink bearer path update and the source
    // context release are later work, and nothing here performs or reports
    // them. An already-notified transaction is a duplicate and is idempotent.
    bool acceptHandoverNotify(const std::vector<uint8_t> &notifyPdu, const HandoverTransactionId &transaction,
                              CoordinationRefusalRecord *failure);

    // One eNB-facing side of this isolated MME. Each eNB binds its association
    // to one of these and transmits real S1AP PDUs into it exactly as it would
    // to a real MME's SCTP endpoint. This is not a test stub that discards
    // bytes: every PDU handed in is recorded and given to the relay, which
    // decodes it with the production codec and acts on what it understands.
    // Anything it does not understand is recorded and refused rather than
    // guessed at.
    class Endpoint : public IS1apSender
    {
      public:
        Endpoint(IsolatedMmeRelay &relay, bool targetSide);
        void sendS1ap(uint16_t stream, const std::vector<uint8_t> &pdu) override;

        // Every PDU this endpoint received, in arrival order.
        [[nodiscard]] const std::vector<std::vector<uint8_t>> &received() const { return m_received; }
        [[nodiscard]] bool targetSide() const { return m_targetSide; }

      private:
        IsolatedMmeRelay &m_relay;
        bool m_targetSide;
        std::vector<std::vector<uint8_t>> m_received;
    };

    // One PDU arriving at the isolated MME from one of its endpoints.
    // `fromTarget` says which side sent it and is the only routing information
    // the relay uses: a Handover Notify from anywhere but the target is
    // refused.
    void onUplink(bool fromTarget, const std::vector<uint8_t> &pdu, CoordinationRefusalRecord *failure);

    // Why the most recent uplink was refused, when one was.
    [[nodiscard]] const std::optional<CoordinationRefusalRecord> &lastRefusal() const { return m_lastRefusal; }

  private:
    HandoverCoordinator &m_coordinator;
    std::optional<CoordinationRefusalRecord> m_lastRefusal;
    uint32_t m_lastNotifiedMmeUeS1apId{};
};

// The coordinator: the one owner of the transaction-level state and of the
// records that authorize a handover. It is production-owned and it is what the
// isolated two-eNB orchestration runs through, but it is not reachable from the
// live S1AP dispatcher and never from an uncontrolled peer.
class HandoverCoordinator
{
  public:
    explicit HandoverCoordinator(ExecutionMode mode);

    [[nodiscard]] ExecutionMode mode() const { return m_mode; }
    // Whether anything here may act at all. Only the isolated simulator mode
    // does; a live EPC process refuses every entry point.
    [[nodiscard]] bool enabled() const { return m_mode == ExecutionMode::ISOLATED_SIMULATOR; }

    // Opens a transaction for a verified source session and an authorized
    // target. Refuses, and states why, when the mode is live, when the source
    // session is not verified, when the named target is not permitted for this
    // source or is not ready, when either association epoch is stale, or when a
    // transaction for this source UE already exists.
    bool openTransaction(const SourceSession &source, const HandoverTargetBinding &target, uint32_t mmeUeS1apId,
                         uint64_t sourceAssociationEpoch, uint64_t targetAssociationEpoch,
                         std::chrono::steady_clock::duration lifetime, CoordinationRecord *record,
                         CoordinationRefusalRecord *failure);

    // Attaches the target preparation's arrival binding and transaction
    // identity to an open record. Without these the record is incomplete and
    // authorizes nothing.
    //
    // The record is addressed by the MME's identity for the UE, which is what
    // the two halves of the binding already agree on. The preparation's
    // transaction identity is the one it replaces the coordinator's
    // provisional identity with, so it cannot also be the lookup key: the two
    // carry different association epochs and would never match. A preparation
    // under another target association epoch is stale, and a repeat that
    // disagrees with a live binding is a conflicting duplicate rather than a
    // second token for the same transaction.
    bool bindPreparation(const HandoverTransactionId &transaction, uint32_t arrivalToken,
                         CoordinationRefusalRecord *failure);

    // Advances a transaction by one authoritative event. Refuses — and moves
    // nothing — when the transaction is absent, terminal, cancelled, expired,
    // or the event does not apply to its state.
    bool advance(const HandoverTransactionId &transaction, OrchestrationState event, CoordinationRefusalRecord *failure);

    // Looks a record up by transaction. Returns null when there is none, and
    // never a cancelled or expired one: those authorize nothing and are not
    // handed out as if they did.
    [[nodiscard]] const CoordinationRecord *find(const HandoverTransactionId &transaction) const;
    CoordinationRecord *findMutable(const HandoverTransactionId &transaction);

    // The same lookup by the MME's identity for the UE, which is what a message
    // arriving with no transaction to name carries. It obeys the same rule: a
    // cancelled or expired record is not handed out.
    [[nodiscard]] const CoordinationRecord *findByMmeUeS1apId(uint32_t mmeUeS1apId) const;

    // Cancels a transaction. Idempotent: cancelling a cancelled transaction
    // succeeds and cancels nothing a second time. A cancelled record is never
    // revived, exactly as a retired TEID is never revived.
    bool cancel(const HandoverTransactionId &transaction, CoordinationRefusalRecord *failure);

    // Expires every record past its deadline. Returns how many moved to
    // CANCELLED. Expiry is not an authorization and never has been: it is how a
    // record stops being usable.
    size_t expireDue(std::chrono::steady_clock::time_point now);

    [[nodiscard]] size_t size() const { return m_records.size(); }

    // Selects the one authorized target for a source session from the explicit
    // inventory. It is not discovery: nothing is scanned, no address a UE named
    // is consulted, and a target is only ever selected because this
    // configuration permitted exactly that pairing. Refuses and states why
    // otherwise.
    static bool SelectTarget(const SourceSession &source, const std::vector<HandoverTargetBinding> &inventory,
                             uint32_t targetEnbId, const HandoverTargetBinding *&selected,
                             CoordinationRefusalRecord *failure);

  private:
    ExecutionMode m_mode;
    // Keyed by MME-UE-S1AP-ID: one handover transaction per UE session at a
    // time, which is exactly the scope the failure matrix names. The
    // `HandoverTransactionId` inside the record is the one the target
    // preparation allocated and is what every other component addresses the
    // record by; it replaces the coordinator's provisional identifier when the
    // preparation is bound.
    std::map<uint32_t, CoordinationRecord> m_records;
    // The provisional sequence of the coordinator's own transaction identifier,
    // until the target preparation's identifier replaces it. It is the same
    // width as the field it fills, so nothing here can silently outgrow the
    // identifier it is being written into.
    uint32_t m_sequence{};
};

} // namespace lte::enb::s1ap
