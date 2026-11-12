//
// This file is a part of UERANSIM project.
// Copyright (c) 2027 ALİ GÜNGÖR.
//
// https://github.com/aligungr/UERANSIM/
// See README, LICENSE, and CONTRIBUTING files for licensing details.
//

// Phase 18-E: the isolated core side of a connected-mode handover.
//
// Phase 18-D ends at AWAITING_CORE_PATH_UPDATE because nothing updated a
// bearer path. This module is that update, and it is deliberately two things
// that are never conflated:
//
//   the MME's decision        a request the MME dispatches and later verifies
//   the SGW's installed map   the forwarding state the core actually holds
//
// A dispatched request is not a committed update. An accepted answer is not
// evidence unless it is read back out of the map the SGW really installed, and
// an answer that cannot be correlated stays indeterminate rather than becoming
// a success. Nothing here is S11 GTPv2-C: the MME/SGW exchange is an explicitly
// labelled simulator-internal typed contract, not a wire format, and no
// Modify Bearer Request is encoded, decoded or claimed anywhere.
//
// What the map actually moves is real: `IsolatedSgw::sendDownlink` consults
// the installed map and sends a genuine GTP-U T-PDU to the endpoint tuple the
// map names. A test that builds a target-bound packet itself proves nothing
// about a path migration, so the sender is the map's, not the caller's.

#pragma once

#include <array>
#include <cstdint>
#include <map>
#include <memory>
#include <optional>
#include <string>
#include <vector>

#include "codec.hpp"
#include "handover_admission.hpp"
#include "handover_preparation.hpp"
#include "user_plane.hpp"

namespace udp
{
class UdpServer;
}

namespace lte::enb
{
class EnbMultiplexer;
}

namespace lte::enb::s1ap
{

// Defined in handover_orchestration.hpp. Declared here with their fixed
// underlying types so this module can refuse to act outside the isolated
// simulator, and can report the state it left the transaction in, without
// depending on the orchestration header that depends on this one.
enum class ExecutionMode : uint8_t;
enum class OrchestrationState : uint8_t;

class HandoverCoordinator;
struct CoordinationRecord;

// --- The session the core map is keyed by --------------------------------

// One verified isolated EPS session. The MME's identity for the UE plus the
// PDN address the UE's own NAS was assigned: the pair names one session and
// never a bearer, and neither half is taken from anything a UE restated.
struct IsolatedSessionKey
{
    uint32_t mmeUeS1apId{};
    std::array<uint8_t, 4> ueIpv4{};
};

bool operator==(const IsolatedSessionKey &a, const IsolatedSessionKey &b);
bool operator!=(const IsolatedSessionKey &a, const IsolatedSessionKey &b);
bool operator<(const IsolatedSessionKey &a, const IsolatedSessionKey &b);
std::string ToString(const IsolatedSessionKey &session);

// --- A downlink destination --------------------------------------------

// Where one bearer's downlink has to go, as the SGW stores it.
//
// It is an endpoint tuple and never a TEID on its own. Two eNBs can legitimately
// hold the same numeric local S1-U TEID — the identifier is allocated by each
// eNB's own registry and means nothing outside it — so a map that keyed a
// destination by TEID alone would deliver one cell's traffic to the other. The
// address is part of the identity, and the port is part of the endpoint.
struct IsolatedDownlinkEndpoint
{
    std::array<uint8_t, 4> address{};
    uint32_t teid{};
    uint16_t port{2152};

    [[nodiscard]] bool complete() const
    {
        return address != std::array<uint8_t, 4>{} && teid != 0;
    }
};

bool operator==(const IsolatedDownlinkEndpoint &a, const IsolatedDownlinkEndpoint &b);
bool operator!=(const IsolatedDownlinkEndpoint &a, const IsolatedDownlinkEndpoint &b);
std::string ToString(const IsolatedDownlinkEndpoint &endpoint);

// --- The accepted target bearer set -------------------------------------

// One bearer of the set the target really holds for the reached UE. Its role
// and linked default come from the transaction's own bearer inventory, its SGW
// TEID is the one the bearer was established with, and its endpoint is the
// target's own S1-U address plus the local TEID the target bound. None of it is
// derived from QCI, from an E-RAB list's order, from a UE's report or from a
// frame.
struct AcceptedTargetEndpoint
{
    uint8_t ebi{};
    BearerRole role{BearerRole::DEDICATED};
    std::optional<uint8_t> linkedDefaultEbi;
    uint32_t sgwTeid{};
    IsolatedDownlinkEndpoint endpoint;
};

// The complete replacement the MME asks the isolated SGW to install.
struct IsolatedPathUpdateRequest
{
    // The target preparation's transaction, which is also the identity the
    // Handover Notify was accepted under.
    HandoverTransactionId transaction;
    IsolatedSessionKey session;
    // The MME-facing association epoch this handover began under. A request
    // under another one is working with a session this side no longer holds.
    uint64_t mmeAssociationEpoch{};
    // The target eNB the endpoints belong to, and that cell's own S1-U
    // address. Every installed endpoint must be on that address, so a request
    // cannot smuggle in a third party's transport.
    uint32_t targetEnbId{};
    std::array<uint8_t, 4> targetS1uAddress{};
    // The generation the MME read before it dispatched. The SGW refuses a
    // request written against a map that has since moved, so an update can
    // never be applied twice against two different starting points.
    uint64_t expectedGeneration{};
    std::vector<AcceptedTargetEndpoint> bearers;
};

// --- Refusals -------------------------------------------------------------

// Why the isolated SGW refused to publish a replacement. Every one of them is
// decided before anything is installed, so a refusal leaves the map exactly as
// it was: no bearer on the target, none of the old set replaced.
enum class CorePathRefusal : uint8_t
{
    // The process is attached to a live EPC. Nothing here may act.
    LIVE_MODE_DISABLED,
    // The request names no session, no transaction or no target.
    INCOMPLETE_REQUEST,
    // The session has no mapping at all, so there is no source path to replace.
    UNKNOWN_SESSION,
    // The session's map is owned by another transaction already.
    CONFLICTING_TRANSACTION,
    // The same transaction asks for a different replacement than the one it
    // already installed.
    CONFLICTING_REPLACEMENT,
    // The request omits a bearer the session holds, or names one it does not.
    BEARER_SET_MISMATCH,
    // The same EBI appears twice in one request.
    DUPLICATE_EBI,
    // A bearer's SGW-side tunnel identity disagrees with the installed mapping.
    WRONG_SGW_TEID,
    // A destination is not a complete endpoint tuple.
    INCOMPLETE_ENDPOINT,
    // A destination is not on the target eNB's own S1-U address.
    WRONG_TARGET_ENDPOINT,
    // A proposed role or linked-default relationship disagrees with the
    // session's own bearer inventory.
    BEARER_RELATIONSHIP_INVALID,
    // The session holds no default bearer, or more than one.
    DEFAULT_BEARER_INVALID,
    // The generation the request expected is not the one the map holds.
    STALE_GENERATION,
    // The request's association epoch is not the session's.
    STALE_ASSOCIATION,
    // The transaction is not at the point where this step may run.
    WRONG_STATE,
    // No verified target arrival has been confirmed for this transaction.
    NOT_ARRIVED,
    // The target has committed no resources for this transaction.
    NOT_COMMITTED,
    // The target no longer holds the reached UE this request is about.
    TARGET_CONTEXT_LOST,
    // A target bearer is no longer ready for forwarding.
    BEARER_NOT_ACTIVE,
    // Another transaction has already switched this session's path.
    CONFLICTING_UPDATE,
    // The socket could not carry the datagram.
    SEND_FAILED
};

const char *ToString(CorePathRefusal refusal);

struct CorePathRefusalRecord
{
    CorePathRefusal refusal{CorePathRefusal::INCOMPLETE_REQUEST};
    std::string detail;
};

// --- Installed state and what a commit reports ---------------------------

// One mapping as the SGW actually holds it.
struct InstalledBearerPath
{
    IsolatedSessionKey session;
    uint8_t ebi{};
    BearerRole role{BearerRole::DEDICATED};
    std::optional<uint8_t> linkedDefaultEbi;
    // The SGW-side tunnel identity the eNB sends uplink to. It is part of the
    // key, not a description: a bearer whose uplink TEID changed is not the
    // same bearer.
    uint32_t sgwTeid{};
    // Where downlink goes now.
    IsolatedDownlinkEndpoint endpoint;
    // Where it went before this update. It is kept so an End Marker can be sent
    // on the old path and so a confirmation can name the mapping it replaced.
    // For a session that has never been updated it equals `endpoint`.
    IsolatedDownlinkEndpoint originalSource;
    // Bumped once per published replacement of the whole session.
    uint64_t generation{};
    // The transaction that installed this set.
    HandoverTransactionId owner;
};

// What one apply actually did. `committed` is true only when the complete
// replacement was published; there is no partial form of it.
struct IsolatedPathUpdateCommit
{
    bool committed{};
    // True when the request was an exact repeat of the replacement this session
    // already holds. Nothing was installed a second time.
    bool replayed{};
    std::optional<CorePathRefusalRecord> refusal;
    IsolatedSessionKey session;
    HandoverTransactionId transaction;
    uint64_t pathGeneration{};
    std::vector<InstalledBearerPath> installed;
};

// --- The isolated SGW -----------------------------------------------------

// The SGW downlink forwarding map, and the sender that consults it.
//
// It owns a real UDP socket bound to the SGW address every E-RAB of the
// isolated campaign names, and it is the only thing in this process that sends
// a downlink G-PDU towards an eNB. It is strictly separate from anything a live
// core does: it speaks no GTP-C, it holds no subscriber state, and it refuses
// every entry point outside the isolated simulator mode.
class IsolatedSgw
{
  public:
    IsolatedSgw(ExecutionMode mode, const std::string &address, uint16_t port);

    IsolatedSgw(const IsolatedSgw &) = delete;
    IsolatedSgw &operator=(const IsolatedSgw &) = delete;

    [[nodiscard]] bool enabled() const;
    [[nodiscard]] InetAddress localAddress() const;

    // Provisions the mapping a session has before any handover: one entry per
    // bearer, all of them pointing at the cell that currently serves the UE.
    // It is how the source mapping measured before the update comes into
    // existence, and it is the only way a session enters the map.
    //
    // The generation starts at one and the owner names no transaction: nothing
    // has been switched yet. The association epoch is recorded so a later
    // request written under another one is refused rather than applied to a
    // session this side no longer holds.
    bool installSession(const IsolatedSessionKey &session, uint64_t mmeAssociationEpoch,
                        const std::vector<AcceptedTargetEndpoint> &bearers, CorePathRefusalRecord *failure);

    // Atomically replaces the accepted endpoint set of one session.
    //
    // Every precondition is validated against the complete set before the first
    // entry is written, and the publication is a single swap of the session's
    // whole replacement map. A failure on the second bearer therefore cannot
    // leave the first one on the target: until the swap, nothing is visible.
    IsolatedPathUpdateCommit apply(const IsolatedPathUpdateRequest &request);

    // The installed state of one session, read back out of the map. It is what
    // the MME reads after an update to confirm that the core really holds the
    // replacement, and what it reads to reconcile an answer it never saw.
    [[nodiscard]] std::optional<uint64_t> generationOf(const IsolatedSessionKey &session) const;
    [[nodiscard]] std::optional<HandoverTransactionId> ownerOf(const IsolatedSessionKey &session) const;
    [[nodiscard]] std::vector<InstalledBearerPath> installed(const IsolatedSessionKey &session) const;
    [[nodiscard]] std::optional<InstalledBearerPath> installed(const IsolatedSessionKey &session, uint8_t ebi) const;
    [[nodiscard]] size_t sessionCount() const { return m_sessions.size(); }

    // What one send consulted and where it went. It is the observation a test
    // reads to show the destination came from the map rather than from the
    // call.
    struct CoreSendRecord
    {
        enum class Kind : uint8_t
        {
            G_PDU,
            END_MARKER
        };

        Kind kind{Kind::G_PDU};
        IsolatedSessionKey session;
        uint8_t ebi{};
        IsolatedDownlinkEndpoint destination;
        uint64_t generation{};
        bool sent{};
    };

    // Sends one downlink T-PDU on the bearer the caller names, to wherever the
    // installed map says that bearer's downlink goes. The caller names a bearer
    // and never a destination.
    bool sendDownlink(const IsolatedSessionKey &session, uint8_t ebi, const uint8_t *payload, size_t size);

    // What the eNBs forwarded uplink to this SGW since the last drain. A G-PDU
    // that reaches this socket is a datagram that left an eNB's real S1-U
    // socket, so it is user-plane evidence and not a method call.
    struct ReceivedUplink
    {
        uint32_t sgwTeid{};
        std::vector<uint8_t> payload;
    };
    std::vector<ReceivedUplink> drainUplink();

    // Sends one End Marker on the path this session's bearer used to have.
    //
    // TS 29.281: the End Marker names the tunnel whose payload stream is ending
    // and carries no T-PDU. It goes to the old endpoint only, it is a control
    // message, and it changes nothing here: the map keeps the new destination,
    // no generation moves and no endpoint is retired. The eNB that receives it
    // records it and moves nothing either.
    bool sendEndMarker(const IsolatedSessionKey &session, uint8_t ebi);

    [[nodiscard]] const std::vector<CoreSendRecord> &sendRecords() const { return m_sends; }
    [[nodiscard]] size_t endMarkersSent() const { return m_endMarkersSent; }

  private:
    struct SessionState
    {
        uint64_t generation{};
        uint64_t associationEpoch{};
        HandoverTransactionId owner;
        std::map<uint8_t, InstalledBearerPath> bearers;
    };

    [[nodiscard]] const SessionState *findSession(const IsolatedSessionKey &session) const;
    static bool SameSet(const std::map<uint8_t, InstalledBearerPath> &installed,
                        const std::vector<AcceptedTargetEndpoint> &proposed);

    ExecutionMode m_mode;
    std::unique_ptr<udp::UdpServer> m_socket;
    std::map<IsolatedSessionKey, SessionState> m_sessions;
    std::vector<CoreSendRecord> m_sends;
    size_t m_endMarkersSent{};
};

// --- The MME's confirmation ----------------------------------------------

// What the MME reads back out of the SGW. It is built from the installed map
// and from nothing else, so an answer can never be produced by the component
// that asked for the update.
struct IsolatedCoreUpdateConfirmation
{
    IsolatedSessionKey session;
    HandoverTransactionId transaction;
    uint64_t mmeAssociationEpoch{};
    uint64_t pathGeneration{};
    std::vector<InstalledBearerPath> installed;
};

// Reads the confirmation for one session and one expected association epoch out
// of the SGW's actual map. Returns nothing when the session is unknown.
std::optional<IsolatedCoreUpdateConfirmation> ReadIsolatedPathState(const IsolatedSgw &sgw,
                                                                    const IsolatedSessionKey &session,
                                                                    uint64_t mmeAssociationEpoch);

// Verifies that a confirmation describes exactly the replacement the MME
// dispatched. Every one of these is a refusal rather than a success with a
// caveat: a missing bearer, an extra one, a different TEID, a different
// endpoint, a different role relationship, a stale generation or another
// transaction's ownership all mean the core does not hold what was asked for.
enum class CorePathConfirmationRefusal : uint8_t
{
    CONFIRMED,
    WRONG_SESSION,
    WRONG_TRANSACTION,
    WRONG_ASSOCIATION_EPOCH,
    WRONG_TARGET,
    MISSING_EBI,
    DUPLICATE_EBI,
    WRONG_SGW_TEID,
    WRONG_ENDPOINT,
    BEARER_RELATIONSHIP_INVALID,
    STALE_GENERATION,
    CONFLICTING_REPLACEMENT,
    INDETERMINATE
};

const char *ToString(CorePathConfirmationRefusal refusal);

struct CorePathConfirmationResult
{
    CorePathConfirmationRefusal verdict{CorePathConfirmationRefusal::INDETERMINATE};
    std::string detail;

    [[nodiscard]] bool confirmed() const
    {
        return verdict == CorePathConfirmationRefusal::CONFIRMED;
    }
};

CorePathConfirmationResult VerifyIsolatedPathConfirmation(const IsolatedPathUpdateRequest &request,
                                                          const IsolatedCoreUpdateConfirmation &confirmation);

// --- The MME's control of one isolated core update ------------------------

// Everything the isolated MME holds about the core phase of one handover
// transaction. It lives inside the coordination record, so a stale caller
// cannot reach it through a record it no longer owns.
struct CorePathTransaction
{
    // Whether this transaction was authorized to continue past the Phase 18-D
    // boundary at all. A record that never set it stays terminal where 18-D
    // left it.
    bool enabled{};
    bool dispatched{};
    bool committed{};
    bool indeterminate{};
    IsolatedPathUpdateRequest request;
    IsolatedCoreUpdateConfirmation confirmation;
    uint64_t pathGeneration{};
    CorePathConfirmationResult verification;
};

// What one step produced. `state` is where the transaction is afterwards,
// and a step that refused names why without moving it beyond the point it had
// genuinely reached.
struct CorePathOutcome
{
    bool committed{};
    bool confirmed{};
    bool indeterminate{};
    // The state the transaction holds afterwards. It is always set by the step
    // that produced this outcome; the optional is here only because the enum
    // itself is declared in the orchestration header.
    std::optional<OrchestrationState> state;
    std::optional<CorePathRefusalRecord> refusal;
    std::string detail;
    uint64_t pathGeneration{};
};

// Reads the accepted target endpoint set out of the target's own reached
// registry entry and cross-checks it against the transaction's bearer
// inventory. Nothing here is a caller assertion: the target must still hold the
// reached UE, every bearer must still be active, and the set must be exactly
// the one the transaction admitted, with the same roles and the same linked
// defaults.
bool ReadAcceptedTargetEndpoints(const CoordinationRecord &record, EnbMultiplexer &target,
                                 std::vector<AcceptedTargetEndpoint> *endpoints, CorePathRefusalRecord *failure);

// The MME's decision to ask for the update, and the validation that precedes
// it: an isolated-simulator coordinator, a transaction that has reached the
// Phase 18-D boundary, an accepted Handover Notify from the verified target,
// a confirmed arrival, committed target resources, an active target bearer set
// and an endpoint set that matches the admitted E-RABs exactly.
//
// It sends nothing to the SGW and installs nothing. It records the request on
// the transaction and moves it to CORE_UPDATE_REQUESTED.
bool BeginIsolatedCorePathUpdate(HandoverCoordinator &coordinator, EnbMultiplexer &target, IsolatedSgw &sgw,
                                 const HandoverTransactionId &transaction, CorePathRefusalRecord *failure);

// Applies the update the transaction already requested.
//
// The order is the phase's contract: the MME moves the transaction to
// CORE_UPDATE_COMMITTING before the SGW is asked, the SGW publishes the whole
// replacement atomically or publishes nothing, and the MME then reads the
// installed map back and verifies it against what it dispatched. Only a verified
// read-back produces CORE_PATH_UPDATED; a refusal produces CORE_UPDATE_FAILED;
// an installed set that cannot be correlated produces CORE_UPDATE_INDETERMINATE
// and is never reported as a success.
CorePathOutcome ApplyIsolatedBearerPathUpdate(IsolatedSgw &sgw, HandoverCoordinator &coordinator,
                                              const HandoverTransactionId &transaction);

// Recovers from an answer that was never observed.
//
// It never applies a second update. It reads the SGW's actual installed
// generation and reconciles only when the exact transaction and the complete
// endpoint set can be proven; otherwise the transaction stays
// CORE_UPDATE_INDETERMINATE. Nothing is released on either side by a
// reconciliation.
CorePathOutcome ReconcileIsolatedPathUpdate(IsolatedSgw &sgw, HandoverCoordinator &coordinator,
                                            const HandoverTransactionId &transaction);

} // namespace lte::enb::s1ap
