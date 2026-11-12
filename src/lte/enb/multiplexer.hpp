//
// This file is a part of UERANSIM project.
// Copyright (c) 2027 ALİ GÜNGÖR.
//
// https://github.com/aligungr/UERANSIM/
// See README, LICENSE, and CONTRIBUTING files for licensing details.
//

#pragma once

#include "codec.hpp"
#include "handover_preparation.hpp"
#include "handover_source_release.hpp"
#include "s1u_endpoint.hpp"
#include "types.hpp"
#include "ue_registry.hpp"

#include <chrono>
#include <cstdint>
#include <memory>
#include <optional>
#include <vector>

#include <lib/udp/server.hpp>
#include <lte/ue/radio_link.hpp>

namespace lte::enb
{

// Destination for S1AP PDUs produced for the MME, normally the shared SCTP
// association. Kept as an interface so the multiplexing logic stays testable
// against a captured sender.
class IS1apSender
{
  public:
    virtual ~IS1apSender() = default;
    virtual void sendS1ap(uint16_t stream, const std::vector<uint8_t> &pdu) = 0;
};

// Association-scoped binding between the multiplexer and one SCTP sender.
//
// A sender is only reachable while its association epoch is the current one.
// Rebinding advances the epoch, so a handler left over from a previous
// association can neither transmit through the new sender nor be mistaken for
// it. An unbound sender is a counted no-op rather than a crash, because UE
// radio and S1-U processing continue while no association exists.
class S1apSenderBinding
{
  public:
    void bind(IS1apSender &sender, uint32_t epoch);
    // Unbinds only while the given epoch is still current, so a late teardown
    // of an old association cannot detach the new one.
    void unbind(uint32_t epoch);
    [[nodiscard]] bool bound() const { return m_sender != nullptr; }
    [[nodiscard]] uint32_t epoch() const { return m_epoch; }
    // Returns false and counts the rejection when the caller's epoch is not
    // the currently bound one.
    bool send(uint32_t epoch, uint16_t stream, const std::vector<uint8_t> &pdu);
    [[nodiscard]] uint64_t staleRejects() const { return m_staleRejects; }
    [[nodiscard]] uint64_t unboundRejects() const { return m_unboundRejects; }

  private:
    IS1apSender *m_sender{};
    uint32_t m_epoch{};
    uint64_t m_staleRejects{};
    uint64_t m_unboundRejects{};
};

// Diagnostics for the non-UE-associated S1AP Paging path. A delivered
// notification is not proof that a page was accepted or that service was
// restored; those are per-UE outcomes.
struct PagingCounters
{
    uint64_t received{};
    uint64_t valid{};
    uint64_t invalid{};
    uint64_t filteredByTac{};
    uint64_t csDomainIgnored{};
    uint64_t unsupportedIdentity{};
    uint64_t notificationsDelivered{};
    uint64_t notificationFailures{};
};

// Per-UE multiplexing over the shared eNB transports: one simulated radio
// UDP link, one S1-U GTP-U endpoint and one S1AP association. Every inbound
// message is routed strictly by validated identity, and a malformed or
// rejected message affecting one UE never disturbs another UE's context.
class EnbMultiplexer
{
  public:
    // Binds the initial sender at epoch 1. The long-lived resources
    // (simulated-radio endpoint, shared S1-U endpoint and UE registry) are
    // owned by this object and survive every association epoch.
    EnbMultiplexer(const EnbConfig &config, IS1apSender &sender);
    // Starts unbound: the caller binds the first association explicitly.
    explicit EnbMultiplexer(const EnbConfig &config);

    // Binds a new SCTP association: allocates the next association epoch,
    // binds the sender to exactly that epoch and installs the stream count
    // negotiated for this association. Returns the epoch that was allocated.
    uint32_t bindAssociation(IS1apSender &sender, int outboundStreams);
    // Detaches the currently bound association sender, if any. It is safe to
    // call repeatedly and while nothing is bound.
    void unbindAssociation();
    [[nodiscard]] bool associationBound() const;
    // The epoch of the currently bound association, or zero while unbound.
    [[nodiscard]] uint32_t associationEpoch() const;
    // The epoch that a subsequent bindAssociation will allocate. Never zero.
    [[nodiscard]] uint32_t nextAssociationEpoch() const;

    // Confirms an unexpected loss of the currently bound association. It is
    // deliberately not a 3GPP UE Context Release: no S1AP message is sent.
    // Every UE that still holds access transport has that transport
    // invalidated, its S1AP identifiers and local TEIDs erased, and is notified
    // through the internal S1_ACCESS_LOST software-radio indication. Confirmed
    // logical EPS bearer identities are retained. Returns the number of UEs
    // whose access was invalidated.
    size_t invalidateAccess();

    // One-shot test seam: the next S1AP PDU that would be sent is dropped and
    // the injection is reported through injectionTriggered(). Disabled unless
    // armed explicitly.
    void armLossBeforeNextS1apSend();
    [[nodiscard]] bool injectionTriggered() const;
    [[nodiscard]] bool injectionArmed() const;
    void clearInjection();

    // Fault-injection accounting. A consumed injection command and the
    // association-loss event it causes are one event, not two: the command is
    // counted as an injected loss when it executes, and the ensuing loss is
    // then classified as injected rather than unexpected. takeInjectedAssociationLoss()
    // consumes that mark, so a real transport failure remains separately
    // observable and a graceful shutdown counts as neither.
    void noteInjectedAssociationLoss();
    bool takeInjectedAssociationLoss();
    // Classifies one association-loss teardown. The outstanding injection mark
    // is always consumed here so it cannot leak into a later teardown. Exactly
    // one category applies to one event: a loss a consumed command asked for is
    // already counted as injected when that command executed, a genuine
    // transport failure after a live association is unexpected, and a graceful
    // shutdown or a never-established association is neither.
    void classifyAssociationLoss(bool stopping, bool established);

    // The negotiated outbound SCTP stream count of the association; it bounds
    // the streams UE-associated signalling may use.
    void setOutboundStreams(int outboundStreams);

    // Drains pending simulated-radio and shared S1-U datagrams with bounded
    // per-call budgets so one busy UE cannot starve the other transports.
    void poll(int radioBudget = 16, int s1uBudget = 16);

    // Consumes one UE-associated S1AP PDU received from the MME.
    void handleS1ap(const uint8_t *data, size_t size, uint16_t stream);

    // Consumes one simulated radio-link datagram received from a UE peer.
    void handleRadioFrame(const uint8_t *data, size_t size, const InetAddress &peer);

    // --- Handover preparation, verified target arrival and Handover Notify ---
    //
    // The preparation owner of the currently bound association, or null while
    // no association is bound. It is created under the epoch that association
    // allocated and destroyed when that association is unbound, so a
    // preparation cannot outlive the association it was made under and a caller
    // presenting an older epoch is refused as stale rather than served.
    [[nodiscard]] s1ap::HandoverPreparationOwner *preparations();
    [[nodiscard]] const s1ap::HandoverPreparationOwner *preparations() const;

    // What establishing a prepared handover transaction at this target reports.
    struct PreparedHandover
    {
        s1ap::HandoverTransactionId transaction;
        // The binding an arriving UE must present. It is handed to the source
        // by the caller of `prepareHandover`, and that hand-off is explicitly
        // test-harness-verified provenance: nothing in this repository carries
        // one over the air between two eNBs or through an S1AP information
        // element. It is a correlation value and not a key.
        uint32_t arrivalToken{};
        // The Handover Request Acknowledge the real codec built from what the
        // commit bound. It is not evidence that a UE arrived.
        s1ap::HandoverRequestAcknowledge acknowledge;
    };

    // Establishes a prepared handover transaction at this target: admits it,
    // commits real target resources and marks the preparation awaiting the
    // UE's access, in that order, stopping at the first refusal. Nothing is
    // allocated for an admission that refuses, and a commit that cannot be
    // made whole is rolled back before this reports anything.
    //
    // The `SourceContext` is supplied by the caller and is explicitly
    // test-harness-verified provenance: a two-eNB harness that has driven both
    // ends can state it, and nothing else in this repository can. It is never
    // derived from the MME-facing SCTP association, from a TAC or PLMN
    // equality, from a matching EBI or TEID, or by parsing an opaque handover
    // container. That is why the live S1AP dispatcher does not call this: it
    // has no way to establish that provenance and Phase 18-C does not give it
    // one, so a Handover Request arriving over S1AP fails closed here rather
    // than starting a preparation on a guessed source.
    //
    // On success `prepared` receives what was bound and the transaction is
    // awaiting the UE's access. Returns false and states why in `failure`
    // otherwise.
    bool prepareHandover(const s1ap::HandoverTransactionId &requested, const s1ap::HandoverRequest &request,
                         const s1ap::SourceContext &source, const s1ap::TargetContext &target,
                         const std::vector<s1ap::BearerRoleBinding> &roles, PreparedHandover *prepared = nullptr,
                         s1ap::CommitRefusalRecord *failure = nullptr, const s1ap::CommitFaultInjector &faults = {});

    // Source side: hands the simulated handover command to the UE this entry
    // already serves, over the real simulated radio link. It is a simulator
    // control exchange and not 3GPP RRC: the bytes it carries never become a
    // transparent container and are never sent to an MME.
    void sendHandoverCommand(EnbUeEntry &entry, const lte::ue::link::SimulatedHandoverCommand &command);

    // Target side: builds a Handover Notify behind the arrival gate and
    // transmits it over the real S1AP association. The gate refuses every
    // attempt that is not a proven arrival with ready bearers, and a send that
    // does not reach the association is reported as a send failure rather than
    // recorded as a notification.
    s1ap::HandoverNotifyOutcome notifyHandover(const s1ap::HandoverTransactionId &id);

    // Source side: records that this eNB has just commanded a UE into a
    // connected-mode handover.
    //
    // It is the source's own statement that it handed the UE to that target,
    // written by the production delivery path and by nothing else. It is half
    // of what authorizes a handover-specific release later: a cell that never
    // sent a command holds no record, and no message can supply one.
    void noteHandoverSourceCommand(const s1ap::HandoverSourceRecord &record);

    // Source side: installs the isolated MME's verified release decision for one
    // transaction. It is explicitly MME-supplied provenance, exactly like the
    // SourceContext a preparation is made with, and it is never derived from a
    // Release Command. Repeated installation for the same transaction replaces
    // the earlier decision rather than stacking a second one.
    void authorizeHandoverSourceRelease(const s1ap::HandoverSourceReleaseDecision &decision);

    // What this cell has been told about handovers it executed, and what the
    // isolated MME has authorized. Read-only observation for a harness; nothing
    // acting on a source release depends on a caller reading these.
    [[nodiscard]] const std::vector<s1ap::HandoverSourceRecord> &handoverSourceRecords() const;
    [[nodiscard]] const std::vector<s1ap::HandoverSourceReleaseDecision> &handoverSourceReleaseDecisions() const;

    // Target side: what the production radio receive path last accepted as a
    // verified arrival. It is the output of
    // `HandoverPreparationOwner::acceptArrival` and nothing else, so it is
    // arrival evidence rather than a claim a caller made: a caller cannot
    // obtain one by setting a flag, and a decoded Handover Request or a
    // committed resource set produces none. It is the only thing that may be
    // reported to a handover coordinator as an arrival.
    [[nodiscard]] const std::optional<s1ap::VerifiedTargetArrival> &lastVerifiedArrival() const;

    [[nodiscard]] UeRegistry &registry();
    [[nodiscard]] const UeRegistry &registry() const;
    [[nodiscard]] InetAddress ueLinkAddress() const;
    [[nodiscard]] InetAddress s1uAddress() const;
    [[nodiscard]] const PagingCounters &pagingCounters() const;
    // The shared S1-U endpoint's own counters. They are endpoint-level and not
    // per-UE, so a retired-TEID drop read here is a statement about this cell
    // and not about any one bearer.
    [[nodiscard]] const S1uEndpointCounters &s1uCounters() const;
    [[nodiscard]] const RecoveryCounters &recoveryCounters() const;
    [[nodiscard]] RecoveryCounters &recoveryCounters();
    // Milliseconds between the most recent access invalidation and the first
    // subsequent successful UE restoration; zero while none has completed.
    [[nodiscard]] uint64_t restorationLatencyMs() const;

    // Logs final per-UE statistics and releases every bearer; the shared
    // sockets remain owned by this object until it is destroyed.
    void shutdown();

  private:
    void onInitialContextSetupRequest(const uint8_t *data, size_t size);
    void onDownlinkNasTransport(const uint8_t *data, size_t size);
    void onUeContextReleaseCommand(const uint8_t *data, size_t size);
    // Non-UE-associated Paging: validates the PDU, filters by tracking area and
    // fans one simulated notification out to retained idle radio endpoints.
    // Adds one network-initiated dedicated E-RAB on an existing S1 context.
    void onErabSetupRequest(const uint8_t *data, size_t size);
    void onErabModifyRequest(const uint8_t *data, size_t size);
    // Releases named dedicated E-RABs without touching the default bearer.
    void onErabReleaseCommand(const uint8_t *data, size_t size);
    void onPaging(const uint8_t *data, size_t size, uint16_t stream);
    [[nodiscard]] bool servesPagingTai(const std::vector<s1ap::Tai> &taiList) const;
    void onBearerReady(EnbUeEntry &entry, const std::vector<uint8_t> &payload);
    // States the S1AP identity pair this UE's S1 context is bound to, once the
    // eNB has made its bearer UE-ready and both identifiers are known. It is
    // the only way the simulator's UE learns a binding that a connected-mode
    // handover command can later be checked against instead of adopted from,
    // and it states only what this eNB already holds. It authorizes nothing.
    void announceS1Context(EnbUeEntry &entry);
    void startInitialUeMessage(EnbUeEntry &entry, std::vector<uint8_t> nasPdu,
                               std::optional<s1ap::STmsi> sTmsi);
    void sendRadio(EnbUeEntry &entry, lte::ue::link::MessageType type, std::vector<uint8_t> payload);
    uint16_t streamFor(const EnbUeEntry &entry) const;
    // Association-aware send. Returns false when the PDU was not transmitted
    // because no current association exists or an injection was armed.
    bool sendS1ap(uint16_t stream, const std::vector<uint8_t> &pdu);
    // The same send under an explicit association epoch, so a handover
    // transaction begun under one epoch cannot transmit through a later
    // association that never saw it.
    bool sendS1ap(uint32_t epoch, uint16_t stream, const std::vector<uint8_t> &pdu);
    // A handover-specific arrival. It is handled before any UE entry lookup on
    // purpose: the arriving UE is not one this registry already serves and
    // must not be registered as a peer by this frame. The target learns of the
    // UE through the committed preparation, and the arrival is what promotes
    // it.
    void onHandoverAccess(const lte::ue::link::Message &radio, const InetAddress &peer);

    // The arrival the radio receive path last accepted, when one has been.
    // Set only by `onHandoverAccess`, and only after `acceptArrival` agreed.
    std::optional<s1ap::VerifiedTargetArrival> m_lastVerifiedArrival;

    // Handovers this cell commanded, and the release decisions the isolated MME
    // installed for them. Both are per-UE and bounded by the transactions the
    // cell actually ran; a completed release erases its own entry from each.
    std::vector<s1ap::HandoverSourceRecord> m_handoverSources;
    std::vector<s1ap::HandoverSourceReleaseDecision> m_releaseDecisions;

    EnbConfig m_config;
    S1apSenderBinding m_sender;
    // Zero while no association is bound. Every bind allocates the next value
    // from m_nextAssociationEpoch, so an epoch is never reused and a callback
    // from a previous association can never match the current one.
    uint32_t m_associationEpoch{};
    uint32_t m_nextAssociationEpoch{};
    int m_outboundStreams{1};
    bool m_injectionArmed{};
    bool m_injectionTriggered{};
    bool m_injectedLossPending{};
    uint64_t m_restorationLatencyMs{};
    std::chrono::steady_clock::time_point m_accessInvalidatedAt{};
    udp::UdpServer m_ueLink;
    UeRegistry m_registry;
    S1uEndpoint m_s1u;
    // The handover preparations of the currently bound association. Declared
    // after the registry on purpose: it is destroyed first, so its cleanup
    // still finds the registry it holds provisional contexts in. A record
    // whose ownership has already been transferred to a reached UE is not
    // touched by that cleanup at all.
    std::unique_ptr<s1ap::HandoverPreparationOwner> m_preparations;
    PagingCounters m_paging;
    RecoveryCounters m_recovery;
};

} // namespace lte::enb
