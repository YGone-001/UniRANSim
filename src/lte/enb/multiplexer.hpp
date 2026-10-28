//
// This file is a part of UERANSIM project.
// Copyright (c) 2027 ALİ GÜNGÖR.
//
// https://github.com/aligungr/UERANSIM/
// See README, LICENSE, and CONTRIBUTING files for licensing details.
//

#pragma once

#include "codec.hpp"
#include "s1u_endpoint.hpp"
#include "types.hpp"
#include "ue_registry.hpp"

#include <chrono>
#include <cstdint>
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

    [[nodiscard]] UeRegistry &registry();
    [[nodiscard]] const UeRegistry &registry() const;
    [[nodiscard]] InetAddress ueLinkAddress() const;
    [[nodiscard]] InetAddress s1uAddress() const;
    [[nodiscard]] const PagingCounters &pagingCounters() const;
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
    void startInitialUeMessage(EnbUeEntry &entry, std::vector<uint8_t> nasPdu,
                               std::optional<s1ap::STmsi> sTmsi);
    void sendRadio(EnbUeEntry &entry, lte::ue::link::MessageType type, std::vector<uint8_t> payload);
    uint16_t streamFor(const EnbUeEntry &entry) const;
    // Association-aware send. Returns false when the PDU was not transmitted
    // because no current association exists or an injection was armed.
    bool sendS1ap(uint16_t stream, const std::vector<uint8_t> &pdu);

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
    PagingCounters m_paging;
    RecoveryCounters m_recovery;
};

} // namespace lte::enb
