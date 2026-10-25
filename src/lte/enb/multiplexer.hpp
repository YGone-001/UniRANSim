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

// Per-UE multiplexing over the shared eNB transports: one simulated radio
// UDP link, one S1-U GTP-U endpoint and one S1AP association. Every inbound
// message is routed strictly by validated identity, and a malformed or
// rejected message affecting one UE never disturbs another UE's context.
class EnbMultiplexer
{
  public:
    EnbMultiplexer(const EnbConfig &config, IS1apSender &sender);

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

    // Logs final per-UE statistics and releases every bearer; the shared
    // sockets remain owned by this object until it is destroyed.
    void shutdown();

  private:
    void onInitialContextSetupRequest(const uint8_t *data, size_t size);
    void onDownlinkNasTransport(const uint8_t *data, size_t size);
    void onUeContextReleaseCommand(const uint8_t *data, size_t size);
    void onBearerReady(EnbUeEntry &entry, const std::vector<uint8_t> &payload);
    void startInitialUeMessage(EnbUeEntry &entry, std::vector<uint8_t> nasPdu,
                               std::optional<s1ap::STmsi> sTmsi);
    void sendRadio(EnbUeEntry &entry, lte::ue::link::MessageType type, std::vector<uint8_t> payload);
    uint16_t streamFor(const EnbUeEntry &entry) const;

    EnbConfig m_config;
    IS1apSender &m_sender;
    int m_outboundStreams{1};
    udp::UdpServer m_ueLink;
    UeRegistry m_registry;
    S1uEndpoint m_s1u;
};

} // namespace lte::enb
