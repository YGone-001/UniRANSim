//
// This file is a part of UERANSIM project.
// Copyright (c) 2027 ALİ GÜNGÖR.
//
// https://github.com/aligungr/UERANSIM/
// See README, LICENSE, and CONTRIBUTING files for licensing details.
//

#pragma once

#include "ue_registry.hpp"

#include <cstdint>
#include <memory>
#include <string>

#include <lib/udp/server.hpp>

namespace lte::enb
{

// Aggregate counters of the shared S1-U endpoint itself, kept distinct from
// the per-UE forwarding counters.
struct S1uEndpointCounters
{
    uint64_t echoRequests{};
    uint64_t malformedDrops{};
    uint64_t unknownTeidDrops{};
};

// The single eNB S1-U GTP-U endpoint. One shared UDP socket serves every
// concurrent default bearer: downlink T-PDUs are demultiplexed by the locally
// allocated receiving TEID to exactly one UE, Echo is handled at the endpoint
// without selecting any bearer, and uplink traffic leaves on each bearer's own
// SGW-U peer and TEID. The socket is never closed for a per-UE release.
class S1uEndpoint
{
  public:
    S1uEndpoint(const std::string &address, uint16_t port, bool allowLoopback, UeRegistry &registry,
                udp::UdpServer &ueLink);

    // Consumes one datagram received at the shared endpoint.
    void handleDatagram(const uint8_t *data, size_t size, const InetAddress &peer);

    // Drains up to budget pending datagrams from the shared socket.
    void poll(int budget = 16);

    // Forwards one uplink IPv4 packet on the UE's default bearer.
    void forwardUplink(EnbUeEntry &entry, const uint8_t *packet, size_t size);
    // Dedicated and default bearers use the same shared socket, but select
    // their own SGW TEID and independently validated readiness state.
    void forwardUplink(EnbUeEntry &entry, BearerContext &bearer, const uint8_t *packet, size_t size);

    [[nodiscard]] InetAddress localAddress() const;
    [[nodiscard]] const S1uEndpointCounters &counters() const;

  private:
    UeRegistry &m_registry;
    udp::UdpServer &m_ueLink;
    std::unique_ptr<udp::UdpServer> m_socket;
    S1uEndpointCounters m_counters{};
};

} // namespace lte::enb
