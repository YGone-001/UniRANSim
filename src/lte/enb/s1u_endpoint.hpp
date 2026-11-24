//
// This file is a part of UERANSIM project.
// Copyright (c) 2027 ALİ GÜNGÖR.
//
// https://github.com/aligungr/UERANSIM/
// See README, LICENSE, and CONTRIBUTING files for licensing details.
//

#pragma once

#include "gtpu.hpp"
#include "ue_registry.hpp"

#include <cstdint>
#include <functional>
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
    // GTP-U End Marker handling. An End Marker is a control message about one
    // tunnel: it is never forwarded as user-plane payload and never creates,
    // releases or rebinds a bearer. The three way counts say which kind of
    // tunnel identifier it named.
    uint64_t endMarkers{};
    uint64_t endMarkerActiveTunnels{};
    uint64_t endMarkerRetiredTunnels{};
    uint64_t endMarkerUnknownTunnels{};
    // A G-PDU whose TEID names a tunnel that has already been retired. Kept
    // apart from unknownTeidDrops so that traffic which outlived its tunnel is
    // observable as such rather than as traffic that never had one.
    uint64_t retiredTeidDrops{};
    uint64_t unsupportedMessageDrops{};
};

// The single eNB S1-U GTP-U endpoint. One shared UDP socket serves every
// concurrent default bearer: downlink G-PDUs are demultiplexed by the locally
// allocated receiving TEID to exactly one UE, GTP-U control messages are
// handled before any bearer is selected and never reach a UE, and uplink
// traffic leaves on each bearer's own SGW-U peer and TEID. The socket is never
// closed for a per-UE release.
//
// The dispatch is the safety boundary of this phase. A G-PDU is the only
// message type that is forwarded to a UE; Echo, the End Marker and anything
// else are answered, recorded or dropped here. In particular an End Marker
// never selects a bearer for forwarding, never carries a payload to the UE
// link, and never starts a procedure: it is recorded against the tunnel it
// names and nothing else moves.
class S1uEndpoint
{
  public:
    // receiveBufferBytes is the opt-in SO_RCVBUF for this one socket. Zero means
    // the configuration stated no size: the socket is then created exactly as
    // the kernel creates it, with no system call at all.
    S1uEndpoint(const std::string &address, uint16_t port, bool allowLoopback, UeRegistry &registry,
                udp::UdpServer &ueLink, int receiveBufferBytes = 0);

    // Consumes one datagram received at the shared endpoint.
    void handleDatagram(const uint8_t *data, size_t size, const InetAddress &peer);

    // Drains up to budget pending datagrams from the shared socket. Returns
    // true when at least one datagram was handled.
    bool poll(int budget = 16);

    // Forwards one uplink IPv4 packet on the UE's default bearer.
    void forwardUplink(EnbUeEntry &entry, const uint8_t *packet, size_t size);
    // Dedicated and default bearers use the same shared socket, but select
    // their own SGW TEID and independently validated readiness state.
    void forwardUplink(EnbUeEntry &entry, BearerContext &bearer, const uint8_t *packet, size_t size);

    // Phase 18-F-B6-D6: the downlink delivery of a Uu/SRB1 UE. The handler
    // protects the packet through the bearer's DRB and hands it to the radio
    // transport. It is never a fallback for a legacy UE and never falls back to
    // the legacy link itself: without a handler, a Uu downlink is dropped and
    // counted rather than misdelivered.
    using UuDownlinkHandler = std::function<bool(EnbUeEntry &, BearerContext &, const uint8_t *, size_t)>;
    void SetUuDownlinkHandler(UuDownlinkHandler handler);

    [[nodiscard]] InetAddress localAddress() const;
    [[nodiscard]] const S1uEndpointCounters &counters() const;

    // The effective receive buffer of the shared socket as getsockopt reports
    // it, or 0 when no explicit size was configured. A configured request that
    // the kernel capped is refused at construction, so a live endpoint always
    // carries the value it was told to use.
    [[nodiscard]] int receiveBufferBytes() const;

  private:
    // The three dispatch targets of handleDatagram, kept separate so that no
    // control message can fall through into G-PDU forwarding.
    void handleEchoRequest(const gtpu::Packet &packet, const InetAddress &peer);
    void handleEndMarker(const gtpu::Packet &packet, const InetAddress &peer);
    void handleGPdu(const gtpu::Packet &packet, const InetAddress &peer);

    UeRegistry &m_registry;
    udp::UdpServer &m_ueLink;
    std::unique_ptr<udp::UdpServer> m_socket;
    UuDownlinkHandler m_uuDownlink{};
    S1uEndpointCounters m_counters{};
    // Effective SO_RCVBUF reported by the kernel, or 0 when the configuration
    // stated no size. It is never the requested value: it is the observed one.
    int m_receiveBufferBytes{};
};

} // namespace lte::enb
