//
// This file is a part of UERANSIM project.
// Copyright (c) 2027 ALİ GÜNGÖR.
//
// https://github.com/aligungr/UERANSIM/
// See README, LICENSE, and CONTRIBUTING files for licensing details.
//

#include "s1u_endpoint.hpp"

#include "gtpu.hpp"

#include <iomanip>
#include <iostream>
#include <sstream>
#include <stdexcept>
#include <utility>
#include <vector>

#include <lte/ue/radio_link.hpp>

namespace lte::enb
{

namespace
{

void Log(const char *level, const std::string &message)
{
    std::cout << "[lte-enb] [" << level << "] " << message << std::endl;
}

std::string Hex(uint32_t value, int width)
{
    std::ostringstream stream;
    stream << "0x" << std::uppercase << std::hex << std::setfill('0') << std::setw(width) << value;
    return stream.str();
}

} // namespace

S1uEndpoint::S1uEndpoint(const std::string &address, uint16_t port, bool allowLoopback, UeRegistry &registry,
                         udp::UdpServer &ueLink)
    : m_registry(registry), m_ueLink(ueLink)
{
    if (address.empty() || address == "0.0.0.0")
        throw std::runtime_error("The advertised eNB S1-U address must be a concrete local IPv4 address");
    if (address.rfind("127.", 0) == 0 && !allowLoopback)
        throw std::runtime_error(
            "Loopback S1-U requires s1u.allowLoopback=true after verifying a shared network namespace");
    m_socket = std::make_unique<udp::UdpServer>(address, port);
}

void S1uEndpoint::handleDatagram(const uint8_t *data, size_t size, const InetAddress &peer)
{
    gtpu::Packet packet;
    try
    {
        packet = gtpu::Decode(data, size);
    }
    catch (const std::exception &e)
    {
        ++m_counters.malformedDrops;
        Log("WARN", std::string("Dropped malformed S1-U datagram: ") + e.what());
        return;
    }

    // GTP-U control messages are dispatched before any bearer is selected and
    // cannot reach the G-PDU forwarding path below. A G-PDU is the only message
    // type that is delivered to a UE.
    switch (packet.messageType)
    {
    case gtpu::EchoRequest:
        handleEchoRequest(packet, peer);
        return;
    case gtpu::EchoResponse:
        return;
    case gtpu::EndMarker:
        handleEndMarker(packet, peer);
        return;
    case gtpu::TPdu:
        break;
    default:
        // Unreachable: Decode admits only the four types above. Kept so that a
        // future message type cannot silently fall through into G-PDU
        // forwarding and reach a UE.
        ++m_counters.unsupportedMessageDrops;
        Log("WARN", "Dropped GTP-U message of unsupported type " + std::to_string(packet.messageType));
        return;
    }
    handleGPdu(packet, peer);
}

void S1uEndpoint::handleEchoRequest(const gtpu::Packet &packet, const InetAddress &peer)
{
    // Echo is a GTP-U control message of the endpoint itself; it is answered
    // directly and never forwarded to a UE bearer or TUN interface.
    if (!packet.sequenceNumber.has_value())
    {
        ++m_counters.malformedDrops;
        Log("WARN", "Dropped GTP-U Echo Request without a sequence number");
        return;
    }
    auto response = gtpu::EncodeEchoResponse(*packet.sequenceNumber);
    m_socket->TrySend(peer, response.data(), response.size());
    ++m_counters.echoRequests;
}

void S1uEndpoint::handleEndMarker(const gtpu::Packet &packet, const InetAddress &peer)
{
    // TS 29.281 7.3.2: the End Marker indicates the end of the payload stream
    // on one GTP-U tunnel. It carries no T-PDU, so it is never forwarded to a
    // UE and never counted as user-plane traffic in either direction.
    //
    // It is also not an instruction to this eNB. An End Marker on a tunnel that
    // is still up does not release that tunnel, does not move its bearer and
    // does not authorise a handover: this phase recognises and records it and
    // leaves the tunnel exactly as it was. The retirement of a tunnel is the
    // explicit S1 release path, not this message.
    ++m_counters.endMarkers;
    const auto location = m_registry.findBearerByLocalTeid(packet.teid);
    if (location.entry != nullptr && location.bearer != nullptr)
    {
        if (peer != InetAddress(Ipv4ToString(location.bearer->parameters().sgwAddress), 2152))
        {
            ++location.entry->counters.unexpectedPeerDrops;
            Log("WARN", "Dropped GTP-U End Marker from unexpected peer " + peer.toString());
            return;
        }
        ++m_counters.endMarkerActiveTunnels;
        location.bearer->recordEndMarker();
        Log("INFO", "GTP-U End Marker for active tunnel TEID " + Hex(packet.teid, 8) + " on LTE UE " +
                        std::to_string(location.entry->radioUeId) +
                        "; the tunnel is left established and no bearer is moved");
        return;
    }
    if (m_registry.isRetiredTeid(packet.teid))
    {
        // The natural case: the peer is announcing the end of a tunnel whose
        // access transport this eNB already released. A repeat of the same
        // announcement lands here too and changes nothing at all.
        ++m_counters.endMarkerRetiredTunnels;
        Log("INFO", "GTP-U End Marker for retired tunnel TEID " + Hex(packet.teid, 8));
        return;
    }
    ++m_counters.endMarkerUnknownTunnels;
    Log("WARN", "Dropped GTP-U End Marker for unknown TEID " + Hex(packet.teid, 8));
}

void S1uEndpoint::handleGPdu(const gtpu::Packet &packet, const InetAddress &peer)
{
    const auto location = m_registry.findBearerByLocalTeid(packet.teid);
    EnbUeEntry *entry = location.entry;
    BearerContext *bearer = location.bearer;
    if (entry == nullptr || bearer == nullptr)
    {
        // A delayed G-PDU for a tunnel that has already been retired is a
        // different event from one that names a TEID which was never issued:
        // the first is traffic that outlived its tunnel, the second is a packet
        // that never had one. Neither may reach a UE, and neither may create or
        // disturb any bearer state, so nothing here is written anywhere except
        // the drop counter.
        if (m_registry.isRetiredTeid(packet.teid))
        {
            ++m_counters.retiredTeidDrops;
            Log("WARN", "Dropped S1-U T-PDU for retired TEID " + Hex(packet.teid, 8));
            return;
        }
        ++m_counters.unknownTeidDrops;
        Log("WARN", "Dropped S1-U T-PDU with unknown/stale TEID " + Hex(packet.teid, 8));
        return;
    }
    if (peer != InetAddress(Ipv4ToString(bearer->parameters().sgwAddress), 2152))
    {
        ++entry->counters.unexpectedPeerDrops;
        Log("WARN", "Dropped S1-U datagram from unexpected peer " + peer.toString());
        return;
    }
    if (!bearer->active())
    {
        ++entry->counters.bearerInactiveDrops;
        return;
    }
    try
    {
        bearer->validateDownlink(packet.teid, packet.payload.data(), packet.payload.size());
    }
    catch (const std::exception &e)
    {
        ++entry->counters.malformedDrops;
        Log("WARN", std::string("Dropped invalid downlink IPv4 packet: ") + e.what());
        return;
    }

    ++entry->counters.s1uDownlinkPackets;
    entry->counters.s1uDownlinkBytes += packet.payload.size();

    // The bearer that received this T-PDU decides the framing the UE sees, so a
    // dedicated packet can never be delivered as if it were default traffic.
    const size_t ipBytes = packet.payload.size();
    std::vector<uint8_t> frame;
    if (bearer->kind() == BearerKind::DEDICATED)
    {
        std::vector<uint8_t> payload;
        payload.reserve(ipBytes + 1U);
        payload.push_back(bearer->parameters().erabId);
        payload.insert(payload.end(), packet.payload.begin(), packet.payload.end());
        frame = lte::ue::link::Encode(
            {lte::ue::link::MessageType::DATA_DOWNLINK_BEARER, entry->radioUeId, std::move(payload)});
    }
    else
    {
        frame = lte::ue::link::Encode(
            {lte::ue::link::MessageType::DATA_DOWNLINK, entry->radioUeId, std::move(packet.payload)});
    }
    if (m_ueLink.TrySend(entry->peer, frame.data(), frame.size()))
    {
        bearer->recordDownlink(ipBytes);
        ++entry->counters.simulatedDownlinkPackets;
        entry->counters.simulatedDownlinkBytes += ipBytes;
    }
}

void S1uEndpoint::poll(int budget)
{
    uint8_t buffer[lte::ue::link::MaxDataPduSize + lte::ue::link::HeaderSize];
    for (; budget > 0; --budget)
    {
        InetAddress peer;
        const int length = m_socket->Receive(buffer, sizeof(buffer), 0, peer);
        if (length <= 0)
            break;
        handleDatagram(buffer, static_cast<size_t>(length), peer);
    }
}

void S1uEndpoint::forwardUplink(EnbUeEntry &entry, const uint8_t *packet, size_t size)
{
    forwardUplink(entry, entry.bearer, packet, size);
}

void S1uEndpoint::forwardUplink(EnbUeEntry &entry, BearerContext &bearer, const uint8_t *packet, size_t size)
{
    if (!bearer.active())
    {
        ++entry.counters.bearerInactiveDrops;
        throw BearerError("Uplink data received before bearer readiness");
    }
    try
    {
        bearer.validateUplink(entry.radioUeId, packet, size);
    }
    catch (const std::exception &)
    {
        ++entry.counters.malformedDrops;
        throw;
    }
    ++entry.counters.simulatedUplinkPackets;
    entry.counters.simulatedUplinkBytes += size;
    auto datagram = gtpu::EncodeTPdu(bearer.parameters().sgwTeid, packet, size);
    const InetAddress destination(Ipv4ToString(bearer.parameters().sgwAddress), 2152);
    if (m_socket->TrySend(destination, datagram.data(), datagram.size()))
    {
        bearer.recordUplink(size);
        ++entry.counters.s1uUplinkPackets;
        entry.counters.s1uUplinkBytes += size;
    }
}

InetAddress S1uEndpoint::localAddress() const
{
    return m_socket->LocalAddress();
}

const S1uEndpointCounters &S1uEndpoint::counters() const
{
    return m_counters;
}

} // namespace lte::enb
