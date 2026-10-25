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

    // Echo is a GTP-U control message of the endpoint itself; it is answered
    // directly and never forwarded to a UE bearer or TUN interface.
    if (packet.messageType == gtpu::EchoRequest)
    {
        if (!packet.sequenceNumber.has_value())
        {
            ++m_counters.malformedDrops;
            Log("WARN", "Dropped GTP-U Echo Request without a sequence number");
            return;
        }
        auto response = gtpu::EncodeEchoResponse(*packet.sequenceNumber);
        m_socket->TrySend(peer, response.data(), response.size());
        ++m_counters.echoRequests;
        return;
    }
    if (packet.messageType == gtpu::EchoResponse)
        return;

    EnbUeEntry *entry = m_registry.findByLocalTeid(packet.teid);
    if (entry == nullptr)
    {
        ++m_counters.unknownTeidDrops;
        Log("WARN", "Dropped S1-U T-PDU with unknown/stale TEID " + Hex(packet.teid, 8));
        return;
    }
    if (peer != entry->sgwPeer)
    {
        ++entry->counters.unexpectedPeerDrops;
        Log("WARN", "Dropped S1-U datagram from unexpected peer " + peer.toString());
        return;
    }
    if (!entry->bearer.active())
    {
        ++entry->counters.bearerInactiveDrops;
        return;
    }
    try
    {
        entry->bearer.validateDownlink(packet.teid, packet.payload.data(), packet.payload.size());
    }
    catch (const std::exception &e)
    {
        ++entry->counters.malformedDrops;
        Log("WARN", std::string("Dropped invalid downlink IPv4 packet: ") + e.what());
        return;
    }

    ++entry->counters.s1uDownlinkPackets;
    entry->counters.s1uDownlinkBytes += packet.payload.size();
    auto frame = lte::ue::link::Encode(
        {lte::ue::link::MessageType::DATA_DOWNLINK, entry->radioUeId, std::move(packet.payload)});
    const size_t ipBytes = frame.size() - lte::ue::link::HeaderSize;
    if (m_ueLink.TrySend(entry->peer, frame.data(), frame.size()))
    {
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
    if (!entry.bearer.active())
    {
        ++entry.counters.bearerInactiveDrops;
        throw BearerError("Uplink data received before bearer readiness");
    }
    try
    {
        entry.bearer.validateUplink(entry.radioUeId, packet, size);
    }
    catch (const std::exception &)
    {
        ++entry.counters.malformedDrops;
        throw;
    }
    ++entry.counters.simulatedUplinkPackets;
    entry.counters.simulatedUplinkBytes += size;
    auto datagram = gtpu::EncodeTPdu(entry.bearer.parameters().sgwTeid, packet, size);
    if (m_socket->TrySend(entry.sgwPeer, datagram.data(), datagram.size()))
    {
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
