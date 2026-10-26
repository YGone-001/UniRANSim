//
// This file is a part of UERANSIM project.
// Copyright (c) 2027 ALİ GÜNGÖR.
//
// https://github.com/aligungr/UERANSIM/
// See README, LICENSE, and CONTRIBUTING files for licensing details.
//

#include "tft.hpp"

#include "ip_packet.hpp"

#include <algorithm>
#include <string>

namespace lte::tft
{

namespace
{

void RequireBytes(size_t offset, size_t needed, size_t end, const char *what)
{
    if (offset + needed > end)
        throw TftError(std::string("Truncated packet filter component: ") + what);
}

uint16_t ReadUint16(const uint8_t *data)
{
    return static_cast<uint16_t>((static_cast<uint16_t>(data[0]) << 8U) | data[1]);
}

PacketFilter DecodeFilter(const uint8_t *data, size_t size, size_t &offset)
{
    if (offset + 3 > size)
        throw TftError("Truncated packet filter header");

    const uint8_t header = data[offset];
    const uint8_t precedence = data[offset + 1];
    const size_t length = data[offset + 2];
    if (length == 0)
        throw TftError("Empty packet filter content", 45);

    // Spare bits must be zero; a non-zero spare is a decoder disagreement, not
    // a filter we may silently reinterpret.
    if ((header & 0xC0U) != 0)
        throw TftError("Packet filter carries non-zero spare bits");

    PacketFilter filter;
    filter.direction = static_cast<FilterDirection>((header >> 4U) & 0x03U);
    filter.identifier = static_cast<uint8_t>(header & 0x0FU);
    filter.precedence = precedence; // full octet, TS 24.008 10.5.6.12

    if (filter.direction == static_cast<FilterDirection>(0))
        throw TftError("Packet filter has an invalid direction");

    offset += 3;
    if (offset + length > size)
        throw TftError("Truncated packet filter content");

    const size_t end = offset + length;
    size_t components = 0;

    while (offset < end)
    {
        if (++components > MaxComponentsPerFilter)
            throw TftError("Packet filter carries more components than supported");

        const uint8_t type = data[offset++];
        switch (type)
        {
        case ComponentIpv4RemoteAddress: {
            if (filter.hasRemoteAddress)
                throw TftError("Duplicate IPv4 remote component", 45);
            RequireBytes(offset, 8, end, "IPv4 remote address");
            std::copy(data + offset, data + offset + 4, filter.remoteAddress.begin());
            std::copy(data + offset + 4, data + offset + 8, filter.remoteMask.begin());
            filter.hasRemoteAddress = true;
            offset += 8;
            break;
        }
        case ComponentIpv4LocalAddress: {
            if (filter.hasLocalAddress)
                throw TftError("Duplicate IPv4 local component", 45);
            RequireBytes(offset, 8, end, "IPv4 local address");
            std::copy(data + offset, data + offset + 4, filter.localAddress.begin());
            std::copy(data + offset + 4, data + offset + 8, filter.localMask.begin());
            filter.hasLocalAddress = true;
            offset += 8;
            break;
        }
        case ComponentProtocolOrNextHeader: {
            if (filter.hasProtocol)
                throw TftError("Duplicate protocol component", 45);
            RequireBytes(offset, 1, end, "protocol identifier");
            filter.protocol = data[offset];
            filter.hasProtocol = true;
            offset += 1;
            break;
        }
        case ComponentSingleLocalPort: {
            if (filter.hasLocalPort)
                throw TftError("Duplicate local port component", 45);
            RequireBytes(offset, 2, end, "single local port");
            filter.localPortLow = filter.localPortHigh = ReadUint16(data + offset);
            filter.hasLocalPort = true;
            offset += 2;
            break;
        }
        case ComponentLocalPortRange: {
            if (filter.hasLocalPort)
                throw TftError("Conflicting local port components", 45);
            RequireBytes(offset, 4, end, "local port range");
            filter.localPortLow = ReadUint16(data + offset);
            filter.localPortHigh = ReadUint16(data + offset + 2);
            filter.hasLocalPort = true;
            offset += 4;
            break;
        }
        case ComponentSingleRemotePort: {
            if (filter.hasRemotePort)
                throw TftError("Duplicate remote port component", 45);
            RequireBytes(offset, 2, end, "single remote port");
            filter.remotePortLow = filter.remotePortHigh = ReadUint16(data + offset);
            filter.hasRemotePort = true;
            offset += 2;
            break;
        }
        case ComponentRemotePortRange: {
            if (filter.hasRemotePort)
                throw TftError("Conflicting remote port components", 45);
            RequireBytes(offset, 4, end, "remote port range");
            filter.remotePortLow = ReadUint16(data + offset);
            filter.remotePortHigh = ReadUint16(data + offset + 2);
            filter.hasRemotePort = true;
            offset += 4;
            break;
        }
        default:
            // An unknown component cannot be ignored: it changes what the flow
            // matches, so accepting the bearer would misroute traffic.
            throw TftError("Unsupported packet filter component type " + std::to_string(type));
        }
    }

    if (filter.hasLocalPort && filter.localPortLow > filter.localPortHigh)
        throw TftError("Packet filter has an inverted local port range");
    if (filter.hasRemotePort && filter.remotePortLow > filter.remotePortHigh)
        throw TftError("Packet filter has an inverted remote port range");

    return filter;
}

bool AddressMatches(const std::array<uint8_t, 4> &address, const std::array<uint8_t, 4> &filterAddress,
                    const std::array<uint8_t, 4> &mask)
{
    for (size_t i = 0; i < 4; ++i)
    {
        if ((address[i] & mask[i]) != (filterAddress[i] & mask[i]))
            return false;
    }
    return true;
}

bool PortMatches(uint16_t port, uint16_t low, uint16_t high)
{
    return port >= low && port <= high;
}

// Open5GS encodes an unconstrained ("any") IPv4 endpoint as address 0.0.0.0
// with mask 255.255.255.255. Read strictly that would match only 0.0.0.0, so a
// bearer created with a wildcard flow would never classify a real packet. This
// is observed wire behaviour from the laboratory EPC, and treating it as "no
// constraint" is the only reading that preserves the network's intent.
bool IsWildcardAddress(const std::array<uint8_t, 4> &address, const std::array<uint8_t, 4> &mask)
{
    return address == std::array<uint8_t, 4>{0, 0, 0, 0} &&
           mask == std::array<uint8_t, 4>{255, 255, 255, 255};
}

} // namespace

TrafficFlowTemplate Decode(const uint8_t *data, size_t size)
{
    if (data == nullptr || size < 1)
        throw TftError("Truncated traffic flow template");
    if (size > MaxTftSize)
        throw TftError("Traffic flow template exceeds the supported size");

    const uint8_t header = data[0];
    const auto operation = static_cast<OperationCode>((header >> 5U) & 0x07U);
    const bool parametersPresent = ((header >> 4U) & 0x01U) != 0;
    const size_t filterCount = static_cast<size_t>(header & 0x0FU);

    if (operation < OperationCode::CREATE_NEW || operation > OperationCode::NO_TFT_OPERATION)
        throw TftError("Unsupported TFT operation code");
    if ((operation == OperationCode::NO_TFT_OPERATION || operation == OperationCode::DELETE_EXISTING) &&
        filterCount != 0)
        throw TftError("A no-TFT operation must not carry packet filters");
    if (operation != OperationCode::NO_TFT_OPERATION && filterCount > MaxPacketFilters)
        throw TftError("TFT carries more packet filters than the encoding allows");
    // The parameters list carries authorization tokens that this implementation
    // does not consume; accepting it would claim a capability we do not have.
    if (parametersPresent)
        throw TftError("TFT parameters list is not supported");

    TrafficFlowTemplate tft;
    tft.operation = operation;
    tft.parametersPresent = parametersPresent;

    size_t offset = 1;
    for (size_t i = 0; i < filterCount; ++i)
    {
        PacketFilter filter;
        if (operation == OperationCode::DELETE_FILTERS)
        {
            RequireBytes(offset, 1, size, "deleted packet filter identifier");
            if (data[offset] & 0xF0U)
                throw TftError("Invalid deleted filter identifier");
            filter.identifier = data[offset++];
        }
        else
            filter = DecodeFilter(data, size, offset);
        for (const auto &existing : tft.filters)
        {
            if (existing.identifier == filter.identifier)
                throw TftError("TFT carries duplicate packet filter identifiers");
        }
        tft.filters.push_back(filter);
    }

    if (offset != size)
        throw TftError("TFT carries trailing octets after the packet filter list");

    if (operation != OperationCode::NO_TFT_OPERATION && operation != OperationCode::DELETE_EXISTING &&
        tft.filters.empty())
        throw TftError("TFT operation requires at least one packet filter");

    return tft;
}

std::vector<uint8_t> Encode(const TrafficFlowTemplate &tft)
{
    if (tft.filters.size() > MaxPacketFilters)
        throw TftError("TFT carries more packet filters than the encoding allows");
    if (tft.parametersPresent)
        throw TftError("TFT parameters list is not supported");
    if (tft.operation < OperationCode::CREATE_NEW || tft.operation > OperationCode::NO_TFT_OPERATION ||
        ((tft.operation == OperationCode::DELETE_EXISTING || tft.operation == OperationCode::NO_TFT_OPERATION) &&
         !tft.filters.empty()))
        throw TftError("Invalid TFT operation/filter count");

    std::vector<uint8_t> out;
    out.push_back(static_cast<uint8_t>((static_cast<uint8_t>(tft.operation) << 5U) |
                                       static_cast<uint8_t>(tft.filters.size() & 0x0FU)));

    for (const auto &filter : tft.filters)
    {
        if (filter.identifier > 15)
            throw TftError("Invalid packet filter identifier");
        if (tft.operation == OperationCode::DELETE_FILTERS)
        {
            out.push_back(filter.identifier);
            continue;
        }
        std::vector<uint8_t> components;
        if (filter.hasProtocol)
        {
            components.push_back(ComponentProtocolOrNextHeader);
            components.push_back(filter.protocol);
        }
        if (filter.hasRemoteAddress)
        {
            components.push_back(ComponentIpv4RemoteAddress);
            components.insert(components.end(), filter.remoteAddress.begin(), filter.remoteAddress.end());
            components.insert(components.end(), filter.remoteMask.begin(), filter.remoteMask.end());
        }
        if (filter.hasLocalAddress)
        {
            components.push_back(ComponentIpv4LocalAddress);
            components.insert(components.end(), filter.localAddress.begin(), filter.localAddress.end());
            components.insert(components.end(), filter.localMask.begin(), filter.localMask.end());
        }
        if (filter.hasLocalPort)
        {
            if (filter.localPortLow == filter.localPortHigh)
            {
                components.push_back(ComponentSingleLocalPort);
                components.push_back(static_cast<uint8_t>(filter.localPortLow >> 8U));
                components.push_back(static_cast<uint8_t>(filter.localPortLow & 0xFFU));
            }
            else
            {
                components.push_back(ComponentLocalPortRange);
                components.push_back(static_cast<uint8_t>(filter.localPortLow >> 8U));
                components.push_back(static_cast<uint8_t>(filter.localPortLow & 0xFFU));
                components.push_back(static_cast<uint8_t>(filter.localPortHigh >> 8U));
                components.push_back(static_cast<uint8_t>(filter.localPortHigh & 0xFFU));
            }
        }
        if (filter.hasRemotePort)
        {
            if (filter.remotePortLow == filter.remotePortHigh)
            {
                components.push_back(ComponentSingleRemotePort);
                components.push_back(static_cast<uint8_t>(filter.remotePortLow >> 8U));
                components.push_back(static_cast<uint8_t>(filter.remotePortLow & 0xFFU));
            }
            else
            {
                components.push_back(ComponentRemotePortRange);
                components.push_back(static_cast<uint8_t>(filter.remotePortLow >> 8U));
                components.push_back(static_cast<uint8_t>(filter.remotePortLow & 0xFFU));
                components.push_back(static_cast<uint8_t>(filter.remotePortHigh >> 8U));
                components.push_back(static_cast<uint8_t>(filter.remotePortHigh & 0xFFU));
            }
        }

        if (components.empty())
            throw TftError("A packet filter must carry at least one component");

        out.push_back(static_cast<uint8_t>((static_cast<uint8_t>(filter.direction) << 4U) |
                                           (filter.identifier & 0x0FU)));
        out.push_back(filter.precedence);
        out.push_back(static_cast<uint8_t>(components.size() & 0xFFU));
        out.insert(out.end(), components.begin(), components.end());
    }

    return out;
}

const PacketFilter *Classify(const std::vector<PacketFilter> &filters, const uint8_t *ipPacket, size_t size,
                             bool uplink)
{
    if (filters.empty())
        return nullptr;

    const auto info = ip::Validate(ipPacket, size);

    uint16_t sourcePort = 0;
    uint16_t destinationPort = 0;
    bool havePorts = false;
    if (!info.fragmented && (info.protocol == 6U || info.protocol == 17U))
    {
        if (info.headerLength + 4U <= size)
        {
            sourcePort = ReadUint16(ipPacket + info.headerLength);
            destinationPort = ReadUint16(ipPacket + info.headerLength + 2U);
            havePorts = true;
        }
    }

    const PacketFilter *best = nullptr;
    for (const auto &filter : filters)
    {
        if (!filter.appliesTo(uplink))
            continue;

        if (filter.hasProtocol && filter.protocol != info.protocol)
            continue;

        const auto &localAddress = uplink ? info.source : info.destination;
        const auto &remoteAddress = uplink ? info.destination : info.source;
        if (filter.hasLocalAddress && !IsWildcardAddress(filter.localAddress, filter.localMask) &&
            !AddressMatches(localAddress, filter.localAddress, filter.localMask))
            continue;
        if (filter.hasRemoteAddress && !IsWildcardAddress(filter.remoteAddress, filter.remoteMask) &&
            !AddressMatches(remoteAddress, filter.remoteAddress, filter.remoteMask))
            continue;

        if (filter.hasLocalPort)
        {
            if (!havePorts)
                continue;
            const uint16_t localPort = uplink ? sourcePort : destinationPort;
            if (!PortMatches(localPort, filter.localPortLow, filter.localPortHigh))
                continue;
        }
        if (filter.hasRemotePort)
        {
            if (!havePorts)
                continue;
            const uint16_t remotePort = uplink ? destinationPort : sourcePort;
            if (!PortMatches(remotePort, filter.remotePortLow, filter.remotePortHigh))
                continue;
        }

        if (best == nullptr || filter.precedence < best->precedence)
            best = &filter;
    }

    return best;
}

void TftState::apply(const TrafficFlowTemplate &tft)
{
    if (tft.parametersPresent)
        throw TftError("Unsupported TFT parameters");
    // All mutation is confined to this candidate, including capacity and final
    // semantic checks. A failed operation leaves every old filter byte intact.
    auto candidate = m_filters;
    auto &filters = candidate;
    std::vector<uint8_t> ids;
    for (const auto &incoming : tft.filters)
    {
        if (incoming.identifier > 15 || std::find(ids.begin(), ids.end(), incoming.identifier) != ids.end())
            throw TftError("Duplicate/invalid packet filter identifier", 45);
        ids.push_back(incoming.identifier);
        if (tft.operation != OperationCode::DELETE_FILTERS &&
            (incoming.direction < FilterDirection::DOWNLINK_ONLY ||
             incoming.direction > FilterDirection::BIDIRECTIONAL ||
             (incoming.hasLocalPort && incoming.localPortLow > incoming.localPortHigh) ||
             (incoming.hasRemotePort && incoming.remotePortLow > incoming.remotePortHigh)))
            throw TftError("Invalid packet filter direction or port range", 44);
    }
    if ((tft.operation == OperationCode::DELETE_EXISTING || tft.operation == OperationCode::NO_TFT_OPERATION) &&
        !tft.filters.empty())
        throw TftError("TFT operation must not contain filters");
    if ((tft.operation == OperationCode::ADD_FILTERS || tft.operation == OperationCode::REPLACE_FILTERS ||
         tft.operation == OperationCode::DELETE_FILTERS || tft.operation == OperationCode::CREATE_NEW) &&
        tft.filters.empty())
        throw TftError("TFT operation requires filters");
    switch (tft.operation)
    {
    case OperationCode::CREATE_NEW:
        filters = tft.filters;
        break;
    case OperationCode::DELETE_EXISTING:
        filters.clear();
        break;
    case OperationCode::ADD_FILTERS:
        for (const auto &incoming : tft.filters)
        {
            for (const auto &existing : filters)
            {
                if (existing.identifier == incoming.identifier)
                    throw TftError("TFT adds a packet filter identifier that already exists", 41);
            }
            filters.push_back(incoming);
        }
        break;
    case OperationCode::REPLACE_FILTERS:
        for (const auto &incoming : tft.filters)
        {
            const auto it = std::find_if(filters.begin(), filters.end(), [&](const PacketFilter &existing) {
                return existing.identifier == incoming.identifier;
            });
            if (it == filters.end())
                throw TftError("TFT replaces a packet filter identifier that does not exist", 41);
            *it = incoming;
        }
        break;
    case OperationCode::DELETE_FILTERS:
        for (const auto &incoming : tft.filters)
        {
            const auto it = std::find_if(filters.begin(), filters.end(), [&](const PacketFilter &existing) {
                return existing.identifier == incoming.identifier;
            });
            if (it == filters.end())
                throw TftError("TFT deletes a packet filter identifier that does not exist", 41);
            filters.erase(it);
        }
        break;
    case OperationCode::NO_TFT_OPERATION:
        break;
    default:
        throw TftError("Invalid TFT operation");
    }

    if (filters.size() > MaxPacketFilters)
        throw TftError("Accumulated TFT exceeds the supported packet filter count", 26);
    for (size_t i = 0; i < filters.size(); ++i)
        for (size_t j = i + 1; j < filters.size(); ++j)
            if (filters[i].precedence == filters[j].precedence)
                throw TftError("Conflicting packet filter evaluation precedence", 44);
    m_filters.swap(candidate);
}

void TftState::clear()
{
    m_filters.clear();
}

const PacketFilter *TftState::classify(const uint8_t *ipPacket, size_t size, bool uplink) const
{
    return Classify(m_filters, ipPacket, size, uplink);
}

} // namespace lte::tft
