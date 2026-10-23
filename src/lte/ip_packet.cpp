//
// This file is a part of UERANSIM project.
// Copyright (c) 2027 ALİ GÜNGÖR.
//
// https://github.com/aligungr/UERANSIM/
// See README, LICENSE, and CONTRIBUTING files for licensing details.
//

#include "ip_packet.hpp"

#include <algorithm>

namespace lte::ip
{

PacketInfo Validate(const uint8_t *data, size_t size, size_t maximumSize)
{
    if (data == nullptr || size < 20)
        throw ValidationError("Truncated IPv4 packet");
    if (size > maximumSize)
        throw ValidationError("IPv4 packet exceeds the supported size");
    if ((data[0] >> 4U) != 4U)
        throw ValidationError("Packet is not IPv4");

    const size_t headerLength = static_cast<size_t>(data[0] & 0x0FU) * 4U;
    if (headerLength < 20 || headerLength > size)
        throw ValidationError("Invalid IPv4 header length");

    const size_t totalLength = (static_cast<size_t>(data[2]) << 8U) | data[3];
    if (totalLength < headerLength || totalLength != size)
        throw ValidationError("Invalid IPv4 total length");

    PacketInfo result{};
    result.headerLength = headerLength;
    result.totalLength = totalLength;
    std::copy(data + 12, data + 16, result.source.begin());
    std::copy(data + 16, data + 20, result.destination.begin());
    const uint16_t fragment = static_cast<uint16_t>((static_cast<uint16_t>(data[6]) << 8U) | data[7]);
    result.fragmented = (fragment & 0x3FFFU) != 0;
    return result;
}

} // namespace lte::ip
