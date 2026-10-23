//
// This file is a part of UERANSIM project.
// Copyright (c) 2027 ALİ GÜNGÖR.
//
// https://github.com/aligungr/UERANSIM/
// See README, LICENSE, and CONTRIBUTING files for licensing details.
//

#include "radio_link.hpp"

#include <algorithm>

namespace lte::ue::link
{
namespace
{
constexpr uint8_t Version = 1;
constexpr size_t HeaderSize = 8;

uint16_t Read16(const uint8_t *p)
{
    return static_cast<uint16_t>((static_cast<uint16_t>(p[0]) << 8U) | p[1]);
}
}

std::vector<uint8_t> Encode(const Message &message)
{
    if (message.ueId == 0 || message.nas.empty() || message.nas.size() > MaxNasPduSize)
        throw DecodeError("Invalid LTE radio-link message");
    std::vector<uint8_t> out(HeaderSize + message.nas.size());
    out[0] = Version;
    out[1] = static_cast<uint8_t>(message.type);
    out[2] = static_cast<uint8_t>(message.ueId >> 24U);
    out[3] = static_cast<uint8_t>(message.ueId >> 16U);
    out[4] = static_cast<uint8_t>(message.ueId >> 8U);
    out[5] = static_cast<uint8_t>(message.ueId);
    out[6] = static_cast<uint8_t>(message.nas.size() >> 8U);
    out[7] = static_cast<uint8_t>(message.nas.size());
    std::copy(message.nas.begin(), message.nas.end(), out.begin() + HeaderSize);
    return out;
}

Message Decode(const uint8_t *data, size_t size)
{
    if (data == nullptr || size < HeaderSize || data[0] != Version)
        throw DecodeError("Malformed LTE radio-link header");
    if (data[1] != static_cast<uint8_t>(MessageType::NAS_UPLINK) && data[1] != static_cast<uint8_t>(MessageType::NAS_DOWNLINK))
        throw DecodeError("Unknown LTE radio-link message type");
    uint16_t length = Read16(data + 6);
    if (length == 0 || length > MaxNasPduSize || size != HeaderSize + length)
        throw DecodeError("Malformed LTE radio-link NAS length");
    uint32_t ueId = (static_cast<uint32_t>(data[2]) << 24U) | (static_cast<uint32_t>(data[3]) << 16U) |
                    (static_cast<uint32_t>(data[4]) << 8U) | data[5];
    if (ueId == 0)
        throw DecodeError("Invalid LTE radio-link UE identity");
    return {static_cast<MessageType>(data[1]), ueId, std::vector<uint8_t>(data + HeaderSize, data + size)};
}

} // namespace lte::ue::link
