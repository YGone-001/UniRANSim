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

uint16_t Read16(const uint8_t *p)
{
    return static_cast<uint16_t>((static_cast<uint16_t>(p[0]) << 8U) | p[1]);
}

bool IsKnown(MessageType type)
{
    return type == MessageType::NAS_UPLINK || type == MessageType::NAS_DOWNLINK ||
           type == MessageType::DATA_UPLINK || type == MessageType::DATA_DOWNLINK ||
           type == MessageType::BEARER_READY || type == MessageType::BEARER_RELEASED;
}

size_t MaximumPayload(MessageType type)
{
    if (type == MessageType::NAS_UPLINK || type == MessageType::NAS_DOWNLINK)
        return MaxNasPduSize;
    if (type == MessageType::DATA_UPLINK || type == MessageType::DATA_DOWNLINK)
        return MaxDataPduSize;
    if (type == MessageType::BEARER_READY)
        return 5;
    return 1;
}
}

std::vector<uint8_t> Encode(const Message &message)
{
    if (!IsKnown(message.type) || message.ueId == 0 || message.payload.empty() ||
        message.payload.size() > MaximumPayload(message.type) ||
        (message.type == MessageType::BEARER_READY && message.payload.size() != 5) ||
        (message.type == MessageType::BEARER_RELEASED && message.payload.size() != 1))
        throw DecodeError("Invalid LTE radio-link message");
    std::vector<uint8_t> out(HeaderSize + message.payload.size());
    out[0] = Version;
    out[1] = static_cast<uint8_t>(message.type);
    out[2] = static_cast<uint8_t>(message.ueId >> 24U);
    out[3] = static_cast<uint8_t>(message.ueId >> 16U);
    out[4] = static_cast<uint8_t>(message.ueId >> 8U);
    out[5] = static_cast<uint8_t>(message.ueId);
    out[6] = static_cast<uint8_t>(message.payload.size() >> 8U);
    out[7] = static_cast<uint8_t>(message.payload.size());
    std::copy(message.payload.begin(), message.payload.end(), out.begin() + HeaderSize);
    return out;
}

Message Decode(const uint8_t *data, size_t size)
{
    if (data == nullptr || size < HeaderSize || data[0] != Version)
        throw DecodeError("Malformed LTE radio-link header");
    const auto type = static_cast<MessageType>(data[1]);
    if (!IsKnown(type))
        throw DecodeError("Unknown LTE radio-link message type");
    uint16_t length = Read16(data + 6);
    if (length == 0 || length > MaximumPayload(type) || size != HeaderSize + length ||
        (type == MessageType::BEARER_READY && length != 5) ||
        (type == MessageType::BEARER_RELEASED && length != 1))
        throw DecodeError("Malformed LTE radio-link payload length");
    uint32_t ueId = (static_cast<uint32_t>(data[2]) << 24U) | (static_cast<uint32_t>(data[3]) << 16U) |
                    (static_cast<uint32_t>(data[4]) << 8U) | data[5];
    if (ueId == 0)
        throw DecodeError("Invalid LTE radio-link UE identity");
    return {type, ueId, std::vector<uint8_t>(data + HeaderSize, data + size)};
}

bool IsUplink(MessageType type)
{
    return type == MessageType::NAS_UPLINK || type == MessageType::DATA_UPLINK || type == MessageType::BEARER_READY;
}

bool IsDownlink(MessageType type)
{
    return type == MessageType::NAS_DOWNLINK || type == MessageType::DATA_DOWNLINK ||
           type == MessageType::BEARER_RELEASED;
}

} // namespace lte::ue::link
