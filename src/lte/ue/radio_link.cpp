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
           type == MessageType::BEARER_READY || type == MessageType::BEARER_RELEASED ||
           type == MessageType::S1_CONTEXT_RELEASE_REQUEST || type == MessageType::S1_CONTEXT_RELEASED ||
           type == MessageType::S1_CONTEXT_RESTORED || type == MessageType::SERVICE_REQUEST ||
           type == MessageType::PAGING_INDICATION || type == MessageType::DATA_UPLINK_BEARER ||
           type == MessageType::DATA_DOWNLINK_BEARER || type == MessageType::BEARER_ACTIVATED ||
           type == MessageType::DEDICATED_BEARER_RESTORED || type == MessageType::BEARER_TRANSPORT_READY ||
           type == MessageType::EPS_SESSION_DELETED;
}

size_t MaximumPayload(MessageType type)
{
    if (type == MessageType::NAS_UPLINK || type == MessageType::NAS_DOWNLINK)
        return MaxNasPduSize;
    if (type == MessageType::DATA_UPLINK || type == MessageType::DATA_DOWNLINK)
        return MaxDataPduSize;
    // One octet of EPS bearer identity precedes the IPv4 payload.
    if (type == MessageType::DATA_UPLINK_BEARER || type == MessageType::DATA_DOWNLINK_BEARER)
        return MaxDataPduSize + 1U;
    if (type == MessageType::S1_CONTEXT_RELEASED || type == MessageType::S1_CONTEXT_RESTORED ||
        type == MessageType::DEDICATED_BEARER_RESTORED || type == MessageType::BEARER_TRANSPORT_READY ||
        type == MessageType::EPS_SESSION_DELETED)
        return 5;
    if (type == MessageType::BEARER_ACTIVATED)
        return 1;
    if (type == MessageType::BEARER_READY)
        return 5;
    if (type == MessageType::SERVICE_REQUEST)
        return 9;
    if (type == MessageType::PAGING_INDICATION)
        return 7;
    return 1;
}
}

std::vector<uint8_t> Encode(const Message &message)
{
    if (!IsKnown(message.type) || message.ueId == 0 || message.payload.empty() ||
        message.payload.size() > MaximumPayload(message.type) ||
        (message.type == MessageType::BEARER_READY && message.payload.size() != 5) ||
        (message.type == MessageType::SERVICE_REQUEST && message.payload.size() != 9) ||
        (message.type == MessageType::PAGING_INDICATION && message.payload.size() != 7) ||
        ((message.type == MessageType::BEARER_RELEASED ||
          message.type == MessageType::S1_CONTEXT_RELEASE_REQUEST ||
          message.type == MessageType::BEARER_ACTIVATED) && message.payload.size() != 1))
        throw DecodeError("Invalid LTE radio-link message");
    if ((message.type == MessageType::S1_CONTEXT_RELEASED || message.type == MessageType::S1_CONTEXT_RESTORED) &&
        message.payload.size() != 1 && message.payload.size() != 5)
        throw DecodeError("Invalid S1 restoration payload length");
    if (message.type == MessageType::DEDICATED_BEARER_RESTORED || message.type == MessageType::BEARER_TRANSPORT_READY ||
        message.type == MessageType::EPS_SESSION_DELETED)
        DecodeBearerRestoration(message.payload);
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
        (type == MessageType::SERVICE_REQUEST && length != 9) ||
        (type == MessageType::PAGING_INDICATION && length != 7) ||
        ((type == MessageType::BEARER_RELEASED || type == MessageType::S1_CONTEXT_RELEASE_REQUEST ||
          type == MessageType::BEARER_ACTIVATED) && length != 1))
        throw DecodeError("Malformed LTE radio-link payload length");
    if ((type == MessageType::S1_CONTEXT_RELEASED || type == MessageType::S1_CONTEXT_RESTORED) &&
        length != 1 && length != 5)
        throw DecodeError("Malformed S1 restoration payload length");
    if (type == MessageType::DEDICATED_BEARER_RESTORED || type == MessageType::BEARER_TRANSPORT_READY ||
        type == MessageType::EPS_SESSION_DELETED)
        DecodeBearerRestoration(std::vector<uint8_t>(data + HeaderSize, data + size));
    uint32_t ueId = (static_cast<uint32_t>(data[2]) << 24U) | (static_cast<uint32_t>(data[3]) << 16U) |
                    (static_cast<uint32_t>(data[4]) << 8U) | data[5];
    if (ueId == 0)
        throw DecodeError("Invalid LTE radio-link UE identity");
    return {type, ueId, std::vector<uint8_t>(data + HeaderSize, data + size)};
}

std::vector<uint8_t> EncodeBearerRestoration(uint8_t ebi, uint32_t generation)
{
    if (ebi < 5 || ebi > 15)
        throw DecodeError("Invalid restoration EBI");
    return {ebi, static_cast<uint8_t>(generation >> 24U), static_cast<uint8_t>(generation >> 16U),
            static_cast<uint8_t>(generation >> 8U), static_cast<uint8_t>(generation)};
}

std::pair<uint8_t, uint32_t> DecodeBearerRestoration(const std::vector<uint8_t> &payload)
{
    if (payload.size() != 5 || payload[0] < 5 || payload[0] > 15)
        throw DecodeError("Invalid bearer restoration payload");
    return {payload[0], (static_cast<uint32_t>(payload[1]) << 24U) |
            (static_cast<uint32_t>(payload[2]) << 16U) | (static_cast<uint32_t>(payload[3]) << 8U) | payload[4]};
}

bool IsUplink(MessageType type)
{
    return type == MessageType::NAS_UPLINK || type == MessageType::DATA_UPLINK || type == MessageType::BEARER_READY ||
           type == MessageType::DATA_UPLINK_BEARER || type == MessageType::BEARER_ACTIVATED ||
           type == MessageType::BEARER_TRANSPORT_READY || type == MessageType::EPS_SESSION_DELETED ||
           type == MessageType::S1_CONTEXT_RELEASE_REQUEST || type == MessageType::SERVICE_REQUEST;
}

bool IsDownlink(MessageType type)
{
    return type == MessageType::NAS_DOWNLINK || type == MessageType::DATA_DOWNLINK ||
           type == MessageType::DATA_DOWNLINK_BEARER || type == MessageType::BEARER_RELEASED ||
           type == MessageType::S1_CONTEXT_RELEASED || type == MessageType::S1_CONTEXT_RESTORED ||
           type == MessageType::PAGING_INDICATION || type == MessageType::DEDICATED_BEARER_RESTORED;
}

std::vector<uint8_t> EncodePagingNotification(const PagingNotification &notification)
{
    if (notification.mTmsi == 0)
        throw DecodeError("A paging notification cannot carry a zero M-TMSI");
    std::vector<uint8_t> payload(7);
    payload[0] = notification.mmeCode;
    payload[1] = static_cast<uint8_t>(notification.mTmsi >> 24U);
    payload[2] = static_cast<uint8_t>(notification.mTmsi >> 16U);
    payload[3] = static_cast<uint8_t>(notification.mTmsi >> 8U);
    payload[4] = static_cast<uint8_t>(notification.mTmsi);
    payload[5] = static_cast<uint8_t>(notification.tac >> 8U);
    payload[6] = static_cast<uint8_t>(notification.tac);
    return payload;
}

PagingNotification DecodePagingNotification(const uint8_t *data, size_t size)
{
    if (data == nullptr || size != 7)
        throw DecodeError("A paging notification must be exactly seven octets");
    PagingNotification notification{};
    notification.mmeCode = data[0];
    notification.mTmsi = (static_cast<uint32_t>(data[1]) << 24U) | (static_cast<uint32_t>(data[2]) << 16U) |
                         (static_cast<uint32_t>(data[3]) << 8U) | data[4];
    notification.tac = Read16(data + 5);
    if (notification.mTmsi == 0)
        throw DecodeError("A paging notification carries a zero M-TMSI");
    return notification;
}

} // namespace lte::ue::link
