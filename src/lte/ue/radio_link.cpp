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
           type == MessageType::EPS_SESSION_DELETED || type == MessageType::S1_ACCESS_LOST ||
           type == MessageType::NAS_UPLINK_MOBILITY || type == MessageType::NAS_UPLINK_MOBILITY_CONTEXT ||
           type == MessageType::SIMULATED_HANDOVER_COMMAND || type == MessageType::SIMULATED_HANDOVER_ACCESS;
}

size_t MaximumPayload(MessageType type)
{
    if (type == MessageType::NAS_UPLINK || type == MessageType::NAS_DOWNLINK)
        return MaxNasPduSize;
    // MMEC || M-TMSI ahead of a full protected NAS PDU.
    if (type == MessageType::NAS_UPLINK_MOBILITY)
        return MaxNasPduSize + 5U;
    // The same identity prefix, then the bounded bearer inventory ahead of the
    // protected NAS PDU.
    if (type == MessageType::NAS_UPLINK_MOBILITY_CONTEXT)
        return MaxNasPduSize + 5U + 2U + MaxDeclaredDedicatedBearers;
    if (type == MessageType::DATA_UPLINK || type == MessageType::DATA_DOWNLINK)
        return MaxDataPduSize;
    // One octet of EPS bearer identity precedes the IPv4 payload.
    if (type == MessageType::DATA_UPLINK_BEARER || type == MessageType::DATA_DOWNLINK_BEARER)
        return MaxDataPduSize + 1U;
    if (type == MessageType::S1_CONTEXT_RELEASED || type == MessageType::S1_CONTEXT_RESTORED ||
        type == MessageType::DEDICATED_BEARER_RESTORED ||
        type == MessageType::EPS_SESSION_DELETED || type == MessageType::S1_ACCESS_LOST)
        return 5;
    // A bearer transport confirmation may additionally restate the PDN address.
    if (type == MessageType::BEARER_TRANSPORT_READY)
        return 9;
    if (type == MessageType::BEARER_ACTIVATED)
        return 1;
    if (type == MessageType::BEARER_READY)
        return 5;
    if (type == MessageType::SERVICE_REQUEST)
        return 9;
    if (type == MessageType::PAGING_INDICATION)
        return 7;
    // The two simulated handover-control payloads are fixed-width and carry
    // nothing variable: a command names one cell and one binding, an access
    // repeats the binding and names both cells.
    if (type == MessageType::SIMULATED_HANDOVER_COMMAND)
        return SimulatedHandoverCommandSize;
    if (type == MessageType::SIMULATED_HANDOVER_ACCESS)
        return SimulatedHandoverAccessSize;
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
        (message.type == MessageType::NAS_UPLINK_MOBILITY && message.payload.size() <= 5) ||
        (message.type == MessageType::NAS_UPLINK_MOBILITY_CONTEXT && message.payload.size() <= 7) ||
        ((message.type == MessageType::BEARER_RELEASED ||
          message.type == MessageType::S1_CONTEXT_RELEASE_REQUEST ||
          message.type == MessageType::BEARER_ACTIVATED) && message.payload.size() != 1) ||
        (message.type == MessageType::SIMULATED_HANDOVER_COMMAND &&
         message.payload.size() != SimulatedHandoverCommandSize) ||
        (message.type == MessageType::SIMULATED_HANDOVER_ACCESS &&
         message.payload.size() != SimulatedHandoverAccessSize))
        throw DecodeError("Invalid LTE radio-link message");
    if ((message.type == MessageType::S1_CONTEXT_RELEASED || message.type == MessageType::S1_CONTEXT_RESTORED) &&
        message.payload.size() != 1 && message.payload.size() != 5)
        throw DecodeError("Invalid S1 restoration payload length");
    if (message.type == MessageType::DEDICATED_BEARER_RESTORED ||
        message.type == MessageType::EPS_SESSION_DELETED || message.type == MessageType::S1_ACCESS_LOST)
        DecodeBearerRestoration(message.payload);
    if (message.type == MessageType::BEARER_TRANSPORT_READY)
        DecodeBearerTransportReady(message.payload.data(), message.payload.size());
    if (message.type == MessageType::NAS_UPLINK_MOBILITY_CONTEXT)
    {
        BearerInventory inventory{};
        const size_t consumed = DecodeBearerInventory(message.payload.data() + 5, message.payload.size() - 5, inventory);
        if (consumed + 1 > message.payload.size() - 5)
            throw DecodeError("A mobility uplink context carries no protected NAS");
    }
    if (message.type == MessageType::SIMULATED_HANDOVER_COMMAND)
        DecodeSimulatedHandoverCommand(message.payload.data(), message.payload.size());
    if (message.type == MessageType::SIMULATED_HANDOVER_ACCESS)
        DecodeSimulatedHandoverAccess(message.payload.data(), message.payload.size());
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
        (type == MessageType::NAS_UPLINK_MOBILITY && length <= 5) ||
        (type == MessageType::NAS_UPLINK_MOBILITY_CONTEXT && length <= 7) ||
        ((type == MessageType::BEARER_RELEASED || type == MessageType::S1_CONTEXT_RELEASE_REQUEST ||
          type == MessageType::BEARER_ACTIVATED) && length != 1) ||
        (type == MessageType::SIMULATED_HANDOVER_COMMAND && length != SimulatedHandoverCommandSize) ||
        (type == MessageType::SIMULATED_HANDOVER_ACCESS && length != SimulatedHandoverAccessSize))
        throw DecodeError("Malformed LTE radio-link payload length");
    if ((type == MessageType::S1_CONTEXT_RELEASED || type == MessageType::S1_CONTEXT_RESTORED) &&
        length != 1 && length != 5)
        throw DecodeError("Malformed S1 restoration payload length");
    if (type == MessageType::DEDICATED_BEARER_RESTORED ||
        type == MessageType::EPS_SESSION_DELETED || type == MessageType::S1_ACCESS_LOST)
        DecodeBearerRestoration(std::vector<uint8_t>(data + HeaderSize, data + size));
    if (type == MessageType::BEARER_TRANSPORT_READY)
        DecodeBearerTransportReady(data + HeaderSize, length);
    if (type == MessageType::NAS_UPLINK_MOBILITY_CONTEXT)
    {
        BearerInventory inventory{};
        const size_t consumed = DecodeBearerInventory(data + HeaderSize + 5, length - 5, inventory);
        if (consumed + 1 > length - 5)
            throw DecodeError("A mobility uplink context carries no protected NAS");
    }
    if (type == MessageType::SIMULATED_HANDOVER_COMMAND)
        DecodeSimulatedHandoverCommand(data + HeaderSize, length);
    if (type == MessageType::SIMULATED_HANDOVER_ACCESS)
        DecodeSimulatedHandoverAccess(data + HeaderSize, length);
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

std::vector<uint8_t> EncodeBearerTransportReady(uint8_t ebi, uint32_t generation,
                                                const std::array<uint8_t, 4> &ueIpv4)
{
    auto payload = EncodeBearerRestoration(ebi, generation);
    if (ueIpv4 == std::array<uint8_t, 4>{} || ueIpv4[0] == 0 || ueIpv4[0] >= 224)
        throw DecodeError("Invalid restated UE IPv4 address");
    payload.insert(payload.end(), ueIpv4.begin(), ueIpv4.end());
    return payload;
}

BearerTransportReady DecodeBearerTransportReady(const uint8_t *data, size_t size)
{
    if (data == nullptr || (size != 5 && size != 9))
        throw DecodeError("Invalid bearer transport confirmation payload");
    const auto restored = DecodeBearerRestoration(std::vector<uint8_t>(data, data + 5));
    BearerTransportReady ready{};
    ready.ebi = restored.first;
    ready.generation = restored.second;
    if (size == 9)
    {
        const std::array<uint8_t, 4> address{{data[5], data[6], data[7], data[8]}};
        if (address[0] == 0 || address[0] >= 224)
            throw DecodeError("Invalid restated UE IPv4 address");
        ready.ueIpv4 = address;
    }
    return ready;
}

std::vector<uint8_t> EncodeBearerInventory(const BearerInventory &inventory)
{
    if (inventory.defaultEbi < 5 || inventory.defaultEbi > 15)
        throw DecodeError("Invalid declared default bearer identity");
    if (inventory.dedicatedEbis.size() > MaxDeclaredDedicatedBearers)
        throw DecodeError("Too many declared dedicated bearer identities");
    std::vector<uint8_t> payload;
    payload.reserve(2 + inventory.dedicatedEbis.size());
    payload.push_back(inventory.defaultEbi);
    payload.push_back(static_cast<uint8_t>(inventory.dedicatedEbis.size()));
    uint8_t previous = inventory.defaultEbi;
    for (const uint8_t ebi : inventory.dedicatedEbis)
    {
        if (ebi < 5 || ebi > 15 || ebi == inventory.defaultEbi || ebi <= previous)
            throw DecodeError("Invalid declared dedicated bearer identity");
        payload.push_back(ebi);
        previous = ebi;
    }
    return payload;
}

size_t DecodeBearerInventory(const uint8_t *data, size_t size, BearerInventory &inventory)
{
    if (data == nullptr || size < 2)
        throw DecodeError("Truncated bearer inventory");
    const uint8_t defaultEbi = data[0];
    const uint8_t count = data[1];
    if (defaultEbi < 5 || defaultEbi > 15)
        throw DecodeError("Invalid declared default bearer identity");
    if (count > MaxDeclaredDedicatedBearers || size < 2U + count)
        throw DecodeError("Truncated bearer inventory");
    BearerInventory decoded{};
    decoded.defaultEbi = defaultEbi;
    decoded.dedicatedEbis.reserve(count);
    uint8_t previous = defaultEbi;
    for (uint8_t i = 0; i < count; ++i)
    {
        const uint8_t ebi = data[2 + i];
        if (ebi < 5 || ebi > 15 || ebi == defaultEbi || ebi <= previous)
            throw DecodeError("Invalid declared dedicated bearer identity");
        decoded.dedicatedEbis.push_back(ebi);
        previous = ebi;
    }
    inventory = std::move(decoded);
    return 2U + count;
}

Message BuildMobilityContext(uint32_t ueId, const std::array<uint8_t, 11> &guti, const BearerInventory &inventory,
                             const std::vector<uint8_t> &protectedNas)
{
    if (protectedNas.empty())
        throw DecodeError("A mobility uplink context must carry a protected NAS");
    // The declaration is encoded first, so an inventory the wire cannot express
    // is refused before any frame exists rather than after one has been sent.
    const auto declared = EncodeBearerInventory(inventory);
    std::vector<uint8_t> payload;
    payload.reserve(5 + declared.size() + protectedNas.size());
    payload.push_back(guti[6]);
    payload.insert(payload.end(), guti.begin() + 7, guti.end());
    payload.insert(payload.end(), declared.begin(), declared.end());
    payload.insert(payload.end(), protectedNas.begin(), protectedNas.end());
    return {MessageType::NAS_UPLINK_MOBILITY_CONTEXT, ueId, std::move(payload)};
}

std::vector<uint8_t> EncodeSimulatedHandoverCommand(const SimulatedHandoverCommand &command)
{
    if (command.arrivalToken == 0)
        throw DecodeError("A simulated handover command carries no arrival binding");
    if (command.targetEnbId == 0)
        throw DecodeError("A simulated handover command names no target eNB");
    if (command.mmeUeS1apId == 0)
        throw DecodeError("A simulated handover command names no UE");
    if (command.ueIpv4 == std::array<uint8_t, 4>{})
        throw DecodeError("A simulated handover command names no UE address");
    std::vector<uint8_t> payload(SimulatedHandoverCommandSize);
    std::copy(command.targetPlmn.begin(), command.targetPlmn.end(), payload.begin());
    payload[3] = static_cast<uint8_t>(command.targetEnbId >> 24U);
    payload[4] = static_cast<uint8_t>(command.targetEnbId >> 16U);
    payload[5] = static_cast<uint8_t>(command.targetEnbId >> 8U);
    payload[6] = static_cast<uint8_t>(command.targetEnbId);
    payload[7] = static_cast<uint8_t>(command.targetTac >> 8U);
    payload[8] = static_cast<uint8_t>(command.targetTac);
    payload[9] = static_cast<uint8_t>(command.arrivalToken >> 24U);
    payload[10] = static_cast<uint8_t>(command.arrivalToken >> 16U);
    payload[11] = static_cast<uint8_t>(command.arrivalToken >> 8U);
    payload[12] = static_cast<uint8_t>(command.arrivalToken);
    payload[13] = static_cast<uint8_t>(command.mmeUeS1apId >> 24U);
    payload[14] = static_cast<uint8_t>(command.mmeUeS1apId >> 16U);
    payload[15] = static_cast<uint8_t>(command.mmeUeS1apId >> 8U);
    payload[16] = static_cast<uint8_t>(command.mmeUeS1apId);
    std::copy(command.ueIpv4.begin(), command.ueIpv4.end(), payload.begin() + 17);
    return payload;
}

SimulatedHandoverCommand DecodeSimulatedHandoverCommand(const uint8_t *data, size_t size)
{
    if (data == nullptr || size != SimulatedHandoverCommandSize)
        throw DecodeError("A simulated handover command is exactly twenty-one octets");
    SimulatedHandoverCommand command{};
    std::copy(data, data + 3, command.targetPlmn.begin());
    command.targetEnbId = (static_cast<uint32_t>(data[3]) << 24U) | (static_cast<uint32_t>(data[4]) << 16U) |
                          (static_cast<uint32_t>(data[5]) << 8U) | data[6];
    command.targetTac = Read16(data + 7);
    command.arrivalToken = (static_cast<uint32_t>(data[9]) << 24U) | (static_cast<uint32_t>(data[10]) << 16U) |
                           (static_cast<uint32_t>(data[11]) << 8U) | data[12];
    command.mmeUeS1apId = (static_cast<uint32_t>(data[13]) << 24U) | (static_cast<uint32_t>(data[14]) << 16U) |
                          (static_cast<uint32_t>(data[15]) << 8U) | data[16];
    std::copy(data + 17, data + 21, command.ueIpv4.begin());
    if (command.arrivalToken == 0)
        throw DecodeError("A simulated handover command carries no arrival binding");
    if (command.targetEnbId == 0)
        throw DecodeError("A simulated handover command names no target eNB");
    if (command.mmeUeS1apId == 0)
        throw DecodeError("A simulated handover command names no UE");
    if (command.ueIpv4 == std::array<uint8_t, 4>{})
        throw DecodeError("A simulated handover command names no UE address");
    return command;
}

std::vector<uint8_t> EncodeSimulatedHandoverAccess(const SimulatedHandoverAccess &access)
{
    if (access.arrivalToken == 0)
        throw DecodeError("A simulated handover access carries no arrival binding");
    if (access.sourceEnbId == 0 || access.targetEnbId == 0)
        throw DecodeError("A simulated handover access names no eNB");
    if (access.mmeUeS1apId == 0)
        throw DecodeError("A simulated handover access names no UE");
    if (access.ueIpv4 == std::array<uint8_t, 4>{})
        throw DecodeError("A simulated handover access names no UE address");
    std::vector<uint8_t> payload(SimulatedHandoverAccessSize);
    payload[0] = static_cast<uint8_t>(access.arrivalToken >> 24U);
    payload[1] = static_cast<uint8_t>(access.arrivalToken >> 16U);
    payload[2] = static_cast<uint8_t>(access.arrivalToken >> 8U);
    payload[3] = static_cast<uint8_t>(access.arrivalToken);
    std::copy(access.sourcePlmn.begin(), access.sourcePlmn.end(), payload.begin() + 4);
    payload[7] = static_cast<uint8_t>(access.sourceEnbId >> 24U);
    payload[8] = static_cast<uint8_t>(access.sourceEnbId >> 16U);
    payload[9] = static_cast<uint8_t>(access.sourceEnbId >> 8U);
    payload[10] = static_cast<uint8_t>(access.sourceEnbId);
    payload[11] = static_cast<uint8_t>(access.sourceTac >> 8U);
    payload[12] = static_cast<uint8_t>(access.sourceTac);
    std::copy(access.targetPlmn.begin(), access.targetPlmn.end(), payload.begin() + 13);
    payload[16] = static_cast<uint8_t>(access.targetEnbId >> 24U);
    payload[17] = static_cast<uint8_t>(access.targetEnbId >> 16U);
    payload[18] = static_cast<uint8_t>(access.targetEnbId >> 8U);
    payload[19] = static_cast<uint8_t>(access.targetEnbId);
    payload[20] = static_cast<uint8_t>(access.targetTac >> 8U);
    payload[21] = static_cast<uint8_t>(access.targetTac);
    payload[22] = static_cast<uint8_t>(access.mmeUeS1apId >> 24U);
    payload[23] = static_cast<uint8_t>(access.mmeUeS1apId >> 16U);
    payload[24] = static_cast<uint8_t>(access.mmeUeS1apId >> 8U);
    payload[25] = static_cast<uint8_t>(access.mmeUeS1apId);
    std::copy(access.ueIpv4.begin(), access.ueIpv4.end(), payload.begin() + 26);
    return payload;
}

SimulatedHandoverAccess DecodeSimulatedHandoverAccess(const uint8_t *data, size_t size)
{
    if (data == nullptr || size != SimulatedHandoverAccessSize)
        throw DecodeError("A simulated handover access is exactly thirty octets");
    SimulatedHandoverAccess access{};
    access.arrivalToken = (static_cast<uint32_t>(data[0]) << 24U) | (static_cast<uint32_t>(data[1]) << 16U) |
                          (static_cast<uint32_t>(data[2]) << 8U) | data[3];
    std::copy(data + 4, data + 7, access.sourcePlmn.begin());
    access.sourceEnbId = (static_cast<uint32_t>(data[7]) << 24U) | (static_cast<uint32_t>(data[8]) << 16U) |
                         (static_cast<uint32_t>(data[9]) << 8U) | data[10];
    access.sourceTac = Read16(data + 11);
    std::copy(data + 13, data + 16, access.targetPlmn.begin());
    access.targetEnbId = (static_cast<uint32_t>(data[16]) << 24U) | (static_cast<uint32_t>(data[17]) << 16U) |
                         (static_cast<uint32_t>(data[18]) << 8U) | data[19];
    access.targetTac = Read16(data + 20);
    access.mmeUeS1apId = (static_cast<uint32_t>(data[22]) << 24U) | (static_cast<uint32_t>(data[23]) << 16U) |
                         (static_cast<uint32_t>(data[24]) << 8U) | data[25];
    std::copy(data + 26, data + 30, access.ueIpv4.begin());
    if (access.arrivalToken == 0)
        throw DecodeError("A simulated handover access carries no arrival binding");
    if (access.sourceEnbId == 0 || access.targetEnbId == 0)
        throw DecodeError("A simulated handover access names no eNB");
    if (access.mmeUeS1apId == 0)
        throw DecodeError("A simulated handover access names no UE");
    if (access.ueIpv4 == std::array<uint8_t, 4>{})
        throw DecodeError("A simulated handover access names no UE address");
    return access;
}

bool IsUplink(MessageType type)
{
    return type == MessageType::NAS_UPLINK || type == MessageType::DATA_UPLINK || type == MessageType::BEARER_READY ||
           type == MessageType::DATA_UPLINK_BEARER || type == MessageType::BEARER_ACTIVATED ||
           type == MessageType::BEARER_TRANSPORT_READY || type == MessageType::EPS_SESSION_DELETED ||
           type == MessageType::S1_CONTEXT_RELEASE_REQUEST || type == MessageType::SERVICE_REQUEST ||
           type == MessageType::NAS_UPLINK_MOBILITY || type == MessageType::NAS_UPLINK_MOBILITY_CONTEXT ||
           type == MessageType::SIMULATED_HANDOVER_ACCESS;
}

bool IsDownlink(MessageType type)
{
    return type == MessageType::NAS_DOWNLINK || type == MessageType::DATA_DOWNLINK ||
           type == MessageType::DATA_DOWNLINK_BEARER || type == MessageType::BEARER_RELEASED ||
           type == MessageType::S1_CONTEXT_RELEASED || type == MessageType::S1_CONTEXT_RESTORED ||
           type == MessageType::PAGING_INDICATION || type == MessageType::DEDICATED_BEARER_RESTORED ||
           type == MessageType::S1_ACCESS_LOST || type == MessageType::SIMULATED_HANDOVER_COMMAND;
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
