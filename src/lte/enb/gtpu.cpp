//
// This file is a part of UERANSIM project.
// Copyright (c) 2027 ALİ GÜNGÖR.
//
// https://github.com/aligungr/UERANSIM/
// See README, LICENSE, and CONTRIBUTING files for licensing details.
//

#include "gtpu.hpp"

#include <algorithm>
#include <array>

namespace lte::enb::gtpu
{
namespace
{
constexpr uint8_t VersionMask = 0xE0;
constexpr uint8_t VersionOne = 0x20;
constexpr uint8_t ProtocolType = 0x10;
constexpr uint8_t ExtensionFlag = 0x04;
constexpr uint8_t SequenceFlag = 0x02;
constexpr uint8_t NPduFlag = 0x01;
constexpr size_t BasicHeaderSize = 8;
constexpr size_t OptionalFieldsSize = 4;

uint16_t Read16(const uint8_t *p)
{
    return static_cast<uint16_t>((static_cast<uint16_t>(p[0]) << 8U) | p[1]);
}

uint32_t Read32(const uint8_t *p)
{
    return (static_cast<uint32_t>(p[0]) << 24U) | (static_cast<uint32_t>(p[1]) << 16U) |
           (static_cast<uint32_t>(p[2]) << 8U) | p[3];
}

void Write16(std::vector<uint8_t> &out, size_t offset, size_t value)
{
    out[offset] = static_cast<uint8_t>((value >> 8U) & 0xFFU);
    out[offset + 1] = static_cast<uint8_t>(value & 0xFFU);
}

void Write32(std::vector<uint8_t> &out, size_t offset, uint32_t value)
{
    out[offset] = static_cast<uint8_t>(value >> 24U);
    out[offset + 1] = static_cast<uint8_t>(value >> 16U);
    out[offset + 2] = static_cast<uint8_t>(value >> 8U);
    out[offset + 3] = static_cast<uint8_t>(value);
}

bool IsSupportedExtension(uint8_t type)
{
    // Types defined for GTP-U payload metadata in TS 29.281. Unknown types are
    // rejected instead of guessing where an inner IPv4 packet begins.
    constexpr std::array<uint8_t, 5> supported{{0x40, 0x85, 0xC0, 0xC1, 0xC2}};
    return std::find(supported.begin(), supported.end(), type) != supported.end();
}
} // namespace

std::vector<uint8_t> EncodeTPdu(uint32_t teid, const uint8_t *payload, size_t payloadSize)
{
    if (teid == 0)
        throw CodecError("A GTP-U T-PDU requires a non-zero TEID");
    if (payload == nullptr || payloadSize == 0 || payloadSize > 0xFFFFU)
        throw CodecError("Invalid GTP-U T-PDU payload length");

    std::vector<uint8_t> out(BasicHeaderSize + payloadSize);
    out[0] = VersionOne | ProtocolType;
    out[1] = TPdu;
    Write16(out, 2, payloadSize);
    Write32(out, 4, teid);
    std::copy(payload, payload + payloadSize, out.begin() + BasicHeaderSize);
    return out;
}

Packet Decode(const uint8_t *data, size_t size)
{
    if (data == nullptr || size < BasicHeaderSize)
        throw CodecError("Truncated GTP-U header");
    if ((data[0] & VersionMask) != VersionOne)
        throw CodecError("Unsupported GTP-U version");
    if ((data[0] & ProtocolType) == 0)
        throw CodecError("GTP-U protocol-type bit is not set");
    if ((data[0] & 0x08U) != 0)
        throw CodecError("Reserved GTP-U flag is set");
    if (data[1] != TPdu && data[1] != EchoRequest && data[1] != EchoResponse)
        throw CodecError("Unsupported GTP-U message type");

    const size_t declaredLength = Read16(data + 2);
    if (declaredLength != size - BasicHeaderSize)
        throw CodecError("GTP-U declared length does not match the datagram");

    Packet result{};
    result.messageType = data[1];
    result.teid = Read32(data + 4);
    size_t offset = BasicHeaderSize;

    const bool hasExtension = (data[0] & ExtensionFlag) != 0;
    const bool hasSequence = (data[0] & SequenceFlag) != 0;
    const bool hasNPdu = (data[0] & NPduFlag) != 0;
    if (hasExtension || hasSequence || hasNPdu)
    {
        if (size - offset < OptionalFieldsSize)
            throw CodecError("Truncated GTP-U optional fields");
        if (hasSequence)
            result.sequenceNumber = Read16(data + offset);
        if (hasNPdu)
            result.npduNumber = data[offset + 2];
        uint8_t nextExtension = data[offset + 3];
        offset += OptionalFieldsSize;

        if (!hasExtension && nextExtension != 0)
            throw CodecError("GTP-U next-extension value is present without the E flag");
        if (hasExtension && nextExtension == 0)
            throw CodecError("GTP-U E flag is set without an extension header");

        size_t extensionCount = 0;
        while (nextExtension != 0)
        {
            if (++extensionCount > 16)
                throw CodecError("GTP-U extension-header chain is too long");
            if (!IsSupportedExtension(nextExtension))
                throw CodecError("Unsupported GTP-U extension-header type");
            if (offset >= size)
                throw CodecError("Truncated GTP-U extension header");
            const size_t extensionSize = static_cast<size_t>(data[offset]) * 4U;
            if (extensionSize < 4 || extensionSize > size - offset)
                throw CodecError("Malformed GTP-U extension header");
            result.extensionTypes.push_back(nextExtension);
            nextExtension = data[offset + extensionSize - 1];
            offset += extensionSize;
        }
    }

    if (result.messageType == TPdu)
    {
        if (result.teid == 0)
            throw CodecError("GTP-U T-PDU has a zero TEID");
        if (offset == size)
            throw CodecError("GTP-U T-PDU has no payload");
    }
    else if (result.teid != 0)
    {
        throw CodecError("GTP-U Echo message has a non-zero TEID");
    }

    result.payload.assign(data + offset, data + size);
    return result;
}

std::vector<uint8_t> EncodeEchoResponse(uint16_t sequenceNumber)
{
    // S flag, four-octet optional block, then the two-octet Recovery TV IE.
    std::vector<uint8_t> out{static_cast<uint8_t>(VersionOne | ProtocolType | SequenceFlag), EchoResponse,
                             0x00, 0x06, 0x00, 0x00, 0x00, 0x00,
                             static_cast<uint8_t>(sequenceNumber >> 8U), static_cast<uint8_t>(sequenceNumber), 0x00,
                             0x00, 0x0E, 0x00};
    return out;
}

} // namespace lte::enb::gtpu
