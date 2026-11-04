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

// TS 29.281 figure 8.6-1 fixes the Private Extension wire layout, identically
// in V9.3.0 and V14.0.0:
//
//   octet 1     Type = 255
//   octets 2-3  Length              (16-bit, network byte order)
//   octets 4-5  Extension Identifier (16-bit, network byte order)
//   octets 6-m  Extension Value     (variable, opaque vendor data)
//
// Section 8.1 defines Length as the size of the information element excluding
// Type and Length themselves, so Length counts the Extension Identifier and the
// whole Extension Value and is therefore at least two. The information element
// occupies 3 + Length octets in total. Section 8.6 permits more than one
// Private Extension in a message, so the walk repeats.
//
// An empty information-element area is the ordinary form of an End Marker.
// Anything else cannot be interpreted safely and is rejected rather than
// guessed at: the information elements of a control message are never
// user-plane payload, and the Extension Identifier is an IANA Private
// Enterprise Number, not a TEID, a bearer identifier or a UE identifier. The
// Extension Value is vendor-specific and is never read as an IP packet.
void ValidateEndMarkerIes(const uint8_t *ies, size_t size)
{
    size_t offset = 0;
    while (offset < size)
    {
        // Type and the two Length octets must all be present before anything
        // can be said about the information element at all.
        if (size - offset < 3)
            throw CodecError("Truncated GTP-U End Marker information element");
        if (ies[offset] != PrivateExtensionType)
            throw CodecError("Unsupported GTP-U End Marker information element");
        // `length` is at most 0xFFFF and `total` therefore at most 65538, so
        // neither the addition nor the comparison below can overflow size_t.
        const size_t length = Read16(ies + offset + 1);
        if (length < 2)
            throw CodecError("GTP-U Private Extension is shorter than its Extension Identifier");
        const size_t total = 3 + length;
        if (total > size - offset)
            throw CodecError("Truncated GTP-U End Marker information element");
        // Structurally consumed only: a vendor/enterprise number that carries
        // no meaning this eNB must act on.
        (void)Read16(ies + offset + 3);
        offset += total;
    }
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
    if (data[1] != TPdu && data[1] != EndMarker && data[1] != EchoRequest && data[1] != EchoResponse)
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

    // Strict LTE compatibility profile for the End Marker.
    //
    // TS 29.281 V14.0.0 (Release 14) §5.1, Sequence number flag (S): "In an End
    // marker message the S flag shall be set to '0'." V9.3.0 (Release 9) §5.1
    // has no End Marker rule at all — it names only Echo Request, Echo
    // Response, Error Indication and Supported Extension Headers Notification
    // as messages whose S flag shall be '1', and G-PDUs, where the flag should
    // be '0'. The change history records CR 0033 "End Marker message"
    // (CT#50, 2010-12) as the End Marker change taking 9.3.0 to 10.0.0.
    //
    // So the requirement is a later release's, and it is adopted here
    // deliberately as the receive profile for the LTE EPC End Marker: a
    // conforming Release 14 sender never sets it, and accepting a set flag
    // would fix non-conforming behaviour in place. No runtime switch is offered
    // to keep the older, laxer reading. The E, PN and extension-header rules
    // are unchanged, because no End Marker-specific rule restricts them.
    if (result.messageType == EndMarker && hasSequence)
        throw CodecError("GTP-U End Marker must not carry a sequence number");

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

    result.payload.assign(data + offset, data + size);

    // Each message type carries a different amount of meaning in its TEID and
    // in its remainder, so the rule is chosen per type rather than shared. A
    // G-PDU names a tunnel and carries its payload; an End Marker names the
    // tunnel that is ending and carries only optional information elements;
    // Echo is addressed to the endpoint itself and names no tunnel at all.
    switch (result.messageType)
    {
    case TPdu:
        if (result.teid == 0)
            throw CodecError("GTP-U T-PDU has a zero TEID");
        if (result.payload.empty())
            throw CodecError("GTP-U T-PDU has no payload");
        break;
    case EndMarker:
        if (result.teid == 0)
            throw CodecError("GTP-U End Marker has a zero TEID");
        // Table 7.3.2-1 admits only the optional Private Extension. The
        // information-element area is validated and then withheld from the
        // caller: an End Marker carries no user-plane payload, and publishing
        // its tail as one would let a caller forward the end of a control
        // message to a UE.
        ValidateEndMarkerIes(result.payload.data(), result.payload.size());
        result.payload.clear();
        break;
    case EchoRequest:
    case EchoResponse:
        if (result.teid != 0)
            throw CodecError("GTP-U Echo message has a non-zero TEID");
        break;
    default:
        throw CodecError("Unsupported GTP-U message type");
    }

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
