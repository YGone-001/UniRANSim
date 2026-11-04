//
// This file is a part of UERANSIM project.
// Copyright (c) 2027 ALİ GÜNGÖR.
//
// https://github.com/aligungr/UERANSIM/
// See README, LICENSE, and CONTRIBUTING files for licensing details.
//

#pragma once

#include <cstddef>
#include <cstdint>
#include <optional>
#include <stdexcept>
#include <vector>

namespace lte::enb::gtpu
{

constexpr uint8_t EchoRequest = 1;
constexpr uint8_t EchoResponse = 2;
// TS 29.281 table 6.1-1. The End Marker names the tunnel whose payload stream
// is ending, so it carries that tunnel's TEID and never a T-PDU. It is a
// control message about a tunnel, not user-plane payload, and it is not a
// handover authorisation.
constexpr uint8_t EndMarker = 254;
constexpr uint8_t TPdu = 255;

// TS 29.281 table 7.3.2-1 lists Private Extension as the only optional
// information element of an End Marker. Its type carries the MSB that marks a
// TLV rather than a TV information element. Figure 8.6-1 gives its layout as
// Type, a 16-bit Length, a 16-bit Extension Identifier and a variable
// Extension Value; section 8.1 makes Length count everything after the Type
// and Length fields, so Length is at least two and the element is 3 + Length
// octets long.
constexpr uint8_t PrivateExtensionType = 0xFF;

struct Packet
{
    uint8_t messageType{};
    uint32_t teid{};
    std::vector<uint8_t> payload;
    std::optional<uint16_t> sequenceNumber;
    std::optional<uint8_t> npduNumber;
    std::vector<uint8_t> extensionTypes;
};

class CodecError : public std::runtime_error
{
  public:
    using std::runtime_error::runtime_error;
};

std::vector<uint8_t> EncodeTPdu(uint32_t teid, const uint8_t *payload, size_t payloadSize);
Packet Decode(const uint8_t *data, size_t size);

// Echo Response includes the request's sequence number and a Recovery IE with
// restart counter zero. GTP-U control messages are never exposed as IP data.
std::vector<uint8_t> EncodeEchoResponse(uint16_t sequenceNumber);

} // namespace lte::enb::gtpu
