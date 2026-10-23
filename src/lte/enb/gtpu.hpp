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
constexpr uint8_t TPdu = 255;

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
