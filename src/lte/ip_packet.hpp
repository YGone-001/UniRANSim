//
// This file is a part of UERANSIM project.
// Copyright (c) 2027 ALİ GÜNGÖR.
//
// https://github.com/aligungr/UERANSIM/
// See README, LICENSE, and CONTRIBUTING files for licensing details.
//

#pragma once

#include <array>
#include <cstddef>
#include <cstdint>
#include <stdexcept>

namespace lte::ip
{

constexpr size_t MaximumPacketSize = 4096;

struct PacketInfo
{
    size_t headerLength{};
    size_t totalLength{};
    std::array<uint8_t, 4> source{};
    std::array<uint8_t, 4> destination{};
    // IPv4 protocol identifier from the header. TFT classification needs it;
    // the transport protocol must never be guessed from port numbers.
    uint8_t protocol{};
    bool fragmented{};
};

class ValidationError : public std::runtime_error
{
  public:
    using std::runtime_error::runtime_error;
};

// Validates the structural fields needed by the user-plane forwarder. IPv4
// fragments are permitted and forwarded unchanged; reassembly remains a Linux
// IP-stack responsibility.
PacketInfo Validate(const uint8_t *data, size_t size, size_t maximumSize = MaximumPacketSize);

} // namespace lte::ip
