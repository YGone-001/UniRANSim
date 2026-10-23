//
// This file is a part of UERANSIM project.
// Copyright (c) 2027 ALİ GÜNGÖR.
//
// https://github.com/aligungr/UERANSIM/
// See README, LICENSE, and CONTRIBUTING files for licensing details.
//

// Minimal, LTE-specific NAS transport between the software UE and eNB.
#pragma once

#include <cstddef>
#include <cstdint>
#include <stdexcept>
#include <vector>

namespace lte::ue::link
{

constexpr size_t MaxNasPduSize = 2048;

enum class MessageType : uint8_t
{
    NAS_UPLINK = 1,
    NAS_DOWNLINK = 2
};

struct Message
{
    MessageType type{};
    uint32_t ueId{};
    std::vector<uint8_t> nas;
};

class DecodeError : public std::runtime_error
{
  public:
    using std::runtime_error::runtime_error;
};

std::vector<uint8_t> Encode(const Message &message);
Message Decode(const uint8_t *data, size_t size);

} // namespace lte::ue::link
