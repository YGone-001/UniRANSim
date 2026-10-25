//
// This file is a part of UERANSIM project.
// Copyright (c) 2027 ALİ GÜNGÖR.
//
// https://github.com/aligungr/UERANSIM/
// See README, LICENSE, and CONTRIBUTING files for licensing details.
//

// Minimal, LTE-specific NAS and IPv4 transport between the software UE and eNB.
#pragma once

#include <cstddef>
#include <cstdint>
#include <stdexcept>
#include <vector>

namespace lte::ue::link
{

constexpr size_t MaxNasPduSize = 2048;
constexpr size_t MaxDataPduSize = 4096;
constexpr size_t HeaderSize = 8;

enum class MessageType : uint8_t
{
    NAS_UPLINK = 1,
    NAS_DOWNLINK = 2,
    DATA_UPLINK = 3,
    DATA_DOWNLINK = 4,
    BEARER_READY = 5,
    // Legacy bearer deletion indication. It remains decodable for wire
    // compatibility but is not used for an ordinary S1 context release.
    BEARER_RELEASED = 6,
    S1_CONTEXT_RELEASE_REQUEST = 7,
    S1_CONTEXT_RELEASED = 8,
    S1_CONTEXT_RESTORED = 9,
    // MMEC(1)||M-TMSI(4)||compact Service Request NAS(4).
    SERVICE_REQUEST = 10
};

struct Message
{
    MessageType type{};
    uint32_t ueId{};
    std::vector<uint8_t> payload;
};

class DecodeError : public std::runtime_error
{
  public:
    using std::runtime_error::runtime_error;
};

std::vector<uint8_t> Encode(const Message &message);
Message Decode(const uint8_t *data, size_t size);
bool IsUplink(MessageType type);
bool IsDownlink(MessageType type);

} // namespace lte::ue::link
