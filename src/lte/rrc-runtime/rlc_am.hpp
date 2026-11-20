//
// This file is a part of UERANSIM project.
// Copyright (c) 2027 ALİ GÜNGÖR.
//

// Phase 18-F-B6-B1: the LTE (TS 36.322 Release 18) RLC AM wire codec.
//
// Separate from the NR wire format of src/lib/rlc: the field layouts differ
// (LTE uses D/C|RF|P|FI|E|SN(10) with an E/LI chain, and a four-bit
// D/C|CPT STATUS header), so this codec is its own translation unit and the NR
// encoder is untouched.
#pragma once

#include <cstdint>
#include <optional>
#include <stdexcept>
#include <string>
#include <vector>

namespace lte::rlc::am
{

constexpr uint16_t SnModulus = 1024;
constexpr uint16_t AmWindow = 512;
constexpr uint16_t SoMax = 0x7FFF;

enum class CodecError : uint8_t
{
    TRUNCATED,
    BAD_DC,
    BAD_RF,
    RESERVED_LI,
    PADDING_NOT_ZERO,
    TOO_MANY_LIS,
    BAD_SN,
    BAD_SO,
    BAD_NACK,
};

const char *ToString(CodecError error);

class CodecException : public std::runtime_error
{
  public:
    explicit CodecException(CodecError reason);

    [[nodiscard]] CodecError Reason() const noexcept
    {
        return reason_;
    }

  private:
    CodecError reason_;
};

// FI as TS 36.322 6.2.2.6 defines it.
enum class FramingInfo : uint8_t
{
    COMPLETE = 0,        // 00: both boundaries
    FIRST_SEGMENT = 1,   // 01
    LAST_SEGMENT = 2,    // 10
    MIDDLE_SEGMENT = 3,  // 11
};

struct AmdPdu
{
    uint16_t sn{0};
    bool poll{false};
    FramingInfo fi{FramingInfo::COMPLETE};
    // The Data field, already concatenated. The LI chain describes how it is
    // split into SDU elements.
    std::vector<uint8_t> data{};
    // Empty means a single element with no LI (E = 0).
    std::vector<uint16_t> li{};

    // Segment fields, used only when segment is true (RF = 1).
    bool segment{false};
    uint16_t so{0};
    bool lsf{false};
};

// Encodes the PDU with the exact LTE bit layout, including the four padding
// bits after an odd number of E/LI elements.
[[nodiscard]] std::vector<uint8_t> EncodeAmd(const AmdPdu &pdu);

// Decodes and validates: D/C, RF consistency, SN range, LI sum against the Data
// length, and non-zero padding. A malformed PDU is refused, never repaired.
[[nodiscard]] bool DecodeAmd(const uint8_t *data, size_t size, AmdPdu &out, std::string *why);

struct StatusNack
{
    uint16_t sn{0};
    std::optional<std::pair<uint16_t, uint16_t>> soRange{};
};

struct StatusPdu
{
    uint16_t ackSn{0};
    std::vector<StatusNack> nacks{};
};

[[nodiscard]] std::vector<uint8_t> EncodeStatus(const StatusPdu &pdu);
[[nodiscard]] bool DecodeStatus(const uint8_t *data, size_t size, StatusPdu &out, std::string *why);

} // namespace lte::rlc::am
