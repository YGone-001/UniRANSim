//
// This file is a part of UERANSIM project.
// Copyright (c) 2027 ALİ GÜNGÖR.
//
// https://github.com/aligungr/UERANSIM/
// See README, LICENSE, and CONTRIBUTING files for licensing details.
//

// Phase 18-F-B5: the three TS 36.331 SecurityMode messages, encoded and decoded
// with the accepted LTE RRC UPER codec. No NR definition, no simulator frame.
#pragma once

#include <cstddef>
#include <cstdint>
#include <string>
#include <vector>

namespace lte::security
{

struct SecurityModeCommandMessage
{
    uint8_t transactionId{0};
    uint8_t cipheringAlgorithm{0};
    uint8_t integrityAlgorithm{0};
};

struct SecurityModeCompleteMessage
{
    uint8_t transactionId{0};
};

struct SecurityModeFailureMessage
{
    uint8_t transactionId{0};
};

// Transaction identifiers are 2 bits in TS 36.331.
constexpr uint8_t MaxRrcTransactionId = 3;

// Each encode refuses an out-of-range field rather than truncating it.
[[nodiscard]] std::vector<uint8_t> EncodeSecurityModeCommand(const SecurityModeCommandMessage &message);
[[nodiscard]] std::vector<uint8_t> EncodeSecurityModeComplete(const SecurityModeCompleteMessage &message);
[[nodiscard]] std::vector<uint8_t> EncodeSecurityModeFailure(const SecurityModeFailureMessage &message);

// Each decode returns false for a malformed or wrong-type PDU, and leaves the
// output untouched in that case.
[[nodiscard]] bool DecodeSecurityModeCommand(const uint8_t *data, size_t size, SecurityModeCommandMessage &out);
[[nodiscard]] bool DecodeSecurityModeComplete(const uint8_t *data, size_t size, SecurityModeCompleteMessage &out);
[[nodiscard]] bool DecodeSecurityModeFailure(const uint8_t *data, size_t size, SecurityModeFailureMessage &out);

} // namespace lte::security
