//
// This file is a part of UERANSIM project.
// Copyright (c) 2027 ALİ GÜNGÖR.
//

// Phase 18-F-B6-B2: RRCConnectionSetupComplete (TS 36.331 6.2.2) encoded and
// decoded with the generated UL-DCCH ASN.1 definitions.
//
// The message carries an opaque NAS PDU. Nothing here interprets it: the caller
// supplies the bytes and the receiver hands the same bytes to its upper-layer
// callback.
#pragma once

#include <cstddef>
#include <cstdint>
#include <vector>

namespace lte::rrc
{

// DedicatedInfoNAS is an OCTET STRING without an ASN.1 size constraint; the
// transport caps a frame at 2048 bytes, and this keeps the RRC message well
// inside that.
constexpr size_t MaxDedicatedInfoNasBytes = 1500;

struct RrcConnectionSetupCompleteMessage
{
    uint8_t transactionId{0};
    // TS 36.331: selectedPLMN-Identity, 1..6.
    uint8_t selectedPlmnIdentity{1};
    std::vector<uint8_t> dedicatedInfoNas{};
};

// Empty on failure: an invalid transaction id, PLMN or NAS length is refused
// rather than encoded.
[[nodiscard]] std::vector<uint8_t> EncodeRrcConnectionSetupComplete(const RrcConnectionSetupCompleteMessage &message);

// Requires the message to be an RRCConnectionSetupComplete-r8 with a
// transaction id in 0..3, a selected PLMN in 1..6 and a non-empty NAS PDU.
[[nodiscard]] bool DecodeRrcConnectionSetupComplete(const uint8_t *data, size_t size,
                                                    RrcConnectionSetupCompleteMessage &out);

} // namespace lte::rrc
