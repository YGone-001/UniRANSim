//
// This file is a part of UERANSIM project.
// Copyright (c) 2027 ALİ GÜNGÖR.
//

// Phase 18-F-B6-D5: RRCConnectionRelease (TS 36.331 6.2.2, 5.3.8).
//
// The network releases the RRC connection while EPS registration stays in
// place. The message carries no NAS payload; it moves the UE to RRC_IDLE and
// says nothing about EMM or ECM state, which the NAS layer decides separately.
#pragma once

#include <cstddef>
#include <cstdint>
#include <vector>

namespace lte::rrc
{

struct RrcConnectionReleaseMessage
{
    uint8_t transactionId{0};
};

// ReleaseCause is encoded as "other" (TS 36.331 ReleaseCause). Returns an empty
// vector when the transaction identifier is out of range.
std::vector<uint8_t> EncodeRrcConnectionRelease(const RrcConnectionReleaseMessage &message);

// True only for one well-formed DL-DCCH RRCConnectionRelease.
bool DecodeRrcConnectionRelease(const uint8_t *data, size_t size, RrcConnectionReleaseMessage &out);

} // namespace lte::rrc
