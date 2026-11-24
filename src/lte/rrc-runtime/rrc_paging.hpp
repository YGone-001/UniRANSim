//
// This file is a part of UERANSIM project.
// Copyright (c) 2027 ALİ GÜNGÖR.
//

// Phase 18-F-B6-D5: the PCCH Paging message (TS 36.331 6.2.2, 5.3.2).
//
// Paging is a PCCH message addressed to a UE in RRC_IDLE by its S-TMSI. It is
// not a NAS message and it never travels on SRB1: the eNB broadcasts it and the
// UE matches its own identity. This codec produces and reads the real RRC Paging
// octets so the simulated Uu carries a protocol message rather than a boolean
// notification.
#pragma once

#include <cstddef>
#include <cstdint>
#include <vector>

namespace lte::rrc
{

struct PagingRecord
{
    uint8_t mmec{0};
    uint32_t mTmsi{0};
    // false is the PS domain, true the CS domain (TS 36.331 PagingRecord).
    bool csDomain{false};
};

struct PagingMessage
{
    std::vector<PagingRecord> records;
};

// At most one page per UE is meaningful on one cell, and a bounded list keeps a
// malformed length from becoming an allocation the receiver cannot refuse.
constexpr size_t MaxPagingRecords = 16;

// Returns an empty vector when the record set is empty or out of range.
std::vector<uint8_t> EncodePaging(const PagingMessage &message);

// Rejects a PDU that is not exactly one well-formed PCCH Paging message.
bool DecodePaging(const uint8_t *data, size_t size, PagingMessage &out);

} // namespace lte::rrc
