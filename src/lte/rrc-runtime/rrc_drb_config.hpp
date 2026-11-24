//
// This file is a part of UERANSIM project.
// Copyright (c) 2027 ALİ GÜNGÖR.
//

// Phase 18-F-B6-D6: the LTE RRC messages that configure a DRB.
//
// TS 36.331 6.2.2: an RRCConnectionReconfiguration carries
// radioResourceConfigDedicated, whose drb-ToAddModList is what creates a DRB on
// the UE. This codec builds and parses exactly that message, through the same
// asn1c TS 36.331 V15.6.0 UPER codec the rest of the LTE RRC runtime uses. No
// private simulator field stands in for a standard one.
//
// The UE answers with RRCConnectionReconfigurationComplete (TS 36.331 6.2.2),
// which is the only acknowledgement of the configuration.
#pragma once

#include "lte_am.hpp"
#include "srb1_rlc_config.hpp"

#include <cstddef>
#include <cstdint>
#include <vector>

namespace lte::rrc
{

// One DRB the network adds. The EPS bearer identity is the ESM identity the
// network assigned; the DRB identity is the radio identity that carries it.
struct DrbToAdd
{
    uint8_t ebi{};                     // eps-BearerIdentity, 5..15
    uint8_t drbIdentity{};             // DRB-Identity, 1..32
    uint8_t logicalChannelIdentity{};  // LogicalChannelIdentity, 3..10
    uint8_t priority{1};               // LogicalChannelConfig priority, 1..16
    rlc::am::AmConfig am{};            // resolved from UL-AM-RLC/DL-AM-RLC
};

struct DrbReconfiguration
{
    uint8_t transactionId{};
    std::vector<DrbToAdd> drbs;
};

constexpr size_t MaxDrbToAdd = 8;
constexpr uint8_t MinDrbIdentity = 1;
constexpr uint8_t MaxDrbIdentity = 32;
constexpr uint8_t MinDrbLogicalChannel = 3;
constexpr uint8_t MaxDrbLogicalChannel = 10;

// Encodes a DL-DCCH-Message carrying an RRCConnectionReconfiguration with only
// radioResourceConfigDedicated.drb-ToAddModList (plus the mandatory RLC/PDCP/
// logical-channel configuration of every DRB). Empty on any refusal.
[[nodiscard]] std::vector<uint8_t> EncodeDrbReconfiguration(const DrbReconfiguration &message);

// Requires the exact message: an RRCConnectionReconfiguration whose
// radioResourceConfigDedicated carries drb-ToAddModList and nothing this codec
// cannot represent. A UM RLC configuration, a missing PDCP/LC configuration, a
// duplicated identity or an out-of-range enumerator is refused whole.
[[nodiscard]] bool DecodeDrbReconfiguration(const uint8_t *data, size_t size, DrbReconfiguration &out);

// UL-DCCH-Message carrying RRCConnectionReconfigurationComplete.
[[nodiscard]] std::vector<uint8_t> EncodeDrbReconfigurationComplete(uint8_t transactionId);
[[nodiscard]] bool DecodeDrbReconfigurationComplete(const uint8_t *data, size_t size, uint8_t &transactionId);

} // namespace lte::rrc
