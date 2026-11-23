//
// This file is a part of UERANSIM project.
// Copyright (c) 2027 ALİ GÜNGÖR.
//

// Phase 18-F-B6-C: the LTE RRC NAS carrier messages of TS 36.331 6.2.2.
//
// ULInformationTransfer and DLInformationTransfer exist for one purpose in this
// simulator: to carry an opaque NAS PDU on SRB1. The NAS bytes are never
// interpreted here, and the message type is decoded from the ASN.1 definition
// rather than from a hand-written bit pattern.
#pragma once

#include "rrc_connection_setup_complete.hpp"

#include <cstddef>
#include <cstdint>
#include <vector>

namespace lte::rrc
{

struct InformationTransferMessage
{
    std::vector<uint8_t> dedicatedInfoNas{};
};

// Empty on failure: an empty or oversized NAS, or a NULL-typed message, is
// refused rather than encoded.
[[nodiscard]] std::vector<uint8_t> EncodeUlInformationTransfer(const InformationTransferMessage &message);
[[nodiscard]] std::vector<uint8_t> EncodeDlInformationTransfer(const InformationTransferMessage &message);

// Require the exact message type and a dedicatedInfoNAS choice; a different
// UL-DCCH/DL-DCCH message, a CDMA2000 payload or an empty NAS is refused.
[[nodiscard]] bool DecodeUlInformationTransfer(const uint8_t *data, size_t size, InformationTransferMessage &out);
[[nodiscard]] bool DecodeDlInformationTransfer(const uint8_t *data, size_t size, InformationTransferMessage &out);

} // namespace lte::rrc
