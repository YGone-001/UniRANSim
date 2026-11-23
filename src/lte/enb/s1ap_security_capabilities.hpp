//
// This file is a part of UERANSIM project.
// Copyright (c) 2027 ALİ GÜNGÖR.
//

// Phase 18-F-B6-C: the UESecurityCapabilities BIT STRING of TS 36.413
// 9.2.1.88 mapped to the algorithm bitmap the AS selection consumes.
//
// The two encodings disagree by convention, not by content. TS 36.413 numbers
// the bits of a 16-bit string from the first (leftmost) one, and the first bit
// is EEA0/EIA0. `UeAlgorithmCapabilities` stores algorithm identity n in bit n
// of a uint16. The first bit of the string is the most significant bit of the
// first octet, so a raw 16-bit read has to be bit-reversed before it can be used
// as an algorithm bitmap. Doing it as a cast reads EEA0 as EEA15.
#pragma once

#include <lte/security/as_algorithm_selection.hpp>

#include <array>
#include <cstdint>

namespace lte::enb::s1ap
{

// `encryption` is encryptionAlgorithms and `integrity` is
// integrityProtectionAlgorithms, both exactly as decoded from the S1AP PDU.
[[nodiscard]] lte::security::UeAlgorithmCapabilities MapUeSecurityCapabilities(
    const std::array<uint8_t, 2> &encryption, const std::array<uint8_t, 2> &integrity);

// The inverse, so a fixture can state a capability bitmap in the same terms the
// selector uses and still produce the octets an MME would send.
[[nodiscard]] std::array<uint8_t, 2> EncodeUeAlgorithmBitmap(uint16_t bitmap);

} // namespace lte::enb::s1ap
