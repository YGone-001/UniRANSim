//
// This file is a part of UERANSIM project.
// Copyright (c) 2027 ALİ GÜNGÖR.
//
// https://github.com/aligungr/UERANSIM/
// See README, LICENSE, and CONTRIBUTING files for licensing details.
//

// Phase 18-F-B4: the standardized 3GPP key derivation function used by the LTE
// Access Stratum key hierarchy (TS 33.220 Annex B.2, invoked from TS 33.401
// Annex A).
//
// The construction is S = FC || P0 || L0 || P1 || L1 ... with two-byte big
// endian lengths and HMAC-SHA-256 as the pseudo-random function. This wrapper
// exists so the AS layer can talk in fixed 256-bit keys and byte strings while
// the encoding itself stays in the project's single KDF implementation
// (crypto::CalculateKdfKey); a second KDF implementation would be a defect.
#pragma once

#include <array>
#include <cstdint>
#include <vector>

namespace lte::security
{

using Key256 = std::array<uint8_t, 32>;
using Key128 = std::array<uint8_t, 16>;
using ByteString = std::vector<uint8_t>;

// S = FC || P0 || L0 || ... for the given parameters, hashed with HMAC-SHA-256
// under the input key. An empty parameter list hashes FC alone.
[[nodiscard]] Key256 Kdf(const Key256 &key, uint8_t fc, const std::vector<ByteString> &parameters);

// The exact input octet string S the KDF hashes. Exposed so a test can pin the
// encoding independently of the hash, and so a failure can name the encoding
// rather than the digest.
[[nodiscard]] ByteString EncodeKdfInput(uint8_t fc, const std::vector<ByteString> &parameters);

} // namespace lte::security
