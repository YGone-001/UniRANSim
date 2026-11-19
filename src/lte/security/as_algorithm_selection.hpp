//
// This file is a part of UERANSIM project.
// Copyright (c) 2027 ALİ GÜNGÖR.
//
// https://github.com/aligungr/UERANSIM/
// See README, LICENSE, and CONTRIBUTING files for licensing details.
//

// Phase 18-F-B5: LTE AS algorithm negotiation (TS 33.401 7.2.4, TS 36.331
// SecurityModeCommand). The eNB owns an ordered allowlist per direction and the
// UE owns a capability bitmap; the selected algorithm is the first entry of the
// allowlist that both sides support and this build implements.
//
// Priority is the operator's order. It is not the numeric order of the
// algorithm identities, and it is not derived from the UE bitmap.
#pragma once

#include <cstdint>
#include <stdexcept>
#include <string>
#include <vector>

namespace lte::security
{

enum class AsAlgorithmDirection : uint8_t
{
    INTEGRITY,
    CIPHERING,
};

// The 16-bit EPS algorithm bitmaps of TS 36.413 UESecurityCapabilities. Bit n
// is algorithm identity n (EEA0/EIA0 is bit 0).
struct UeAlgorithmCapabilities
{
    bool present{false};
    uint16_t ciphering{0};
    uint16_t integrity{0};
};

// An operator-configured ordered allowlist. The generation is what a selection
// records and what a stale request is checked against.
struct AlgorithmAllowlist
{
    std::vector<uint8_t> ordered{};
    uint64_t generation{0};
};

struct AsAlgorithmConfiguration
{
    AlgorithmAllowlist ciphering{};
    AlgorithmAllowlist integrity{};
    // The NAS integrity algorithm currently in use. TS 33.401 restricts EIA0 to
    // a UE whose NAS integrity is also null, so the AS selection needs it.
    uint8_t nasIntegrityAlgorithm{0};
};

enum class SelectionError : uint8_t
{
    UE_CAPABILITIES_MISSING,
    UE_CAPABILITIES_MALFORMED,
    ALLOWLIST_EMPTY,
    NO_COMMON_ALGORITHM,
    UNSUPPORTED_ALGORITHM,
    STALE_CONFIGURATION,
    EIA0_WITHOUT_NULL_NAS_INTEGRITY,
    INVALID_ALGORITHM_IDENTITY,
};

const char *ToString(SelectionError error);

class SelectionException : public std::runtime_error
{
  public:
    explicit SelectionException(SelectionError reason);

    [[nodiscard]] SelectionError Reason() const noexcept
    {
        return reason_;
    }

  private:
    SelectionError reason_;
};

// The algorithms this build can actually run. An identity outside these sets is
// refused, never selected and then quietly ignored.
[[nodiscard]] bool IsImplemented(AsAlgorithmDirection direction, uint8_t identity);

// True when the algorithm provides the protection its direction names. EEA0
// provides no confidentiality and EIA0 provides no integrity.
[[nodiscard]] bool ProvidesProtection(AsAlgorithmDirection direction, uint8_t identity);

struct AlgorithmSelection
{
    uint8_t ciphering{0};
    uint8_t integrity{0};
    uint64_t configurationGeneration{0};
    bool cipheringNull{false};
    bool integrityNull{false};

    // A human-readable classification that never overstates null algorithms.
    [[nodiscard]] std::string Describe() const;
};

// Selects one algorithm per direction: the first allowlist entry that the UE
// advertises and this build implements. Deterministic for a given request.
[[nodiscard]] uint8_t SelectAlgorithm(AsAlgorithmDirection direction, const UeAlgorithmCapabilities &ue,
                                      const AlgorithmAllowlist &allowlist, uint8_t nasIntegrityAlgorithm);

[[nodiscard]] AlgorithmSelection SelectAsAlgorithms(const UeAlgorithmCapabilities &ue,
                                                    const AsAlgorithmConfiguration &configuration,
                                                    uint64_t expectedConfigurationGeneration);

} // namespace lte::security
