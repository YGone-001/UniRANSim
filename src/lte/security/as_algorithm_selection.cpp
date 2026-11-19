//
// This file is a part of UERANSIM project.
// Copyright (c) 2027 ALİ GÜNGÖR.
//
// https://github.com/aligungr/UERANSIM/
// See README, LICENSE, and CONTRIBUTING files for licensing details.
//

#include "as_algorithm_selection.hpp"

#include <sstream>

namespace lte::security
{
namespace
{

constexpr uint8_t MaxAlgorithmIdentity = 15;

[[noreturn]] void Fail(SelectionError reason)
{
    throw SelectionException(reason);
}

bool Advertises(uint16_t bitmap, uint8_t identity)
{
    return (bitmap & static_cast<uint16_t>(1U << identity)) != 0;
}

} // namespace

const char *ToString(SelectionError error)
{
    switch (error)
    {
    case SelectionError::UE_CAPABILITIES_MISSING: return "UE_CAPABILITIES_MISSING";
    case SelectionError::UE_CAPABILITIES_MALFORMED: return "UE_CAPABILITIES_MALFORMED";
    case SelectionError::ALLOWLIST_EMPTY: return "ALLOWLIST_EMPTY";
    case SelectionError::NO_COMMON_ALGORITHM: return "NO_COMMON_ALGORITHM";
    case SelectionError::UNSUPPORTED_ALGORITHM: return "UNSUPPORTED_ALGORITHM";
    case SelectionError::STALE_CONFIGURATION: return "STALE_CONFIGURATION";
    case SelectionError::EIA0_WITHOUT_NULL_NAS_INTEGRITY: return "EIA0_WITHOUT_NULL_NAS_INTEGRITY";
    case SelectionError::INVALID_ALGORITHM_IDENTITY: return "INVALID_ALGORITHM_IDENTITY";
    }
    return "UNKNOWN_SELECTION_ERROR";
}

SelectionException::SelectionException(SelectionError reason)
    : std::runtime_error(std::string("AS algorithm selection refusal: ") + ToString(reason)), reason_(reason)
{
}

bool IsImplemented(AsAlgorithmDirection direction, uint8_t identity)
{
    // This build implements EEA0-EEA3 and EIA0-EIA3 through crypto::EncryptEea*
    // and crypto::ComputeMacEia*. Anything else is not advertised and never
    // selected.
    (void)direction;
    return identity <= 3;
}

bool ProvidesProtection(AsAlgorithmDirection direction, uint8_t identity)
{
    (void)direction;
    // EEA0 and EIA0 are the null algorithms in both directions: identity 0.
    return identity != 0;
}

uint8_t SelectAlgorithm(AsAlgorithmDirection direction, const UeAlgorithmCapabilities &ue,
                        const AlgorithmAllowlist &allowlist, uint8_t nasIntegrityAlgorithm)
{
    if (!ue.present)
        Fail(SelectionError::UE_CAPABILITIES_MISSING);
    if (ue.ciphering == 0 || ue.integrity == 0)
        Fail(SelectionError::UE_CAPABILITIES_MALFORMED);
    if (allowlist.ordered.empty())
        Fail(SelectionError::ALLOWLIST_EMPTY);

    const uint16_t advertised = direction == AsAlgorithmDirection::INTEGRITY ? ue.integrity : ue.ciphering;

    for (uint8_t identity : allowlist.ordered)
    {
        if (identity > MaxAlgorithmIdentity)
            Fail(SelectionError::INVALID_ALGORITHM_IDENTITY);
        if (!Advertises(advertised, identity))
            continue;
        if (!IsImplemented(direction, identity))
            continue;
        if (direction == AsAlgorithmDirection::INTEGRITY && identity == 0 && nasIntegrityAlgorithm != 0)
        {
            // TS 33.401: EIA0 is only usable by a UE whose NAS integrity is also
            // null. The policy is a refusal, not a silent skip to the next entry.
            Fail(SelectionError::EIA0_WITHOUT_NULL_NAS_INTEGRITY);
        }
        return identity;
    }

    Fail(SelectionError::NO_COMMON_ALGORITHM);
}

AlgorithmSelection SelectAsAlgorithms(const UeAlgorithmCapabilities &ue, const AsAlgorithmConfiguration &configuration,
                                      uint64_t expectedConfigurationGeneration)
{
    if (configuration.ciphering.generation != expectedConfigurationGeneration ||
        configuration.integrity.generation != expectedConfigurationGeneration)
        Fail(SelectionError::STALE_CONFIGURATION);

    AlgorithmSelection selection;
    selection.integrity =
        SelectAlgorithm(AsAlgorithmDirection::INTEGRITY, ue, configuration.integrity, configuration.nasIntegrityAlgorithm);
    selection.ciphering = SelectAlgorithm(AsAlgorithmDirection::CIPHERING, ue, configuration.ciphering,
                                          configuration.nasIntegrityAlgorithm);
    selection.configurationGeneration = expectedConfigurationGeneration;
    selection.integrityNull = !ProvidesProtection(AsAlgorithmDirection::INTEGRITY, selection.integrity);
    selection.cipheringNull = !ProvidesProtection(AsAlgorithmDirection::CIPHERING, selection.ciphering);
    return selection;
}

std::string AlgorithmSelection::Describe() const
{
    std::ostringstream out;
    out << "integrity=" << static_cast<int>(integrity) << (integrityNull ? " (null: no integrity protection)" : "")
        << " ciphering=" << static_cast<int>(ciphering) << (cipheringNull ? " (null: no confidentiality)" : "")
        << " configGen=" << configurationGeneration;
    return out.str();
}

} // namespace lte::security
