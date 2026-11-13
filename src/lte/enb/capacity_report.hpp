//
// This file is a part of UERANSIM project.
// Copyright (c) 2027 ALİ GÜNGÖR.
//
// https://github.com/aligungr/UERANSIM/
// See README, LICENSE, and CONTRIBUTING files for licensing details.
//

// Phase 19-B: structured capacity evidence.
//
// Phase 19-A recorded the nine capacity classifications in comments. This is
// the machine-readable form: one record per checkpoint, with every
// classification named and an evidence state that distinguishes "measured and
// failed" from "not measured" from "blocked on authorization". An unavailable
// measurement is never converted into a negative result.

#pragma once

#include <cstddef>
#include <cstdint>
#include <string>

namespace lte::enb
{

enum class EvidenceState : uint8_t
{
    // Observed and the requirement holds.
    PASS,
    // Observed and the requirement does not hold.
    FAIL,
    // No observation was made; this is not a negative result.
    NOT_MEASURED,
    // The requirement does not apply to this measurement.
    NOT_APPLICABLE,
    // The observation is not authorized in the current scope.
    BLOCKED_AUTHORIZATION
};

const char *ToString(EvidenceState state);

// The nine capacity classifications. Only the first is what an isolated
// registry or radio-ingress test can establish; the rest require real EPC
// evidence and are reported as such.
struct CapacityClassifications
{
    EvidenceState isolatedContextCapacity{EvidenceState::NOT_MEASURED};
    EvidenceState simulatedAttachSuccess{EvidenceState::NOT_APPLICABLE};
    EvidenceState realEpcAuthenticatedAttach{EvidenceState::BLOCKED_AUTHORIZATION};
    EvidenceState simultaneousEpsRegistration{EvidenceState::BLOCKED_AUTHORIZATION};
    EvidenceState simultaneousDefaultBearers{EvidenceState::NOT_APPLICABLE};
    EvidenceState independentUeIpv4Assignment{EvidenceState::NOT_APPLICABLE};
    EvidenceState userPlaneReady{EvidenceState::NOT_APPLICABLE};
    EvidenceState stableRegistrationRetained{EvidenceState::NOT_MEASURED};
    EvidenceState cleanupComplete{EvidenceState::NOT_MEASURED};
};

// One capacity checkpoint. Every field is an observation the harness made, not
// a claim about real EPC capacity.
struct CapacityCheckpoint
{
    size_t requestedCount{};
    size_t createdContexts{};
    size_t activeContexts{};
    size_t failedCreations{};
    size_t peakContexts{};
    double registrationDurationMs{};
    double lookupDurationMs{};
    double cleanupDurationMs{};
    uint64_t peakRssBytes{};
    size_t remainingContexts{};
    bool configurationLimitReached{};
    CapacityClassifications classifications;
};

// A single-line machine-readable rendering of one checkpoint. Stable field
// order so two runs can be compared mechanically.
std::string DescribeCheckpoint(const CapacityCheckpoint &checkpoint);

} // namespace lte::enb
