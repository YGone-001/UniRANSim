//
// This file is a part of UERANSIM project.
// Copyright (c) 2027 ALİ GÜNGÖR.
//
// https://github.com/aligungr/UERANSIM/
// See README, LICENSE, and CONTRIBUTING files for licensing details.
//

// Phase 19-B/19-C: structured capacity evidence.
//
// Phase 19-A recorded the capacity classifications in comments. This is the
// machine-readable form: one record per checkpoint, with every
// classification named and an evidence state that distinguishes "measured and
// failed" from "not measured" from "blocked on authorization". An unavailable
// measurement is never converted into a negative result.
//
// Phase 19-C extends the model without changing any historical meaning. The
// additions exist because Phase 19-B marked STABLE_REGISTRATION_RETAINED as
// PASS after filling a synthetic registry and emptying it again. No EPS
// registration happened and no retention window was observed. The field now
// means EPS registration retention only, and context persistence has its own
// classification, ISOLATED_CONTEXT_RETAINED. A running UE process, a radio
// peer and an Attach Request each get their own field for the same reason.

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
    BLOCKED_AUTHORIZATION,
    // The workload could not complete within a declared resource budget.
    // This is a measured stopping point, not a failure of the feature.
    BLOCKED_RESOURCE_LIMIT
};

const char *ToString(EvidenceState state);

// The capacity classifications. Each names one workload; none is inferred from
// another. In particular:
//   - a synthetic registry entry establishes ISOLATED_REGISTRY_CONTEXT_ACTIVE
//     and never a registration,
//   - a UDP radio peer establishes SIMULATED_RADIO_ENDPOINT_ACTIVE and never
//     an EPS bearer,
//   - a live lte-ue process establishes ACTUAL_LTE_UE_PROCESS_ALIVE and never
//     authentication,
//   - an Attach Request establishes PRE_AUTH_ATTACH_ATTEMPT and never an
//     Attach Accept.
struct CapacityClassifications
{
    // Phase 19-B fields. Only the first is what an isolated registry or
    // radio-ingress test can establish; the rest require real EPC evidence.
    EvidenceState isolatedContextCapacity{EvidenceState::NOT_MEASURED};
    EvidenceState simulatedAttachSuccess{EvidenceState::NOT_APPLICABLE};
    EvidenceState realEpcAuthenticatedAttach{EvidenceState::BLOCKED_AUTHORIZATION};
    EvidenceState simultaneousEpsRegistration{EvidenceState::BLOCKED_AUTHORIZATION};
    EvidenceState simultaneousDefaultBearers{EvidenceState::NOT_APPLICABLE};
    EvidenceState independentUeIpv4Assignment{EvidenceState::NOT_APPLICABLE};
    EvidenceState userPlaneReady{EvidenceState::NOT_APPLICABLE};
    // EPS registration retention over a sustained window. A registry that held
    // synthetic contexts and released them is NOT this, and the field must stay
    // NOT_MEASURED for a registry-only workload.
    EvidenceState stableRegistrationRetained{EvidenceState::NOT_MEASURED};
    EvidenceState cleanupComplete{EvidenceState::NOT_MEASURED};

    // Phase 19-C concepts. Each is separate on purpose.
    EvidenceState isolatedRegistryContextActive{EvidenceState::NOT_MEASURED};
    EvidenceState simulatedRadioEndpointActive{EvidenceState::NOT_APPLICABLE};
    EvidenceState actualLteUeProcessAlive{EvidenceState::NOT_MEASURED};
    EvidenceState preAuthAttachAttempt{EvidenceState::NOT_APPLICABLE};
    // Context persistence only: the same non-EPS registry entry still resolved
    // after a declared observation window. Never EPS registration retention.
    EvidenceState isolatedContextRetained{EvidenceState::NOT_MEASURED};
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
    // Memory is reported as three distinct observations. baselineRssBytes is
    // taken before the workload, observedRssBytes after it, and peakRssBytes is
    // the kernel's VmHWM for this process. The three are never conflated.
    uint64_t baselineRssBytes{};
    uint64_t observedRssBytes{};
    uint64_t peakRssBytes{};
    uint64_t pssBytes{};
    bool pssAvailable{};
    size_t rssSampleCount{};
    // Observed minus baseline divided by the contexts created. It is an
    // incremental whole-process delta, not a per-context heap measurement, and
    // it can be negative because allocator and page-cache behaviour is not
    // attributable to one context.
    int64_t perContextRssDeltaBytes{};
    // How long the contexts were held before release, in milliseconds.
    double retentionObservationMs{};
    size_t remainingContexts{};
    bool configurationLimitReached{};
    CapacityClassifications classifications;
};

// A single-line machine-readable rendering of one checkpoint. Stable field
// order so two runs can be compared mechanically; new Phase 19-C fields are
// appended, historical keys keep their positions.
std::string DescribeCheckpoint(const CapacityCheckpoint &checkpoint);

} // namespace lte::enb
