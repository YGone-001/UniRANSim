//
// This file is a part of UERANSIM project.
// Copyright (c) 2027 ALİ GÜNGÖR.
//
// https://github.com/aligungr/UERANSim/
// See README, LICENSE, and CONTRIBUTING files for licensing details.
//

#include "capacity_report.hpp"

namespace lte::enb
{

const char *ToString(EvidenceState state)
{
    switch (state)
    {
    case EvidenceState::PASS: return "PASS";
    case EvidenceState::FAIL: return "FAIL";
    case EvidenceState::NOT_MEASURED: return "NOT_MEASURED";
    case EvidenceState::NOT_APPLICABLE: return "NOT_APPLICABLE";
    case EvidenceState::BLOCKED_AUTHORIZATION: return "BLOCKED_AUTHORIZATION";
    case EvidenceState::BLOCKED_RESOURCE_LIMIT: return "BLOCKED_RESOURCE_LIMIT";
    }
    return "UNKNOWN_EVIDENCE_STATE";
}

std::string DescribeCheckpoint(const CapacityCheckpoint &checkpoint)
{
    const auto &c = checkpoint.classifications;
    std::string out;
    out += "requested=" + std::to_string(checkpoint.requestedCount);
    out += " created=" + std::to_string(checkpoint.createdContexts);
    out += " active=" + std::to_string(checkpoint.activeContexts);
    out += " failed=" + std::to_string(checkpoint.failedCreations);
    out += " peak=" + std::to_string(checkpoint.peakContexts);
    out += " registration_ms=" + std::to_string(checkpoint.registrationDurationMs);
    out += " lookup_ms=" + std::to_string(checkpoint.lookupDurationMs);
    out += " cleanup_ms=" + std::to_string(checkpoint.cleanupDurationMs);
    out += " peak_rss=" + std::to_string(checkpoint.peakRssBytes);
    out += " remaining=" + std::to_string(checkpoint.remainingContexts);
    out += " config_limit=" + std::string(checkpoint.configurationLimitReached ? "yes" : "no");
    out += " isolated=" + std::string(ToString(c.isolatedContextCapacity));
    out += " attach=" + std::string(ToString(c.simulatedAttachSuccess));
    out += " real_epc=" + std::string(ToString(c.realEpcAuthenticatedAttach));
    out += " eps_reg=" + std::string(ToString(c.simultaneousEpsRegistration));
    out += " bearers=" + std::string(ToString(c.simultaneousDefaultBearers));
    out += " ipv4=" + std::string(ToString(c.independentUeIpv4Assignment));
    out += " user_plane=" + std::string(ToString(c.userPlaneReady));
    out += " retained=" + std::string(ToString(c.stableRegistrationRetained));
    out += " cleanup=" + std::string(ToString(c.cleanupComplete));
    // Phase 19-C additions, appended so historical keys never move.
    out += " registry_active=" + std::string(ToString(c.isolatedRegistryContextActive));
    out += " radio_endpoint=" + std::string(ToString(c.simulatedRadioEndpointActive));
    out += " ue_process_alive=" + std::string(ToString(c.actualLteUeProcessAlive));
    out += " preauth_attach=" + std::string(ToString(c.preAuthAttachAttempt));
    out += " ctx_retained=" + std::string(ToString(c.isolatedContextRetained));
    out += " rss_baseline=" + std::to_string(checkpoint.baselineRssBytes);
    out += " rss_observed=" + std::to_string(checkpoint.observedRssBytes);
    out += " rss_peak=" + std::to_string(checkpoint.peakRssBytes);
    out += " pss=" + std::to_string(checkpoint.pssBytes);
    out += " pss_available=" + std::string(checkpoint.pssAvailable ? "yes" : "no");
    out += " rss_samples=" + std::to_string(checkpoint.rssSampleCount);
    out += " rss_per_context_delta=" + std::to_string(checkpoint.perContextRssDeltaBytes);
    out += " retention_ms=" + std::to_string(checkpoint.retentionObservationMs);
    return out;
}

} // namespace lte::enb
