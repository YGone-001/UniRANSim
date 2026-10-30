// This file is a part of UERANSIM project.
// https://github.com/aligungr/UERANSIM/
// See README, LICENSE, and CONTRIBUTING files for licensing details.
#pragma once
#include "lifecycle.hpp"
#include "nas.hpp"
#include "radio_link.hpp"

#include <algorithm>

namespace lte::ue
{
// NAS owns logical identity/QoS/TFT; S1 restoration changes only access readiness.
struct DedicatedBearerRuntime : nas::EpsBearerConfiguration
{
    bool accessReady{true};
    uint64_t uplinkPackets{}, downlinkPackets{}, inactiveDrops{};

    void releaseAccessTransport() { accessReady = false; }
    void restoreAccess(const MobilityContext &mobility, uint8_t restoredEbi, uint32_t generation)
    {
        mobility.validateAccessRestoration(restoredEbi, generation, true);
        if (ebi != restoredEbi || linkedEbi != mobility.defaultEbi || accessReady || !mobility.canForwardUserPlane())
            throw LifecycleError("Unknown, inconsistent or duplicate dedicated bearer restoration");
        accessReady = true;
    }
};

struct UplinkBearerSelection
{
    uint8_t ebi{};
    bool accessReady{};
};

// The EPS bearer identities the UE still holds: the network-assigned default
// plus every accepted dedicated context. The identities are read back out of
// the live contexts instead of being assumed, so a default bearer outside 5..6
// is still reported and a dedicated bearer the network released is not.
inline std::vector<uint8_t> RetainedBearerIdentities(uint8_t defaultEbi,
                                                     const std::vector<DedicatedBearerRuntime> &bearers)
{
    std::vector<uint8_t> identities{defaultEbi};
    for (const auto &bearer : bearers)
        identities.push_back(bearer.ebi);
    return identities;
}

// The declaration a freshly reached cell needs before it can restore this
// session: the network-assigned default EPS bearer identity plus every
// dedicated identity the UE still holds. The identities are read back out of
// the live NAS-confirmed contexts and out of nothing else, so a default the
// network never assigned is reported rather than rounded to a plausible one, a
// dedicated context the network released is no longer present at all, and no
// QCI, E-RAB list order or earlier registry contents can leak into the claim.
//
// The claim is a set of identities, and the wire encodes it in ascending order,
// so the dedicated identities are canonicalised here rather than presented in
// whatever order the network happened to activate them in. Anything the
// encoding cannot express — an unassigned default, a dedicated identity equal
// to it or linked to a different default, a duplicate, or more identities than
// one UE can hold — is refused here instead of being transmitted as a
// declaration a target would act on. There is no fallback to a plainer form: a
// fresh target that needs the declaration is never given a message without it.
inline link::BearerInventory ValidateBearerInventory(uint8_t defaultEbi,
                                                     const std::vector<DedicatedBearerRuntime> &bearers)
{
    if (defaultEbi < 5 || defaultEbi > 15)
        throw LifecycleError("Cannot declare an unassigned default EPS bearer identity");
    link::BearerInventory inventory;
    inventory.defaultEbi = defaultEbi;
    inventory.dedicatedEbis.reserve(bearers.size());
    for (const auto &bearer : bearers)
    {
        if (bearer.ebi < 5 || bearer.ebi > 15 || bearer.ebi == defaultEbi || bearer.linkedEbi != defaultEbi)
            throw LifecycleError("Cannot declare a dedicated EPS bearer that is not valid on this default bearer");
        if (std::find(inventory.dedicatedEbis.begin(), inventory.dedicatedEbis.end(), bearer.ebi) !=
            inventory.dedicatedEbis.end())
            throw LifecycleError("Cannot declare a duplicated dedicated EPS bearer identity");
        inventory.dedicatedEbis.push_back(bearer.ebi);
    }
    std::sort(inventory.dedicatedEbis.begin(), inventory.dedicatedEbis.end());
    if (inventory.dedicatedEbis.size() > link::MaxDeclaredDedicatedBearers)
        throw LifecycleError("Cannot declare more dedicated EPS bearer identities than one UE can hold");
    return inventory;
}

struct BearerReconciliation
{
    std::vector<DedicatedBearerRuntime> retained;
    std::vector<uint8_t> released;
};

// The EPS bearer context status carried by a Tracking Area Update Accept is the
// network's view of the session and it is authoritative: a dedicated context
// the network no longer reports has been deactivated, so the UE must stop
// claiming it exists instead of carrying it forward into the next procedure.
// Losing the active default bearer is not a reconciliation but the end of the
// session, and is refused rather than quietly downgraded.
inline BearerReconciliation ReconcileRetainedBearers(const std::vector<DedicatedBearerRuntime> &bearers,
                                                     uint16_t networkStatus, uint8_t defaultEbi)
{
    // Only 5..15 are assignable EPS bearer identities, and a bit outside the
    // sixteen the status carries would shift past the end of the word.
    if (defaultEbi < 5 || defaultEbi > 15)
        throw nas::DecodeError("The network referred to an unassignable default bearer identity");
    if ((networkStatus & static_cast<uint16_t>(1U << defaultEbi)) == 0)
        throw nas::DecodeError("Tracking Area Update Accept removed the active default bearer");
    BearerReconciliation result;
    for (const auto &bearer : bearers)
    {
        if (bearer.ebi < 5 || bearer.ebi > 15)
            throw nas::DecodeError("The network referred to an unassignable dedicated bearer identity");
        if ((networkStatus & static_cast<uint16_t>(1U << bearer.ebi)) != 0)
            result.retained.push_back(bearer);
        else
            result.released.push_back(bearer.ebi);
    }
    return result;
}

struct TauAcceptance
{
    // Dedicated EPS bearer identities the network's status no longer reports.
    // They are dropped from the live set and must never be claimed again.
    std::vector<uint8_t> releasedDedicated;
    // True when the Accept assigned a new GUTI and therefore owes the network a
    // protected TAU Complete before the update is terminated.
    bool completeRequired{};
};

// Applies a Tracking Area Update Accept to the trusted UE state in one step.
//
// The Accept is a single NAS message carrying several independent assignments:
// an update result, a possible new GUTI, a possible new tracking area list, a
// possible periodic timer and a possible bearer context status. Each of them is
// validated, and the bearer reconciliation is computed, before any of them is
// committed, so an Accept that is malformed in any one element leaves the
// bearer set, the GUTI, the tracking areas and the pending procedure exactly as
// they were. The commit itself cannot fail.
inline TauAcceptance ApplyTauAccept(MobilityContext &mobility, std::vector<DedicatedBearerRuntime> &bearers,
                                    const nas::TauAccept &accept)
{
    const auto plan = mobility.planTauAccepted(accept.updateResult, accept.guti, accept.taiList, accept.t3412);
    TauAcceptance outcome;
    outcome.completeRequired = plan.completeRequired;
    if (accept.bearerContextStatus.has_value())
    {
        auto reconciliation = ReconcileRetainedBearers(bearers, *accept.bearerContextStatus, mobility.defaultEbi);
        outcome.releasedDedicated = std::move(reconciliation.released);
        bearers = std::move(reconciliation.retained);
    }
    mobility.commitTauAccepted(plan);
    return outcome;
}

inline UplinkBearerSelection SelectUplinkBearer(uint8_t defaultEbi,
    const std::vector<DedicatedBearerRuntime> &bearers, const uint8_t *packet, size_t size)
{
    UplinkBearerSelection selection{defaultEbi, true};
    int precedence = 256;
    for (const auto &bearer : bearers)
    {
        const auto *filter = bearer.tft.classify(packet, size, true);
        if (filter != nullptr && filter->precedence < precedence)
        {
            precedence = filter->precedence;
            selection = {bearer.ebi, bearer.accessReady};
        }
    }
    return selection;
}
} // namespace lte::ue
