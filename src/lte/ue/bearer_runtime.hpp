// This file is a part of UERANSIM project.
// https://github.com/aligungr/UERANSIM/
// See README, LICENSE, and CONTRIBUTING files for licensing details.
#pragma once
#include "lifecycle.hpp"
#include "nas.hpp"

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
