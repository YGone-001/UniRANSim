// This file is a part of UERANSIM project.
// https://github.com/aligungr/UERANSIM/
// See README, LICENSE, and CONTRIBUTING files for licensing details.
#pragma once

#include <cstdint>
#include <optional>

namespace lte
{
// Negotiated metadata, in bits/second. No radio scheduler is modelled.
struct GbrQos
{
    uint64_t maximumDl{}, maximumUl{}, guaranteedDl{}, guaranteedUl{};
};

struct ErabQos
{
    uint8_t qci{};
    uint8_t priorityLevel{};
    bool preemptionCapability{}, preemptionVulnerability{};
    std::optional<GbrQos> gbr;

    [[nodiscard]] bool valid() const
    {
        return qci != 0 && priorityLevel >= 1 && priorityLevel <= 15 && ((qci > 4) || gbr.has_value()) &&
               (!gbr || (gbr->guaranteedDl <= gbr->maximumDl && gbr->guaranteedUl <= gbr->maximumUl &&
                         gbr->maximumDl <= 10000000000ULL && gbr->maximumUl <= 10000000000ULL));
    }
};

struct UeAmbr
{
    uint64_t downlink{}, uplink{};
};
} // namespace lte
