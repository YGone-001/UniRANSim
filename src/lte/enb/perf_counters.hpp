//
// This file is a part of UERANSIM project.
// Copyright (c) 2027 ALİ GÜNGÖR.
//
// https://github.com/aligungr/UERANSIM/
// See README, LICENSE, and CONTRIBUTING files for licensing details.
//

// Phase 19-A: opt-in performance counters for the LTE capacity and throughput
// baseline.
//
// They are off by default and cost one relaxed atomic increment each when on.
// They hold no IMSI, no key and no authentication material, they never log per
// packet, and they open no management port. The existing per-UE
// `UserPlaneCounters` and per-endpoint `S1uEndpointCounters` stay as they are;
// these are the shared, whole-eNB counters the baseline needs and neither of
// those can provide.

#pragma once

#include <atomic>
#include <cstdint>

namespace lte::enb
{

struct PerfCounters
{
    // Counters are only written when this is set, so a normal run pays nothing.
    std::atomic<bool> enabled{false};

    std::atomic<uint64_t> pollIterations{0};
    std::atomic<uint64_t> radioPacketsPolled{0};
    std::atomic<uint64_t> s1uPacketsPolled{0};
    std::atomic<uint64_t> sctpMessagesReceived{0};
    std::atomic<uint64_t> registrations{0};
    std::atomic<uint64_t> teardowns{0};
    // The highest concurrent UE count the registry has held.
    std::atomic<uint64_t> registryHighWater{0};
    std::atomic<uint64_t> socketSendFailures{0};

    void reset()
    {
        pollIterations = 0;
        radioPacketsPolled = 0;
        s1uPacketsPolled = 0;
        sctpMessagesReceived = 0;
        registrations = 0;
        teardowns = 0;
        registryHighWater = 0;
        socketSendFailures = 0;
    }
};

} // namespace lte::enb
