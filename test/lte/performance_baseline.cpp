//
// This file is a part of UERANSIM project.
// Copyright (c) 2027 ALİ GÜNGÖR.
//
// https://github.com/aligungr/UERANSIM/
// See README, LICENSE, and CONTRIBUTING files for licensing details.
//

// Phase 19-A: the isolated capacity harness and the opt-in instrumentation.
//
// What these cases measure is genuine production UE-registry allocation with
// test-owned synthetic contexts. A synthetic entry is isolated context
// capacity and nothing more: it is not an authenticated EPS Attach, it holds
// no independent UE IPv4 assignment, and it must never be reported as a real
// EPC registration. The classifications below say exactly that, and the
// harness refuses to report a checkpoint it did not actually reach.

#include <ext/doctest/doctest.h>

#include <chrono>
#include <string>
#include <vector>

#include <lte/enb/multiplexer.hpp>
#include <lte/enb/perf_counters.hpp>
#include <lte/enb/ue_registry.hpp>
#include <utils/network.hpp>

namespace
{

using namespace lte::enb;
using Clock = std::chrono::steady_clock;

// The progressive checkpoint ladder from the work order. The eNB configuration
// validation accepts maxUes in 1..64, so the ladder above 64 cannot be
// exercised as a registry bound without changing that validation — which this
// phase does not do.
constexpr size_t kCheckpoints[] = {1, 2, 4, 8, 16, 32, 64};
constexpr size_t kConfigCeiling = 64;

// One isolated registry checkpoint: fill a registry to `count` synthetic
// contexts and report what it cost. Nothing here talks to an MME, an HSS or
// any EPC component.
struct CheckpointResult
{
    size_t target{};
    size_t registered{};
    bool capacityRefusedFurther{};
    double registrationMillis{};
    bool reached{};
};

CheckpointResult RunCheckpoint(size_t count)
{
    CheckpointResult result;
    result.target = count;

    UeRegistry registry(count);
    const auto start = Clock::now();
    for (size_t i = 0; i < count; ++i)
    {
        // Distinct radio identities and distinct peers: exactly what the
        // production registration path requires, and nothing more.
        const uint32_t radioUeId = static_cast<uint32_t>(1000 + i);
        const InetAddress peer{"127.0.0.1", static_cast<uint16_t>(20000 + i)};
        try
        {
            (void)registry.registerPeer(radioUeId, peer);
            ++result.registered;
        }
        catch (const RegistryError &)
        {
            break;
        }
    }
    const auto end = Clock::now();
    result.registrationMillis = std::chrono::duration<double, std::milli>(end - start).count();
    result.reached = result.registered == count;

    // The bound must be exact: one more context is refused rather than
    // silently accepted.
    if (result.reached)
    {
        try
        {
            (void)registry.registerPeer(999999, InetAddress{"127.0.0.1", 65000});
        }
        catch (const RegistryError &)
        {
            result.capacityRefusedFurther = true;
        }
    }
    return result;
}

} // namespace

TEST_CASE("lte/performance/capacity: isolated registry checkpoints hold and the bound is exact")
{
    for (const size_t count : kCheckpoints)
    {
        const auto result = RunCheckpoint(count);
        INFO("checkpoint " << count);
        CHECK(result.reached);
        CHECK(result.registered == count);
        CHECK(result.capacityRefusedFurther);

        // Classification, stated per checkpoint and never collapsed into a
        // single "supported" claim:
        //
        //   ISOLATED_CONTEXT_CAPACITY        yes — the registry held them
        //   SIMULATED_ATTACH_SUCCESS         no — no NAS procedure ran
        //   REAL_EPC_AUTHENTICATED_ATTACH    no — no EPC was involved
        //   SIMULTANEOUS_EPS_REGISTRATION    no — no MME registration exists
        //   SIMULTANEOUS_DEFAULT_BEARERS     no — no bearer was established
        //   INDEPENDENT_UE_IPV4_ASSIGNMENT   no — no PDN address exists
        //   USER_PLANE_READY                 no — no S1-U transport was set up
        //   STABLE_REGISTRATION_RETAINED     not measured by this harness
        //   CLEANUP_COMPLETE                 not measured by this harness
        //
        // Only the first is what this case establishes.
        CHECK(result.registered > 0);
    }
}

TEST_CASE("lte/performance/capacity: the configuration ceiling is named, not silently exceeded")
{
    // The eNB configuration parser accepts maxUes in 1..64. That is the first
    // ceiling a 512-UE goal meets, and it is a validation bound, not a
    // measured capacity result.
    CHECK(kConfigCeiling == 64);

    // A registry can be constructed above the ceiling in code, but the
    // production configuration path cannot express it. This case exists to
    // state the difference rather than to claim scalability support.
    UeRegistry registry(512);
    CHECK(registry.capacity() == 512);
    // ... and even then it holds isolated contexts, not EPS registrations.
}

TEST_CASE("lte/performance/capacity: per-context memory accounting is measured, not assumed")
{
    // The one number the capacity accounting needs and can measure exactly:
    // how large a production UE context is. Everything beyond it (map
    // overhead, allocator overhead) is reported as an estimate in the record.
    //
    // A 512-UE goal is 512 of these plus the indexes and the sockets; on this
    // host 7.6 GiB of RAM is not the first constraint and the registry is not
    // either. The first constraint is the configuration validation ceiling.
    constexpr size_t entryBytes = sizeof(EnbUeEntry);
    CHECK(entryBytes > 0);
    CHECK(entryBytes < 65536);
    // The registry keeps five lookup indexes plus the provisional map, each a
    // pointer per entry, so per-UE overhead is the entry plus index pointers.
    constexpr size_t indexPointersPerUe = 6 * sizeof(void *);
    constexpr size_t perUeBytes = entryBytes + indexPointersPerUe;
    // 512 UEs must fit comfortably in host memory for the isolated path to be
    // worth measuring at all.
    CHECK(perUeBytes * 512 < 64 * 1024 * 1024);
}

TEST_CASE("lte/performance/capacity: a full registry refuses rather than degrading")
{
    UeRegistry registry(4);
    for (size_t i = 0; i < 4; ++i)
        (void)registry.registerPeer(static_cast<uint32_t>(10 + i), InetAddress{"127.0.0.1", static_cast<uint16_t>(3000 + i)});
    CHECK(registry.size() == 4);

    // The refusal is deterministic and names the reason.
    CHECK_THROWS_AS(registry.registerPeer(50, InetAddress{"127.0.0.1", 3999}), RegistryError);

    // Releasing one context makes exactly one slot available again.
    for (auto *entry : registry.all())
    {
        registry.remove(*entry);
        break;
    }
    CHECK(registry.size() == 3);
    CHECK_NOTHROW(registry.registerPeer(51, InetAddress{"127.0.0.1", 3998}));
}

TEST_CASE("lte/performance/capacity: instrumentation is off by default and counts when enabled")
{
    UeRegistry registry(8);
    PerfCounters counters;
    registry.setPerfCounters(&counters);

    // Off by default: nothing is counted.
    (void)registry.registerPeer(1, InetAddress{"127.0.0.1", 4001});
    CHECK(counters.registrations.load() == 0);
    CHECK(counters.registryHighWater.load() == 0);

    // Enabled: each registration is counted and the high-water mark follows.
    counters.enabled.store(true);
    (void)registry.registerPeer(2, InetAddress{"127.0.0.1", 4002});
    (void)registry.registerPeer(3, InetAddress{"127.0.0.1", 4003});
    CHECK(counters.registrations.load() == 2);
    CHECK(counters.registryHighWater.load() == 3);

    // Teardowns are counted too, and disabling stops the counting again.
    for (auto *entry : registry.all())
    {
        registry.remove(*entry);
        break;
    }
    CHECK(counters.teardowns.load() == 1);
    counters.enabled.store(false);
    for (auto *entry : registry.all())
    {
        registry.remove(*entry);
        break;
    }
    CHECK(counters.teardowns.load() == 1);

    // The counters carry no subscriber material by construction: they are
    // integers and nothing else.
    CHECK(sizeof(PerfCounters) < 256);
}

TEST_CASE("lte/performance/capacity: poll counters record iterations and radio packets")
{
    // A configuration the test owns: a loopback S1-U endpoint and a radio link
    // on ephemeral local ports, so nothing touches the laboratory network.
    EnbConfig config;
    config.plmn = Plmn{"460", "02"};
    config.enbId = 0x00ABCDE;
    config.tac = 7;
    config.localAddress = "127.0.0.1";
    config.mmeAddress = "127.0.0.1";
    config.ueLinkAddress = "127.0.0.1";
    config.ueLinkPort = 0;
    config.s1uAddress = "127.0.0.1";
    config.s1uPort = 0;
    config.allowLoopbackS1u = true;
    EnbMultiplexer multiplexer{config};
    PerfCounters &counters = multiplexer.perfCounters();

    // Off by default.
    multiplexer.poll(16, 16);
    CHECK(counters.pollIterations.load() == 0);

    counters.enabled.store(true);
    multiplexer.poll(16, 16);
    multiplexer.poll(16, 16);
    CHECK(counters.pollIterations.load() == 2);
    // With no radio traffic in the test environment, no packets are polled.
    CHECK(counters.radioPacketsPolled.load() == 0);

    counters.reset();
    CHECK(counters.pollIterations.load() == 0);
}
