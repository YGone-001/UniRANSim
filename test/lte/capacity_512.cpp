//
// This file is a part of UERANSIM project.
// Copyright (c) 2027 ALİ GÜNGÖR.
//
// https://github.com/aligungr/UERANSIM/
// See README, LICENSE, and CONTRIBUTING files for licensing details.
//

// Phase 19-B/19-C: production 512-context capacity, isolated.
//
// These cases exercise the production registry and the production radio
// ingress with test-owned contexts and test-owned UDP peers. Everything here
// is ISOLATED_REGISTRY_CONTEXT_ACTIVE, ISOLATED_CONTEXT_RETAINED or
// SIMULATED_RADIO_ENDPOINT_ACTIVE and nothing else: no NAS procedure runs, no
// EPC is contacted, and a synthetic context is never an authenticated EPS
// Attach or a retained EPS registration.

#include <ext/doctest/doctest.h>

#include <algorithm>
#include <chrono>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <fstream>
#include <memory>
#include <random>
#include <string>
#include <thread>
#include <vector>

#include <lte/enb/capacity_report.hpp>
#include <lte/enb/config.hpp>
#include <lte/enb/runtime_metrics.hpp>
#include <lte/enb/multiplexer.hpp>
#include <lte/enb/ue_registry.hpp>
#include <lte/ue/radio_link.hpp>
#include <utils/network.hpp>

namespace
{

using namespace lte::enb;
using Clock = std::chrono::steady_clock;

// The complete ladder, including the checkpoints the previous phase could not
// reach because the configuration parser rejected them.
constexpr size_t kLadder[] = {1, 2, 4, 8, 16, 32, 64, 128, 256, 512};

double MillisSince(Clock::time_point start)
{
    return std::chrono::duration<double, std::milli>(Clock::now() - start).count();
}

std::string WriteConfig(const std::string &body)
{
    static int counter = 0;
    const std::string path = "/tmp/uniransim-capacity-" + std::to_string(counter++) + ".yaml";
    std::ofstream out(path);
    out << body;
    return path;
}

std::string BaseConfig()
{
    return "mcc: 460\n"
           "mnc: 02\n"
           "enbId: 703710\n"
           "tac: 7\n"
           "s1apIp: 127.0.0.1\n"
           "mme:\n"
           "  address: 127.0.0.1\n"
           "  port: 36412\n"
           "pagingDrx: 128\n";
}

// Fills one production registry to `count` contexts and records what it cost.
CapacityCheckpoint RunRegistryCheckpoint(size_t count)
{
    CapacityCheckpoint checkpoint;
    checkpoint.requestedCount = count;

    // The three memory observations are taken at distinct points and are never
    // collapsed into one number. VmHWM is the kernel's peak for this process;
    // a single current-RSS sample is not a peak.
    const auto baseline = ReadSelfMemory();
    checkpoint.baselineRssBytes = baseline.currentRssBytes;

    UeRegistry registry(count);
    const auto registrationStart = Clock::now();
    for (size_t i = 0; i < count; ++i)
    {
        try
        {
            (void)registry.registerPeer(static_cast<uint32_t>(1000 + i),
                                        InetAddress{"127.0.0.1", static_cast<uint16_t>(20000 + i)});
            ++checkpoint.createdContexts;
        }
        catch (const RegistryError &)
        {
            ++checkpoint.failedCreations;
        }
    }
    checkpoint.registrationDurationMs = MillisSince(registrationStart);
    checkpoint.activeContexts = registry.size();
    checkpoint.peakContexts = registry.size();

    // Every context must be independently addressable by radio identity and by
    // peer; a collision would mean one index silently overwrote another.
    const auto lookupStart = Clock::now();
    size_t found = 0;
    for (size_t i = 0; i < count; ++i)
    {
        const auto *byRadio = registry.find(static_cast<uint32_t>(1000 + i));
        const auto *byPeer = registry.findByPeer(InetAddress{"127.0.0.1", static_cast<uint16_t>(20000 + i)});
        if (byRadio != nullptr && byRadio == byPeer)
            ++found;
    }
    checkpoint.lookupDurationMs = MillisSince(lookupStart);
    if (found != count)
        ++checkpoint.failedCreations;

    // The bound must be exact: one more context is refused.
    try
    {
        (void)registry.registerPeer(999999, InetAddress{"127.0.0.1", 65000});
        ++checkpoint.failedCreations;
    }
    catch (const RegistryError &)
    {
        checkpoint.configurationLimitReached = true;
    }

    // A declared retention window: the same contexts must still resolve after
    // it. This is ISOLATED_CONTEXT_RETAINED, not EPS registration retention.
    const auto retentionStart = Clock::now();
    std::this_thread::sleep_for(std::chrono::milliseconds(100));
    size_t retained = 0;
    for (size_t i = 0; i < count; ++i)
        if (registry.find(static_cast<uint32_t>(1000 + i)) != nullptr)
            ++retained;
    checkpoint.retentionObservationMs = MillisSince(retentionStart);
    const bool contextRetained = retained == count && registry.size() == count;

    const auto observed = ReadSelfMemory();
    checkpoint.observedRssBytes = observed.currentRssBytes;
    checkpoint.peakRssBytes = observed.peakObserved ? observed.peakRssBytes : observed.currentRssBytes;
    checkpoint.pssBytes = observed.pssBytes;
    checkpoint.pssAvailable = observed.sharedPagesResolved;
    checkpoint.rssSampleCount = 2;
    if (checkpoint.createdContexts != 0)
    {
        const int64_t delta = static_cast<int64_t>(checkpoint.observedRssBytes) -
                              static_cast<int64_t>(checkpoint.baselineRssBytes);
        checkpoint.perContextRssDeltaBytes = delta / static_cast<int64_t>(checkpoint.createdContexts);
    }

    // Release every context and verify nothing is left behind.
    const auto cleanupStart = Clock::now();
    while (registry.size() > 0)
    {
        auto *entry = *registry.all().begin();
        registry.remove(*entry);
    }
    checkpoint.cleanupDurationMs = MillisSince(cleanupStart);
    checkpoint.remainingContexts = registry.size();

    // Only what was actually observed is claimed. A synthetic registry entry
    // establishes isolated context capacity and context persistence; it is not
    // an EPS registration, is not retained registration and is not an Attach.
    if (checkpoint.createdContexts == count && checkpoint.failedCreations == 0 &&
        checkpoint.remainingContexts == 0 && checkpoint.configurationLimitReached)
    {
        checkpoint.classifications.isolatedContextCapacity = EvidenceState::PASS;
        checkpoint.classifications.isolatedRegistryContextActive = EvidenceState::PASS;
        checkpoint.classifications.cleanupComplete = EvidenceState::PASS;
    }
    else
    {
        checkpoint.classifications.isolatedContextCapacity = EvidenceState::FAIL;
        checkpoint.classifications.isolatedRegistryContextActive = EvidenceState::FAIL;
        checkpoint.classifications.cleanupComplete = EvidenceState::FAIL;
    }
    checkpoint.classifications.isolatedContextRetained =
        contextRetained ? EvidenceState::PASS : EvidenceState::FAIL;
    // EPS registration retention is never established by a registry workload.
    // Phase 19-B set this to PASS here; that was a misclassification.
    checkpoint.classifications.stableRegistrationRetained = EvidenceState::NOT_MEASURED;
    // Everything below requires real EPC or process evidence and is never
    // inferred from a synthetic context.
    checkpoint.classifications.simulatedAttachSuccess = EvidenceState::NOT_APPLICABLE;
    checkpoint.classifications.realEpcAuthenticatedAttach = EvidenceState::BLOCKED_AUTHORIZATION;
    checkpoint.classifications.simultaneousEpsRegistration = EvidenceState::BLOCKED_AUTHORIZATION;
    checkpoint.classifications.simultaneousDefaultBearers = EvidenceState::NOT_APPLICABLE;
    checkpoint.classifications.independentUeIpv4Assignment = EvidenceState::NOT_APPLICABLE;
    checkpoint.classifications.userPlaneReady = EvidenceState::NOT_APPLICABLE;
    checkpoint.classifications.simulatedRadioEndpointActive = EvidenceState::NOT_APPLICABLE;
    checkpoint.classifications.actualLteUeProcessAlive = EvidenceState::NOT_MEASURED;
    checkpoint.classifications.preAuthAttachAttempt = EvidenceState::NOT_APPLICABLE;
    return checkpoint;
}

EnbConfig IsolatedMultiplexerConfig()
{
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
    config.maxUes = 512;
    return config;
}

} // namespace

TEST_CASE("lte/capacity: the production configuration path accepts 512 and rejects what it must")
{
    // Accepted after Phase 19-B.
    for (const char *value : {"1", "64", "65", "128", "256", "512"})
    {
        const auto path = WriteConfig(BaseConfig() + "maxUes: " + value + "\n");
        const auto config = LoadConfig(path);
        CHECK(config.maxUes == static_cast<int>(std::strtol(value, nullptr, 10)));
    }

    // The default is preserved when the field is absent.
    const auto defaultPath = WriteConfig(BaseConfig());
    CHECK(LoadConfig(defaultPath).maxUes == 8);

    // Rejected: above the supported bound, zero, negative and non-integers.
    for (const char *value : {"513", "0", "-1", "abc", "999999999999"})
    {
        const auto path = WriteConfig(BaseConfig() + "maxUes: " + value + "\n");
        CHECK_THROWS(LoadConfig(path));
    }
}

TEST_CASE("lte/capacity: the complete ladder fills the production registry to 512 contexts")
{
    for (const size_t count : kLadder)
    {
        const auto checkpoint = RunRegistryCheckpoint(count);
        INFO("checkpoint " << DescribeCheckpoint(checkpoint));
        CHECK(checkpoint.createdContexts == count);
        CHECK(checkpoint.activeContexts == count);
        CHECK(checkpoint.failedCreations == 0);
        CHECK(checkpoint.configurationLimitReached);
        CHECK(checkpoint.remainingContexts == 0);
        CHECK(checkpoint.classifications.isolatedContextCapacity == EvidenceState::PASS);
        CHECK(checkpoint.classifications.isolatedRegistryContextActive == EvidenceState::PASS);
        CHECK(checkpoint.classifications.isolatedContextRetained == EvidenceState::PASS);
        CHECK(checkpoint.classifications.cleanupComplete == EvidenceState::PASS);
        // A synthetic context is never a real EPC Attach and never a simulated
        // one either: no NAS procedure ran.
        CHECK(checkpoint.classifications.realEpcAuthenticatedAttach == EvidenceState::BLOCKED_AUTHORIZATION);
        CHECK(checkpoint.classifications.simulatedAttachSuccess == EvidenceState::NOT_APPLICABLE);
        CHECK(checkpoint.classifications.actualLteUeProcessAlive == EvidenceState::NOT_MEASURED);
        CHECK(checkpoint.classifications.preAuthAttachAttempt == EvidenceState::NOT_APPLICABLE);
        // The Phase 19-B defect: no EPS registration exists, so its retention
        // cannot be claimed by this workload.
        CHECK(checkpoint.classifications.stableRegistrationRetained == EvidenceState::NOT_MEASURED);
        CHECK(checkpoint.classifications.stableRegistrationRetained != EvidenceState::PASS);
        // Memory: peak is VmHWM, current is VmRSS, baseline was taken first.
        // VmHWM is the kernel's high-water mark and is updated at the
        // allocator's own granularity, so a later VmRSS sample can exceed it by
        // a few pages; the two are separate observations, not one ordering.
        CHECK(checkpoint.baselineRssBytes > 0);
        CHECK(checkpoint.observedRssBytes > 0);
        CHECK(checkpoint.peakRssBytes > 0);
        CHECK(checkpoint.rssSampleCount == 2);
    }
}

TEST_CASE("lte/capacity: a synthetic registry cannot claim eps registration or registration retention")
{
    // The Phase 19-B checkpoint set STABLE_REGISTRATION_RETAINED to PASS after
    // an immediate synthetic allocation and cleanup. This case is the
    // regression: no EPS registration exists, so every EPS concept must stay
    // unproven while context persistence is reported under its own field.
    const auto checkpoint = RunRegistryCheckpoint(8);

    CHECK(checkpoint.classifications.isolatedContextCapacity == EvidenceState::PASS);
    CHECK(checkpoint.classifications.isolatedRegistryContextActive == EvidenceState::PASS);
    CHECK(checkpoint.classifications.isolatedContextRetained == EvidenceState::PASS);

    const EvidenceState epsConcepts[] = {
        checkpoint.classifications.stableRegistrationRetained,
        checkpoint.classifications.simulatedAttachSuccess,
        checkpoint.classifications.realEpcAuthenticatedAttach,
        checkpoint.classifications.simultaneousEpsRegistration,
        checkpoint.classifications.simultaneousDefaultBearers,
        checkpoint.classifications.independentUeIpv4Assignment,
        checkpoint.classifications.userPlaneReady,
    };
    for (const auto state : epsConcepts)
        CHECK(state != EvidenceState::PASS);

    CHECK(checkpoint.classifications.stableRegistrationRetained == EvidenceState::NOT_MEASURED);
    CHECK(checkpoint.classifications.simulatedAttachSuccess == EvidenceState::NOT_APPLICABLE);
    CHECK(checkpoint.classifications.realEpcAuthenticatedAttach == EvidenceState::BLOCKED_AUTHORIZATION);
    CHECK(checkpoint.classifications.simultaneousEpsRegistration == EvidenceState::BLOCKED_AUTHORIZATION);

    // A resource-limited workload has its own state and is not folded into a
    // failure or into NOT_MEASURED.
    CHECK(std::string(ToString(EvidenceState::BLOCKED_RESOURCE_LIMIT)) == "BLOCKED_RESOURCE_LIMIT");
}

TEST_CASE("lte/capacity: five hundred and twelve contexts are independently indexed")
{
    const auto checkpoint = RunRegistryCheckpoint(512);
    CHECK(checkpoint.createdContexts == 512);
    CHECK(checkpoint.activeContexts == 512);
    CHECK(checkpoint.peakContexts == 512);

    // The lookup pass inside the checkpoint verified every radio identity and
    // every peer association resolves to the same entry; a collision would have
    // counted as a failed creation.
    CHECK(checkpoint.failedCreations == 0);
    CHECK(checkpoint.lookupDurationMs >= 0.0);
}

TEST_CASE("lte/capacity: identity collisions are refused and do not cost a slot")
{
    UeRegistry registry(8);
    (void)registry.registerPeer(100, InetAddress{"127.0.0.1", 21000});
    CHECK(registry.size() == 1);

    // The same radio identity on a different peer, and the same peer with a
    // different identity: both are refused, and neither consumes a slot.
    CHECK_THROWS_AS(registry.registerPeer(100, InetAddress{"127.0.0.1", 21001}), RegistryError);
    CHECK_THROWS_AS(registry.registerPeer(101, InetAddress{"127.0.0.1", 21000}), RegistryError);
    CHECK(registry.size() == 1);

    // A zero radio identity is refused before any allocation.
    CHECK_THROWS_AS(registry.registerPeer(0, InetAddress{"127.0.0.1", 21002}), RegistryError);
    CHECK(registry.size() == 1);

    // The refused registrations left the registry usable to its full bound.
    for (size_t i = 0; i < 7; ++i)
        CHECK_NOTHROW(registry.registerPeer(static_cast<uint32_t>(200 + i),
                                            InetAddress{"127.0.0.1", static_cast<uint16_t>(21100 + i)}));
    CHECK(registry.size() == 8);
}

TEST_CASE("lte/capacity: teardown under random order and repetition leaves no stale index")
{
    UeRegistry registry(64);
    for (size_t i = 0; i < 64; ++i)
        (void)registry.registerPeer(static_cast<uint32_t>(1000 + i),
                                    InetAddress{"127.0.0.1", static_cast<uint16_t>(30000 + i)});
    CHECK(registry.size() == 64);

    // Remove in a shuffled order: the indexes must stay consistent whatever
    // the deletion order, and the same identity must be reusable afterwards.
    std::vector<uint32_t> identities;
    for (size_t i = 0; i < 64; ++i)
        identities.push_back(static_cast<uint32_t>(1000 + i));
    std::mt19937 rng{12345};
    std::shuffle(identities.begin(), identities.end(), rng);
    for (const uint32_t id : identities)
    {
        auto *entry = registry.find(id);
        REQUIRE(entry != nullptr);
        registry.remove(*entry);
    }
    CHECK(registry.size() == 0);

    // No stale mapping survives: every identity and peer is free again, and a
    // repeated removal of the same identity cannot succeed twice.
    for (size_t i = 0; i < 64; ++i)
    {
        CHECK(registry.find(static_cast<uint32_t>(1000 + i)) == nullptr);
        CHECK(registry.findByPeer(InetAddress{"127.0.0.1", static_cast<uint16_t>(30000 + i)}) == nullptr);
    }
    CHECK_NOTHROW(registry.registerPeer(1000, InetAddress{"127.0.0.1", 30000}));

    // Repeated cycles do not accumulate residue.
    for (int cycle = 0; cycle < 3; ++cycle)
    {
        UeRegistry again(512);
        for (size_t i = 0; i < 512; ++i)
            (void)again.registerPeer(static_cast<uint32_t>(i + 1), InetAddress{"127.0.0.1", static_cast<uint16_t>(40000 + i)});
        CHECK(again.size() == 512);
        while (again.size() > 0)
            again.remove(**again.all().begin());
        CHECK(again.size() == 0);
    }
}

TEST_CASE("lte/capacity: a provisional context consumes a slot and a full registry still releases")
{
    UeRegistry registry(2);
    auto &provisional = registry.allocateProvisional();
    // `size()` counts reached UEs; the provisional context is accounted in the
    // capacity bound rather than in that number.
    CHECK(registry.size() == 0);
    (void)registry.registerPeer(300, InetAddress{"127.0.0.1", 22000});
    CHECK(registry.size() == 1);

    // The bound is over both kinds of entry, so a registry of two with one
    // provisional context already refuses a third.
    CHECK_THROWS_AS(registry.registerPeer(301, InetAddress{"127.0.0.1", 22001}), RegistryError);
    registry.removeProvisional(provisional);
    CHECK(registry.size() == 1);
    CHECK_NOTHROW(registry.registerPeer(301, InetAddress{"127.0.0.1", 22001}));
}

TEST_CASE("lte/capacity: production radio ingress registers hundreds of peers")
{
    // The production multiplexer, real UDP datagrams from hundreds of
    // test-owned peers, real frame decoding and real peer registration. This
    // is SIMULATED_RADIO_CONTEXT_ACTIVE: a radio frame is not an authenticated
    // UE and no NAS procedure runs.
    EnbConfig config = IsolatedMultiplexerConfig();
    EnbMultiplexer multiplexer{config};
    const InetAddress radio = multiplexer.ueLinkAddress();
    REQUIRE(radio.getPort() != 0);

    // Each simulated radio endpoint is its own UDP socket, because the
    // registry keys a UE on its peer address and one shared socket would
    // present every frame as the same endpoint.
    constexpr size_t kPeers = 300;
    std::vector<std::unique_ptr<udp::UdpServer>> senders;
    for (size_t i = 0; i < kPeers; ++i)
        senders.push_back(std::make_unique<udp::UdpServer>("127.0.0.1", 0));
    // Send in batches and drain between them. Queuing every datagram before
    // any receive makes this kernel drop the excess: a raw UDP probe with 300
    // sender sockets delivers 222 of 300, deterministically. That is a burst
    // behaviour of the environment, not of the simulator, and interleaving the
    // sends with the poll loop is also how independent radios actually behave.
    for (size_t i = 0; i < kPeers; ++i)
    {
        const uint32_t ueId = static_cast<uint32_t>(5000 + i);
        lte::ue::link::Message frame;
        frame.type = lte::ue::link::MessageType::NAS_UPLINK;
        frame.ueId = ueId;
        frame.payload = {0x01, 0x02};
        const auto bytes = lte::ue::link::Encode(frame);
        senders[i]->Send(radio, bytes.data(), bytes.size());
        if ((i % 16) == 15)
            multiplexer.poll(64, 64);
    }

    // Drain the bounded poll loop until the burst is consumed or the budget is
    // clearly exhausted; the loop must make progress and must not hang.
    size_t iterations = 0;
    for (; iterations < 2000 && multiplexer.registry().size() < kPeers; ++iterations)
        multiplexer.poll(64, 64);

    CHECK(multiplexer.registry().size() == kPeers);
    CHECK(iterations < 2000);

    // Registration is independently addressable for every peer.
    size_t verified = 0;
    for (size_t i = 0; i < kPeers; ++i)
        if (multiplexer.registry().find(static_cast<uint32_t>(5000 + i)) != nullptr)
            ++verified;
    CHECK(verified == kPeers);
}

TEST_CASE("lte/capacity: radio processing stays bounded and one ue cannot starve another")
{
    EnbConfig config = IsolatedMultiplexerConfig();
    EnbMultiplexer multiplexer{config};
    const InetAddress radio = multiplexer.ueLinkAddress();
    // One socket per radio endpoint: the hot UE and each idle UE are separate
    // peers, exactly as separate simulated radios would be.
    udp::UdpServer hot{"127.0.0.1", 0};
    constexpr size_t kIdle = 20;
    std::vector<std::unique_ptr<udp::UdpServer>> cold;
    for (size_t i = 0; i < kIdle; ++i)
        cold.push_back(std::make_unique<udp::UdpServer>("127.0.0.1", 0));

    // One hot UE sends a burst; many idle UEs send one frame each. With a
    // bounded poll budget the idle UEs must still be served.
    // Interleaved with the poll loop so the kernel queue is never asked to
    // hold the whole burst at once.
    for (int i = 0; i < 50; ++i)
    {
        lte::ue::link::Message frame;
        frame.type = lte::ue::link::MessageType::NAS_UPLINK;
        frame.ueId = 9000;
        frame.payload = {0x00};
        const auto bytes = lte::ue::link::Encode(frame);
        hot.Send(radio, bytes.data(), bytes.size());
        if ((i % 8) == 7)
            multiplexer.poll(8, 8);
    }
    for (size_t i = 0; i < kIdle; ++i)
    {
        lte::ue::link::Message frame;
        frame.type = lte::ue::link::MessageType::NAS_UPLINK;
        frame.ueId = static_cast<uint32_t>(9100 + i);
        frame.payload = {0x00};
        const auto bytes = lte::ue::link::Encode(frame);
        cold[i]->Send(radio, bytes.data(), bytes.size());
        multiplexer.poll(8, 8);
    }

    for (int i = 0; i < 500 && multiplexer.registry().size() < kIdle + 1; ++i)
        multiplexer.poll(8, 8);

    // The hot UE cannot keep the idle ones from being served: every idle
    // identity is registered alongside it.
    CHECK(multiplexer.registry().find(9000) != nullptr);
    size_t idleServed = 0;
    for (size_t i = 0; i < kIdle; ++i)
        if (multiplexer.registry().find(static_cast<uint32_t>(9100 + i)) != nullptr)
            ++idleServed;
    CHECK(idleServed == kIdle);
}

TEST_CASE("lte/capacity: structured checkpoint records are reproducible")
{
    const auto first = RunRegistryCheckpoint(64);
    const auto second = RunRegistryCheckpoint(64);
    // The structural fields are identical run to run; only the durations and
    // the RSS figure are observations of the moment.
    CHECK(first.createdContexts == second.createdContexts);
    CHECK(first.activeContexts == second.activeContexts);
    CHECK(first.remainingContexts == second.remainingContexts);
    CHECK(first.classifications.isolatedContextCapacity == second.classifications.isolatedContextCapacity);

    // The rendering is machine-readable and names every classification.
    const std::string line = DescribeCheckpoint(first);
    CHECK(line.find("requested=64") != std::string::npos);
    CHECK(line.find("isolated=PASS") != std::string::npos);
    CHECK(line.find("real_epc=BLOCKED_AUTHORIZATION") != std::string::npos);
    CHECK(line.find("cleanup=PASS") != std::string::npos);
    // Phase 19-C keys are appended and each names its own workload.
    CHECK(line.find("registry_active=PASS") != std::string::npos);
    CHECK(line.find("radio_endpoint=NOT_APPLICABLE") != std::string::npos);
    CHECK(line.find("ue_process_alive=NOT_MEASURED") != std::string::npos);
    CHECK(line.find("preauth_attach=NOT_APPLICABLE") != std::string::npos);
    CHECK(line.find("ctx_retained=PASS") != std::string::npos);
    CHECK(line.find("retained=NOT_MEASURED") != std::string::npos);
    CHECK(line.find("rss_samples=2") != std::string::npos);
    CHECK(line.find("rss_per_context_delta=") != std::string::npos);
    CHECK(line.find("pss_available=") != std::string::npos);
}
