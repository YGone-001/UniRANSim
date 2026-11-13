//
// This file is a part of UERANSIM project.
// Copyright (c) 2027 ALİ GÜNGÖR.
//
// https://github.com/aligungr/UERANSIM/
// See README, LICENSE, and CONTRIBUTING files for licensing details.
//

// Phase 19-C: the real LTE UE process fleet.
//
// The short case launches two actual lte-ue executables and verifies the
// launcher, the observation and the cleanup. It runs only where the built
// binary is present and otherwise reports that it was not exercised; it never
// turns an absent binary into a pass.
//
// The progressive 1 -> 512 fleet is opt-in and local-only:
//
//   UNIRANSIM_RUN_PROCESS_FLEET=1 ./nr-tests --test-case="lte/fleet: progressive"
//
// It is deliberately not part of the ordinary CI matrix, which does not build
// the lte-ue executable in the sanitizer and coverage jobs.

#include <ext/doctest/doctest.h>

#include <chrono>
#include <cstdint>
#include <cstdlib>
#include <iostream>
#include <memory>
#include <string>
#include <thread>
#include <vector>

#include <lte/enb/capacity_report.hpp>
#include <lte/enb/multiplexer.hpp>
#include <lte/enb/process_fleet.hpp>
#include <lte/enb/runtime_metrics.hpp>
#include <lte/enb/ue_registry.hpp>
#include <lib/udp/server.hpp>

#include <unistd.h>

namespace
{

using namespace lte::enb;
using Clock = std::chrono::steady_clock;

struct CapturingSender : IS1apSender
{
    size_t messages{};
    void sendS1ap(uint16_t, const std::vector<uint8_t> &) override
    {
        ++messages;
    }
};

std::string SelfExecutable()
{
    char buffer[4096];
    const ssize_t length = readlink("/proc/self/exe", buffer, sizeof(buffer) - 1);
    if (length <= 0)
        return {};
    buffer[length] = '\0';
    return buffer;
}

EnbConfig FleetEnbConfig(size_t maxUes)
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
    config.maxUes = maxUes;
    return config;
}

uint16_t FreeUdpPort()
{
    udp::UdpServer probe{"127.0.0.1", 0};
    return probe.LocalAddress().getPort();
}

int EnvInt(const char *name, int fallback)
{
    const char *value = std::getenv(name);
    if (value == nullptr || value[0] == '\0')
        return fallback;
    try
    {
        return std::stoi(value);
    }
    catch (const std::exception &)
    {
        return fallback;
    }
}

// Drives the production multiplexer until every started child's radio identity
// is registered, or the deadline passes. Returns the number of peers seen.
size_t DriveUntilPeers(ProcessFleet &fleet, EnbMultiplexer &multiplexer, size_t target, int deadlineMs)
{
    const auto deadline = Clock::now() + std::chrono::milliseconds(deadlineMs);
    while (multiplexer.registry().size() < target && Clock::now() < deadline)
    {
        multiplexer.poll();
        fleet.ObservePeers(multiplexer);
        fleet.ReapExited();
        std::this_thread::sleep_for(std::chrono::milliseconds(1));
    }
    fleet.ObservePeers(multiplexer);
    return multiplexer.registry().size();
}

} // namespace

TEST_CASE("lte/fleet: the launcher starts and cleans up real lte ue processes")
{
    const std::string binary = ProcessFleet::ResolveBinary(SelfExecutable());
    if (binary.empty())
    {
        MESSAGE("lte-ue binary not present in this build; the process launcher was not exercised");
        return;
    }

    FleetConfig config;
    config.binaryPath = binary;
    config.workDirectory = "/tmp/uniransim-fleet-smoke";
    config.mcc = "001";
    config.mnc = "01";
    config.baseUeId = 70000;
    config.localPorts = {FreeUdpPort(), FreeUdpPort()};
    config.ueTimeoutMs = 10000;
    config.memoryReserveBytes = 64ULL * 1024ULL * 1024ULL;

    CapturingSender sender;
    EnbMultiplexer multiplexer{FleetEnbConfig(8), sender};
    config.enbPort = multiplexer.ueLinkAddress().getPort();
    REQUIRE(config.enbPort != 0);

    ProcessFleet fleet{config};
    REQUIRE(fleet.Prepare());
    const auto started = fleet.StartUpTo(2);
    REQUIRE(started.started == 2);
    CHECK(started.failed == 0);

    const size_t peers = DriveUntilPeers(fleet, multiplexer, 2, 5000);
    CHECK(peers == 2);
    CHECK(sender.messages == 2);

    fleet.BeginObservationWindow();
    std::this_thread::sleep_for(std::chrono::milliseconds(200));
    auto checkpoint = fleet.Observe(multiplexer);
    CHECK(checkpoint.aliveAtObservation == 2);
    CHECK(checkpoint.radioEndpoints == 2);
    CHECK(checkpoint.aggregateRssBytes > 0);
    CHECK(checkpoint.perProcessRss.count == 2);
    CHECK(checkpoint.tunDevices == 0); // pre-authentication: no TUN exists
    // A child inherits no harness descriptor: one radio UDP socket per UE, and
    // stdio plus that socket only.
    CHECK(checkpoint.aggregateUdpSockets == 2);
    // stdio plus one radio socket per child. A small tolerance keeps a
    // sanitizer or coverage runtime's own descriptor out of the assertion
    // while still catching an inherited harness socket.
    CHECK(checkpoint.aggregateFileDescriptors >= 8);
    CHECK(checkpoint.aggregateFileDescriptors <= 12);
    CHECK(checkpoint.classifications.actualLteUeProcessAlive == EvidenceState::PASS);
    CHECK(checkpoint.classifications.simulatedRadioEndpointActive == EvidenceState::PASS);
    CHECK(checkpoint.classifications.preAuthAttachAttempt == EvidenceState::PASS);
    // A live process and an Attach Request are still not EPS registration.
    CHECK(checkpoint.classifications.stableRegistrationRetained == EvidenceState::NOT_MEASURED);
    CHECK(checkpoint.classifications.realEpcAuthenticatedAttach == EvidenceState::BLOCKED_AUTHORIZATION);

    fleet.StopAll();
    const auto stopped = fleet.Observe(multiplexer);
    CHECK(stopped.aliveAtObservation == 0);
    CHECK(stopped.orphans == 0);
    CHECK(stopped.residualSockets == 0);
    CHECK(stopped.cleanupComplete);
}

TEST_CASE("lte/fleet: a child that cannot execute is reaped without leaking")
{
    // No real binary is needed: this exercises the launcher's failure path. The
    // fork succeeds, exec fails, and the launcher must report a startup failure
    // and leave no unreaped child, no residual socket and no extra descriptor.
    FleetConfig config;
    config.binaryPath = "/nonexistent/uniransim-lte-ue-for-failure-test";
    config.workDirectory = "/tmp/uniransim-fleet-failure";
    config.baseUeId = 80000;
    config.baseLocalPort = 25000;
    config.ueTimeoutMs = 5000;
    config.memoryReserveBytes = 64ULL * 1024ULL * 1024ULL;

    CapturingSender sender;
    EnbMultiplexer multiplexer{FleetEnbConfig(8), sender};
    config.enbPort = multiplexer.ueLinkAddress().getPort();
    REQUIRE(config.enbPort != 0);

    const size_t descriptorsBefore = CountOpenFileDescriptors(static_cast<int>(getpid()));
    ProcessFleet fleet{config};
    REQUIRE(fleet.Prepare());
    const auto started = fleet.StartUpTo(2);
    CHECK(started.started == 2);

    // Give the short-lived children time to fail exec and be reaped.
    std::this_thread::sleep_for(std::chrono::milliseconds(200));
    const auto checkpoint = fleet.Observe(multiplexer);
    CHECK(checkpoint.aliveAtObservation == 0);
    CHECK(checkpoint.startupFailures == 2);
    CHECK(checkpoint.radioEndpoints == 0);
    CHECK(checkpoint.classifications.actualLteUeProcessAlive == EvidenceState::FAIL);
    CHECK(checkpoint.classifications.preAuthAttachAttempt == EvidenceState::NOT_MEASURED);
    // An exec failure is not EPS authentication and not a radio endpoint.
    CHECK(checkpoint.classifications.realEpcAuthenticatedAttach == EvidenceState::BLOCKED_AUTHORIZATION);

    fleet.StopAll();
    const auto finalState = fleet.Observe(multiplexer);
    CHECK(finalState.aliveAtObservation == 0);
    CHECK(finalState.orphans == 0);
    CHECK(finalState.residualSockets == 0);
    CHECK(finalState.exitedNonZero == 2);
    const size_t descriptorsAfter = CountOpenFileDescriptors(static_cast<int>(getpid()));
    CHECK(descriptorsAfter <= descriptorsBefore + 2);
}

TEST_CASE("lte/fleet: progressive real lte ue process checkpoints")
{
    if (std::getenv("UNIRANSIM_RUN_PROCESS_FLEET") == nullptr)
    {
        MESSAGE("process fleet is opt-in; set UNIRANSIM_RUN_PROCESS_FLEET=1 to run it");
        return;
    }
    const std::string binary = ProcessFleet::ResolveBinary(SelfExecutable());
    REQUIRE(!binary.empty());

    constexpr size_t ladder[] = {1, 2, 4, 8, 16, 32, 64, 128, 256, 512};
    const int stableMs = EnvInt("UNIRANSIM_FLEET_STABLE_MS", 1500);
    const int reserveMb = EnvInt("UNIRANSIM_FLEET_RESERVE_MB", 512);

    for (const size_t count : ladder)
    {
        FleetConfig config;
        config.binaryPath = binary;
        config.workDirectory = "/tmp/uniransim-fleet-progressive";
        config.baseUeId = 50000;
        config.baseLocalPort = 20000;
        config.ueTimeoutMs = 60000;
        config.memoryReserveBytes = static_cast<uint64_t>(reserveMb) * 1024ULL * 1024ULL;

        CapturingSender sender;
        EnbMultiplexer multiplexer{FleetEnbConfig(512), sender};
        config.enbPort = multiplexer.ueLinkAddress().getPort();
        REQUIRE(config.enbPort != 0);

        ProcessFleet fleet{config};
        REQUIRE(fleet.Prepare());
        const auto started = fleet.StartUpTo(count, [&] {
            multiplexer.poll();
            fleet.ObservePeers(multiplexer);
            fleet.ReapExited();
            std::this_thread::sleep_for(std::chrono::milliseconds(1));
        });
        if (started.started == 0)
        {
            std::cout << "UNIRANSIM-FLEET-NOT-ATTEMPTED requested=" << count
                      << " reason=\"" << started.reason << "\"" << std::endl;
            break;
        }

        const auto startupBegin = Clock::now();
        const size_t peers = DriveUntilPeers(fleet, multiplexer, started.started,
                                             started.started >= 256 ? 30000 : 10000);
        const double startupWindowMs =
            std::chrono::duration<double, std::milli>(Clock::now() - startupBegin).count();
        const bool allSeen = peers == started.started;

        fleet.BeginObservationWindow();
        std::this_thread::sleep_for(std::chrono::milliseconds(stableMs));
        auto checkpoint = fleet.Observe(multiplexer);
        fleet.StopAll();
        checkpoint.shutdownMs = fleet.ShutdownDurationMs();
        // Ask the stopped fleet for its own cleanup verdict via a final
        // observation: no child is alive and no child socket remains.
        const auto finalState = fleet.Observe(multiplexer);
        checkpoint.orphans = finalState.orphans;
        checkpoint.residualSockets = finalState.residualSockets;
        checkpoint.cleanupComplete = finalState.cleanupComplete;
        checkpoint.classifications.cleanupComplete =
            finalState.cleanupComplete ? EvidenceState::PASS : EvidenceState::FAIL;
        checkpoint.stopReason = started.reason;
        checkpoint.resourceLimited = started.resourceLimited;
        checkpoint.allPeersSeen = allSeen;

        std::cout << "UNIRANSIM-FLEET requested=" << count << " spawn_ms=" << started.spawnDurationMs
                  << " startup_window_ms=" << startupWindowMs
                  << " " << DescribeFleetCheckpoint(checkpoint) << std::endl;

        for (auto *entry : multiplexer.registry().all())
            multiplexer.registry().remove(*entry);

        if (!allSeen || started.started != count || !checkpoint.cleanupComplete)
            break;
    }
}