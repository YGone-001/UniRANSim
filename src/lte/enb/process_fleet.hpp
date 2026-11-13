//
// This file is a part of UERANSIM project.
// Copyright (c) 2027 ALİ GÜNGÖR.
//
// https://github.com/aligungr/UERANSIM/
// See README, LICENSE, and CONTRIBUTING files for licensing details.
//

// Phase 19-C: an isolated launcher for real LTE UE processes.
//
// The measured process is the actual lte-ue executable, not a registry entry
// and not a fixture socket. Each child receives a generated temporary
// configuration with a test-owned identity, its own local UDP port and a
// simulated-radio endpoint that is the caller's isolated eNB multiplexer. The
// children never touch a real EPC: no MME address from the laboratory is used,
// no subscriber secret is copied, and the generated identities are unmistakably
// artificial and exist only for the lifetime of the run.
//
// This is a bounded harness, not a production feature. It stops at a declared
// memory reserve, a startup deadline or a fork failure, and it always reaps what
// it started.

#pragma once

#include "capacity_report.hpp"
#include "multiplexer.hpp"
#include "runtime_metrics.hpp"

#include <cstddef>
#include <cstdint>
#include <functional>
#include <map>
#include <string>
#include <vector>

#include <sys/types.h>

namespace lte::enb
{

struct FleetConfig
{
    // Absolute path to the real lte-ue executable.
    std::string binaryPath;
    // Directory for the generated temporary configurations. It must be
    // test-owned and is created if absent.
    std::string workDirectory{"/tmp/uniransim-fleet"};
    // Test PLMN and IMSI prefix. 001/01 is the reserved test network used
    // throughout this repository's offline fixtures.
    std::string mcc{"001"};
    std::string mnc{"01"};
    uint32_t baseUeId{50000};
    uint16_t baseLocalPort{20000};
    // Optional explicit per-child local ports. When set, they take precedence
    // over baseLocalPort + index; the smoke test uses two probed free ports so
    // a busy fixed port cannot turn a launcher test into an environment test.
    std::vector<uint16_t> localPorts;
    std::string enbAddress{"127.0.0.1"};
    uint16_t enbPort{};
    int ueTimeoutMs{6000};
    // The launcher refuses to start another child when MemAvailable is below
    // this reserve. It is a stopping rule, not a tuning knob.
    uint64_t memoryReserveBytes{512ULL * 1024ULL * 1024ULL};
    std::string tunPrefix{"uniransim-lte"};
};

// The evidence for one attempted checkpoint. Every field is an observation of
// this run; a checkpoint that was not attempted is reported as a reason string
// rather than as a failure.
struct FleetCheckpoint
{
    size_t requested{};
    size_t started{};
    size_t aliveAtObservation{};
    size_t exitedBeforeObservation{};
    size_t startupFailures{};
    size_t exitedZero{};
    size_t exitedNonZero{};
    size_t killedBySignal{};
    size_t radioEndpoints{};
    size_t expectedPeers{};
    bool allPeersSeen{};

    uint64_t aggregateRssBytes{};
    uint64_t aggregatePssBytes{};
    uint64_t aggregatePrivateBytes{};
    bool pssComplete{};
    SizeSummary perProcessRss;

    double startupCpuPercentOfOneCore{};
    double startupCpuPercentOfHost{};
    double aggregateCpuPercentOfOneCore{};
    double aggregateCpuPercentOfHost{};
    size_t aggregateThreads{};
    size_t aggregateFileDescriptors{};
    size_t aggregateUdpSockets{};
    size_t tunDevices{};

    LatencySummary startupMs;
    double stableWindowMs{};
    double shutdownMs{};
    size_t orphans{};
    size_t residualSockets{};
    bool cleanupComplete{};

    uint64_t availableMemoryAtObservation{};
    uint64_t memoryReserveBytes{};
    bool resourceLimited{};
    std::string stopReason;
    CapacityClassifications classifications;
};

class ProcessFleet
{
  public:
    explicit ProcessFleet(FleetConfig config);
    ~ProcessFleet();

    ProcessFleet(const ProcessFleet &) = delete;
    ProcessFleet &operator=(const ProcessFleet &) = delete;

    // Creates the work directory. Returns false if it cannot be used.
    bool Prepare();

    struct StartResult
    {
        size_t started{};
        size_t failed{};
        bool resourceLimited{};
        double spawnDurationMs{};
        std::string reason;
    };

    // Starts children until the fleet holds the requested total of alive
    // processes, the memory reserve would be crossed, or a fork/exec failure
    // occurs. The count is the total for this checkpoint, not an increment.
    //
    // betweenSpawns runs after every few spawns. The caller uses it to drain
    // the production radio socket, so a 512-process startup is a sequence of
    // bounded arrivals and not an accidental microburst.
    StartResult StartUpTo(size_t count, const std::function<void()> &betweenSpawns);
    StartResult StartUpTo(size_t count);

    // Called by the driver after each production poll. Records the first moment
    // the eNB registry held each expected radio identity, which is the moment
    // the simulated radio endpoint became established.
    void ObservePeers(const EnbMultiplexer &multiplexer);

    // Starts the CPU and wall-clock window used by the next Observe().
    void BeginObservationWindow();

    // Reads one observation of every child and of the shared host state. It
    // never kills or waits for a child.
    FleetCheckpoint Observe(const EnbMultiplexer &multiplexer);

    // Non-blocking reaping. A child that has exited is no longer alive; its
    // status is recorded so a startup failure is distinguishable from a
    // shutdown.
    void ReapExited();

    // Sends SIGTERM to every live child, waits for the deadline, then SIGKILLs
    // the remainder. Safe to call repeatedly and from the destructor.
    void StopAll();

    [[nodiscard]] size_t Started() const { return m_spawned; }
    [[nodiscard]] size_t Alive() const;
    [[nodiscard]] uint32_t UeIdAt(size_t index) const { return m_config.baseUeId + static_cast<uint32_t>(index); }
    [[nodiscard]] uint16_t LocalPortAt(size_t index) const
    {
        if (index < m_config.localPorts.size())
            return m_config.localPorts[index];
        return static_cast<uint16_t>(m_config.baseLocalPort + index);
    }
    [[nodiscard]] const FleetConfig &Config() const { return m_config; }
    [[nodiscard]] double ShutdownDurationMs() const { return m_lastShutdownMs; }

    // Resolves the real lte-ue binary without guessing silently: an explicit
    // environment variable wins, then the build directory next to the test
    // executable, then the repository's build directory.
    static std::string ResolveBinary(const std::string &testExecutablePath);

  private:
    struct Child
    {
        pid_t pid{-1};
        std::string configPath;
        bool reaped{};
        int status{};
        bool seen{};
        double firstSeenMs{-1.0};
        uint64_t cpuAtWindowStart{};
        uint64_t cpuAtFirstSeen{};
        uint64_t rssBytes{};
    };

    bool WriteConfig(size_t index);
    bool Spawn(size_t index);
    void ReapOne(size_t index, bool blocking);

    FleetConfig m_config;
    std::vector<Child> m_children;
    std::vector<double> m_spawnMs;
    std::chrono::steady_clock::time_point m_runStart;
    std::chrono::steady_clock::time_point m_windowStart;
    bool m_windowStarted{};
    double m_lastShutdownMs{};
    size_t m_spawned{};
    size_t m_lastOrphans{};
    size_t m_lastResidualSockets{};
    bool m_lastCleanupComplete{};
    bool m_lastResourceLimited{};
    bool m_stopped{};
    std::string m_lastStopReason;
};

// A stable single-line rendering of one fleet checkpoint.
std::string DescribeFleetCheckpoint(const FleetCheckpoint &checkpoint);

} // namespace lte::enb