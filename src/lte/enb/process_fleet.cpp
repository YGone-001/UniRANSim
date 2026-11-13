//
// This file is a part of UERANSIM project.
// Copyright (c) 2027 ALİ GÜNGÖR.
//
// https://github.com/aligungr/UERANSIM/
// See README, LICENSE, and CONTRIBUTING files for licensing details.
//

#include "process_fleet.hpp"

#include <algorithm>
#include <cerrno>
#include <chrono>
#include <cstdlib>
#include <cstring>
#include <filesystem>
#include <fstream>
#include <sstream>
#include <stdexcept>
#include <string>
#include <thread>
#include <unistd.h>

#include <fcntl.h>
#include <signal.h>
#include <sys/resource.h>
#include <sys/syscall.h>
#include <sys/wait.h>

namespace lte::enb
{
namespace
{

double MillisBetween(const std::chrono::steady_clock::time_point &from,
                     const std::chrono::steady_clock::time_point &to)
{
    return std::chrono::duration<double, std::milli>(to - from).count();
}

bool ProcessExists(pid_t pid)
{
    if (pid <= 0)
        return false;
    return std::filesystem::exists("/proc/" + std::to_string(pid));
}

} // namespace

ProcessFleet::ProcessFleet(FleetConfig config) : m_config(std::move(config))
{
}

ProcessFleet::~ProcessFleet()
{
    StopAll();
}

bool ProcessFleet::Prepare()
{
    std::error_code error;
    std::filesystem::create_directories(m_config.workDirectory, error);
    if (error)
        return false;
    // One private subdirectory per run keeps two concurrent harness runs from
    // overwriting each other's configurations.
    m_config.workDirectory += "/run-" + std::to_string(static_cast<long>(getpid()));
    std::filesystem::create_directories(m_config.workDirectory, error);
    m_runStart = std::chrono::steady_clock::now();
    return !error;
}

bool ProcessFleet::WriteConfig(size_t index)
{
    const std::string name = "ue-" + std::to_string(index) + ".yaml";
    const std::string path = m_config.workDirectory + "/" + name;
    std::ofstream out(path);
    if (!out)
        return false;
    // The identity is artificial and carries the reserved test MCC/MNC 001/01.
    // It is never sent to a real EPC: the radio endpoint is the caller's
    // isolated multiplexer and the timeout is short.
    const std::string imsi = m_config.mcc + m_config.mnc +
                             std::to_string(1000000000ULL + static_cast<unsigned long long>(index)).substr(1);
    out << "imsi: \"" << imsi << "\"\n";
    out << "mcc: \"" << m_config.mcc << "\"\n";
    out << "mnc: \"" << m_config.mnc << "\"\n";
    out << "ueId: " << (m_config.baseUeId + static_cast<uint32_t>(index)) << "\n";
    // Fixed, unmistakably synthetic key material. No subscriber secret is
    // cloned, and no authentication ever runs in this harness.
    out << "k: \"00112233445566778899aabbccddeeff\"\n";
    out << "opc: \"00112233445566778899aabbccddeeff\"\n";
    out << "amf: \"8000\"\n";
    out << "initialSqn: \"000000000000\"\n";
    out << "pdnType: IPv4\n";
    out << "enbLink:\n";
    out << "  localAddress: " << m_config.enbAddress << "\n";
    out << "  localPort: " << (m_config.baseLocalPort + index) << "\n";
    out << "  address: " << m_config.enbAddress << "\n";
    out << "  port: " << m_config.enbPort << "\n";
    out << "  timeoutMs: " << m_config.ueTimeoutMs << "\n";
    out << "tun:\n";
    out << "  required: false\n";
    out << "  namePrefix: " << m_config.tunPrefix << "\n";
    out << "  mtu: 1400\n";
    out.flush();
    if (!out)
        return false;
    m_children[index].configPath = path;
    return true;
}

bool ProcessFleet::Spawn(size_t index)
{
    if (!WriteConfig(index))
        return false;
    const std::string binary = m_config.binaryPath;
    const std::string configPath = m_children[index].configPath;
    const auto spawnStart = std::chrono::steady_clock::now();
    const pid_t pid = fork();
    if (pid < 0)
        return false;
    if (pid == 0)
    {
        const int devNull = open("/dev/null", O_RDWR);
        if (devNull >= 0)
        {
            dup2(devNull, STDIN_FILENO);
            dup2(devNull, STDOUT_FILENO);
            dup2(devNull, STDERR_FILENO);
        }
        // The child must inherit nothing else. Without this, every UE would
        // hold a duplicate of the harness's radio and S1-U sockets, inflating
        // the descriptor and UDP-socket counts and keeping the harness sockets
        // alive after their owner closed them.
#ifdef SYS_close_range
        if (syscall(SYS_close_range, 3U, ~0U, 0U) != 0)
#endif
        {
            for (int fd = 3; fd < 1024; ++fd)
                close(fd);
        }
        execl(binary.c_str(), binary.c_str(), "-c", configPath.c_str(), static_cast<char *>(nullptr));
        _exit(127);
    }
    m_children[index].pid = pid;
    m_children[index].reaped = false;
    m_children[index].seen = false;
    m_children[index].firstSeenMs = -1.0;
    m_spawnMs[index] = MillisBetween(m_runStart, spawnStart);
    return true;
}

ProcessFleet::StartResult ProcessFleet::StartUpTo(size_t count)
{
    return StartUpTo(count, {});
}

ProcessFleet::StartResult ProcessFleet::StartUpTo(size_t count, const std::function<void()> &betweenSpawns)
{
    StartResult result;
    const auto spawnBegin = std::chrono::steady_clock::now();
    if (count > m_children.size())
    {
        m_children.resize(count);
        m_spawnMs.resize(count, 0.0);
    }
    struct rlimit limit{};
    const bool haveLimit = getrlimit(RLIMIT_NOFILE, &limit) == 0;
    for (size_t index = 0; index < count; ++index)
    {
        if (m_children[index].pid > 0)
            continue;
        const uint64_t available = ReadAvailableMemoryBytes();
        if (available != 0 && available < m_config.memoryReserveBytes)
        {
            result.resourceLimited = true;
            result.reason = "MemAvailable=" + std::to_string(available) + " below reserve=" +
                            std::to_string(m_config.memoryReserveBytes);
            break;
        }
        if (haveLimit && index + 64 >= static_cast<size_t>(limit.rlim_cur))
        {
            result.resourceLimited = true;
            result.reason = "file descriptor soft limit " + std::to_string(limit.rlim_cur) + " is close";
            break;
        }
        if (!Spawn(index))
        {
            ++result.failed;
            result.resourceLimited = true;
            result.reason = "fork or configuration write failed at index " + std::to_string(index);
            break;
        }
        ++result.started;
        ++m_spawned;
        if (betweenSpawns && ((index % 4) == 3))
            betweenSpawns();
    }
    if (betweenSpawns)
        betweenSpawns();
    result.spawnDurationMs = MillisBetween(spawnBegin, std::chrono::steady_clock::now());
    m_lastResourceLimited = result.resourceLimited;
    m_lastStopReason = result.reason;
    return result;
}

void ProcessFleet::ObservePeers(const EnbMultiplexer &multiplexer)
{
    const auto now = std::chrono::steady_clock::now();
    for (size_t index = 0; index < m_children.size(); ++index)
    {
        if (m_children[index].seen || m_children[index].pid <= 0)
            continue;
        if (multiplexer.registry().find(UeIdAt(index)) == nullptr)
            continue;
        m_children[index].seen = true;
        m_children[index].firstSeenMs = MillisBetween(m_runStart, now) - m_spawnMs[index];
        m_children[index].cpuAtFirstSeen = ReadProcessCpuTimeMicros(m_children[index].pid);
    }
}

void ProcessFleet::BeginObservationWindow()
{
    m_windowStart = std::chrono::steady_clock::now();
    m_windowStarted = true;
    for (auto &child : m_children)
        child.cpuAtWindowStart = child.reaped ? 0 : ReadProcessCpuTimeMicros(child.pid);
}

void ProcessFleet::ReapOne(size_t index, bool blocking)
{
    auto &child = m_children[index];
    if (child.pid <= 0 || child.reaped)
        return;
    int status = 0;
    const pid_t result = waitpid(child.pid, &status, blocking ? 0 : WNOHANG);
    if (result == child.pid)
    {
        child.reaped = true;
        child.status = status;
    }
}

void ProcessFleet::ReapExited()
{
    for (size_t index = 0; index < m_children.size(); ++index)
        ReapOne(index, false);
}

size_t ProcessFleet::Alive() const
{
    size_t alive = 0;
    for (const auto &child : m_children)
        if (!child.reaped && ProcessExists(child.pid))
            ++alive;
    return alive;
}

FleetCheckpoint ProcessFleet::Observe(const EnbMultiplexer &multiplexer)
{
    // Reap first: a zombie still has a /proc entry and must not be counted as a
    // live UE.
    ReapExited();
    FleetCheckpoint checkpoint;
    checkpoint.pssComplete = !m_children.empty();
    checkpoint.requested = m_children.size();
    checkpoint.started = Started();
    checkpoint.expectedPeers = checkpoint.started;

    std::vector<uint64_t> rssSamples;
    std::vector<double> startupSamples;
    uint64_t cpuMicros = 0;
    uint64_t startupCpuMicros = 0;
    double startupAgeMs = 0.0;
    bool haveCpu = false;
    const auto now = std::chrono::steady_clock::now();

    for (size_t index = 0; index < m_children.size(); ++index)
    {
        const auto &child = m_children[index];
        if (child.pid <= 0)
            continue;
        if (multiplexer.registry().find(UeIdAt(index)) != nullptr)
            ++checkpoint.radioEndpoints;
        const bool alive = !child.reaped && ProcessExists(child.pid);
        if (!alive)
        {
            if (!child.seen)
                ++checkpoint.startupFailures;
            else
                ++checkpoint.exitedBeforeObservation;
            if (child.reaped)
            {
                if (WIFSIGNALED(child.status))
                    ++checkpoint.killedBySignal;
                else if (WIFEXITED(child.status) && WEXITSTATUS(child.status) == 0)
                    ++checkpoint.exitedZero;
                else
                    ++checkpoint.exitedNonZero;
            }
            continue;
        }
        ++checkpoint.aliveAtObservation;
        auto memory = ReadProcessMemory(child.pid);
        if (!memory.sharedPagesResolved && ProcessExists(child.pid))
            memory = ReadProcessMemory(child.pid);
        checkpoint.aggregateRssBytes += memory.currentRssBytes;
        checkpoint.aggregatePssBytes += memory.pssBytes;
        checkpoint.aggregatePrivateBytes += memory.privateBytes;
        if (!memory.sharedPagesResolved)
            checkpoint.pssComplete = false;
        if (memory.currentRssBytes != 0)
            rssSamples.push_back(memory.currentRssBytes);
        checkpoint.aggregateThreads += CountThreads(child.pid);
        checkpoint.aggregateFileDescriptors += CountOpenFileDescriptors(child.pid);
        checkpoint.aggregateUdpSockets += CountUdpSockets(child.pid);
        const uint64_t processCpu = ReadProcessCpuTimeMicros(child.pid);
        if (m_windowStarted)
        {
            haveCpu = true;
            if (processCpu > child.cpuAtWindowStart)
                cpuMicros += processCpu - child.cpuAtWindowStart;
        }
        if (child.seen)
        {
            startupSamples.push_back(child.firstSeenMs);
            startupCpuMicros += child.cpuAtFirstSeen;
            startupAgeMs += child.firstSeenMs;
        }
    }
    if (checkpoint.aliveAtObservation < checkpoint.started)
        checkpoint.pssComplete = false;
    checkpoint.perProcessRss = SummarizeSizes(std::move(rssSamples));
    checkpoint.startupMs = SummarizeLatencies(std::move(startupSamples));
    checkpoint.allPeersSeen = checkpoint.radioEndpoints == checkpoint.started && checkpoint.started > 0;

    if (startupAgeMs > 0.0)
    {
        checkpoint.startupCpuPercentOfOneCore =
            100.0 * (static_cast<double>(startupCpuMicros) / 1000000.0) / (startupAgeMs / 1000.0);
        const long startupProcessors = sysconf(_SC_NPROCESSORS_ONLN);
        checkpoint.startupCpuPercentOfHost =
            startupProcessors > 0 ? checkpoint.startupCpuPercentOfOneCore / static_cast<double>(startupProcessors) : 0.0;
    }
    if (m_windowStarted)
    {
        checkpoint.stableWindowMs = MillisBetween(m_windowStart, now);
        if (haveCpu && checkpoint.stableWindowMs > 0.0)
        {
            checkpoint.aggregateCpuPercentOfOneCore =
                100.0 * (static_cast<double>(cpuMicros) / 1000000.0) / (checkpoint.stableWindowMs / 1000.0);
            const long processors = sysconf(_SC_NPROCESSORS_ONLN);
            checkpoint.aggregateCpuPercentOfHost =
                processors > 0 ? checkpoint.aggregateCpuPercentOfOneCore / static_cast<double>(processors) : 0.0;
        }
    }
    checkpoint.tunDevices = CountInterfacesWithPrefix(m_config.tunPrefix);
    checkpoint.availableMemoryAtObservation = ReadAvailableMemoryBytes();
    checkpoint.memoryReserveBytes = m_config.memoryReserveBytes;
    checkpoint.resourceLimited = m_lastResourceLimited;
    checkpoint.stopReason = m_lastStopReason;
    checkpoint.shutdownMs = m_lastShutdownMs;
    checkpoint.orphans = m_lastOrphans;
    checkpoint.residualSockets = m_lastResidualSockets;
    checkpoint.cleanupComplete = m_lastCleanupComplete;

    // Every classification names the workload that produced it. A live process
    // is not authentication, a radio peer is not a bearer, and an Attach
    // Request is not an Attach Accept.
    auto &c = checkpoint.classifications;
    c.actualLteUeProcessAlive =
        checkpoint.started > 0 && checkpoint.aliveAtObservation == checkpoint.started ? EvidenceState::PASS
                                                                                        : EvidenceState::FAIL;
    c.simulatedRadioEndpointActive =
        checkpoint.started > 0 && checkpoint.radioEndpoints == checkpoint.started ? EvidenceState::PASS
                                                                                   : EvidenceState::FAIL;
    c.preAuthAttachAttempt = checkpoint.radioEndpoints > 0 ? EvidenceState::PASS : EvidenceState::NOT_MEASURED;
    c.isolatedRegistryContextActive =
        multiplexer.registry().size() > 0 ? EvidenceState::PASS : EvidenceState::NOT_MEASURED;
    c.isolatedContextRetained =
        checkpoint.allPeersSeen ? EvidenceState::PASS : EvidenceState::NOT_MEASURED;
    // EPS concepts stay unproven no matter how many processes are alive.
    c.stableRegistrationRetained = EvidenceState::NOT_MEASURED;
    c.simulatedAttachSuccess = EvidenceState::NOT_APPLICABLE;
    c.realEpcAuthenticatedAttach = EvidenceState::BLOCKED_AUTHORIZATION;
    c.simultaneousEpsRegistration = EvidenceState::BLOCKED_AUTHORIZATION;
    c.simultaneousDefaultBearers = EvidenceState::NOT_APPLICABLE;
    c.independentUeIpv4Assignment = EvidenceState::NOT_APPLICABLE;
    c.userPlaneReady = EvidenceState::NOT_APPLICABLE;
    c.cleanupComplete = checkpoint.cleanupComplete ? EvidenceState::PASS : EvidenceState::NOT_MEASURED;
    return checkpoint;
}

void ProcessFleet::StopAll()
{
    if (m_stopped)
        return;
    m_stopped = true;
    const auto start = std::chrono::steady_clock::now();
    for (const auto &child : m_children)
        if (child.pid > 0 && !child.reaped && ProcessExists(child.pid))
            kill(child.pid, SIGTERM);
    // Bounded graceful window: the UE checks its shutdown flag once per
    // receive iteration, so this is normally well under a second.
    const auto deadline = start + std::chrono::milliseconds(5000);
    for (;;)
    {
        bool remaining = false;
        for (size_t index = 0; index < m_children.size(); ++index)
        {
            if (m_children[index].pid > 0 && !m_children[index].reaped)
            {
                ReapOne(index, false);
                if (!m_children[index].reaped)
                    remaining = true;
            }
        }
        if (!remaining || std::chrono::steady_clock::now() >= deadline)
            break;
        std::this_thread::sleep_for(std::chrono::milliseconds(2));
    }
    // Anything that outlived the graceful window is killed, then reaped.
    for (auto &child : m_children)
        if (child.pid > 0 && !child.reaped && ProcessExists(child.pid))
            kill(child.pid, SIGKILL);
    for (size_t index = 0; index < m_children.size(); ++index)
        ReapOne(index, true);
    m_lastShutdownMs = MillisBetween(start, std::chrono::steady_clock::now());

    size_t orphans = 0;
    size_t residual = 0;
    for (size_t index = 0; index < m_children.size(); ++index)
    {
        if (m_children[index].pid > 0 && !m_children[index].reaped)
            ++orphans;
        if (m_children[index].pid > 0 &&
            (ReadUdpSocketAccounting(LocalPortAt(index)).found || ReadUdp6SocketAccounting(LocalPortAt(index)).found))
            ++residual;
    }
    m_lastOrphans = orphans;
    m_lastResidualSockets = residual;
    m_lastCleanupComplete = orphans == 0 && residual == 0;
}

std::string ProcessFleet::ResolveBinary(const std::string &testExecutablePath)
{
    if (const char *explicitPath = std::getenv("UNIRANSIM_LTE_UE_BINARY"))
        if (explicitPath[0] != '\0')
            return explicitPath;
    std::error_code error;
    const auto executable = std::filesystem::absolute(testExecutablePath, error);
    if (error)
        return {};
    const auto directory = executable.parent_path();
    const auto candidates = {directory / "lte-ue", directory.parent_path() / "build" / "lte-ue"};
    for (const auto &candidate : candidates)
        if (std::filesystem::exists(candidate))
            return candidate.string();
    return {};
}

std::string DescribeFleetCheckpoint(const FleetCheckpoint &checkpoint)
{
    std::ostringstream out;
    out << "requested=" << checkpoint.requested << " started=" << checkpoint.started
        << " alive=" << checkpoint.aliveAtObservation << " exited=" << checkpoint.exitedBeforeObservation
        << " startup_failures=" << checkpoint.startupFailures << " exit0=" << checkpoint.exitedZero
        << " exit_nonzero=" << checkpoint.exitedNonZero << " signaled=" << checkpoint.killedBySignal
        << " radio_endpoints=" << checkpoint.radioEndpoints
        << " peers_seen=" << (checkpoint.allPeersSeen ? "yes" : "no");
    out << " rss_sum_bytes=" << checkpoint.aggregateRssBytes << " pss_sum_bytes=" << checkpoint.aggregatePssBytes
        << " pss_complete=" << (checkpoint.pssComplete ? "yes" : "no") << " rss_p50_bytes=" << checkpoint.perProcessRss.p50
        << " rss_p95_bytes=" << checkpoint.perProcessRss.p95 << " rss_p99_bytes=" << checkpoint.perProcessRss.p99
        << " rss_max_bytes=" << checkpoint.perProcessRss.maximum;
    out << " startup_cpu_pct_one_core=" << checkpoint.startupCpuPercentOfOneCore
        << " startup_cpu_pct_host=" << checkpoint.startupCpuPercentOfHost
        << " cpu_pct_one_core=" << checkpoint.aggregateCpuPercentOfOneCore
        << " cpu_pct_host=" << checkpoint.aggregateCpuPercentOfHost << " threads=" << checkpoint.aggregateThreads
        << " fds=" << checkpoint.aggregateFileDescriptors << " udp_sockets=" << checkpoint.aggregateUdpSockets
        << " tun_devices=" << checkpoint.tunDevices
        << " mem_available_bytes=" << checkpoint.availableMemoryAtObservation
        << " mem_reserve_bytes=" << checkpoint.memoryReserveBytes;
    out << " " << DescribeLatency(checkpoint.startupMs) << " stable_ms=" << checkpoint.stableWindowMs
        << " shutdown_ms=" << checkpoint.shutdownMs << " orphans=" << checkpoint.orphans
        << " residual_sockets=" << checkpoint.residualSockets
        << " cleanup=" << (checkpoint.cleanupComplete ? "yes" : "no");
    const auto &c = checkpoint.classifications;
    out << " ue_process_alive=" << ToString(c.actualLteUeProcessAlive)
        << " radio_endpoint=" << ToString(c.simulatedRadioEndpointActive)
        << " preauth_attach=" << ToString(c.preAuthAttachAttempt)
        << " registry_active=" << ToString(c.isolatedRegistryContextActive)
        << " ctx_retained=" << ToString(c.isolatedContextRetained)
        << " retained=" << ToString(c.stableRegistrationRetained)
        << " real_epc=" << ToString(c.realEpcAuthenticatedAttach) << " cleanup_state=" << ToString(c.cleanupComplete)
        << " resource_limited=" << (checkpoint.resourceLimited ? "yes" : "no")
        << " stop_reason=\"" << checkpoint.stopReason << "\"";
    return out.str();
}

} // namespace lte::enb
