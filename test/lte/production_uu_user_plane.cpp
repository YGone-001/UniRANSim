//
// This file is a part of UERANSIM project.
// Copyright (c) 2027 ALİ GÜNGÖR.
//
// Phase 18-F-B6-D7: the production-UE TUN-backed DRB end-to-end acceptance.
//
// Three operating-system processes in two isolated network namespaces:
//
//   d7ran: production lte-ue  <-> loopback Uu <-> production EnbMultiplexer +
//          deterministic MME (lte-uu-user-plane-peer), S1-U on the veth end
//   d7core: deterministic SGW-U/PGW-U (lte-uu-sgw-peer) with a real Core TUN
//
// The UE TUN and the Core TUN are in different namespaces, connected only by
// the Uu UDP socket and the S1-U GTP-U UDP socket. ICMP, UDP and TCP traffic is
// real Linux application traffic; payload hashes are checked. The case is
// privileged, skipped in the ordinary suite, and run by its own CI job.
//
// Sentinels: UNIRANSIM-PHASE18D7-PRIVILEGED-EXECUTED / ...-COMPLETE.
#include <ext/doctest/doctest.h>

#include <lte/enb/process_fleet.hpp>

#include <algorithm>
#include <chrono>
#include <cstdlib>
#include <filesystem>
#include <fstream>
#include <functional>
#include <map>
#include <optional>
#include <regex>
#include <sstream>
#include <string>
#include <thread>
#include <vector>

#include <arpa/inet.h>
#include <fcntl.h>
#include <netinet/in.h>
#include <signal.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>

namespace
{

using Clock = std::chrono::steady_clock;

std::string SelfExecutable()
{
    char buffer[4096];
    const ssize_t length = readlink("/proc/self/exe", buffer, sizeof(buffer) - 1);
    if (length <= 0)
        return {};
    buffer[length] = '\0';
    return buffer;
}

std::string ResolveBinary(const std::string &testBinary, const std::string &name, const char *overrideEnv)
{
    if (overrideEnv != nullptr)
        if (const char *explicitPath = std::getenv(overrideEnv))
            if (explicitPath[0] != '\0')
                return explicitPath;
    const auto directory = std::filesystem::path(testBinary).parent_path();
    for (const auto &candidate : {directory / name, directory.parent_path() / name,
                                  std::filesystem::path("build") / name})
        if (std::filesystem::exists(candidate))
            return candidate.string();
    return {};
}

uint16_t FreeUdpPort()
{
    const int fd = ::socket(AF_INET, SOCK_DGRAM, 0);
    if (fd < 0)
        return 0;
    sockaddr_in address{};
    address.sin_family = AF_INET;
    address.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    address.sin_port = 0;
    ::bind(fd, reinterpret_cast<const sockaddr *>(&address), sizeof(address));
    socklen_t length = sizeof(address);
    ::getsockname(fd, reinterpret_cast<sockaddr *>(&address), &length);
    ::close(fd);
    return ntohs(address.sin_port);
}

bool ReadFile(const std::string &path, std::string &out)
{
    std::ifstream in(path);
    if (!in)
        return false;
    std::ostringstream buffer;
    buffer << in.rdbuf();
    out = buffer.str();
    return true;
}

bool Contains(const std::string &text, const std::string &needle)
{
    return text.find(needle) != std::string::npos;
}

bool WaitFor(const std::function<bool()> &predicate, int milliseconds)
{
    const auto deadline = Clock::now() + std::chrono::milliseconds(milliseconds);
    while (Clock::now() < deadline)
    {
        if (predicate())
            return true;
        std::this_thread::sleep_for(std::chrono::milliseconds(20));
    }
    return predicate();
}

bool WaitForFile(const std::string &path, int milliseconds)
{
    return WaitFor([&path] { return std::filesystem::exists(path); }, milliseconds);
}

bool WaitForText(const std::string &path, const std::string &needle, int milliseconds)
{
    return WaitFor(
        [&path, &needle] {
            std::string text;
            return ReadFile(path, text) && Contains(text, needle);
        },
        milliseconds);
}

struct Process
{
    pid_t pid{-1};
    std::string log;
};

Process Spawn(const std::vector<std::string> &argv, const std::string &logPath)
{
    Process process;
    process.log = logPath;
    process.pid = ::fork();
    if (process.pid != 0)
        return process;
    const int fd = ::open(logPath.c_str(), O_WRONLY | O_CREAT | O_TRUNC, 0644);
    if (fd >= 0)
    {
        ::dup2(fd, STDOUT_FILENO);
        ::dup2(fd, STDERR_FILENO);
        ::close(fd);
    }
    std::vector<char *> args;
    for (const auto &argument : argv)
        args.push_back(const_cast<char *>(argument.c_str()));
    args.push_back(nullptr);
    ::execvp(args[0], args.data());
    ::_exit(127);
}

int WaitProcess(pid_t pid, int milliseconds)
{
    const auto deadline = Clock::now() + std::chrono::milliseconds(milliseconds);
    while (Clock::now() < deadline)
    {
        int status = 0;
        const pid_t reaped = ::waitpid(pid, &status, WNOHANG);
        if (reaped == pid)
            return WIFEXITED(status) ? WEXITSTATUS(status) : -1;
        std::this_thread::sleep_for(std::chrono::milliseconds(20));
    }
    ::kill(pid, SIGKILL);
    int status = 0;
    ::waitpid(pid, &status, 0);
    return -1;
}

int StopProcess(pid_t pid, int milliseconds = 5000)
{
    if (pid <= 0)
        return -1;
    ::kill(pid, SIGTERM);
    return WaitProcess(pid, milliseconds);
}

int RunProcess(const std::vector<std::string> &argv, const std::string &logPath, int timeoutMs)
{
    const Process process = Spawn(argv, logPath);
    return WaitProcess(process.pid, timeoutMs);
}

int RunShell(const std::string &command, const std::string &logPath, int timeoutMs)
{
    return RunProcess({"/bin/bash", "-c", command}, logPath, timeoutMs);
}

struct NetnsCommand
{
    std::string ns;
    std::vector<std::string> argv;
};

std::vector<std::string> InNetns(const std::string &ns, const std::vector<std::string> &argv)
{
    std::vector<std::string> out{"ip", "netns", "exec", ns};
    out.insert(out.end(), argv.begin(), argv.end());
    return out;
}
struct CpuSample
{
    uint64_t ticks{0};
    uint64_t rssKb{0};
};

CpuSample SampleProcess(pid_t pid)
{
    CpuSample sample;
    std::string stat;
    if (ReadFile("/proc/" + std::to_string(pid) + "/stat", stat))
    {
        // utime and stime are fields 14 and 15, after the command name.
        const auto close = stat.rfind(')');
        if (close != std::string::npos)
        {
            std::istringstream rest(stat.substr(close + 2));
            std::string field;
            int index = 3;
            uint64_t utime = 0;
            uint64_t stime = 0;
            while (rest >> field)
            {
                if (index == 14)
                    utime = std::stoull(field);
                if (index == 15)
                {
                    stime = std::stoull(field);
                    break;
                }
                ++index;
            }
            sample.ticks = utime + stime;
        }
    }
    std::string status;
    if (ReadFile("/proc/" + std::to_string(pid) + "/status", status))
    {
        std::istringstream lines(status);
        std::string line;
        while (std::getline(lines, line))
            if (line.rfind("VmHWM:", 0) == 0)
            {
                std::istringstream value(line.substr(6));
                value >> sample.rssKb;
            }
    }
    return sample;
}

struct ResultFields
{
    std::map<std::string, std::string> values;

    std::optional<std::string> Get(const std::string &key) const
    {
        const auto it = values.find(key);
        return it == values.end() ? std::nullopt : std::make_optional(it->second);
    }
    uint64_t U64(const std::string &key) const
    {
        const auto value = Get(key);
        return value.has_value() ? std::stoull(*value) : 0;
    }
};

ResultFields ParseFields(const std::string &text)
{
    ResultFields fields;
    std::istringstream lines(text);
    std::string line;
    while (std::getline(lines, line))
    {
        const auto equals = line.find('=');
        if (equals == std::string::npos)
            continue;
        fields.values[line.substr(0, equals)] = line.substr(equals + 1);
    }
    return fields;
}

// The whole laboratory. Its destructor stops every child and deletes both
// namespaces, so a failed assertion never leaves a process, a veth or a TUN.
struct Lab
{
    std::string testBinary;
    std::string ueBinary;
    std::string peerBinary;
    std::string sgwBinary;
    std::string probeBinary;
    std::string work;
    std::string evidence;
    std::string ranNs;
    std::string coreNs;
    std::string vethRan;
    std::string vethCore;
    uint16_t uuPort{0};
    uint16_t ueUuPort{0};
    uint16_t ueLegacyPort{0};
    uint16_t unusedEnbPort{0};
    std::string mapPath;
    std::string peerReady;
    std::string peerResult;
    std::string releasePath;
    std::string stopPath;
    std::string sgwReady;
    std::string sgwResult;
    std::string ueConfig;
    std::string ueLog;
    std::string peerLog;
    std::string sgwLog;
    Process ue;
    Process peer;
    Process sgw;
    std::vector<Process> extras;
    std::vector<pid_t> tcpdumps;
    bool pcapGenerated{false};
    bool iperfAvailable{false};
    std::string trafficSummary;
    std::string taps;

    Lab()
    {
        testBinary = SelfExecutable();
        ueBinary = lte::enb::ProcessFleet::ResolveBinary(testBinary);
        peerBinary = ResolveBinary(testBinary, "lte-uu-user-plane-peer", "UNIRANSIM_LTE_UP_PEER_BINARY");
        sgwBinary = ResolveBinary(testBinary, "lte-uu-sgw-peer", "UNIRANSIM_LTE_SGW_PEER_BINARY");
        probeBinary = ResolveBinary(testBinary, "lte-uu-traffic-probe", "UNIRANSIM_LTE_TRAFFIC_PROBE_BINARY");
        work = "/tmp/uniransim-d7-user-plane";
        evidence = std::string(UNIRANSIM_SOURCE_DIR) + "/reports/evidence/phase-18-f-b6-d7";
        const std::string suffix = std::to_string(static_cast<long>(getpid()));
        ranNs = "d7ran-" + suffix;
        coreNs = "d7core-" + suffix;
        vethRan = "vr" + suffix;
        vethCore = "vc" + suffix;
        std::filesystem::remove_all(work);
        std::filesystem::create_directories(work);
        std::filesystem::create_directories(evidence);
        std::filesystem::create_directories("/var/run/netns");

        mapPath = work + "/bearer.map";
        peerReady = work + "/peer.ready";
        peerResult = work + "/peer.result";
        releasePath = work + "/release.trigger";
        stopPath = work + "/stop.trigger";
        sgwReady = work + "/sgw.ready";
        sgwResult = work + "/sgw.result";
        ueConfig = work + "/ue.yaml";
        ueLog = work + "/ue.log";
        peerLog = work + "/enb.log";
        sgwLog = work + "/sgw.log";
        trafficSummary = evidence + "/traffic-summary.json";

        uuPort = FreeUdpPort();
        ueUuPort = FreeUdpPort();
        ueLegacyPort = FreeUdpPort();
        unusedEnbPort = FreeUdpPort();
        while (ueUuPort == uuPort || ueUuPort == ueLegacyPort || ueUuPort == unusedEnbPort ||
               ueLegacyPort == uuPort || ueLegacyPort == unusedEnbPort || unusedEnbPort == uuPort)
        {
            ueUuPort = FreeUdpPort();
            ueLegacyPort = FreeUdpPort();
            unusedEnbPort = FreeUdpPort();
        }
    }

    ~Lab() { Cleanup(); }

    void RunOrFail(const std::string &command, const std::string &log, int timeoutMs)
    {
        if (RunShell(command, log, timeoutMs) != 0)
            throw std::runtime_error("command failed: " + command + " (see " + log + ")");
    }

    void Setup()
    {
        // A previous interrupted run may have left the names. They are ours to
        // recreate only because this lab is the sole user of these names.
        RunShell("ip netns del " + ranNs + " 2>/dev/null", work + "/cleanup1.log", 5000);
        RunShell("ip netns del " + coreNs + " 2>/dev/null", work + "/cleanup2.log", 5000);
        RunOrFail("ip netns add " + ranNs, work + "/ns-ran.log", 5000);
        RunOrFail("ip netns add " + coreNs, work + "/ns-core.log", 5000);
        RunOrFail("ip link add " + vethRan + " type veth peer name " + vethCore, work + "/veth.log", 5000);
        RunOrFail("ip link set " + vethRan + " netns " + ranNs, work + "/veth-ran.log", 5000);
        RunOrFail("ip link set " + vethCore + " netns " + coreNs, work + "/veth-core.log", 5000);
        RunOrFail("ip netns exec " + ranNs + " ip addr add 192.168.77.1/24 dev " + vethRan,
                  work + "/ran-addr.log", 5000);
        RunOrFail("ip netns exec " + ranNs + " ip link set " + vethRan + " up", work + "/ran-up.log", 5000);
        RunOrFail("ip netns exec " + ranNs + " ip link set lo up", work + "/ran-lo.log", 5000);
        RunOrFail("ip netns exec " + coreNs + " ip addr add 192.168.77.2/24 dev " + vethCore,
                  work + "/core-addr.log", 5000);
        RunOrFail("ip netns exec " + coreNs + " ip link set " + vethCore + " up", work + "/core-up.log", 5000);
        RunOrFail("ip netns exec " + coreNs + " ip link set lo up", work + "/core-lo.log", 5000);

        iperfAvailable = RunShell("command -v iperf3 >/dev/null 2>&1", work + "/iperf-check.log", 5000) == 0;
    }

    void WriteUeConfig()
    {
        std::ofstream config(ueConfig);
        config << "imsi: \"460020000000400\"\n";
        config << "mcc: \"460\"\n";
        config << "mnc: \"02\"\n";
        config << "ueId: 46001\n";
        config << "k: \"00112233445566778899aabbccddeeff\"\n";
        config << "opc: \"00112233445566778899aabbccddeeff\"\n";
        config << "amf: \"8000\"\n";
        config << "initialSqn: \"000000000001\"\n";
        config << "pdnType: IPv4\n";
        config << "enbLink:\n";
        config << "  localAddress: 127.0.0.1\n";
        config << "  localPort: " << ueLegacyPort << "\n";
        config << "  address: 127.0.0.1\n";
        config << "  port: " << unusedEnbPort << "\n";
        config << "  tac: 1\n";
        config << "  timeoutMs: 30000\n";
        config << "uu:\n";
        config << "  localAddress: 127.0.0.1\n";
        config << "  localPort: " << ueUuPort << "\n";
        config << "  address: 127.0.0.1\n";
        config << "  port: " << uuPort << "\n";
        config << "tun:\n";
        config << "  required: true\n";
        config << "  namePrefix: d7ue\n";
        config << "  mtu: 1500\n";
        config << "  routes:\n";
        config << "    - 10.45.0.1/32\n";
        config << "lifecycle:\n";
        config << "  scenario: user-plane\n";
        config << "  triggerAfterMs: 1000\n";
        config << "  procedureTimeoutMs: 20000\n";
        config << "  pagingWaitMs: 60000\n";
        config << "  idleRounds: 1\n";
        config.flush();
        if (!config.good())
            throw std::runtime_error("the UE configuration could not be written");
    }

    void Start()
    {
        sgw = Spawn(InNetns(coreNs, {sgwBinary, "--gtpu-address", "192.168.77.2", "--gtpu-port", "2152",
                                     "--core-tun-prefix", "d7core", "--core-ip", "10.45.0.1", "--ue-ip",
                                     "10.45.0.2", "--mtu", "1500", "--map-file", mapPath, "--ready-file", sgwReady,
                                     "--result-file", sgwResult, "--stop-file", stopPath}),
                    sgwLog);
        peer = Spawn(InNetns(ranNs, {peerBinary, "--uu-port", std::to_string(uuPort), "--s1u-address",
                                     "192.168.77.1", "--s1u-port", "2152", "--sgw-address", "192.168.77.2",
                                     "--sgw-port", "2152", "--ue-ip", "10.45.0.2", "--ebi", "5", "--qci", "9",
                                     "--map-file", mapPath, "--ready-file", peerReady, "--result-file", peerResult,
                                     "--release-file", releasePath, "--stop-file", stopPath}),
                    peerLog);
        // The eNB Uu socket and the SGW GTP-U/Core-TUN endpoint must be alive
        // before the UE sends its first RRCConnectionRequest; the request is not
        // retried by the transport and a lost one would hang the whole case.
        if (!WaitForFile(sgwReady, 5000) || !WaitForFile(peerReady, 5000))
            throw std::runtime_error("the eNB or SGW did not become ready");
        WriteUeConfig();
        ue = Spawn(InNetns(ranNs, {ueBinary, "-c", ueConfig}), ueLog);
    }

    void StartCaptures()
    {
        if (RunShell("command -v tcpdump >/dev/null 2>&1", work + "/tcpdump-check.log", 5000) != 0)
            return;
        std::string ueTun;
        WaitFor(
            [&] {
                std::string text;
                if (!ReadFile(ueLog, text))
                    return false;
                const auto at = text.find("LTE TUN ");
                if (at == std::string::npos)
                    return false;
                const auto end = text.find(' ', at + 8);
                ueTun = text.substr(at + 8, end - (at + 8));
                return !ueTun.empty();
            },
            10000);
        std::string coreTun;
        WaitFor(
            [&] {
                std::string text;
                if (!ReadFile(sgwReady, text))
                    return false;
                ResultFields fields = ParseFields(text);
                const auto value = fields.Get("tun");
                if (!value.has_value())
                    return false;
                coreTun = *value;
                return true;
            },
            10000);
        if (ueTun.empty() || coreTun.empty())
            return;
        tcpdumps.push_back(Spawn(InNetns(ranNs, {"tcpdump", "-i", "lo", "-w", evidence + "/uu.pcap", "udp",
                                                  "port", std::to_string(uuPort)}), work + "/tcpdump-uu.log").pid);
        tcpdumps.push_back(Spawn(InNetns(ranNs, {"tcpdump", "-i", vethRan, "-w", evidence + "/s1u-gtpu.pcap",
                                                  "udp", "port", "2152"}), work + "/tcpdump-s1u.log").pid);
        tcpdumps.push_back(Spawn(InNetns(ranNs, {"tcpdump", "-i", ueTun, "-w", evidence + "/ue-tun.pcap"}),
                                 work + "/tcpdump-ue.log").pid);
        tcpdumps.push_back(Spawn(InNetns(coreNs, {"tcpdump", "-i", coreTun, "-w", evidence + "/core-tun.pcap"}),
                                 work + "/tcpdump-core.log").pid);
        pcapGenerated = true;
    }

    void StopCaptures()
    {
        for (pid_t pid : tcpdumps)
            StopProcess(pid, 5000);
        tcpdumps.clear();
    }

    int Ping(const std::string &fromNs, const std::string &target, int size, const std::string &log)
    {
        return RunProcess(InNetns(fromNs, {"ping", "-c", "3", "-W", "2", "-s", std::to_string(size), "-q", target}), log,
                          15000);
    }

    int StartUdpServer(const std::string &ns, const std::string &bind, uint16_t port, const std::string &result,
                       const std::string &ready)
    {
        extras.push_back(Spawn(InNetns(ns, {probeBinary, "udp-echo-server", "--bind", bind, "--port",
                                            std::to_string(port), "--result", result, "--ready", ready, "--stop",
                                            stopPath}),
                               work + "/udp-server.log"));
        return WaitForFile(ready, 5000) ? 0 : 1;
    }

    int UdpClient(const std::string &ns, const std::string &bind, const std::string &to, uint16_t port, int count,
                  int size, const std::string &result, const std::string &log)
    {
        return RunProcess(InNetns(ns, {probeBinary, "udp-client", "--bind", bind, "--to", to, "--port",
                                       std::to_string(port), "--count", std::to_string(count), "--size",
                                       std::to_string(size), "--result", result}),
                          log, 20000);
    }

    int StartTcpServer(const std::string &ns, const std::string &bind, uint16_t port, const std::string &result,
                       const std::string &ready)
    {
        extras.push_back(Spawn(InNetns(ns, {probeBinary, "tcp-echo-server", "--bind", bind, "--port",
                                            std::to_string(port), "--result", result, "--ready", ready}),
                               work + "/tcp-server.log"));
        return WaitForFile(ready, 5000) ? 0 : 1;
    }

    int TcpClient(const std::string &ns, const std::string &bind, const std::string &to, uint16_t port, int bytes,
                  const std::string &result, const std::string &log)
    {
        return RunProcess(InNetns(ns, {probeBinary, "tcp-client", "--bind", bind, "--to", to, "--port",
                                       std::to_string(port), "--bytes", std::to_string(bytes), "--result", result}),
                          log, 30000);
    }

    void Cleanup()
    {
        StopCaptures();
        StopProcess(ue.pid, 3000);
        StopProcess(peer.pid, 3000);
        StopProcess(sgw.pid, 3000);
        for (auto &process : extras)
            StopProcess(process.pid, 2000);
        extras.clear();
        RunShell("ip netns del " + ranNs + " 2>/dev/null", work + "/cleanup-ran.log", 5000);
        RunShell("ip netns del " + coreNs + " 2>/dev/null", work + "/cleanup-core.log", 5000);
    }

    void CopyEvidence()
    {
        auto copy = [&](const std::string &from, const std::string &to) {
            std::error_code error;
            std::filesystem::copy_file(from, to, std::filesystem::copy_options::overwrite_existing, error);
        };
        copy(ueLog, evidence + "/ue.log");
        copy(peerLog, evidence + "/enb.log");
        copy(sgwLog, evidence + "/sgw-upgw.log");
        copy(peerResult, evidence + "/peer.result");
        copy(sgwResult, evidence + "/sgw.result");
        copy(mapPath, evidence + "/bearer.map");
    }
};

} // namespace

TEST_CASE("lte/d7/acceptance: the production ue carries tun ip traffic over drb and gtpu end to end" *
          doctest::skip())
{
    if (std::getenv("UNIRANSIM_RUN_PRIVILEGED_TUN_TESTS") == nullptr)
        FAIL("the D7 multi-process user-plane acceptance requires UNIRANSIM_RUN_PRIVILEGED_TUN_TESTS=1");
    if (geteuid() != 0)
        FAIL("the D7 multi-process user-plane acceptance requires root for TUN and network namespaces");

    MESSAGE("UNIRANSIM-PHASE18D7-PRIVILEGED-EXECUTED");

    Lab lab;
    REQUIRE_FALSE(lab.ueBinary.empty());
    REQUIRE_FALSE(lab.peerBinary.empty());
    REQUIRE_FALSE(lab.sgwBinary.empty());
    REQUIRE_FALSE(lab.probeBinary.empty());
    lab.Setup();
    lab.Start();

    REQUIRE(WaitForFile(lab.sgwReady, 10000));
    REQUIRE(WaitForFile(lab.peerReady, 10000));

    // The UE reaches the attached, DRB-configured state; the eNB answered the
    // Initial Context Setup and wrote the downlink bearer map.
    REQUIRE(WaitForText(lab.ueLog, "DRB user plane configured", 30000));
    REQUIRE(WaitFor([&] {
        std::string result;
        return ReadFile(lab.peerResult, result) && Contains(result, "stage=REGISTERED") &&
               Contains(result, "map_generation=1");
    }, 30000));
    lab.StartCaptures();

    // ---- Pre-idle application traffic -----------------------------------
    const std::string pingUl = lab.work + "/ping-ul.log";
    const std::string pingDl = lab.work + "/ping-dl.log";
    REQUIRE(lab.Ping(lab.ranNs, "10.45.0.1", 56, pingUl) == 0);
    REQUIRE(lab.Ping(lab.coreNs, "10.45.0.2", 56, pingDl) == 0);
    {
        std::string text;
        REQUIRE(ReadFile(pingUl, text));
        CHECK(Contains(text, "0% packet loss"));
        CHECK(Contains(text, "3 received"));
        REQUIRE(ReadFile(pingDl, text));
        CHECK(Contains(text, "0% packet loss"));
        CHECK(Contains(text, "3 received"));
    }
    REQUIRE(lab.Ping(lab.ranNs, "10.45.0.1", 1400, lab.work + "/ping-ul-mtu.log") == 0);
    REQUIRE(lab.Ping(lab.coreNs, "10.45.0.2", 1400, lab.work + "/ping-dl-mtu.log") == 0);

    const uint16_t udpUlPort = FreeUdpPort();
    const std::string udpUlServerReady = lab.work + "/udp-ul-server.ready";
    const std::string udpUlClientResult = lab.work + "/udp-ul-client.result";
    REQUIRE(lab.StartUdpServer(lab.coreNs, "10.45.0.1", udpUlPort, lab.work + "/udp-ul-server.result",
                               udpUlServerReady) == 0);
    REQUIRE(lab.UdpClient(lab.ranNs, "10.45.0.2", "10.45.0.1", udpUlPort, 20, 64, udpUlClientResult,
                          lab.work + "/udp-ul-client.log") == 0);
    {
        std::string text;
        REQUIRE(ReadFile(udpUlClientResult, text));
        const auto fields = ParseFields(text);
        CHECK(fields.Get("result").value_or("") == "COMPLETE");
        CHECK(fields.U64("loss") == 0);
        CHECK(fields.U64("duplicate") == 0);
        CHECK(fields.U64("out_of_order") == 0);
        CHECK(fields.U64("corrupt") == 0);
        CHECK(fields.U64("received") == 20);
    }

    const uint16_t udpUlMtuPort = FreeUdpPort();
    REQUIRE(lab.StartUdpServer(lab.coreNs, "10.45.0.1", udpUlMtuPort, lab.work + "/udp-ul-mtu-server.result",
                               lab.work + "/udp-ul-mtu-server.ready") == 0);
    REQUIRE(lab.UdpClient(lab.ranNs, "10.45.0.2", "10.45.0.1", udpUlMtuPort, 10, 1400,
                          lab.work + "/udp-ul-mtu-client.result", lab.work + "/udp-ul-mtu-client.log") == 0);

    const uint16_t udpDlPort = FreeUdpPort();
    REQUIRE(lab.StartUdpServer(lab.ranNs, "10.45.0.2", udpDlPort, lab.work + "/udp-dl-server.result",
                               lab.work + "/udp-dl-server.ready") == 0);
    REQUIRE(lab.UdpClient(lab.coreNs, "10.45.0.1", "10.45.0.2", udpDlPort, 20, 64,
                          lab.work + "/udp-dl-client.result", lab.work + "/udp-dl-client.log") == 0);
    {
        std::string text;
        REQUIRE(ReadFile(lab.work + "/udp-dl-client.result", text));
        const auto fields = ParseFields(text);
        CHECK(fields.Get("result").value_or("") == "COMPLETE");
        CHECK(fields.U64("loss") == 0);
        CHECK(fields.U64("corrupt") == 0);
    }

    const uint16_t tcpUlPort = FreeUdpPort();
    REQUIRE(lab.StartTcpServer(lab.coreNs, "10.45.0.1", tcpUlPort, lab.work + "/tcp-ul-server.result",
                               lab.work + "/tcp-ul-server.ready") == 0);
    REQUIRE(lab.TcpClient(lab.ranNs, "10.45.0.2", "10.45.0.1", tcpUlPort, 256 * 1024,
                          lab.work + "/tcp-ul-client.result", lab.work + "/tcp-ul-client.log") == 0);
    {
        std::string text;
        REQUIRE(ReadFile(lab.work + "/tcp-ul-client.result", text));
        CHECK(Contains(text, "result=COMPLETE"));
        const auto fields = ParseFields(text);
        CHECK(fields.Get("expected_hash").value_or("") == fields.Get("actual_hash").value_or("?"));
    }

    const uint16_t tcpDlPort = FreeUdpPort();
    REQUIRE(lab.StartTcpServer(lab.ranNs, "10.45.0.2", tcpDlPort, lab.work + "/tcp-dl-server.result",
                               lab.work + "/tcp-dl-server.ready") == 0);
    REQUIRE(lab.TcpClient(lab.coreNs, "10.45.0.1", "10.45.0.2", tcpDlPort, 256 * 1024,
                          lab.work + "/tcp-dl-client.result", lab.work + "/tcp-dl-client.log") == 0);
    {
        std::string text;
        REQUIRE(ReadFile(lab.work + "/tcp-dl-client.result", text));
        CHECK(Contains(text, "result=COMPLETE"));
        const auto fields = ParseFields(text);
        CHECK(fields.Get("expected_hash").value_or("") == fields.Get("actual_hash").value_or("?"));
    }

    // ---- iperf3 baseline (attempted; never fabricated) ------------------
    std::string iperfSummary = "NOT_AVAILABLE";
    if (lab.iperfAvailable)
    {
        const auto runIperf = [&](const std::string &clientNs, const std::string &clientBind,
                                  const std::string &serverNs, const std::string &serverBind,
                                  const std::string &tag) -> std::string {
            const uint16_t iperfPort = FreeUdpPort();
            const Process server = Spawn(InNetns(serverNs, {"iperf3", "-s", "-B", serverBind, "-p",
                                                             std::to_string(iperfPort), "-1"}),
                                         lab.work + "/iperf-" + tag + "-server.log");
            std::this_thread::sleep_for(std::chrono::milliseconds(500));
            RunProcess(InNetns(clientNs, {"iperf3", "-c", serverBind, "-B", clientBind, "-p",
                                          std::to_string(iperfPort), "-t", "5", "-i", "1", "--forceflush", "-f",
                                          "m"}),
                       lab.work + "/iperf-" + tag + "-client.log", 12000);
            StopProcess(server.pid, 3000);
            std::string text;
            ReadFile(lab.work + "/iperf-" + tag + "-client.log", text);
            const std::regex rate(R"(([0-9]+\.[0-9]+)\s+Mbits/sec)");
            std::string lastRate;
            double peak = 0;
            for (auto it = std::sregex_iterator(text.begin(), text.end(), rate); it != std::sregex_iterator(); ++it)
            {
                lastRate = (*it)[1];
                peak = std::max(peak, std::stod(lastRate));
            }
            if (lastRate.empty())
                return "PARTIAL";
            return "peak_mbps=" + std::to_string(peak) + " last_mbps=" + lastRate;
        };
        const std::string ulRate = runIperf(lab.ranNs, "10.45.0.2", lab.coreNs, "10.45.0.1", "ul");
        const std::string dlRate = runIperf(lab.coreNs, "10.45.0.1", lab.ranNs, "10.45.0.2", "dl");
        iperfSummary = "ul_" + ulRate + " dl_" + dlRate;
    }

    // ---- ECM-IDLE and Service Request restoration ------------------------
    const uint64_t preIdleUl = [&] {
        std::string text;
        return ReadFile(lab.sgwResult, text) ? ParseFields(text).U64("ul_packets") : 0;
    }();
    {
        std::ofstream trigger(lab.releasePath);
        trigger << "release\n";
    }
    REQUIRE(WaitForText(lab.ueLog, "RRC connection released by the network", 30000));
    REQUIRE(WaitForText(lab.ueLog, "EPS Service Request accepted; AS security restored", 30000));
    REQUIRE(WaitFor([&] {
        std::string result;
        return ReadFile(lab.peerResult, result) && Contains(result, "context_restored=1") &&
               Contains(result, "map_generation=2");
    }, 30000));
    REQUIRE(WaitForText(lab.ueLog, "DRB user plane configured", 30000));

    // ---- Post-restoration traffic on the same EPS bearer -----------------
    REQUIRE(lab.Ping(lab.ranNs, "10.45.0.1", 56, lab.work + "/ping-restored-ul.log") == 0);
    REQUIRE(lab.Ping(lab.coreNs, "10.45.0.2", 56, lab.work + "/ping-restored-dl.log") == 0);
    const uint16_t restoredUdpPort = FreeUdpPort();
    REQUIRE(lab.StartUdpServer(lab.coreNs, "10.45.0.1", restoredUdpPort,
                               lab.work + "/udp-restored-server.result",
                               lab.work + "/udp-restored-server.ready") == 0);
    REQUIRE(lab.UdpClient(lab.ranNs, "10.45.0.2", "10.45.0.1", restoredUdpPort, 20, 64,
                          lab.work + "/udp-restored-client.result", lab.work + "/udp-restored-client.log") == 0);
    {
        std::string text;
        REQUIRE(ReadFile(lab.work + "/udp-restored-client.result", text));
        const auto fields = ParseFields(text);
        CHECK(fields.Get("result").value_or("") == "COMPLETE");
        CHECK(fields.U64("loss") == 0);
        CHECK(fields.U64("corrupt") == 0);
    }

    // ---- Final evidence --------------------------------------------------
    lab.StopCaptures();
    const pid_t uePid = lab.ue.pid;
    const pid_t enbPid = lab.peer.pid;
    const pid_t sgwPid = lab.sgw.pid;
    const CpuSample ueCpu = SampleProcess(lab.ue.pid);
    const CpuSample peerCpu = SampleProcess(lab.peer.pid);
    const CpuSample sgwCpu = SampleProcess(lab.sgw.pid);
    const int ueExit = StopProcess(lab.ue.pid, 5000);
    const int peerExit = StopProcess(lab.peer.pid, 5000);
    const int sgwExit = StopProcess(lab.sgw.pid, 5000);
    lab.ue.pid = lab.peer.pid = lab.sgw.pid = -1;

    CHECK(ueExit == 0);
    CHECK(peerExit == 0);
    CHECK(sgwExit == 0);

    std::string peerText;
    std::string sgwText;
    std::string ueText;
    REQUIRE(ReadFile(lab.peerResult, peerText));
    REQUIRE(ReadFile(lab.sgwResult, sgwText));
    REQUIRE(ReadFile(lab.ueLog, ueText));
    const auto peerFields = ParseFields(peerText);
    const auto sgwFields = ParseFields(sgwText);
    INFO("peer result:\n" << peerText);
    INFO("sgw result:\n" << sgwText);

    CHECK(peerFields.Get("result").value_or("") == "COMPLETE");
    CHECK(peerFields.U64("registered") == 1);
    CHECK(peerFields.U64("release_complete") == 1);
    CHECK(peerFields.U64("service_request_verified") == 1);
    CHECK(peerFields.U64("context_restored") == 1);
    CHECK(peerFields.U64("map_generation") == 2);
    // D8: the restored DRB RLC must still be ACTIVE after the measured flow.
    // A failed AM entity is the sustained-stall signature this phase fixed.
    CHECK(peerFields.U64("rlc_state") == 0);

    CHECK(sgwFields.Get("result").value_or("") == "COMPLETE");
    CHECK(sgwFields.U64("map_updates") >= 2);
    CHECK(sgwFields.U64("active_generation") == 2);
    CHECK(sgwFields.U64("ul_packets") > preIdleUl);
    CHECK(sgwFields.U64("dl_packets") > 0);
    {
        const auto retired = sgwFields.Get("retired_teids").value_or("");
        CHECK(!retired.empty());
    }

    // The production UE itself reports the DRB path counters: the traffic did
    // not bypass PDCP/RLC on its way to the TUN.
    CHECK(Contains(ueText, "DRB user-plane statistics:"));
    CHECK(Contains(ueText, "User-plane statistics: tun-ul="));
    CHECK(!Contains(ueText, "DRB configuration failed"));

    std::ostringstream summary;
    std::string ueTunName;
    std::string coreTunName;
    {
        const auto at = ueText.find("LTE TUN ");
        if (at != std::string::npos)
        {
            const auto end = ueText.find(' ', at + 8);
            ueTunName = ueText.substr(at + 8, end - (at + 8));
        }
        std::string ready;
        if (ReadFile(lab.sgwReady, ready))
            coreTunName = ParseFields(ready).Get("tun").value_or("");
    }
    const long ticksPerSecond = sysconf(_SC_CLK_TCK);
    summary << "{\n";
    summary << "  \"ue_pid\": " << uePid << ",\n";
    summary << "  \"enb_pid\": " << enbPid << ",\n";
    summary << "  \"sgw_pid\": " << sgwPid << ",\n";
    summary << "  \"ue_tun\": \"" << ueTunName << "\",\n";
    summary << "  \"core_tun\": \"" << coreTunName << "\",\n";
    summary << "  \"uu_port\": " << lab.uuPort << ",\n";
    summary << "  \"gtpu\": \"192.168.77.2:2152\",\n";
    summary << "  \"s1u\": \"192.168.77.1:2152\",\n";
    summary << "  \"ue_ul_packets\": " << sgwFields.U64("ul_packets") << ",\n";
    summary << "  \"ue_dl_packets\": " << sgwFields.U64("dl_packets") << ",\n";
    summary << "  \"ue_ul_bytes\": " << sgwFields.U64("ul_bytes") << ",\n";
    summary << "  \"ue_dl_bytes\": " << sgwFields.U64("dl_bytes") << ",\n";
    summary << "  \"map_updates\": " << sgwFields.U64("map_updates") << ",\n";
    summary << "  \"active_generation\": " << sgwFields.U64("active_generation") << ",\n";
    summary << "  \"retired_teids\": \"" << sgwFields.Get("retired_teids").value_or("") << "\",\n";
    summary << "  \"pcap\": \"" << (lab.pcapGenerated ? "generated" : "NOT_GENERATED") << "\",\n";
    summary << "  \"iperf3\": \"" << iperfSummary << "\",\n";
    summary << "  \"ue_cpu_ticks\": " << ueCpu.ticks << ",\n";
    summary << "  \"enb_cpu_ticks\": " << peerCpu.ticks << ",\n";
    summary << "  \"sgw_cpu_ticks\": " << sgwCpu.ticks << ",\n";
    summary << "  \"clock_ticks_per_second\": " << ticksPerSecond << ",\n";
    summary << "  \"ue_vmhwm_kb\": " << ueCpu.rssKb << ",\n";
    summary << "  \"enb_vmhwm_kb\": " << peerCpu.rssKb << ",\n";
    summary << "  \"sgw_vmhwm_kb\": " << sgwCpu.rssKb << "\n";
    summary << "}\n";
    {
        std::ofstream out(lab.trafficSummary);
        out << summary.str();
    }
    lab.CopyEvidence();

    MESSAGE("UNIRANSIM-PHASE18D7-PRIVILEGED-COMPLETE");
}
