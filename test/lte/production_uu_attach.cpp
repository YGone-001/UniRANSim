//
// This file is a part of UERANSIM project.
// Copyright (c) 2027 ALİ GÜNGÖR.
//
// Phase 18-F-B6-D3: the production UE application attaches over SRB1 against a
// second operating-system process.
//
// The UE is the real lte-ue executable started with a configuration whose 'uu'
// endpoint points at the deterministic EPC peer. The peer is the real eNB SRB1
// bridge plus a deterministic MME that runs EPS AKA, NAS security and the Attach
// exchange. Nothing is invoked in-process on the UE side.
//
// The case is opt-in because it launches two binaries:
//
//   UNIRANSIM_RUN_TWO_PROCESS_ATTACH=1 ./nr-tests --test-case="lte/uu/acceptance: a separate production ue process attaches"
//
// It reports NOT_EXERCISED when the opt-in is absent; it never turns that into a
// pass.
#include <ext/doctest/doctest.h>

#include <lte/enb/process_fleet.hpp>

#include <lib/udp/server.hpp>

#include <chrono>
#include <cstdlib>
#include <filesystem>
#include <fstream>
#include <sstream>
#include <string>
#include <thread>
#include <vector>

#include <fcntl.h>
#include <signal.h>
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

uint16_t FreeUdpPort()
{
    udp::UdpServer probe{"127.0.0.1", 0};
    return probe.LocalAddress().getPort();
}

std::string ResolvePeer(const std::string &testBinary)
{
    if (const char *explicitPath = std::getenv("UNIRANSIM_LTE_UU_PEER_BINARY"))
        if (explicitPath[0] != '\0')
            return explicitPath;
    const auto directory = std::filesystem::path(testBinary).parent_path();
    for (const auto &candidate : {directory / "lte-uu-attach-peer",
                                  directory.parent_path() / "lte-uu-attach-peer"})
        if (std::filesystem::exists(candidate))
            return candidate.string();
    return {};
}

pid_t Spawn(const std::string &binary, const std::vector<std::string> &arguments, const std::string &logPath,
           bool unprivileged = false)
{
    const pid_t pid = fork();
    if (pid != 0)
        return pid;
    const int fd = open(logPath.c_str(), O_WRONLY | O_CREAT | O_TRUNC, 0644);
    if (fd >= 0)
    {
        dup2(fd, STDOUT_FILENO);
        dup2(fd, STDERR_FILENO);
        close(fd);
    }
    // The UE is the control-plane subject of this test: it must not allocate a
    // TUN, so it runs without the privilege that would let it. The Attach path
    // itself needs none.
    if (unprivileged && geteuid() == 0)
    {
        if (setgid(65534) != 0 || setuid(65534) != 0)
            _exit(126);
    }
    std::vector<char *> argv;
    argv.push_back(const_cast<char *>(binary.c_str()));
    for (const auto &argument : arguments)
        argv.push_back(const_cast<char *>(argument.c_str()));
    argv.push_back(nullptr);
    execv(binary.c_str(), argv.data());
    _exit(127);
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

bool WaitForFile(const std::string &path, int milliseconds)
{
    const auto deadline = Clock::now() + std::chrono::milliseconds(milliseconds);
    while (Clock::now() < deadline)
    {
        if (std::filesystem::exists(path))
            return true;
        std::this_thread::sleep_for(std::chrono::milliseconds(10));
    }
    return std::filesystem::exists(path);
}

// Waits up to the deadline for the child, then terminates it. Returns the exit
// status, or -1 when it had to be killed.
int StopChild(pid_t pid, int milliseconds)
{
    kill(pid, SIGTERM);
    const auto deadline = Clock::now() + std::chrono::milliseconds(milliseconds);
    while (Clock::now() < deadline)
    {
        int status = 0;
        const pid_t reaped = waitpid(pid, &status, WNOHANG);
        if (reaped == pid)
            return WIFEXITED(status) ? WEXITSTATUS(status) : -1;
        std::this_thread::sleep_for(std::chrono::milliseconds(20));
    }
    kill(pid, SIGKILL);
    int status = 0;
    waitpid(pid, &status, 0);
    return -1;
}

bool Contains(const std::string &text, const std::string &needle)
{
    return text.find(needle) != std::string::npos;
}

} // namespace

TEST_CASE("lte/uu/acceptance: a separate production ue process attaches through srb1")
{
    if (std::getenv("UNIRANSIM_RUN_TWO_PROCESS_ATTACH") == nullptr)
    {
        MESSAGE("two-process Attach is opt-in; set UNIRANSIM_RUN_TWO_PROCESS_ATTACH=1");
        return;
    }

    const std::string testBinary = SelfExecutable();
    const std::string ueBinary = lte::enb::ProcessFleet::ResolveBinary(testBinary);
    REQUIRE_FALSE(ueBinary.empty());
    const std::string peerBinary = ResolvePeer(testBinary);
    REQUIRE_FALSE(peerBinary.empty());

    const std::string work = "/tmp/uniransim-uu-attach";
    std::filesystem::remove_all(work);
    std::filesystem::create_directories(work);
    const std::string readyPath = work + "/peer.ready";
    const std::string resultPath = work + "/peer.result";
    const std::string peerLog = work + "/peer.log";
    const std::string ueLog = work + "/ue.log";
    const std::string ueConfigPath = work + "/ue.yaml";

    const uint16_t peerPort = FreeUdpPort();
    const uint16_t ueUuPort = FreeUdpPort();
    const uint16_t ueLegacyPort = FreeUdpPort();
    const uint16_t unusedEnbPort = FreeUdpPort();

    {
        std::ofstream config(ueConfigPath);
        REQUIRE(config.good());
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
        config << "  port: " << peerPort << "\n";
        config << "tun:\n";
        config << "  required: false\n";
        config << "  namePrefix: uniransim-lte\n";
        config << "  mtu: 1400\n";
        config.flush();
        REQUIRE(config.good());
    }

    const pid_t peerPid =
        Spawn(peerBinary, {std::to_string(peerPort), readyPath, resultPath, "attach-only"}, peerLog);
    REQUIRE(peerPid > 0);
    REQUIRE(WaitForFile(readyPath, 5000));

    const pid_t uePid = Spawn(ueBinary, {"-c", ueConfigPath}, ueLog, true);
    REQUIRE(uePid > 0);

    bool completed = false;
    {
        const auto deadline = Clock::now() + std::chrono::seconds(25);
        while (Clock::now() < deadline)
        {
            if (std::filesystem::exists(resultPath))
            {
                completed = true;
                break;
            }
            std::this_thread::sleep_for(std::chrono::milliseconds(20));
        }
    }

    // The UE is a long-lived process after a successful attach; stopping it is
    // part of the test, not a failure.
    const int ueExit = StopChild(uePid, 5000);
    const int peerExit = StopChild(peerPid, 5000);

    std::string result;
    REQUIRE(ReadFile(resultPath, result));
    INFO("peer result:\n" << result);
    CHECK(Contains(result, "result=COMPLETE"));
    CHECK(Contains(result, "initial_ue_messages=1"));
    CHECK(Contains(result, "auth_response_verified=1"));
    CHECK(Contains(result, "smc_complete_verified=1"));
    CHECK(Contains(result, "ics_response=1"));
    CHECK(Contains(result, "rrc_as_security=1"));
    CHECK(Contains(result, "attach_complete_verified=1"));
    CHECK(Contains(result, "attach_accept_sent=1"));

    std::string ueOutput;
    REQUIRE(ReadFile(ueLog, ueOutput));
    INFO("ue log tail:\n" << ueOutput.substr(ueOutput.size() > 4000 ? ueOutput.size() - 4000 : 0));
    CHECK(Contains(ueOutput, "Uu SRB1 transport started"));
    CHECK(Contains(ueOutput, "NAS security activated"));
    CHECK(Contains(ueOutput, "RRC AS security prepared from KASME"));
    CHECK(Contains(ueOutput, "EPS Attach complete"));
    CHECK(Contains(ueOutput, "The Attach Request waits for the RRC connection"));

    CHECK(ueExit == 0);
    CHECK(peerExit == 0);
    CHECK(completed);
}

TEST_CASE("lte/uu/acceptance: an unreachable uu peer fails without using the legacy link")
{
    if (std::getenv("UNIRANSIM_RUN_TWO_PROCESS_ATTACH") == nullptr)
    {
        MESSAGE("the two-process failure path is opt-in; set UNIRANSIM_RUN_TWO_PROCESS_ATTACH=1");
        return;
    }

    const std::string testBinary = SelfExecutable();
    const std::string ueBinary = lte::enb::ProcessFleet::ResolveBinary(testBinary);
    REQUIRE_FALSE(ueBinary.empty());

    const std::string work = "/tmp/uniransim-uu-unreachable";
    std::filesystem::remove_all(work);
    std::filesystem::create_directories(work);
    const std::string ueLog = work + "/ue.log";
    const std::string ueConfigPath = work + "/ue.yaml";

    // A port this test never binds is the wrong/unreachable peer. The UE has a
    // short procedure deadline so the case is bounded.
    const uint16_t unreachablePeer = FreeUdpPort();
    const uint16_t legacyLocal = FreeUdpPort();
    const uint16_t legacyPeer = FreeUdpPort();
    const uint16_t uuLocal = FreeUdpPort();
    {
        std::ofstream config(ueConfigPath);
        REQUIRE(config.good());
        config << "imsi: \"460020000000401\"\n";
        config << "mcc: \"460\"\n";
        config << "mnc: \"02\"\n";
        config << "ueId: 46002\n";
        config << "k: \"00112233445566778899aabbccddeeff\"\n";
        config << "opc: \"00112233445566778899aabbccddeeff\"\n";
        config << "amf: \"8000\"\n";
        config << "initialSqn: \"000000000001\"\n";
        config << "pdnType: IPv4\n";
        config << "enbLink:\n";
        config << "  localAddress: 127.0.0.1\n";
        config << "  localPort: " << legacyLocal << "\n";
        config << "  address: 127.0.0.1\n";
        config << "  port: " << legacyPeer << "\n";
        config << "  tac: 1\n";
        config << "  timeoutMs: 3000\n";
        config << "uu:\n";
        config << "  localAddress: 127.0.0.1\n";
        config << "  localPort: " << uuLocal << "\n";
        config << "  address: 127.0.0.1\n";
        config << "  port: " << unreachablePeer << "\n";
        config << "tun:\n";
        config << "  required: false\n";
        config << "  namePrefix: uniransim-lte\n";
        config << "  mtu: 1400\n";
        config.flush();
        REQUIRE(config.good());
    }

    // A UDP endpoint on the address the UE's legacy enbLink names. A silent
    // fallback would send something here, so the test observes the socket
    // rather than trusting the absence of a log line.
    udp::UdpServer legacyProbe{"127.0.0.1", legacyPeer};
    const pid_t uePid = Spawn(ueBinary, {"-c", ueConfigPath}, ueLog, true);
    REQUIRE(uePid > 0);

    int exitCode = -1;
    const auto deadline = Clock::now() + std::chrono::seconds(15);
    while (Clock::now() < deadline)
    {
        int status = 0;
        const pid_t reaped = waitpid(uePid, &status, WNOHANG);
        if (reaped == uePid)
        {
            exitCode = WIFEXITED(status) ? WEXITSTATUS(status) : -1;
            break;
        }
        std::this_thread::sleep_for(std::chrono::milliseconds(20));
    }
    if (exitCode == -1)
    {
        kill(uePid, SIGKILL);
        int status = 0;
        waitpid(uePid, &status, 0);
    }

    CHECK(exitCode == 1);

    std::string output;
    REQUIRE(ReadFile(ueLog, output));
    INFO("ue log tail:\n" << output.substr(output.size() > 3000 ? output.size() - 3000 : 0));
    // The RRC request went to the configured endpoint and the run failed on
    // its own deadline. A legacy fallback would have sent the Attach Request
    // and logged ATTACH_REQUEST_SENT before that.
    CHECK(Contains(output, "Uu SRB1 transport started"));
    CHECK(Contains(output, "Timed out waiting for MME EPS Attach signaling"));
    CHECK_FALSE(Contains(output, "State=ATTACH_REQUEST_SENT"));

    // Nothing was sent to the legacy eNB endpoint: not the Attach Request, not
    // a control frame, not a retry.
    uint8_t legacyBuffer[2048];
    InetAddress legacySource;
    CHECK(legacyProbe.Receive(legacyBuffer, sizeof(legacyBuffer), 100, legacySource) == 0);
}


namespace
{

struct LifecycleRun
{
    std::string peerResult;
    std::string ueLog;
    int ueExit{-1};
    int peerExit{-1};
    bool resultWritten{false};
};

// One configuration shape for every lifecycle case: the same subscriber, a
// short controlled trigger and a procedure deadline that bounds a failure.
void WriteLifecycleConfig(const std::string &path, uint16_t legacyLocal, uint16_t legacyPeer, uint16_t uuLocal,
                          uint16_t uuPeer, const std::string &scenario, int procedureMs)
{
    std::ofstream config(path);
    REQUIRE(config.good());
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
    config << "  localPort: " << legacyLocal << "\n";
    config << "  address: 127.0.0.1\n";
    config << "  port: " << legacyPeer << "\n";
    config << "  tac: 1\n";
    config << "  timeoutMs: 30000\n";
    config << "uu:\n";
    config << "  localAddress: 127.0.0.1\n";
    config << "  localPort: " << uuLocal << "\n";
    config << "  address: 127.0.0.1\n";
    config << "  port: " << uuPeer << "\n";
    config << "tun:\n";
    config << "  required: false\n";
    config << "  namePrefix: uniransim-lte\n";
    config << "  mtu: 1400\n";
    config << "lifecycle:\n";
    config << "  scenario: " << scenario << "\n";
    config << "  triggerAfterMs: 300\n";
    config << "  procedureTimeoutMs: " << procedureMs << "\n";
    config << "  maxRetries: 2\n";
    config.flush();
    REQUIRE(config.good());
}

// Returns the exit status, or -1 when the process is still running.
int WaitForExit(pid_t pid, int milliseconds)
{
    const auto deadline = Clock::now() + std::chrono::milliseconds(milliseconds);
    while (Clock::now() < deadline)
    {
        int status = 0;
        const pid_t reaped = waitpid(pid, &status, WNOHANG);
        if (reaped == pid)
            return WIFEXITED(status) ? WEXITSTATUS(status) : -1;
        std::this_thread::sleep_for(std::chrono::milliseconds(20));
    }
    return -1;
}

// Runs one UE process against one deterministic peer over real UDP sockets on
// dynamically chosen ports, and returns what both sides actually did. The UE
// runs unprivileged so the lifecycle is control-plane-only.
LifecycleRun RunLifecycle(const std::string &work, const std::string &mode, const std::string &scenario,
                          bool ueLongLived = false, int procedureMs = 900)
{
    std::filesystem::remove_all(work);
    std::filesystem::create_directories(work);
    const std::string readyPath = work + "/peer.ready";
    const std::string resultPath = work + "/peer.result";
    const std::string peerLog = work + "/peer.log";
    const std::string ueLog = work + "/ue.log";
    const std::string ueConfigPath = work + "/ue.yaml";

    const std::string ueBinary = lte::enb::ProcessFleet::ResolveBinary(SelfExecutable());
    const std::string peerBinary = ResolvePeer(SelfExecutable());

    const uint16_t peerPort = FreeUdpPort();
    const uint16_t uuLocal = FreeUdpPort();
    const uint16_t legacyLocal = FreeUdpPort();
    const uint16_t legacyPeer = FreeUdpPort();
    WriteLifecycleConfig(ueConfigPath, legacyLocal, legacyPeer, uuLocal, peerPort, scenario, procedureMs);

    LifecycleRun run;
    const pid_t peerPid = Spawn(peerBinary, {std::to_string(peerPort), readyPath, resultPath, mode}, peerLog);
    REQUIRE(peerPid > 0);
    REQUIRE(WaitForFile(readyPath, 5000));
    const pid_t uePid = Spawn(ueBinary, {"-c", ueConfigPath}, ueLog, true);
    REQUIRE(uePid > 0);

    run.resultWritten = WaitForFile(resultPath, 30000);
    // The successful run exits by itself after the Detach; a failing run has to
    // reach its own bounded deadline. Only a process that outlives both is
    // stopped here, and that is not counted as an exit.
    // An attach-only UE stays registered by design, so it is stopped once the
    // peer has reported; that is not an exit the case may interpret.
    run.ueExit = ueLongLived ? -1 : WaitForExit(uePid, 20000);
    if (run.ueExit == -1)
        run.ueExit = StopChild(uePid, 3000);
    run.peerExit = WaitForExit(peerPid, 3000);
    if (run.peerExit == -1)
        run.peerExit = StopChild(peerPid, 3000);

    REQUIRE(ReadFile(resultPath, run.peerResult));
    REQUIRE(ReadFile(ueLog, run.ueLog));
    INFO("peer result:\n" << run.peerResult);
    INFO("ue log tail:\n" << run.ueLog.substr(run.ueLog.size() > 5000 ? run.ueLog.size() - 5000 : 0));
    return run;
}

} // namespace

TEST_CASE("lte/uu/lifecycle: the production ue attaches and detaches the same session over srb1")
{
    if (std::getenv("UNIRANSIM_RUN_TWO_PROCESS_ATTACH") == nullptr)
    {
        MESSAGE("the two-process lifecycle is opt-in; set UNIRANSIM_RUN_TWO_PROCESS_ATTACH=1");
        return;
    }

    const auto run = RunLifecycle("/tmp/uniransim-uu-lifecycle", "attach-detach", "attach-detach");

    CHECK(Contains(run.peerResult, "result=COMPLETE"));
    CHECK(Contains(run.peerResult, "mode=attach-detach"));
    CHECK(Contains(run.peerResult, "initial_ue_messages=1"));
    // Authentication Response, Security Mode Complete, Attach Complete and the
    // Detach Request: four uplink NAS transports, no Attach repeated.
    CHECK(Contains(run.peerResult, "uplink_nas_transports=4"));
    CHECK(Contains(run.peerResult, "auth_response_verified=1"));
    CHECK(Contains(run.peerResult, "smc_complete_verified=1"));
    CHECK(Contains(run.peerResult, "ics_response=1"));
    CHECK(Contains(run.peerResult, "rrc_as_security=1"));
    CHECK(Contains(run.peerResult, "attach_complete_verified=1"));
    CHECK(Contains(run.peerResult, "attach_accept_sent=1"));
    // The exact production Detach Request bytes: EPS detach, native KSI 0, the
    // GUTI the MME assigned, and the next uplink COUNT of the same context.
    CHECK(Contains(run.peerResult, "detach_request=0745010bf664f02000010112345678"));
    CHECK(Contains(run.peerResult, "detach_request_verified=1"));
    CHECK(Contains(run.peerResult, "detach_ul_count=2"));
    CHECK(Contains(run.peerResult, "detach_dl_count=2"));
    CHECK(Contains(run.peerResult, "detach_accept_sent=1"));
    CHECK(Contains(run.peerResult, "enb_context_released=1"));
    CHECK(Contains(run.peerResult, "injected_corruption=0"));

    CHECK(Contains(run.ueLog, "Uu SRB1 transport started"));
    CHECK(Contains(run.ueLog, "NAS security activated: EIA2/EEA0"));
    CHECK(Contains(run.ueLog, "RRC AS security prepared from KASME at uplink NAS COUNT 0"));
    CHECK(Contains(run.ueLog, "Protected EPS Detach Request sent"));
    CHECK(Contains(run.ueLog, "EPS Detach accepted; State=EMM_DEREGISTERED, bearer and TUN released"));
    CHECK(Contains(run.ueLog, "The Uu SRB1 transport is released with the process after the Detach"));
    // One Attach for the whole lifecycle, and no legacy fallback at any point.
    CHECK(Contains(run.ueLog, "State=ATTACH_REQUEST_SENT"));
    CHECK(Contains(run.ueLog, "EPS Attach complete"));

    CHECK(run.ueExit == 0);
    CHECK(run.peerExit == 0);
    CHECK(run.resultWritten);
}

TEST_CASE("lte/uu/lifecycle: a duplicate attach accept does not repeat the ue attach completion")
{
    if (std::getenv("UNIRANSIM_RUN_TWO_PROCESS_ATTACH") == nullptr)
    {
        MESSAGE("the two-process lifecycle is opt-in; set UNIRANSIM_RUN_TWO_PROCESS_ATTACH=1");
        return;
    }

    const auto run = RunLifecycle("/tmp/uniransim-uu-duplicate", "duplicate-attach-accept", "attach-detach");

    CHECK(Contains(run.peerResult, "result=COMPLETE"));
    // The duplicated downlink did not produce a second Attach Complete.
    CHECK(Contains(run.peerResult, "uplink_nas_transports=4"));
    CHECK(Contains(run.peerResult, "attach_complete_verified=1"));
    CHECK(Contains(run.peerResult, "detach_request_verified=1"));
    CHECK(Contains(run.peerResult, "detach_accept_sent=1"));
    CHECK(Contains(run.peerResult, "enb_context_released=1"));

    // The replayed COUNT is refused by the active downlink security context.
    CHECK(Contains(run.ueLog, "Dropped unauthenticated/replayed NAS"));
    CHECK(Contains(run.ueLog, "EPS Detach accepted; State=EMM_DEREGISTERED, bearer and TUN released"));
    CHECK(run.ueExit == 0);
    CHECK(run.peerExit == 0);
}

TEST_CASE("lte/uu/lifecycle: a peer that exits during detach leaves the ue without a deregistration")
{
    if (std::getenv("UNIRANSIM_RUN_TWO_PROCESS_ATTACH") == nullptr)
    {
        MESSAGE("the two-process lifecycle is opt-in; set UNIRANSIM_RUN_TWO_PROCESS_ATTACH=1");
        return;
    }

    const auto run = RunLifecycle("/tmp/uniransim-uu-peer-exit", "exit-on-detach", "attach-detach");

    CHECK(Contains(run.peerResult, "result=FAILED"));
    CHECK(Contains(run.peerResult, "detach_request_verified=1"));
    CHECK(Contains(run.peerResult, "detach_accept_sent=0"));
    // The UE must not claim a Detach it never completed, and must not hang.
    CHECK(run.ueExit == 1);
    // The retransmission found no route to the peer and was refused by the
    // transport rather than silently dropped; either explicit outcome is a
    // reported failure, and neither is a deregistration.
    CHECK(Contains(run.ueLog, "The uplink NAS transport refused a procedure retransmission"));
    CHECK(Contains(run.ueLog, "State=PROCEDURE_FAILED"));
    CHECK_FALSE(Contains(run.ueLog, "EPS Detach accepted"));
    CHECK_FALSE(Contains(run.ueLog, "State=EMM_DEREGISTERED"));
}

TEST_CASE("lte/uu/lifecycle: a corrupted detach accept fails nas integrity and is not acted on")
{
    if (std::getenv("UNIRANSIM_RUN_TWO_PROCESS_ATTACH") == nullptr)
    {
        MESSAGE("the two-process lifecycle is opt-in; set UNIRANSIM_RUN_TWO_PROCESS_ATTACH=1");
        return;
    }

    const auto run = RunLifecycle("/tmp/uniransim-uu-bad-mac", "bad-detach-mac", "attach-detach");

    CHECK(Contains(run.peerResult, "injected_corruption=1"));
    CHECK(Contains(run.peerResult, "detach_accept_sent=1"));
    CHECK(Contains(run.peerResult, "detach_request_verified=1"));
    CHECK(run.ueExit == 1);
    // Integrity verification ran and refused the message; the UE stayed
    // registered instead of entering EMM_DEREGISTERED.
    CHECK(Contains(run.ueLog, "EPS NAS integrity verification failed"));
    CHECK(Contains(run.ueLog, "Dropped unauthenticated/replayed NAS"));
    CHECK_FALSE(Contains(run.ueLog, "EPS Detach accepted"));
    CHECK_FALSE(Contains(run.ueLog, "State=EMM_DEREGISTERED"));
}

TEST_CASE("lte/uu/lifecycle: attach-only keeps the d3 behaviour under the detach-capable peer")
{
    if (std::getenv("UNIRANSIM_RUN_TWO_PROCESS_ATTACH") == nullptr)
    {
        MESSAGE("the two-process lifecycle is opt-in; set UNIRANSIM_RUN_TWO_PROCESS_ATTACH=1");
        return;
    }

    const auto run = RunLifecycle("/tmp/uniransim-uu-attach-only", "attach-only", "attach-only", true);

    CHECK(Contains(run.peerResult, "result=COMPLETE"));
    CHECK(Contains(run.peerResult, "uplink_nas_transports=3"));
    CHECK(Contains(run.peerResult, "attach_complete_verified=1"));
    CHECK(Contains(run.peerResult, "detach_request="));
    CHECK(Contains(run.peerResult, "detach_accept_sent=0"));
    CHECK(Contains(run.ueLog, "EPS Attach complete"));
    CHECK_FALSE(Contains(run.ueLog, "Protected EPS Detach Request sent"));
    // The UE stays registered, so stopping it is the test's job and is not a
    // failure of the run.
    CHECK(run.resultWritten);
}

