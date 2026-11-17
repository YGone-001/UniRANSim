//
// This file is a part of UERANSIM project.
// Copyright (c) 2027 ALİ GÜNGÖR.
//
// https://github.com/aligungr/UERANSIM/
// See README, LICENSE, and CONTRIBUTING files for licensing details.
//

// Offline downlink receive experiment (Phase 19-F-B).
//
// This tool is NOT part of the build or of the CI matrix. It is the controlled
// A/B measurement behind docs/lte-downlink-receive-performance.md, and it is
// built only with -DBUILD_EXPERIMENTS=ON.
//
// What it measures is the real receive path of the LTE UE, not a synthetic
// shortcut:
//
//   * the production udp::UdpServer the UE owns;
//   * the production link::Decode of a frame built by the production
//     link::Encode;
//   * the production downlink direction, identity and IPv4 validation;
//   * the production TunDevice::writePacket into a real kernel TUN, when the
//     tool runs with the capability to create one (TUN name prefix p19fb);
//   * the production RadioReceiveTimeoutMs receive policy.
//
// Variant A is the current behaviour: one radio datagram per main-loop turn.
// Variant B is the bounded drain: the same turn reads up to --batch frames,
// with a non-blocking timeout after the first. The only difference between the
// two runs is that number, so the comparison isolates receive scheduling.
//
// The main-loop prologue of src/lte/ue/app.cpp is modelled, not executed: one
// monotonic clock read, one non-blocking TUN uplink read that finds nothing,
// and the receive-timeout policy call. Everything the frame itself costs is
// the production code.
//
// Latency is reported at five separate boundaries, and each one is named by the
// two points it joins:
//
//   send->radio        sender wrote the datagram to Receive() returning it
//   radio->decode      Receive() to link::Decode returning
//   decode->validate   link::Decode to ip::Validate returning
//   validate->tun-write  ip::Validate to the TUN write returning
//   send->tun-write    the whole path
//
// The earlier version of this tool reported a single "latency" that was in fact
// send->radio, and a reader could take it for a receive-to-TUN-write time. It is
// not one, and it is no longer reported as one.
//
// The sink is reported explicitly: REAL_TUN_MEASUREMENT when the frame really
// went through a kernel TUN, PIPE_PROXY_MEASUREMENT when the tool had to fall
// back to a non-blocking pipe. The two are never mixed in one conclusion.
//
// Affinity is verified, not assumed: sched_setaffinity's result and the CPU the
// thread actually ran on are both printed, for the receiver and for the sender,
// so a run that failed to pin is visible instead of being taken as controlled.

#include <algorithm>
#include <array>
#include <atomic>
#include <chrono>
#include <cmath>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <fcntl.h>
#include <memory>
#include <stdexcept>
#include <string>
#include <thread>
#include <vector>

#include <sched.h>
#include <sys/resource.h>
#include <time.h>
#include <unistd.h>

#include <lib/udp/server.hpp>
#include <lte/enb/runtime_metrics.hpp>
#include <lte/ip_packet.hpp>
#include <lte/ue/radio_link.hpp>
#include <lte/ue/runtime_policy.hpp>
#include <lte/ue/tun.hpp>
#include <lte/ue/types.hpp>

namespace
{

using Clock = std::chrono::steady_clock;
namespace link = lte::ue::link;

constexpr uint32_t kUeId = 7;
constexpr size_t kTimestampOffset = 8; // inside the IPv4/UDP payload

struct Options
{
    int seconds{5};
    int batch{8};
    int payloadBytes{1400};
    int pps{0}; // 0 = unthrottled
    bool timing{true};
    bool tun{true};
    int senderCpu{4};
    int receiverCpu{2};
};

struct StageTimes
{
    uint64_t decodeNanos{0};
    uint64_t validateNanos{0};
    uint64_t writeNanos{0};
};

struct RunResult
{
    std::string variant;
    bool realTun{false};
    int requestedCpu{-1};
    int actualCpu{-1};
    bool affinityApplied{false};
    int senderRequestedCpu{-1};
    int senderActualCpu{-1};
    bool senderAffinityApplied{false};
    int batch{0};
    int pps{0};
    bool timed{true};

    uint64_t turns{0};
    uint64_t receiveAttempts{0};
    uint64_t frames{0};
    uint64_t bytes{0};
    uint64_t emptyReceives{0};
    uint64_t peerRejects{0};
    uint64_t identityRejects{0};
    uint64_t receiveErrors{0};
    uint64_t decodeFailures{0};
    uint64_t tunWrites{0};
    uint64_t tunWriteErrors{0};
    uint64_t frameBudgetExhausted{0};
    uint64_t maxFramesPerTurn{0};

    uint64_t kernelDrops{0};
    uint64_t sendBlocked{0};
    uint64_t sent{0};

    double wallSeconds{0};
    double cpuUserSeconds{0};
    double cpuSystemSeconds{0};
    long voluntarySwitches{0};
    long involuntarySwitches{0};

    StageTimes stage{};
    // Five separate intervals, each measured at its own boundary. The old
    // single "latency" value was sender-timestamp to completed radio receive
    // and was never a receive-to-TUN-write number; it is kept under its real
    // name here.
    std::vector<double> sendToRadioMillis;
    std::vector<double> radioToDecodeMillis;
    std::vector<double> decodeToValidateMillis;
    std::vector<double> validateToTunMillis;
    std::vector<double> sendToTunMillis;

    double FramesPerSecond() const { return wallSeconds > 0 ? static_cast<double>(frames) / wallSeconds : 0; }
    double BytesPerSecond() const { return wallSeconds > 0 ? static_cast<double>(bytes) / wallSeconds : 0; }
    double CpuPercent() const
    {
        return wallSeconds > 0 ? 100.0 * (cpuUserSeconds + cpuSystemSeconds) / wallSeconds : 0;
    }
    double MeanStageNanos(uint64_t total, uint64_t count) const
    {
        return count == 0 ? 0 : static_cast<double>(total) / static_cast<double>(count);
    }
    const char *MeasurementClass() const
    {
        return realTun ? "REAL_TUN_MEASUREMENT" : "PIPE_PROXY_MEASUREMENT";
    }
};

uint16_t OnesComplementSum(const uint8_t *data, size_t size)
{
    uint32_t sum = 0;
    for (size_t i = 0; i + 1 < size; i += 2)
        sum += (static_cast<uint32_t>(data[i]) << 8U) | data[i + 1];
    if (size % 2 != 0)
        sum += static_cast<uint32_t>(data[size - 1]) << 8U;
    while ((sum >> 16U) != 0)
        sum = (sum & 0xFFFFU) + (sum >> 16U);
    return static_cast<uint16_t>(sum);
}

// A well-formed IPv4/UDP datagram of the requested size. The UDP checksum is
// written as zero, which IPv4 permits: the payload then carries the sender's
// timestamp for the latency measurement without invalidating anything the
// UE's own ip::Validate checks.
std::vector<uint8_t> BuildFrame(const std::array<uint8_t, 4> &destination, size_t payloadBytes)
{
    const size_t bodyBytes = payloadBytes > 28 ? payloadBytes - 28 : 16;
    const std::vector<uint8_t> body(bodyBytes, 0x5A);
    const size_t udpLength = 8 + body.size();
    const size_t totalLength = 20 + udpLength;
    std::vector<uint8_t> packet(totalLength, 0);
    packet[0] = 0x45;
    packet[2] = static_cast<uint8_t>(totalLength >> 8U);
    packet[3] = static_cast<uint8_t>(totalLength);
    packet[6] = 0x40;
    packet[8] = 64;
    packet[9] = 17;
    packet[12] = 10;
    packet[13] = 99;
    packet[14] = 0;
    packet[15] = 1;
    std::copy(destination.begin(), destination.end(), packet.begin() + 16);
    const uint16_t ipSum = static_cast<uint16_t>(~OnesComplementSum(packet.data(), 20));
    packet[10] = static_cast<uint8_t>(ipSum >> 8U);
    packet[11] = static_cast<uint8_t>(ipSum);

    packet[20] = static_cast<uint8_t>(40000 >> 8U);
    packet[21] = static_cast<uint8_t>(40000);
    packet[22] = static_cast<uint8_t>(5001 >> 8U);
    packet[23] = static_cast<uint8_t>(5001);
    packet[24] = static_cast<uint8_t>(udpLength >> 8U);
    packet[25] = static_cast<uint8_t>(udpLength);
    // Byte 26/27 stay zero: no UDP checksum, which IPv4 allows.
    std::copy(body.begin(), body.end(), packet.begin() + 28);
    return packet;
}

// Pins the calling thread and reports whether the kernel accepted it. A
// measurement that claims an isolated core must prove it got one: a failed
// sched_setaffinity leaves the thread free to migrate, and the CPU percentage
// then describes a moving target. On failure the run is still executed, but it
// is reported as unpinned instead of being silently treated as controlled.
bool PinToCpu(int cpu)
{
    if (cpu < 0)
        return false;
    cpu_set_t set;
    CPU_ZERO(&set);
    CPU_SET(cpu, &set);
    return sched_setaffinity(0, sizeof(set), &set) == 0;
}

// The timeout policy Variant B proposes: the first frame of a turn keeps the
// runtime receive policy, the additional frames do not block. Variant A is the
// production behaviour, which never asks for a second frame.
int TurnReceiveTimeoutMs(int firstTimeoutMs, int frameIndex)
{
    return frameIndex == 0 ? firstTimeoutMs : 0;
}

uint64_t NowNanos()
{
    return static_cast<uint64_t>(
        std::chrono::duration_cast<std::chrono::nanoseconds>(Clock::now().time_since_epoch()).count());
}

struct LatencySummary
{
    size_t samples{0};
    double p50{0};
    double p95{0};
    double p99{0};
    double maximum{0};
};

// Nearest-rank percentiles over the observed samples, so a reported tail is an
// observation and not an interpolation between two observations.
LatencySummary Summarize(std::vector<double> &values)
{
    LatencySummary summary;
    summary.samples = values.size();
    if (values.empty())
        return summary;
    std::sort(values.begin(), values.end());
    const auto at = [&values](double fraction) {
        const double rank = fraction * static_cast<double>(values.size() - 1);
        return values[static_cast<size_t>(std::llround(rank))];
    };
    summary.p50 = at(0.50);
    summary.p95 = at(0.95);
    summary.p99 = at(0.99);
    summary.maximum = values.back();
    return summary;
}

// The sender. It owns its own UDP socket, so the frames the receiver sees left
// a real socket, and it paces to a target rate in fixed one-millisecond ticks
// so the offered load is the same for both variants.
class Sender
{
  public:
    Sender(const InetAddress &destination, const std::vector<uint8_t> &frame, int pps)
        : m_destination(destination), m_frame(frame), m_pps(pps), m_socket("127.0.0.1", 0)
    {
    }

    [[nodiscard]] bool AffinityApplied() const { return m_affinityApplied; }
    [[nodiscard]] int ActualCpu() const { return m_actualCpu.load(); }

    void Run(std::atomic_bool &stop, std::atomic<uint64_t> &sent, std::atomic<uint64_t> &blocked)
    {
        m_affinityApplied = PinToCpu(m_pinnedCpu);
        m_actualCpu = sched_getcpu();
        if (m_pps <= 0)
        {
            while (!stop.load(std::memory_order_relaxed))
            {
                for (int i = 0; i < 64; ++i)
                    SendOne(sent, blocked);
            }
            return;
        }

        const int perTick = std::max(1, m_pps / 1000);
        const auto start = Clock::now();
        uint64_t tick = 0;
        while (!stop.load(std::memory_order_relaxed))
        {
            const auto due = start + std::chrono::microseconds(tick * 1000);
            const auto now = Clock::now();
            if (now < due)
            {
                const auto wait = std::chrono::duration_cast<std::chrono::nanoseconds>(due - now).count();
                timespec request{};
                request.tv_sec = wait / 1000000000LL;
                request.tv_nsec = wait % 1000000000LL;
                (void)clock_nanosleep(CLOCK_MONOTONIC, 0, &request, nullptr);
            }
            for (int i = 0; i < perTick; ++i)
                SendOne(sent, blocked);
            ++tick;
        }
    }

    void SetCpu(int cpu) { m_pinnedCpu = cpu; }
    [[nodiscard]] InetAddress LocalAddress() const { return m_socket.LocalAddress(); }

  private:
    void SendOne(std::atomic<uint64_t> &sent, std::atomic<uint64_t> &blocked)
    {
        const uint64_t stamp = NowNanos();
        std::memcpy(m_frame.data() + link::HeaderSize + 28 + kTimestampOffset, &stamp, sizeof(stamp));
        if (m_socket.TrySend(m_destination, m_frame.data(), m_frame.size()))
            sent.fetch_add(1, std::memory_order_relaxed);
        else
            blocked.fetch_add(1, std::memory_order_relaxed);
    }

    InetAddress m_destination;
    std::vector<uint8_t> m_frame;
    int m_pps{0};
    int m_pinnedCpu{4};
    std::atomic<bool> m_affinityApplied{false};
    std::atomic<int> m_actualCpu{-1};
    udp::UdpServer m_socket;
};

RunResult RunVariant(const Options &options, const std::string &variant, int batch, bool timing)
{
    RunResult result;
    result.variant = variant;
    result.batch = batch;
    result.pps = options.pps;
    result.timed = timing;
    result.realTun = false;

    // A real TUN when the process may create one; otherwise the same write()
    // onto a non-blocking pipe, which is reported as a proxy.
    lte::ue::TunConfig tunConfig;
    tunConfig.namePrefix = "p19fb";
    tunConfig.mtu = static_cast<int>(options.payloadBytes);
    tunConfig.required = true;
    const std::array<uint8_t, 4> tunAddress{10, 99, 0, 2};

    std::unique_ptr<lte::ue::TunDevice> tun;
    int pipeFds[2]{-1, -1};
    bool realTun = false;
    if (options.tun)
    {
        try
        {
            tun = std::make_unique<lte::ue::TunDevice>(tunConfig, tunAddress);
            realTun = true;
        }
        catch (const std::exception &e)
        {
            std::fprintf(stderr, "[experiment] TUN unavailable (%s); using a pipe sink\n", e.what());
        }
    }
    if (!tun)
    {
        if (::pipe(pipeFds) != 0)
            throw std::runtime_error("pipe() failed");
        const int flags = ::fcntl(pipeFds[1], F_GETFL, 0);
        (void)::fcntl(pipeFds[1], F_SETFL, flags | O_NONBLOCK);
    }

    result.realTun = realTun;
    const auto framePacket = BuildFrame(tunAddress, static_cast<size_t>(options.payloadBytes));
    const auto frame = link::Encode({link::MessageType::DATA_DOWNLINK, kUeId, framePacket});

    udp::UdpServer receiver("127.0.0.1", 0);
    const uint16_t receiverPort = receiver.LocalAddress().getPort();
    const InetAddress destination("127.0.0.1", receiverPort);

    Sender sender(destination, frame, options.pps);
    sender.SetCpu(options.senderCpu);

    std::atomic_bool stop{false};
    std::atomic<uint64_t> sent{0};
    std::atomic<uint64_t> blocked{0};
    std::thread senderThread([&] { sender.Run(stop, sent, blocked); });

    result.requestedCpu = options.receiverCpu;
    result.affinityApplied = PinToCpu(options.receiverCpu);
    result.actualCpu = sched_getcpu();

    const auto dropsBefore = lte::enb::ReadUdpSocketAccounting(receiverPort).drops;
    // The receiver thread's own cost: the sender runs on its own thread and
    // must not be charged to the receive path.
    rusage usageBefore{};
    (void)getrusage(RUSAGE_THREAD, &usageBefore);

    // The peer identity the UE's own receive path checks: every datagram must
    // come from the eNB endpoint the configuration named.
    const InetAddress senderAddress = sender.LocalAddress();
    const int firstTimeoutMs = lte::ue::RadioReceiveTimeoutMs(true, false);
    uint8_t buffer[link::MaxDataPduSize + link::HeaderSize];
    std::vector<uint8_t> probe;
    // Bounded sample storage: five vectors of one million doubles, pre-reserved
    // so a run never grows them mid-measurement and never samples unboundedly.
    result.sendToRadioMillis.reserve(1u << 20);
    result.radioToDecodeMillis.reserve(1u << 20);
    result.decodeToValidateMillis.reserve(1u << 20);
    result.validateToTunMillis.reserve(1u << 20);
    result.sendToTunMillis.reserve(1u << 20);

    const auto started = Clock::now();
    const auto deadline = started + std::chrono::seconds(options.seconds);
    while (Clock::now() < deadline)
    {
        // The app.cpp prologue, modelled: one clock read, one non-blocking TUN
        // uplink read that finds nothing, and the receive-timeout policy.
        ++result.turns;
        (void)Clock::now();
        (void)tun->readPacket(probe);

        uint64_t framesThisTurn = 0;
        for (int index = 0; index < batch; ++index)
        {
            const bool lastAllowed = index + 1 == batch;
            const int timeoutMs = TurnReceiveTimeoutMs(firstTimeoutMs, index);
            InetAddress peer;
            ++result.receiveAttempts;
            int received = 0;
            try
            {
                received = receiver.Receive(buffer, sizeof(buffer), timeoutMs, peer);
            }
            catch (const std::exception &)
            {
                ++result.receiveErrors;
                break;
            }
            if (received <= 0)
            {
                ++result.emptyReceives;
                break;
            }
            if (peer != senderAddress)
            {
                ++result.peerRejects;
                continue;
            }
            // The stage clocks exist only in a timed run. An untimed run is the
            // control for the instrumentation cost, so it must not pay for a
            // clock read it never uses.
            //
            // Five boundaries, each measured where it actually happens:
            //   sentAt              sender wrote the datagram
            //   radioReceivedAt     Receive() returned the frame
            //   decodedAt           link::Decode returned
            //   validatedAt         ip::Validate returned
            //   writtenAt           the TUN write returned
            const uint64_t radioReceivedAt = timing ? NowNanos() : 0;
            try
            {
                auto message = link::Decode(buffer, static_cast<size_t>(received));
                const uint64_t decodedAt = timing ? NowNanos() : 0;
                if (!link::IsDownlink(message.type) || message.ueId != kUeId)
                {
                    ++result.identityRejects;
                    continue;
                }
                const auto ipv4 = lte::ip::Validate(message.payload.data(), message.payload.size(),
                                                    static_cast<size_t>(options.payloadBytes));
                const uint64_t validatedAt = timing ? NowNanos() : 0;
                if (ipv4.destination != tunAddress)
                    throw lte::ip::ValidationError("Downlink destination does not match the assigned UE IPv4 address");
                bool wrote = false;
                if (tun)
                    wrote = tun->writePacket(message.payload.data(), message.payload.size());
                else
                    wrote = ::write(pipeFds[1], message.payload.data(), message.payload.size()) ==
                            static_cast<ssize_t>(message.payload.size());
                const uint64_t writtenAt = timing ? NowNanos() : 0;
                if (!wrote)
                {
                    ++result.tunWriteErrors;
                    continue;
                }
                ++result.tunWrites;
                ++result.frames;
                result.bytes += message.payload.size();
                ++framesThisTurn;
                if (timing)
                {
                    result.stage.decodeNanos += decodedAt - radioReceivedAt;
                    result.stage.validateNanos += validatedAt - decodedAt;
                    result.stage.writeNanos += writtenAt - validatedAt;
                    if (result.sendToTunMillis.size() < result.sendToTunMillis.capacity() &&
                        message.payload.size() >= 28 + kTimestampOffset + sizeof(uint64_t))
                    {
                        uint64_t sentAt = 0;
                        std::memcpy(&sentAt, message.payload.data() + 28 + kTimestampOffset, sizeof(sentAt));
                        if (sentAt != 0 && writtenAt > sentAt && writtenAt > radioReceivedAt &&
                            radioReceivedAt > sentAt)
                        {
                            result.sendToRadioMillis.push_back(static_cast<double>(radioReceivedAt - sentAt) / 1e6);
                            result.radioToDecodeMillis.push_back(static_cast<double>(decodedAt - radioReceivedAt) / 1e6);
                            result.decodeToValidateMillis.push_back(
                                static_cast<double>(validatedAt - decodedAt) / 1e6);
                            result.validateToTunMillis.push_back(static_cast<double>(writtenAt - validatedAt) / 1e6);
                            result.sendToTunMillis.push_back(static_cast<double>(writtenAt - sentAt) / 1e6);
                        }
                    }
                }
            }
            catch (const std::exception &)
            {
                ++result.decodeFailures;
                continue;
            }
            if (lastAllowed)
                ++result.frameBudgetExhausted;
        }
        result.maxFramesPerTurn = std::max<uint64_t>(result.maxFramesPerTurn, framesThisTurn);
    }
    stop.store(true);
    senderThread.join();
    result.senderRequestedCpu = options.senderCpu;
    result.senderAffinityApplied = sender.AffinityApplied();
    result.senderActualCpu = sender.ActualCpu();

    const auto finished = Clock::now();
    rusage usageAfter{};
    (void)getrusage(RUSAGE_THREAD, &usageAfter);
    result.wallSeconds = std::chrono::duration<double>(finished - started).count();
    result.cpuUserSeconds = static_cast<double>(usageAfter.ru_utime.tv_sec - usageBefore.ru_utime.tv_sec) +
                            static_cast<double>(usageAfter.ru_utime.tv_usec - usageBefore.ru_utime.tv_usec) / 1e6;
    result.cpuSystemSeconds = static_cast<double>(usageAfter.ru_stime.tv_sec - usageBefore.ru_stime.tv_sec) +
                              static_cast<double>(usageAfter.ru_stime.tv_usec - usageBefore.ru_stime.tv_usec) / 1e6;
    result.voluntarySwitches = usageAfter.ru_nvcsw - usageBefore.ru_nvcsw;
    result.involuntarySwitches = usageAfter.ru_nivcsw - usageBefore.ru_nivcsw;
    result.kernelDrops = lte::enb::ReadUdpSocketAccounting(receiverPort).drops - dropsBefore;
    result.sent = sent.load();
    result.sendBlocked = blocked.load();

    if (tun)
        tun.reset();
    if (pipeFds[0] >= 0)
        ::close(pipeFds[0]);
    if (pipeFds[1] >= 0)
        ::close(pipeFds[1]);
    return result;
}

void PrintLatency(const char *name, std::vector<double> &values)
{
    const auto summary = Summarize(values);
    std::printf("  lat %-20s p50=%.4f p95=%.4f p99=%.4f max=%.4f ms n=%zu\n", name, summary.p50, summary.p95,
                summary.p99, summary.maximum, summary.samples);
}

void Print(RunResult &r)
{
    std::printf("RESULT variant=%s batch=%d offered-pps=%d timed=%d sink=%s measurement=%s\n", r.variant.c_str(),
                r.batch, r.pps, r.timed ? 1 : 0, r.realTun ? "real-tun" : "pipe-proxy", r.MeasurementClass());
    std::printf("  affinity receiver=requested:%d applied:%d actual:%d sender=requested:%d applied:%d actual:%d\n",
                r.requestedCpu, r.affinityApplied ? 1 : 0, r.actualCpu, r.senderRequestedCpu,
                r.senderAffinityApplied ? 1 : 0, r.senderActualCpu);
    std::printf("  wall=%.3fs turns=%llu receive-attempts=%llu frames=%llu sent=%llu\n", r.wallSeconds,
                static_cast<unsigned long long>(r.turns), static_cast<unsigned long long>(r.receiveAttempts),
                static_cast<unsigned long long>(r.frames), static_cast<unsigned long long>(r.sent));
    std::printf("  fps=%.0f bytes/s=%.0f max-frames-per-turn=%llu budget-exhausted=%llu\n", r.FramesPerSecond(),
                r.BytesPerSecond(), static_cast<unsigned long long>(r.maxFramesPerTurn),
                static_cast<unsigned long long>(r.frameBudgetExhausted));
    std::printf("  empty=%llu peer-rejects=%llu identity-rejects=%llu receive-errors=%llu decode-failures=%llu\n",
                static_cast<unsigned long long>(r.emptyReceives), static_cast<unsigned long long>(r.peerRejects),
                static_cast<unsigned long long>(r.identityRejects), static_cast<unsigned long long>(r.receiveErrors),
                static_cast<unsigned long long>(r.decodeFailures));
    std::printf("  tun-writes=%llu tun-write-errors=%llu kernel-drops=%llu send-blocked=%llu\n",
                static_cast<unsigned long long>(r.tunWrites), static_cast<unsigned long long>(r.tunWriteErrors),
                static_cast<unsigned long long>(r.kernelDrops), static_cast<unsigned long long>(r.sendBlocked));
    std::printf("  cpu=%.1f%% user=%.3fs sys=%.3fs vcsw=%ld ivcsw=%ld\n", r.CpuPercent(), r.cpuUserSeconds,
                r.cpuSystemSeconds, r.voluntarySwitches, r.involuntarySwitches);
    // Each interval is named by its two boundaries. "send-to-radio" is what the
    // earlier single latency figure actually measured; it is not a
    // receive-to-TUN-write time and is no longer reported as one.
    PrintLatency("send->radio", r.sendToRadioMillis);
    PrintLatency("radio->decode", r.radioToDecodeMillis);
    PrintLatency("decode->validate", r.decodeToValidateMillis);
    PrintLatency("validate->tun-write", r.validateToTunMillis);
    PrintLatency("send->tun-write", r.sendToTunMillis);
    std::printf("  stage-mean-ns decode=%.0f validate=%.0f tun-write=%.0f\n",
                r.MeanStageNanos(r.stage.decodeNanos, r.frames), r.MeanStageNanos(r.stage.validateNanos, r.frames),
                r.MeanStageNanos(r.stage.writeNanos, r.frames));
    const auto endToEnd = Summarize(r.sendToTunMillis);
    std::printf("  summary fps=%.0f cpu=%.1f%% send-to-tun-p99=%.4fms drops=%llu\n", r.FramesPerSecond(),
                r.CpuPercent(), endToEnd.p99, static_cast<unsigned long long>(r.kernelDrops));
}

Options ParseOptions(int argc, char **argv)
{
    Options options;
    for (int i = 1; i < argc; ++i)
    {
        const std::string argument = argv[i];
        const auto next = [&]() -> int {
            if (i + 1 >= argc)
            {
                std::fprintf(stderr, "missing value for %s\n", argument.c_str());
                std::exit(2);
            }
            return std::atoi(argv[++i]);
        };
        if (argument == "--seconds")
            options.seconds = next();
        else if (argument == "--batch")
            options.batch = next();
        else if (argument == "--pps")
            options.pps = next();
        else if (argument == "--payload")
            options.payloadBytes = next();
        else if (argument == "--sender-cpu")
            options.senderCpu = next();
        else if (argument == "--receiver-cpu")
            options.receiverCpu = next();
        else if (argument == "--no-timing")
            options.timing = false;
        else if (argument == "--no-tun")
            options.tun = false;
        else
        {
            std::fprintf(stderr, "unknown option %s\n", argument.c_str());
            std::exit(2);
        }
    }
    return options;
}

} // namespace

int main(int argc, char **argv)
{
    const Options options = ParseOptions(argc, argv);

    // Variant A then B, each twice: the second run of a variant repeats the
    // offered workload so run-to-run variance is visible instead of being
    // folded into the comparison.
    std::vector<RunResult> results;
    for (int repeat = 0; repeat < 2; ++repeat)
    {
        results.push_back(RunVariant(options, "A-single", 1, options.timing));
        results.push_back(RunVariant(options, "B-batch", options.batch, options.timing));
    }
    if (options.timing)
    {
        // The instrumentation-overhead control: the same loop with the stage
        // clocks and latency samples removed.
        results.push_back(RunVariant(options, "A-single", 1, false));
        results.push_back(RunVariant(options, "B-batch", options.batch, false));
    }

    for (auto &r : results)
    {
        Print(r);
        std::printf("\n");
    }
    return 0;
}