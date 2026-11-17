//
// This file is a part of UERANSIM project.
// Copyright (c) 2027 ALİ GÜNGÖR.
//
// https://github.com/aligungr/UERANSIM/
// See README, LICENSE, and CONTRIBUTING files for licensing details.
//

// Offline receive-buffer experiment (Phase 19-F-D).
//
// Built only with -DBUILD_EXPERIMENTS=ON and never part of the CI matrix. It
// measures what an explicit SO_RCVBUF does to a real socket under a real burst,
// using the production udp::UdpServer::ConfigureReceiveBuffer:
//
//   * default socket, no request at all;
//   * explicit request at the kernel cap the operator can actually obtain;
//   * explicit request above the cap, which must be refused rather than
//     silently reduced.
//
// For each case it sends a bounded burst from a second socket, reads everything
// that arrived, and reports the delivered count, the kernel drop count from
// /proc/net/udp and the effective buffer readback. Nothing here is a throughput
// claim: it is a socket-level comparison at a fixed offered burst.

#include <algorithm>
#include <array>
#include <chrono>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <fstream>
#include <string>
#include <vector>

#include <unistd.h>

#include <lib/udp/server.hpp>
#include <lte/enb/runtime_metrics.hpp>

namespace
{

int KernelRmemMax()
{
    std::ifstream in("/proc/sys/net/core/rmem_max");
    int value = 0;
    if (!(in >> value) || value <= 0)
        return 0;
    return value;
}

struct BurstResult
{
    std::string label;
    int requested{0};
    int effective{0};
    bool applied{false};
    std::string error;
    uint64_t offered{0};
    uint64_t delivered{0};
    uint64_t kernelDrops{0};
    uint64_t bytes{0};
};

BurstResult RunBurst(const std::string &label, int request, uint64_t count, size_t payloadBytes, bool configure)
{
    BurstResult result;
    result.label = label;
    result.requested = request;

    udp::UdpServer receiver("127.0.0.1", 0);
    udp::UdpServer sender("127.0.0.1", 0);
    if (configure)
    {
        const auto status = receiver.ConfigureReceiveBuffer(request);
        result.applied = status.applied;
        result.effective = status.effectiveBytes;
        result.error = status.error;
        if (!status.applied)
            return result;
    }
    else
    {
        result.effective = lte::enb::ReadSocketReceiveBuffer(receiver.NativeFd());
    }

    const uint16_t port = receiver.LocalAddress().getPort();
    const auto dropsBefore = lte::enb::ReadUdpSocketAccounting(port).drops;

    std::vector<uint8_t> payload(payloadBytes, 0x5A);
    for (uint64_t i = 0; i < count; ++i)
        sender.Send(receiver.LocalAddress(), payload.data(), payload.size());
    result.offered = count;

    // Drain what survived. The burst is bounded, so this terminates.
    std::vector<uint8_t> buffer(payloadBytes + 64);
    InetAddress peer;
    for (;;)
    {
        const int received = receiver.Receive(buffer.data(), buffer.size(), 0, peer);
        if (received <= 0)
            break;
        ++result.delivered;
        result.bytes += static_cast<uint64_t>(received);
    }
    result.kernelDrops = lte::enb::ReadUdpSocketAccounting(port).drops - dropsBefore;
    return result;
}

void Print(const BurstResult &r)
{
    std::printf("RESULT %-24s requested=%9d effective=%9d applied=%d offered=%llu delivered=%llu drops=%llu\n",
                r.label.c_str(), r.requested, r.effective, r.applied ? 1 : 0,
                static_cast<unsigned long long>(r.offered), static_cast<unsigned long long>(r.delivered),
                static_cast<unsigned long long>(r.kernelDrops));
    if (!r.error.empty())
        std::printf("       reason: %s\n", r.error.c_str());
}

} // namespace

int main(int argc, char **argv)
{
    uint64_t count = 2000;
    size_t payload = 1400;
    int explicitRequest = 4194304;
    if (argc > 1)
        count = static_cast<uint64_t>(std::strtoull(argv[1], nullptr, 10));
    if (argc > 2)
        payload = static_cast<size_t>(std::strtoul(argv[2], nullptr, 10));
    if (argc > 3)
        explicitRequest = std::atoi(argv[3]);

    const int cap = KernelRmemMax();
    std::printf("HOST net.core.rmem_max=%d\n", cap);

    Print(RunBurst("default", 0, count, payload, false));
    Print(RunBurst("at-cap", cap, count, payload, true));
    Print(RunBurst("explicit", explicitRequest, count, payload, true));
    Print(RunBurst("above-cap", std::min(2 * cap, udp::MaxConfiguredReceiveBufferBytes), count, payload, true));
    return 0;
}
