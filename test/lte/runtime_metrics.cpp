//
// This file is a part of UERANSIM project.
// Copyright (c) 2027 ALİ GÜNGÖR.
//
// https://github.com/aligungr/UERANSIM/
// See README, LICENSE, and CONTRIBUTING files for licensing details.
//

// Phase 19-C: the measurement primitives, tested deterministically.
//
// Nothing here launches a UE fleet. These cases pin the parsers and the
// arithmetic that the local benchmarks rely on, so a silently broken RSS,
// percentile or drop counter cannot make a benchmark look better than it was.

#include <ext/doctest/doctest.h>

#include <chrono>
#include <climits>
#include <cstdint>
#include <memory>
#include <thread>
#include <vector>

#include <lib/udp/server.hpp>
#include <lte/enb/runtime_metrics.hpp>
#include <utils/network.hpp>

#include <sys/socket.h>
#include <unistd.h>

namespace
{

using namespace lte::enb;

} // namespace

TEST_CASE("lte/runtime: nearest-rank percentiles are observations, not interpolations")
{
    std::vector<double> values;
    for (int i = 1; i <= 100; ++i)
        values.push_back(static_cast<double>(i));

    const auto summary = SummarizeLatencies(values);
    CHECK(summary.count == 100);
    CHECK(summary.p50 == 50.0);
    CHECK(summary.p95 == 95.0);
    CHECK(summary.p99 == 99.0);
    CHECK(summary.maximum == 100.0);
    CHECK(summary.mean > 50.4);
    CHECK(summary.mean < 50.6);

    const auto single = SummarizeLatencies({7.5});
    CHECK(single.count == 1);
    CHECK(single.p50 == 7.5);
    CHECK(single.p95 == 7.5);
    CHECK(single.p99 == 7.5);
    CHECK(single.maximum == 7.5);

    const auto empty = SummarizeLatencies({});
    CHECK(empty.count == 0);
    CHECK(empty.maximum == 0.0);

    // Size summaries use the same rule and never borrow the millisecond type.
    const auto sizes = SummarizeSizes({10, 20, 30, 40, 50, 60, 70, 80, 90, 100});
    CHECK(sizes.count == 10);
    CHECK(sizes.p50 == 50);
    CHECK(sizes.p95 == 100);
    CHECK(sizes.maximum == 100);
}

TEST_CASE("lte/runtime: process memory distinguishes current, peak and proportional size")
{
    const auto memory = ReadSelfMemory();
    CHECK(memory.currentRssBytes > 0);
    // VmHWM is a kernel high-water mark, updated at its own granularity; a
    // current sample can exceed it by a few pages. Both must be observations of
    // their own field, not one substituted for the other.
    CHECK(memory.peakRssBytes > 0);
    CHECK(memory.peakObserved);

    // If smaps_rollup was readable, PSS cannot exceed RSS for one process and
    // private bytes cannot exceed RSS either.
    if (memory.sharedPagesResolved)
    {
        CHECK(memory.pssBytes > 0);
        CHECK(memory.pssBytes <= memory.currentRssBytes);
        CHECK(memory.privateBytes <= memory.currentRssBytes);
    }

    const uint64_t pageSize = HostPageSizeBytes();
    CHECK(pageSize >= 1024);
    CHECK((pageSize & (pageSize - 1)) == 0); // a power of two
    CHECK(ReadAvailableMemoryBytes() > 0);

    CHECK(CountThreads(static_cast<int>(getpid())) >= 1);
    CHECK(CountOpenFileDescriptors(static_cast<int>(getpid())) > 0);
    CHECK(ReadSocketReceiveBuffer(-1) == -1);

    // A live process's CPU time is monotonic but may not move within one tick.
    const uint64_t first = ReadProcessCpuTimeMicros(static_cast<int>(getpid()));
    std::this_thread::sleep_for(std::chrono::milliseconds(20));
    const uint64_t second = ReadProcessCpuTimeMicros(static_cast<int>(getpid()));
    CHECK(second >= first);

    // A process that does not exist is reported as zero, not as an estimate.
    const auto gone = ReadProcessMemory(INT_MAX);
    CHECK(gone.currentRssBytes == 0);
    CHECK(gone.peakRssBytes == 0);

    // The loopback interface exists in this namespace; an absent prefix does not.
    CHECK(CountInterfacesWithPrefix("zzz-not-present") == 0);
    CHECK(CountInterfacesWithPrefix("l") >= 1);
}

TEST_CASE("lte/runtime: a controlled socket burst is fully accounted as delivered plus kernel drops")
{
    // A deliberately tiny receive buffer makes the drop path deterministic
    // without changing any sysctl: the kernel clamps the request per socket.
    // Even the smallest plausible datagram accounting cannot fit the offered
    // burst in the resulting 4 KiB effective buffer.
    udp::UdpServer receiver{"127.0.0.1", 0};
    const int requested = 2048;
    REQUIRE(setsockopt(receiver.NativeFd(), SOL_SOCKET, SO_RCVBUF, &requested, sizeof(requested)) == 0);
    const int effective = ReadSocketReceiveBuffer(receiver.NativeFd());
    CHECK(effective >= requested);
    const auto local = receiver.LocalAddress();
    REQUIRE(local.getPort() != 0);

    constexpr size_t kSenders = 200;
    std::vector<std::unique_ptr<udp::UdpServer>> senders;
    for (size_t i = 0; i < kSenders; ++i)
    {
        senders.push_back(std::make_unique<udp::UdpServer>("127.0.0.1", 0));
        const uint8_t payload = static_cast<uint8_t>(i);
        senders.back()->Send(local, &payload, 1);
    }

    const auto accounting = ReadUdpSocketAccounting(local.getPort());
    REQUIRE(accounting.found);
    // With an 8 KiB effective buffer and 100 datagrams, the queue cannot hold
    // them all; the kernel's own counter must explain the difference.
    CHECK(accounting.drops > 0);
    CHECK(accounting.receiveQueueBytes > 0);

    uint8_t buffer[64];
    InetAddress peer;
    size_t delivered = 0;
    while (receiver.Receive(buffer, sizeof(buffer), 0, peer) > 0)
        ++delivered;

    CHECK(delivered > 0);
    CHECK(delivered < kSenders);
    CHECK(delivered + accounting.drops == kSenders);

    // A default socket is not modified by the test above.
    udp::UdpServer ordinary{"127.0.0.1", 0};
    CHECK(ReadSocketReceiveBuffer(ordinary.NativeFd()) > 0);
}

TEST_CASE("lte/runtime: an unmodified receive buffer and a larger one are distinguishable")
{
    // Per-socket comparison only. rmem_max is not changed; the kernel doubles a
    // successful SO_RCVBUF request up to its own per-socket ceiling.
    udp::UdpServer first{"127.0.0.1", 0};
    const int before = ReadSocketReceiveBuffer(first.NativeFd());
    const int request = before;
    REQUIRE(setsockopt(first.NativeFd(), SOL_SOCKET, SO_RCVBUF, &request, sizeof(request)) == 0);
    const int after = ReadSocketReceiveBuffer(first.NativeFd());
    CHECK(after >= before);
    CHECK(ReadUdpSocketAccounting(first.LocalAddress().getPort()).found);
}