//
// This file is a part of UERANSIM project.
// Copyright (c) 2027 ALİ GÜNGÖR.
//
// https://github.com/aligungr/UERANSIM/
// See README, LICENSE, and CONTRIBUTING files for licensing details.
//

// Phase 19-C: runtime resource and evidence measurement.
//
// Phase 19-B reported a single current-RSS sample from /proc/self/statm with a
// hardcoded 4096-byte page assumption and called it a peak. This module is the
// corrected primitive set: peak RSS comes from VmHWM, current RSS from VmRSS,
// proportional set size and private bytes from smaps_rollup where the kernel
// provides them, and the page size comes from the host through sysconf(3).
//
// Everything here is a read-only observation of the current host or of a
// process the caller owns. Nothing writes to /proc, nothing changes a sysctl and
// nothing reads subscriber material.

#pragma once

#include <chrono>
#include <cstddef>
#include <cstdint>
#include <string>
#include <vector>

namespace lte::enb
{

// Memory attribution for one process, all values in bytes.
//
// pssBytes and privateBytes are only meaningful when sharedPagesResolved is
// true: PSS needs the shared-page breakdown that smaps_rollup provides. A plain
// RSS sum over many processes double-counts every shared library page, so the
// aggregate is reported separately from the per-process distribution.
struct MemoryAttribution
{
    uint64_t currentRssBytes{};
    uint64_t peakRssBytes{};
    uint64_t pssBytes{};
    uint64_t privateBytes{};
    bool sharedPagesResolved{};
    bool peakObserved{};
};

// Current RSS, peak RSS, PSS and private bytes of one live process. Returns a
// zeroed record when the process is gone; peakObserved says which happened
// without inventing a measurement.
MemoryAttribution ReadProcessMemory(int pid);

// The same attribution for the calling process.
MemoryAttribution ReadSelfMemory();

// The host's actual memory-page size, used wherever a page count has to become
// a byte count. Never assume 4096.
uint64_t HostPageSizeBytes();

// Memory available to new work, from /proc/meminfo MemAvailable.
uint64_t ReadAvailableMemoryBytes();

// A monotonic latency distribution. Values are milliseconds.
struct LatencySummary
{
    size_t count{};
    double p50{};
    double p95{};
    double p99{};
    double maximum{};
    double mean{};
};

// Nearest-rank percentiles over the samples (no interpolation): p95 is the
// smallest observed value at or above the 95th percentile. This is deliberate:
// a tail number in the report must be an observation, not an interpolated
// value between two observations.
LatencySummary SummarizeLatencies(std::vector<double> samplesMs);

// The same nearest-rank rule for byte sizes, used for per-process RSS/PSS
// distributions. A size is never reported through the millisecond type.
struct SizeSummary
{
    size_t count{};
    uint64_t p50{};
    uint64_t p95{};
    uint64_t p99{};
    uint64_t maximum{};
    double mean{};
};

SizeSummary SummarizeSizes(std::vector<uint64_t> samplesBytes);

// Per-socket UDP accounting read from /proc/net/udp in the current network
// namespace. drops is the kernel's own count for that socket, not an inference
// from a missing packet.
struct UdpSocketAccounting
{
    bool found{};
    uint64_t drops{};
    uint64_t receiveQueueBytes{};
};

UdpSocketAccounting ReadUdpSocketAccounting(uint16_t localPort);
UdpSocketAccounting ReadUdp6SocketAccounting(uint16_t localPort);

// Effective SO_RCVBUF of a live socket descriptor, in bytes.
int ReadSocketReceiveBuffer(int fd);

// Number of entries in /proc/<pid>/fd, or zero when the process is gone.
size_t CountOpenFileDescriptors(int pid);

// Number of threads in /proc/<pid>/status.
size_t CountThreads(int pid);

// Task CPU time (user + system) in microseconds, from /proc/<pid>/stat.
uint64_t ReadProcessCpuTimeMicros(int pid);

// Number of UDP sockets the process owns, resolved by intersecting the
// process's socket inodes with /proc/net/udp and /proc/net/udp6.
size_t CountUdpSockets(int pid);

// Number of network interfaces in the current namespace whose name starts with
// the given prefix, from /proc/net/dev. The TUN device count before an EPS
// Attach is expected to be zero.
size_t CountInterfacesWithPrefix(const std::string &prefix);

// Renders one latency summary as a stable single line: count, p50, p95, p99,
// maximum and mean, all in milliseconds.
std::string DescribeLatency(const LatencySummary &summary);

} // namespace lte::enb
