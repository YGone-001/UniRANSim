//
// This file is a part of UERANSIM project.
// Copyright (c) 2027 ALİ GÜNGÖR.
//
// https://github.com/aligungr/UERANSIM/
// See README, LICENSE, and CONTRIBUTING files for licensing details.
//

#include "runtime_metrics.hpp"

#include <algorithm>
#include <cerrno>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <filesystem>
#include <fstream>
#include <set>
#include <sstream>
#include <string>
#include <unistd.h>

#include <sys/socket.h>

namespace lte::enb
{
namespace
{

bool ReadKeyedKilobytes(const std::string &path, const std::string &key, uint64_t &out)
{
    std::ifstream in(path);
    if (!in)
        return false;
    std::string line;
    while (std::getline(in, line))
    {
        if (line.rfind(key, 0) != 0)
            continue;
        // The value follows the colon, in kB for status and meminfo.
        const auto colon = line.find(':');
        if (colon == std::string::npos)
            return false;
        std::istringstream values(line.substr(colon + 1));
        uint64_t kilobytes = 0;
        if (!(values >> kilobytes))
            return false;
        out = kilobytes * 1024ULL;
        return true;
    }
    return false;
}

// Reads smaps_rollup for PSS and private bytes. The file is optional: a kernel
// without it, or a process the caller may not inspect, leaves the values at
// zero and sharedPagesResolved false.
bool ReadSmapsRollup(const std::string &path, uint64_t &pss, uint64_t &privateBytes)
{
    std::ifstream in(path);
    if (!in)
        return false;
    std::string line;
    bool havePss = false;
    uint64_t privateClean = 0;
    uint64_t privateDirty = 0;
    bool haveClean = false;
    bool haveDirty = false;
    while (std::getline(in, line))
    {
        const auto colon = line.find(':');
        if (colon == std::string::npos)
            continue;
        std::istringstream values(line.substr(colon + 1));
        uint64_t kilobytes = 0;
        if (!(values >> kilobytes))
            continue;
        if (line.rfind("Pss:", 0) == 0)
        {
            pss = kilobytes * 1024ULL;
            havePss = true;
        }
        else if (line.rfind("Private_Clean:", 0) == 0)
        {
            privateClean = kilobytes * 1024ULL;
            haveClean = true;
        }
        else if (line.rfind("Private_Dirty:", 0) == 0)
        {
            privateDirty = kilobytes * 1024ULL;
            haveDirty = true;
        }
    }
    privateBytes = privateClean + privateDirty;
    return havePss && haveClean && haveDirty;
}

std::string PathFor(int pid, const char *leaf)
{
    return "/proc/" + std::to_string(pid) + "/" + leaf;
}

bool ParseStatCpuTime(const std::string &path, uint64_t &micros)
{
    std::ifstream in(path);
    if (!in)
        return false;
    std::string line;
    if (!std::getline(in, line))
        return false;
    // The comm field is parenthesised and may itself contain spaces, so tokenise
    // from the last ')' and read fields 14 and 15 (utime and stime) there.
    const auto close = line.rfind(')');
    if (close == std::string::npos)
        return false;
    std::istringstream rest(line.substr(close + 1));
    uint64_t utime = 0;
    uint64_t stime = 0;
    for (int field = 3; field <= 15; ++field)
    {
        uint64_t value = 0;
        if (!(rest >> value))
            return false;
        if (field == 14)
            utime = value;
        else if (field == 15)
            stime = value;
    }
    const long ticks = sysconf(_SC_CLK_TCK);
    if (ticks <= 0)
        return false;
    micros = (utime + stime) * 1000000ULL / static_cast<uint64_t>(ticks);
    return true;
}

std::set<uint64_t> ReadUdpInodes(const char *path)
{
    std::set<uint64_t> inodes;
    std::ifstream in(path);
    if (!in)
        return inodes;
    std::string line;
    std::getline(in, line); // header
    while (std::getline(in, line))
    {
        std::istringstream fields(line);
        std::string sl;
        std::string local;
        std::string remote;
        std::string state;
        std::string queues;
        std::string timer;
        std::string retransmits;
        std::string uid;
        std::string timeout;
        std::string inode;
        if (!(fields >> sl >> local >> remote >> state >> queues >> timer >> retransmits >> uid >> timeout >> inode))
            continue;
        try
        {
            inodes.insert(std::stoull(inode));
        }
        catch (const std::exception &)
        {
        }
    }
    return inodes;
}

UdpSocketAccounting ReadUdpAccountingPath(const char *path, uint16_t localPort)
{
    UdpSocketAccounting accounting;
    std::ifstream in(path);
    if (!in)
        return accounting;
    std::string line;
    std::getline(in, line); // header
    while (std::getline(in, line))
    {
        std::istringstream fields(line);
        std::string sl;
        std::string local;
        std::string remote;
        std::string state;
        std::string queues;
        std::string timer;
        std::string retransmits;
        std::string uid;
        std::string timeout;
        std::string inode;
        std::string ref;
        std::string pointer;
        std::string drops;
        if (!(fields >> sl >> local >> remote >> state >> queues >> timer >> retransmits >> uid >> timeout >> inode >> ref >>
              pointer >> drops))
            continue;
        const auto colon = local.find(':');
        if (colon == std::string::npos)
            continue;
        uint16_t port = 0;
        try
        {
            port = static_cast<uint16_t>(std::stoul(local.substr(colon + 1), nullptr, 16));
        }
        catch (const std::exception &)
        {
            continue;
        }
        if (port != localPort)
            continue;
        accounting.found = true;
        try
        {
            accounting.drops = std::stoull(drops);
        }
        catch (const std::exception &)
        {
        }
        const auto queueColon = queues.find(':');
        if (queueColon != std::string::npos)
        {
            try
            {
                accounting.receiveQueueBytes = std::stoull(queues.substr(queueColon + 1), nullptr, 16);
            }
            catch (const std::exception &)
            {
            }
        }
        return accounting;
    }
    return accounting;
}

} // namespace

MemoryAttribution ReadProcessMemory(int pid)
{
    MemoryAttribution memory;
    if (pid <= 0)
        return memory;
    const std::string status = PathFor(pid, "status");
    memory.peakObserved = ReadKeyedKilobytes(status, "VmHWM:", memory.peakRssBytes);
    if (!ReadKeyedKilobytes(status, "VmRSS:", memory.currentRssBytes))
        return {};
    uint64_t pss = 0;
    uint64_t privateBytes = 0;
    memory.sharedPagesResolved = ReadSmapsRollup(PathFor(pid, "smaps_rollup"), pss, privateBytes);
    memory.pssBytes = pss;
    memory.privateBytes = privateBytes;
    return memory;
}

MemoryAttribution ReadSelfMemory()
{
    return ReadProcessMemory(static_cast<int>(getpid()));
}

uint64_t HostPageSizeBytes()
{
    const long pageSize = sysconf(_SC_PAGESIZE);
    return pageSize > 0 ? static_cast<uint64_t>(pageSize) : 0;
}

uint64_t ReadAvailableMemoryBytes()
{
    uint64_t available = 0;
    if (!ReadKeyedKilobytes("/proc/meminfo", "MemAvailable:", available))
        return 0;
    return available;
}

LatencySummary SummarizeLatencies(std::vector<double> samplesMs)
{
    LatencySummary summary;
    summary.count = samplesMs.size();
    if (samplesMs.empty())
        return summary;
    std::sort(samplesMs.begin(), samplesMs.end());
    // Nearest rank: the smallest observation whose rank covers the percentile,
    // i.e. index ceil(p * n) - 1. No interpolation between observations.
    const auto rank = [&samplesMs](double percentile) {
        const double scaled = percentile * static_cast<double>(samplesMs.size());
        size_t index = static_cast<size_t>(scaled);
        if (scaled > static_cast<double>(index))
            ++index;
        if (index == 0)
            index = 1;
        return samplesMs[index - 1];
    };
    summary.p50 = rank(0.50);
    summary.p95 = rank(0.95);
    summary.p99 = rank(0.99);
    summary.maximum = samplesMs.back();
    double sum = 0.0;
    for (const double value : samplesMs)
        sum += value;
    summary.mean = sum / static_cast<double>(samplesMs.size());
    return summary;
}

SizeSummary SummarizeSizes(std::vector<uint64_t> samplesBytes)
{
    SizeSummary summary;
    summary.count = samplesBytes.size();
    if (samplesBytes.empty())
        return summary;
    std::sort(samplesBytes.begin(), samplesBytes.end());
    const auto rank = [&samplesBytes](double percentile) {
        const double scaled = percentile * static_cast<double>(samplesBytes.size());
        size_t index = static_cast<size_t>(scaled);
        if (scaled > static_cast<double>(index))
            ++index;
        if (index == 0)
            index = 1;
        return samplesBytes[index - 1];
    };
    summary.p50 = rank(0.50);
    summary.p95 = rank(0.95);
    summary.p99 = rank(0.99);
    summary.maximum = samplesBytes.back();
    double sum = 0.0;
    for (const uint64_t value : samplesBytes)
        sum += static_cast<double>(value);
    summary.mean = sum / static_cast<double>(samplesBytes.size());
    return summary;
}

UdpSocketAccounting ReadUdpSocketAccounting(uint16_t localPort)
{
    return ReadUdpAccountingPath("/proc/net/udp", localPort);
}

UdpSocketAccounting ReadUdp6SocketAccounting(uint16_t localPort)
{
    return ReadUdpAccountingPath("/proc/net/udp6", localPort);
}

int ReadSocketReceiveBuffer(int fd)
{
    if (fd < 0)
        return -1;
    int value = 0;
    socklen_t length = sizeof(value);
    if (getsockopt(fd, SOL_SOCKET, SO_RCVBUF, &value, &length) != 0)
        return -1;
    return value;
}

size_t CountOpenFileDescriptors(int pid)
{
    if (pid <= 0)
        return 0;
    std::error_code error;
    const auto directory = "/proc/" + std::to_string(pid) + "/fd";
    size_t count = 0;
    for (const auto &entry : std::filesystem::directory_iterator(directory, error))
    {
        (void)entry;
        ++count;
    }
    return error ? 0 : count;
}

size_t CountThreads(int pid)
{
    if (pid <= 0)
        return 0;
    std::ifstream in(PathFor(pid, "status"));
    if (!in)
        return 0;
    std::string line;
    while (std::getline(in, line))
    {
        if (line.rfind("Threads:", 0) != 0)
            continue;
        std::istringstream values(line.substr(8));
        size_t threads = 0;
        if (values >> threads)
            return threads;
    }
    return 0;
}

uint64_t ReadProcessCpuTimeMicros(int pid)
{
    if (pid <= 0)
        return 0;
    uint64_t micros = 0;
    if (!ParseStatCpuTime(PathFor(pid, "stat"), micros))
        return 0;
    return micros;
}

size_t CountUdpSockets(int pid)
{
    if (pid <= 0)
        return 0;
    const auto udp4 = ReadUdpInodes("/proc/net/udp");
    const auto udp6 = ReadUdpInodes("/proc/net/udp6");
    std::error_code error;
    const auto directory = "/proc/" + std::to_string(pid) + "/fd";
    size_t count = 0;
    for (const auto &entry : std::filesystem::directory_iterator(directory, error))
    {
        std::error_code linkError;
        const auto target = std::filesystem::read_symlink(entry.path(), linkError);
        if (linkError)
            continue;
        const std::string text = target.string();
        constexpr const char *prefix = "socket:[";
        if (text.rfind(prefix, 0) != 0)
            continue;
        const auto close = text.find(']');
        if (close == std::string::npos)
            continue;
        uint64_t inode = 0;
        try
        {
            inode = std::stoull(text.substr(std::strlen(prefix), close - std::strlen(prefix)));
        }
        catch (const std::exception &)
        {
            continue;
        }
        if (udp4.count(inode) != 0 || udp6.count(inode) != 0)
            ++count;
    }
    return error ? 0 : count;
}

size_t CountInterfacesWithPrefix(const std::string &prefix)
{
    std::ifstream in("/proc/net/dev");
    if (!in)
        return 0;
    std::string line;
    std::getline(in, line);
    std::getline(in, line);
    size_t count = 0;
    while (std::getline(in, line))
    {
        const auto colon = line.find(':');
        if (colon == std::string::npos)
            continue;
        std::string name = line.substr(0, colon);
        // The interface name is left padded in the procfs layout.
        const auto first = name.find_first_not_of(" \t");
        if (first == std::string::npos)
            continue;
        name = name.substr(first);
        if (name.rfind(prefix, 0) == 0 && name.size() > prefix.size())
            ++count;
    }
    return count;
}

std::string DescribeLatency(const LatencySummary &summary)
{
    std::ostringstream out;
    out << "count=" << summary.count << " p50_ms=" << summary.p50 << " p95_ms=" << summary.p95
        << " p99_ms=" << summary.p99 << " max_ms=" << summary.maximum << " mean_ms=" << summary.mean;
    return out.str();
}

} // namespace lte::enb
