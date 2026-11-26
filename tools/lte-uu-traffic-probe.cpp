//
// This file is a part of UERANSIM project.
// Copyright (c) 2027 ALİ GÜNGÖR.
//
// Phase 18-F-B6-D7: application traffic probe for the production user-plane
// acceptance. It is a test tool that runs inside a network namespace and uses
// ordinary Linux UDP/TCP sockets; it never touches PDCP, RLC, GTP-U or a TUN.
//
// Modes:
//   udp-echo-server --bind <ipv4> --port <p> --result <path> [--stop <path>]
//   udp-client      --bind <ipv4> --to <ipv4> --port <p> --count <n> --size <s>
//                   --result <path> [--timeout-ms <ms>]
//   tcp-echo-server --bind <ipv4> --port <p> --result <path> [--stop <path>]
//   tcp-client      --bind <ipv4> --to <ipv4> --port <p> --bytes <n> --result <path>
//                   [--timeout-ms <ms>]
#include <algorithm>
#include <array>
#include <atomic>
#include <chrono>
#include <algorithm>
#include <cerrno>
#include <chrono>
#include <csignal>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <fstream>
#include <iostream>
#include <optional>
#include <set>
#include <sstream>
#include <string>
#include <thread>
#include <vector>

#include <arpa/inet.h>
#include <fcntl.h>
#include <netinet/in.h>
#include <poll.h>
#include <sys/socket.h>
#include <unistd.h>

namespace
{

using Clock = std::chrono::steady_clock;

std::atomic_bool g_stop{false};
void Signal(int) { g_stop = true; }

std::array<uint8_t, 4> ParseIpv4(const std::string &text)
{
    std::array<uint8_t, 4> address{};
    std::istringstream stream(text);
    std::string part;
    int index = 0;
    while (std::getline(stream, part, '.'))
    {
        if (index >= 4)
            throw std::runtime_error("invalid IPv4 address: " + text);
        const int value = std::stoi(part);
        if (value < 0 || value > 255)
            throw std::runtime_error("invalid IPv4 address: " + text);
        address[index++] = static_cast<uint8_t>(value);
    }
    if (index != 4)
        throw std::runtime_error("invalid IPv4 address: " + text);
    return address;
}

sockaddr_in ToSockaddr(const std::array<uint8_t, 4> &address, uint16_t port)
{
    sockaddr_in out{};
    out.sin_family = AF_INET;
    out.sin_port = htons(port);
    std::memcpy(&out.sin_addr, address.data(), 4);
    return out;
}

uint32_t Fnv1a(const uint8_t *data, size_t size)
{
    uint32_t hash = 2166136261U;
    for (size_t i = 0; i < size; ++i)
    {
        hash ^= data[i];
        hash *= 16777619U;
    }
    return hash;
}

uint8_t Pattern(size_t index)
{
    return static_cast<uint8_t>((index * 131U + 7U) & 0xFFU);
}

void WriteResult(const std::string &path, const std::string &text)
{
    std::ofstream out(path);
    out << text;
}

void WriteAtomically(const std::string &path, const std::string &text)
{
    const std::string temporary = path + ".tmp";
    WriteResult(temporary, text);
    std::rename(temporary.c_str(), path.c_str());
}

bool StopFileSeen(const std::string &path)
{
    return !path.empty() && std::ifstream(path).good();
}

struct UdpClientResult
{
    uint64_t sent{0};
    uint64_t received{0};
    uint64_t duplicate{0};
    uint64_t outOfOrder{0};
    uint64_t corrupt{0};
    uint64_t bytes{0};
    uint64_t minRttUs{0};
    uint64_t maxRttUs{0};
    uint64_t totalRttUs{0};
};

std::string UdpClientText(const UdpClientResult &r, const std::string &failure)
{
    std::ostringstream out;
    out << (failure.empty() ? "result=COMPLETE" : "result=FAILED") << "\n";
    if (!failure.empty())
        out << "failure=" << failure << "\n";
    out << "sent=" << r.sent << "\n";
    out << "received=" << r.received << "\n";
    out << "loss=" << (r.sent >= r.received ? r.sent - r.received : 0) << "\n";
    out << "duplicate=" << r.duplicate << "\n";
    out << "out_of_order=" << r.outOfOrder << "\n";
    out << "corrupt=" << r.corrupt << "\n";
    out << "bytes=" << r.bytes << "\n";
    out << "min_rtt_us=" << r.minRttUs << "\n";
    out << "max_rtt_us=" << r.maxRttUs << "\n";
    out << "avg_rtt_us=" << (r.received == 0 ? 0 : r.totalRttUs / r.received) << "\n";
    return out.str();
}

// --- compact SHA-256 for the TCP payload evidence -------------------------
struct Sha256
{
    uint32_t state[8];
    uint64_t length;
    uint8_t block[64];
    size_t used;

    static uint32_t Rotr(uint32_t x, uint32_t n) { return (x >> n) | (x << (32U - n)); }

    void Reset()
    {
        static const uint32_t init[8] = {0x6a09e667U, 0xbb67ae85U, 0x3c6ef372U, 0xa54ff53aU,
                                         0x510e527fU, 0x9b05688cU, 0x1f83d9abU, 0x5be0cd19U};
        std::memcpy(state, init, sizeof(init));
        length = 0;
        used = 0;
    }

    void Transform(const uint8_t *p)
    {
        static const uint32_t k[64] = {
            0x428a2f98U, 0x71374491U, 0xb5c0fbcfU, 0xe9b5dba5U, 0x3956c25bU, 0x59f111f1U, 0x923f82a4U, 0xab1c5ed5U,
            0xd807aa98U, 0x12835b01U, 0x243185beU, 0x550c7dc3U, 0x72be5d74U, 0x80deb1feU, 0x9bdc06a7U, 0xc19bf174U,
            0xe49b69c1U, 0xefbe4786U, 0x0fc19dc6U, 0x240ca1ccU, 0x2de92c6fU, 0x4a7484aaU, 0x5cb0a9dcU, 0x76f988daU,
            0x983e5152U, 0xa831c66dU, 0xb00327c8U, 0xbf597fc7U, 0xc6e00bf3U, 0xd5a79147U, 0x06ca6351U, 0x14292967U,
            0x27b70a85U, 0x2e1b2138U, 0x4d2c6dfcU, 0x53380d13U, 0x650a7354U, 0x766a0abbU, 0x81c2c92eU, 0x92722c85U,
            0xa2bfe8a1U, 0xa81a664bU, 0xc24b8b70U, 0xc76c51a3U, 0xd192e819U, 0xd6990624U, 0xf40e3585U, 0x106aa070U,
            0x19a4c116U, 0x1e376c08U, 0x2748774cU, 0x34b0bcb5U, 0x391c0cb3U, 0x4ed8aa4aU, 0x5b9cca4fU, 0x682e6ff3U,
            0x748f82eeU, 0x78a5636fU, 0x84c87814U, 0x8cc70208U, 0x90befffaU, 0xa4506cebU, 0xbef9a3f7U, 0xc67178f2U};
        uint32_t w[64];
        for (int i = 0; i < 16; ++i)
            w[i] = (static_cast<uint32_t>(p[i * 4]) << 24U) | (static_cast<uint32_t>(p[i * 4 + 1]) << 16U) |
                   (static_cast<uint32_t>(p[i * 4 + 2]) << 8U) | static_cast<uint32_t>(p[i * 4 + 3]);
        for (int i = 16; i < 64; ++i)
        {
            const uint32_t s0 = Rotr(w[i - 15], 7) ^ Rotr(w[i - 15], 18) ^ (w[i - 15] >> 3U);
            const uint32_t s1 = Rotr(w[i - 2], 17) ^ Rotr(w[i - 2], 19) ^ (w[i - 2] >> 10U);
            w[i] = w[i - 16] + s0 + w[i - 7] + s1;
        }
        uint32_t a = state[0], b = state[1], c = state[2], d = state[3];
        uint32_t e = state[4], f = state[5], g = state[6], h = state[7];
        for (int i = 0; i < 64; ++i)
        {
            const uint32_t s1 = Rotr(e, 6) ^ Rotr(e, 11) ^ Rotr(e, 25);
            const uint32_t ch = (e & f) ^ (~e & g);
            const uint32_t t1 = h + s1 + ch + k[i] + w[i];
            const uint32_t s0 = Rotr(a, 2) ^ Rotr(a, 13) ^ Rotr(a, 22);
            const uint32_t maj = (a & b) ^ (a & c) ^ (b & c);
            const uint32_t t2 = s0 + maj;
            h = g; g = f; f = e; e = d + t1; d = c; c = b; b = a; a = t1 + t2;
        }
        state[0] += a; state[1] += b; state[2] += c; state[3] += d;
        state[4] += e; state[5] += f; state[6] += g; state[7] += h;
    }

    void Update(const uint8_t *data, size_t size)
    {
        length += static_cast<uint64_t>(size) * 8U;
        while (size > 0)
        {
            const size_t take = std::min(size, sizeof(block) - used);
            std::memcpy(block + used, data, take);
            used += take;
            data += take;
            size -= take;
            if (used == sizeof(block))
            {
                Transform(block);
                used = 0;
            }
        }
    }

    void Final(uint8_t out[32])
    {
        const uint64_t bits = length;
        block[used++] = 0x80;
        if (used > 56)
        {
            std::memset(block + used, 0, 64 - used);
            Transform(block);
            used = 0;
        }
        std::memset(block + used, 0, 56 - used);
        for (int i = 0; i < 8; ++i)
            block[56 + i] = static_cast<uint8_t>((bits >> (56U - 8U * static_cast<uint32_t>(i))) & 0xFFU);
        Transform(block);
        for (int i = 0; i < 8; ++i)
        {
            out[i * 4] = static_cast<uint8_t>((state[i] >> 24U) & 0xFFU);
            out[i * 4 + 1] = static_cast<uint8_t>((state[i] >> 16U) & 0xFFU);
            out[i * 4 + 2] = static_cast<uint8_t>((state[i] >> 8U) & 0xFFU);
            out[i * 4 + 3] = static_cast<uint8_t>(state[i] & 0xFFU);
        }
    }
};

std::string DigestHex(const uint8_t *digest, size_t size)
{
    static const char *hex = "0123456789abcdef";
    std::string out;
    out.reserve(size * 2);
    for (size_t i = 0; i < size; ++i)
    {
        out.push_back(hex[digest[i] >> 4U]);
        out.push_back(hex[digest[i] & 0x0FU]);
    }
    return out;
}

std::string Sha256Hex(const uint8_t *data, size_t size)
{
    Sha256 sha;
    sha.Reset();
    sha.Update(data, size);
    uint8_t digest[32];
    sha.Final(digest);
    return DigestHex(digest, sizeof(digest));
}

int UdpClient(const std::array<uint8_t, 4> &bindAddress, const std::array<uint8_t, 4> &to, uint16_t port,
              int count, int size, const std::string &resultPath, int timeoutMs)
{
    UdpClientResult result;
    std::string failure;
    const int fd = ::socket(AF_INET, SOCK_DGRAM, 0);
    if (fd < 0)
    {
        WriteResult(resultPath, UdpClientText(result, "socket() failed"));
        return 1;
    }
    const auto local = ToSockaddr(bindAddress, 0);
    if (::bind(fd, reinterpret_cast<const sockaddr *>(&local), sizeof(local)) != 0)
    {
        WriteResult(resultPath, UdpClientText(result, "bind() failed"));
        ::close(fd);
        return 1;
    }
    const auto server = ToSockaddr(to, port);
    if (::connect(fd, reinterpret_cast<const sockaddr *>(&server), sizeof(server)) != 0)
    {
        WriteResult(resultPath, UdpClientText(result, "connect() failed"));
        ::close(fd);
        return 1;
    }

    std::set<uint32_t> seen;
    uint32_t highest = 0;
    const size_t payloadSize = size < 16 ? 16 : static_cast<size_t>(size);
    const auto start = Clock::now();
    const auto deadline = start + std::chrono::milliseconds(timeoutMs);
    std::vector<uint64_t> sentAtUs(static_cast<size_t>(count), 0);

    for (int index = 0; index < count; ++index)
    {
        std::vector<uint8_t> packet(payloadSize, 0);
        packet[0] = static_cast<uint8_t>((static_cast<uint32_t>(index) >> 24U) & 0xFFU);
        packet[1] = static_cast<uint8_t>((static_cast<uint32_t>(index) >> 16U) & 0xFFU);
        packet[2] = static_cast<uint8_t>((static_cast<uint32_t>(index) >> 8U) & 0xFFU);
        packet[3] = static_cast<uint8_t>(index & 0xFF);
        for (size_t i = 8; i < packet.size(); ++i)
            packet[i] = Pattern(i + static_cast<size_t>(index));
        const uint32_t hash = Fnv1a(packet.data() + 8, packet.size() - 8);
        packet[4] = static_cast<uint8_t>((hash >> 24U) & 0xFFU);
        packet[5] = static_cast<uint8_t>((hash >> 16U) & 0xFFU);
        packet[6] = static_cast<uint8_t>((hash >> 8U) & 0xFFU);
        packet[7] = static_cast<uint8_t>(hash & 0xFFU);
        if (::send(fd, packet.data(), packet.size(), 0) == static_cast<ssize_t>(packet.size()))
        {
            ++result.sent;
            sentAtUs[static_cast<size_t>(index)] =
                static_cast<uint64_t>(std::chrono::duration_cast<std::chrono::microseconds>(Clock::now() - start)
                                          .count());
        }
        std::this_thread::sleep_for(std::chrono::microseconds(300));
    }

    while (!g_stop && Clock::now() < deadline && result.received < static_cast<uint64_t>(count))
    {
        pollfd entry{fd, POLLIN, 0};
        const int ready = ::poll(&entry, 1, 100);
        if (ready <= 0)
            continue;
        std::vector<uint8_t> packet(payloadSize + 8, 0);
        const ssize_t length = ::recv(fd, packet.data(), packet.size(), 0);
        if (length < 8)
            continue;
        const uint32_t sequence = (static_cast<uint32_t>(packet[0]) << 24U) |
                                  (static_cast<uint32_t>(packet[1]) << 16U) |
                                  (static_cast<uint32_t>(packet[2]) << 8U) | packet[3];
        const uint32_t hash = (static_cast<uint32_t>(packet[4]) << 24U) |
                              (static_cast<uint32_t>(packet[5]) << 16U) |
                              (static_cast<uint32_t>(packet[6]) << 8U) | packet[7];
        if (static_cast<size_t>(length) != payloadSize ||
            Fnv1a(packet.data() + 8, static_cast<size_t>(length) - 8) != hash)
        {
            ++result.corrupt;
            continue;
        }
        if (seen.count(sequence) != 0)
        {
            ++result.duplicate;
            continue;
        }
        if (sequence < highest)
            ++result.outOfOrder;
        highest = std::max(highest, sequence);
        seen.insert(sequence);
        ++result.received;
        result.bytes += static_cast<uint64_t>(length);
        if (sequence < sentAtUs.size() && sentAtUs[sequence] != 0)
        {
            const auto nowUs =
                static_cast<uint64_t>(std::chrono::duration_cast<std::chrono::microseconds>(Clock::now() - start)
                                          .count());
            const uint64_t rtt = nowUs > sentAtUs[sequence] ? nowUs - sentAtUs[sequence] : 0;
            result.totalRttUs += rtt;
            if (result.minRttUs == 0 || rtt < result.minRttUs)
                result.minRttUs = rtt;
            result.maxRttUs = std::max(result.maxRttUs, rtt);
        }
    }
    if (result.received != static_cast<uint64_t>(count))
        failure = "the expected number of echoes did not arrive";
    if (result.corrupt != 0 || result.duplicate != 0 || result.outOfOrder != 0)
        failure = "duplicate, out-of-order or corrupt payloads were observed";
    WriteResult(resultPath, UdpClientText(result, failure));
    ::close(fd);
    return failure.empty() ? 0 : 1;
}

int UdpEchoServer(const std::array<uint8_t, 4> &bindAddress, uint16_t port, const std::string &resultPath,
                  const std::string &stopPath, const std::string &readyPath)
{
    const int fd = ::socket(AF_INET, SOCK_DGRAM, 0);
    if (fd < 0)
    {
        WriteResult(resultPath, "result=FAILED\nfailure=socket() failed\n");
        return 1;
    }
    const auto local = ToSockaddr(bindAddress, port);
    if (::bind(fd, reinterpret_cast<const sockaddr *>(&local), sizeof(local)) != 0)
    {
        WriteResult(resultPath, "result=FAILED\nfailure=bind() failed\n");
        ::close(fd);
        return 1;
    }
    if (!readyPath.empty())
        WriteResult(readyPath, "ready\n");
    uint64_t received = 0;
    uint64_t bytes = 0;
    uint64_t malformed = 0;
    auto last = Clock::now();
    while (!g_stop && !StopFileSeen(stopPath))
    {
        pollfd entry{fd, POLLIN, 0};
        if (::poll(&entry, 1, 100) <= 0)
            continue;
        std::array<uint8_t, 4096> buffer{};
        sockaddr_in peer{};
        socklen_t peerLength = sizeof(peer);
        const ssize_t length =
            ::recvfrom(fd, buffer.data(), buffer.size(), 0, reinterpret_cast<sockaddr *>(&peer), &peerLength);
        if (length <= 0)
            continue;
        if (static_cast<size_t>(length) < 8)
        {
            ++malformed;
            continue;
        }
        ++received;
        bytes += static_cast<uint64_t>(length);
        ::sendto(fd, buffer.data(), static_cast<size_t>(length), 0, reinterpret_cast<const sockaddr *>(&peer),
                 peerLength);
        const auto now = Clock::now();
        if (now - last >= std::chrono::milliseconds(100))
        {
            last = now;
            std::ostringstream out;
            out << "received=" << received << "\nbytes=" << bytes << "\nmalformed=" << malformed << "\n";
            WriteAtomically(resultPath, out.str());
        }
    }
    std::ostringstream out;
    out << "received=" << received << "\nbytes=" << bytes << "\nmalformed=" << malformed << "\n";
    WriteResult(resultPath, out.str());
    ::close(fd);
    return malformed == 0 ? 0 : 1;
}

int TcpEchoServer(const std::array<uint8_t, 4> &bindAddress, uint16_t port, const std::string &resultPath,
                  const std::string &readyPath)
{
    const int fd = ::socket(AF_INET, SOCK_STREAM, 0);
    if (fd < 0)
    {
        WriteResult(resultPath, "result=FAILED\nfailure=socket() failed\n");
        return 1;
    }
    int one = 1;
    ::setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &one, sizeof(one));
    const auto local = ToSockaddr(bindAddress, port);
    if (::bind(fd, reinterpret_cast<const sockaddr *>(&local), sizeof(local)) != 0 || ::listen(fd, 4) != 0)
    {
        WriteResult(resultPath, "result=FAILED\nfailure=bind/listen failed\n");
        ::close(fd);
        return 1;
    }
    std::ostringstream ready;
    ready << "bound=" << static_cast<int>(bindAddress[0]) << "." << static_cast<int>(bindAddress[1]) << "."
          << static_cast<int>(bindAddress[2]) << "." << static_cast<int>(bindAddress[3]) << ":" << port << "\n";
    WriteResult(readyPath.empty() ? resultPath : readyPath, ready.str());
    const int client = ::accept(fd, nullptr, nullptr);
    if (client < 0)
    {
        ::close(fd);
        return 1;
    }
    timeval timeout{15, 0};
    ::setsockopt(client, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout));
    uint64_t bytes = 0;
    Sha256 sha;
    sha.Reset();
    std::array<uint8_t, 16 * 1024> buffer{};
    for (;;)
    {
        const ssize_t length = ::recv(client, buffer.data(), buffer.size(), 0);
        if (length <= 0)
            break;
        sha.Update(buffer.data(), static_cast<size_t>(length));
        size_t offset = 0;
        while (offset < static_cast<size_t>(length))
        {
            const ssize_t written = ::send(client, buffer.data() + offset, static_cast<size_t>(length) - offset, 0);
            if (written <= 0)
                break;
            offset += static_cast<size_t>(written);
        }
        bytes += static_cast<uint64_t>(length);
    }
    ::close(client);
    ::close(fd);
    uint8_t digest[32];
    sha.Final(digest);
    std::ostringstream out;
    out << "bytes=" << bytes << "\nsha256=" << DigestHex(digest, sizeof(digest)) << "\n";
    WriteResult(resultPath, out.str());
    return bytes == 0 ? 1 : 0;
}

int TcpClient(const std::array<uint8_t, 4> &bindAddress, const std::array<uint8_t, 4> &to, uint16_t port,
              int totalBytes, const std::string &resultPath, int timeoutMs)
{
    const int fd = ::socket(AF_INET, SOCK_STREAM, 0);
    if (fd < 0)
    {
        WriteResult(resultPath, "result=FAILED\nfailure=socket() failed\n");
        return 1;
    }
    const auto local = ToSockaddr(bindAddress, 0);
    if (::bind(fd, reinterpret_cast<const sockaddr *>(&local), sizeof(local)) != 0)
    {
        WriteResult(resultPath, "result=FAILED\nfailure=bind() failed\n");
        ::close(fd);
        return 1;
    }
    const auto started = Clock::now();
    const int flags = ::fcntl(fd, F_GETFL, 0);
    ::fcntl(fd, F_SETFL, flags | O_NONBLOCK);
    const auto server = ToSockaddr(to, port);
    int connected = ::connect(fd, reinterpret_cast<const sockaddr *>(&server), sizeof(server));
    if (connected != 0 && errno != EINPROGRESS)
    {
        WriteResult(resultPath, "result=FAILED\nfailure=connect() failed\n");
        ::close(fd);
        return 1;
    }
    if (connected != 0)
    {
        // A bounded connect: a peer whose path silently drops SYNs must not
        // block the test for minutes.
        pollfd writable{fd, POLLOUT, 0};
        const int ready = ::poll(&writable, 1, timeoutMs);
        int error = 0;
        socklen_t length = sizeof(error);
        if (ready <= 0)
        {
            WriteResult(resultPath, "result=FAILED\nfailure=connect() timeout\n");
            ::close(fd);
            return 1;
        }
        if (::getsockopt(fd, SOL_SOCKET, SO_ERROR, &error, &length) != 0 || error != 0)
        {
            WriteResult(resultPath, "result=FAILED\nfailure=connect() failed\n");
            ::close(fd);
            return 1;
        }
    }

    std::vector<uint8_t> payload(static_cast<size_t>(totalBytes));
    for (size_t i = 0; i < payload.size(); ++i)
        payload[i] = Pattern(i);
    const std::string shaSent = Sha256Hex(payload.data(), payload.size());

    // Send and receive concurrently. Sending the whole payload before the first
    // read deadlocks an echo endpoint as soon as both socket buffers fill; the
    // poll loop below keeps both directions moving and handles partial I/O.
    std::vector<uint8_t> received(payload.size());
    size_t sent = 0;
    size_t got = 0;
    bool writeClosed = false;
    std::string failure;
    const auto deadline = started + std::chrono::milliseconds(timeoutMs);
    while (sent < payload.size() || got < payload.size())
    {
        if (Clock::now() >= deadline)
        {
            failure = "timeout before the complete echo";
            break;
        }
        pollfd entry{fd, 0, 0};
        if (sent < payload.size())
            entry.events |= POLLOUT;
        if (got < payload.size())
            entry.events |= POLLIN;
        const int ready = ::poll(&entry, 1, 50);
        if (ready < 0)
        {
            if (errno == EINTR)
                continue;
            failure = "poll() failed";
            break;
        }
        if (ready == 0)
            continue;
        if ((entry.revents & POLLOUT) != 0 && sent < payload.size())
        {
            const size_t chunk = std::min<size_t>(16 * 1024, payload.size() - sent);
            const ssize_t written = ::send(fd, payload.data() + sent, chunk, MSG_NOSIGNAL);
            if (written > 0)
                sent += static_cast<size_t>(written);
            else if (written < 0 && errno != EAGAIN && errno != EWOULDBLOCK)
            {
                failure = "send() failed";
                break;
            }
        }
        if (sent == payload.size() && !writeClosed)
        {
            ::shutdown(fd, SHUT_WR);
            writeClosed = true;
        }
        if ((entry.revents & POLLIN) != 0 && got < payload.size())
        {
            const size_t chunk = std::min<size_t>(16 * 1024, payload.size() - got);
            const ssize_t length = ::recv(fd, received.data() + got, chunk, 0);
            if (length > 0)
                got += static_cast<size_t>(length);
            else if (length == 0)
            {
                failure = "the echo closed before the complete payload";
                break;
            }
            else if (errno != EAGAIN && errno != EWOULDBLOCK)
            {
                failure = "recv() failed";
                break;
            }
        }
    }
    const auto durationUs =
        std::chrono::duration_cast<std::chrono::microseconds>(Clock::now() - started).count();
    const std::string shaReceived = Sha256Hex(received.data(), got);
    if (failure.empty() &&
        (sent != payload.size() || got != payload.size() || shaReceived != shaSent))
        failure = "the TCP echo did not return the complete payload with the same hash";

    std::ostringstream out;
    out << (failure.empty() ? "result=COMPLETE" : "result=FAILED") << "\n";
    if (!failure.empty())
        out << "failure=" << failure << "\n";
    out << "sent_bytes=" << sent << "\n";
    out << "received_bytes=" << got << "\n";
    out << "expected_hash=" << shaSent << "\n";
    out << "actual_hash=" << shaReceived << "\n";
    out << "sha256_sent=" << shaSent << "\n";
    out << "sha256_received=" << shaReceived << "\n";
    out << "duration_ms=" << (durationUs / 1000) << "\n";
    if (durationUs > 0)
        out << "goodput_mbps=" << (static_cast<double>(got) * 8.0 / static_cast<double>(durationUs)) << "\n";
    WriteResult(resultPath, out.str());
    ::close(fd);
    return failure.empty() ? 0 : 1;
}


} // namespace

int main(int argc, char **argv)
{
    if (argc < 2)
    {
        std::cerr << "usage: " << argv[0] << " <mode> [options]" << std::endl;
        return 1;
    }
    const std::string mode = argv[1];
    std::string bindText;
    std::string toText;
    std::string resultPath;
    std::string stopPath;
    std::string readyPath;
    uint16_t port = 0;
    int count = 0;
    int size = 64;
    int totalBytes = 0;
    int timeoutMs = 5000;
    try
    {
        for (int i = 2; i < argc; ++i)
        {
            const std::string arg = argv[i];
            auto next = [&]() -> std::string {
                if (i + 1 >= argc)
                    throw std::runtime_error("missing value for " + arg);
                return argv[++i];
            };
            if (arg == "--bind")
                bindText = next();
            else if (arg == "--to")
                toText = next();
            else if (arg == "--port")
                port = static_cast<uint16_t>(std::stoi(next()));
            else if (arg == "--result")
                resultPath = next();
            else if (arg == "--stop")
                stopPath = next();
            else if (arg == "--ready")
                readyPath = next();
            else if (arg == "--count")
                count = std::stoi(next());
            else if (arg == "--size")
                size = std::stoi(next());
            else if (arg == "--bytes")
                totalBytes = std::stoi(next());
            else if (arg == "--timeout-ms")
                timeoutMs = std::stoi(next());
            else
                throw std::runtime_error("unknown argument " + arg);
        }
        if (mode == "sha256-selftest")
        {
            const auto abc = Sha256Hex(reinterpret_cast<const uint8_t *>("abc"), 3);
            const bool ok = abc == "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad";
            std::cout << "sha256(abc)=" << abc << (ok ? " OK" : " MISMATCH") << std::endl;
            return ok ? 0 : 1;
        }
        if (bindText.empty() || resultPath.empty())
            throw std::runtime_error("--bind and --result are required");
        std::signal(SIGINT, Signal);
        std::signal(SIGTERM, Signal);
        const auto bindAddress = ParseIpv4(bindText);
        if (mode == "udp-echo-server")
            return UdpEchoServer(bindAddress, port, resultPath, stopPath, readyPath);
        if (mode == "udp-client")
            return UdpClient(bindAddress, ParseIpv4(toText), port, count, size, resultPath, timeoutMs);
        if (mode == "tcp-echo-server")
            return TcpEchoServer(bindAddress, port, resultPath, readyPath);
        if (mode == "tcp-client")
            return TcpClient(bindAddress, ParseIpv4(toText), port, totalBytes, resultPath, timeoutMs);
        throw std::runtime_error("unknown mode " + mode);
    }
    catch (const std::exception &e)
    {
        WriteResult(resultPath, std::string("result=FAILED\nfailure=") + e.what() + "\n");
        std::cerr << "lte-uu-traffic-probe: " << e.what() << std::endl;
        return 1;
    }
}
