//
// This file is a part of UERANSIM project.
// Copyright (c) 2027 ALİ GÜNGÖR.
//
// https://github.com/aligungr/UERANSIM/
// See README, LICENSE, and CONTRIBUTING files for licensing details.
//

#pragma once

#include <string>
#include <utils/network.hpp>

namespace udp
{

// The largest receive buffer a configuration may ask for. It bounds what one
// socket can be told to reserve and keeps a typo from becoming an allocation
// request. The kernel still caps the effective value at net.core.rmem_max.
constexpr int MaxConfiguredReceiveBufferBytes = 64 * 1024 * 1024;

// What a receive-buffer request actually produced.
//
// Linux doubles a requested SO_RCVBUF for its own accounting and returns the
// doubled value from getsockopt(2), so an applied request reads back as twice
// what was asked. Anything lower means the kernel capped the request at
// net.core.rmem_max, and the requested budget was therefore NOT established:
// the caller must treat that as a failure rather than as a success with a
// smaller number.
struct ReceiveBufferStatus
{
    int requestedBytes{0};
    // What getsockopt reported, which is the doubled accounting value on Linux.
    int effectiveBytes{0};
    // What the socket can actually queue, after undoing the doubling.
    int usableBytes{0};
    bool applied{false};
    // Empty when applied. Otherwise names the requested value, the effective
    // value and the kernel cap so a configuration error is actionable.
    std::string error;
};

class UdpServer
{
  private:
    std::vector<Socket> sockets;

  public:
    UdpServer();
    UdpServer(const std::string &address, uint16_t port);
    ~UdpServer();

    // Applies SO_RCVBUF to this server's sockets and verifies what the kernel
    // granted. It is only called when a configuration explicitly asked for a
    // size; an absent setting performs no system call at all and leaves the
    // socket exactly as the operating system created it.
    ReceiveBufferStatus ConfigureReceiveBuffer(int requestedBytes);

    int Receive(uint8_t *buffer, size_t bufferSize, int timeoutMs, InetAddress &outPeerAddress) const;
    void Send(const InetAddress &address, const uint8_t *buffer, size_t bufferSize) const;
    bool TrySend(const InetAddress &address, const uint8_t *buffer, size_t bufferSize) const;
    [[nodiscard]] InetAddress LocalAddress() const;
    // Read-only access to the bound descriptor, for socket observation.
    [[nodiscard]] int NativeFd() const;
};

} // namespace udp
