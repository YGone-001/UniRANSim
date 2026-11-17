//
// This file is a part of UERANSIM project.
// Copyright (c) 2027 ALİ GÜNGÖR.
//
// https://github.com/aligungr/UERANSIM/
// See README, LICENSE, and CONTRIBUTING files for licensing details.
//

#include "server.hpp"

#include <cerrno>
#include <cstring>
#include <sys/socket.h>

#include <utils/common.hpp>

namespace udp
{

UdpServer::UdpServer() : sockets{Socket::CreateUdp4(), Socket::CreateUdp6()}
{
}

UdpServer::UdpServer(const std::string &address, uint16_t port) : sockets{Socket::CreateAndBindUdp({address, port})}
{
}

int UdpServer::Receive(uint8_t *buffer, size_t bufferSize, int timeoutMs, InetAddress &outPeerAddress) const
{
    // Socket::Select uses a zero timeout to mean "wait indefinitely".  UDP
    // users need zero to be a genuine non-blocking poll; in particular, the
    // LTE eNB must check S1-U without stopping radio-link processing while no
    // downlink packet is available.
    if (timeoutMs == 0)
    {
        for (const auto &socket : sockets)
        {
            if (!socket.hasFd())
                continue;
            const int received = socket.receive(buffer, bufferSize, 0, outPeerAddress);
            if (received > 0)
                return received;
        }
        return 0;
    }

    auto socket = Socket::Select(sockets, {}, timeoutMs);
    if (!socket.hasFd())
        return 0;
    return socket.receive(buffer, bufferSize, timeoutMs, outPeerAddress);
}

ReceiveBufferStatus UdpServer::ConfigureReceiveBuffer(int requestedBytes)
{
    ReceiveBufferStatus status;
    status.requestedBytes = requestedBytes;
    if (requestedBytes <= 0)
    {
        status.error = "a receive buffer request must be positive";
        return status;
    }
    if (requestedBytes > MaxConfiguredReceiveBufferBytes)
    {
        status.error = "a receive buffer request of " + std::to_string(requestedBytes) +
                       " bytes exceeds the supported maximum of " +
                       std::to_string(MaxConfiguredReceiveBufferBytes) + " bytes";
        return status;
    }

    bool configured = false;
    for (const auto &socket : sockets)
    {
        if (!socket.hasFd())
            continue;
        configured = true;
        const int fd = socket.getFd();
        if (::setsockopt(fd, SOL_SOCKET, SO_RCVBUF, &requestedBytes, sizeof(requestedBytes)) != 0)
        {
            status.error = "setsockopt(SO_RCVBUF, " + std::to_string(requestedBytes) +
                           ") failed: " + std::strerror(errno);
            return status;
        }
        int effective = 0;
        socklen_t length = sizeof(effective);
        if (::getsockopt(fd, SOL_SOCKET, SO_RCVBUF, &effective, &length) != 0)
        {
            status.error = std::string("getsockopt(SO_RCVBUF) failed: ") + std::strerror(errno);
            return status;
        }
        status.effectiveBytes = effective;
        // Linux stores the requested value capped at net.core.rmem_max and
        // returns twice that, which is where the factor two comes from.
        status.usableBytes = effective / 2;
        status.applied = static_cast<long long>(effective) >= 2LL * requestedBytes;
        if (!status.applied)
        {
            status.error = "SO_RCVBUF request of " + std::to_string(requestedBytes) + " bytes was capped: effective " +
                           std::to_string(effective) + " bytes (" + std::to_string(status.usableBytes) +
                           " bytes usable) means net.core.rmem_max is lower than the request";
            return status;
        }
    }
    if (!configured)
    {
        status.error = "the socket has no open descriptor to configure";
        return status;
    }
    return status;
}

void UdpServer::Send(const InetAddress &address, const uint8_t *buffer, size_t bufferSize) const
{
    (void)TrySend(address, buffer, bufferSize);
}

bool UdpServer::TrySend(const InetAddress &address, const uint8_t *buffer, size_t bufferSize) const
{
    int version = address.getIpVersion();
    if (version != 4 && version != 6)
        throw std::runtime_error{"UdpServer::Send failure: Invalid IP version"};

    for (const Socket &s : sockets)
    {
        if (s.hasFd() && s.getIpVersion() == version)
        {
            return s.trySend(address, buffer, bufferSize);
        }
    }

    throw std::runtime_error{"UdpServer::Send failure: No IP socket found"};
}

int UdpServer::NativeFd() const
{
    for (const auto &s : sockets)
        if (s.hasFd())
            return s.getFd();
    return -1;
}

InetAddress UdpServer::LocalAddress() const
{
    for (const Socket &s : sockets)
        if (s.hasFd())
            return s.getAddress();
    return {};
}

UdpServer::~UdpServer()
{
    for (auto &s : sockets)
        s.close();
}

} // namespace udp
