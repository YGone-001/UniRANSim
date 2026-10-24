//
// This file is a part of UERANSIM project.
// Copyright (c) 2027 ALİ GÜNGÖR.
//
// https://github.com/aligungr/UERANSIM/
// See README, LICENSE, and CONTRIBUTING files for licensing details.
//

#include "server.hpp"

#include <cstring>
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
