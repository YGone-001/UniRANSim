//
// This file is a part of UERANSIM project.
// Copyright (c) 2027 ALİ GÜNGÖR.
//
// https://github.com/aligungr/UERANSIM/
// See README, LICENSE, and CONTRIBUTING files for licensing details.
//

#include "tun.hpp"

#include <cerrno>
#include <cstring>
#include <fcntl.h>
#include <stdexcept>
#include <sys/wait.h>
#include <unistd.h>

#include <lte/ip_packet.hpp>
#include <ue/tun/tun.hpp>

namespace lte::ue
{
namespace
{
bool RunIpRoute(const char *operation, const std::string &route, const std::string &interfaceName)
{
    const pid_t child = fork();
    if (child < 0)
        throw std::runtime_error("Unable to fork ip route command: " + std::string(std::strerror(errno)));
    if (child == 0)
    {
        execlp("ip", "ip", "route", operation, route.c_str(), "dev", interfaceName.c_str(), "proto", "static",
               static_cast<char *>(nullptr));
        _exit(127);
    }
    int status = 0;
    while (waitpid(child, &status, 0) < 0)
    {
        if (errno != EINTR)
            throw std::runtime_error("Unable to wait for ip route command");
    }
    return WIFEXITED(status) && WEXITSTATUS(status) == 0;
}
} // namespace

std::string Ipv4ToString(const std::array<uint8_t, 4> &address)
{
    return std::to_string(address[0]) + "." + std::to_string(address[1]) + "." +
           std::to_string(address[2]) + "." + std::to_string(address[3]);
}

TunDevice::TunDevice(const TunConfig &config, const std::array<uint8_t, 4> &ipv4Address)
{
    if (ipv4Address == std::array<uint8_t, 4>{})
        throw std::runtime_error("Cannot create LTE TUN with a zero IPv4 address");

    std::string error;
    m_fd = nr::ue::tun::TunAllocate(config.namePrefix.c_str(), m_name, {}, false, error);
    if (m_fd < 0)
        throw std::runtime_error("LTE TUN allocation failed: " + error);

    try
    {
        if (!nr::ue::tun::TunConfigure(m_name, Ipv4ToString(ipv4Address), "255.255.255.255", config.mtu, {}, false,
                                       false, error))
            throw std::runtime_error("LTE TUN configuration failed: " + error);
        const int flags = fcntl(m_fd, F_GETFL, 0);
        if (flags < 0 || fcntl(m_fd, F_SETFL, flags | O_NONBLOCK) < 0)
            throw std::runtime_error("Unable to make LTE TUN non-blocking");

        for (const auto &route : config.routes)
        {
            if (!RunIpRoute("add", route, m_name))
                throw std::runtime_error("Unable to install requested LTE test route " + route);
            m_installedRoutes.push_back(route);
        }
    }
    catch (...)
    {
        for (auto it = m_installedRoutes.rbegin(); it != m_installedRoutes.rend(); ++it)
        {
            try { (void)RunIpRoute("del", *it, m_name); }
            catch (...) { }
        }
        close(m_fd);
        m_fd = -1;
        throw;
    }
}

TunDevice::~TunDevice()
{
    for (auto it = m_installedRoutes.rbegin(); it != m_installedRoutes.rend(); ++it)
    {
        try { (void)RunIpRoute("del", *it, m_name); }
        catch (...) { }
    }
    if (m_fd >= 0)
        close(m_fd);
}

bool TunDevice::ReadFromFd(int fd, std::vector<uint8_t> &packet)
{
    uint8_t buffer[ip::MaximumPacketSize];
    const ssize_t count = read(fd, buffer, sizeof(buffer));
    if (count < 0)
    {
        if (errno == EAGAIN || errno == EWOULDBLOCK || errno == EINTR)
            return false;
        throw std::runtime_error("LTE TUN read failed: " + std::string(std::strerror(errno)));
    }
    if (count == 0)
        return false;
    packet.assign(buffer, buffer + count);
    return true;
}

bool TunDevice::WriteToFd(int fd, const uint8_t *packet, size_t size)
{
    if (packet == nullptr || size == 0)
        throw std::runtime_error("Cannot write an empty packet to LTE TUN");
    const ssize_t count = write(fd, packet, size);
    if (count < 0)
    {
        if (errno == EAGAIN || errno == EWOULDBLOCK || errno == EINTR)
            return false;
        throw std::runtime_error("LTE TUN write failed: " + std::string(std::strerror(errno)));
    }
    if (static_cast<size_t>(count) != size)
        throw std::runtime_error("LTE TUN completed a partial packet write");
    return true;
}

bool TunDevice::readPacket(std::vector<uint8_t> &packet)
{
    return ReadFromFd(m_fd, packet);
}

bool TunDevice::writePacket(const uint8_t *packet, size_t size)
{
    return WriteToFd(m_fd, packet, size);
}

} // namespace lte::ue
