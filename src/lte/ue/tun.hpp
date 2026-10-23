//
// This file is a part of UERANSIM project.
// Copyright (c) 2027 ALİ GÜNGÖR.
//
// https://github.com/aligungr/UERANSIM/
// See README, LICENSE, and CONTRIBUTING files for licensing details.
//

#pragma once

#include "types.hpp"

#include <array>
#include <cstddef>
#include <cstdint>
#include <string>
#include <vector>

namespace lte::ue
{

class TunDevice
{
  public:
    TunDevice(const TunConfig &config, const std::array<uint8_t, 4> &ipv4Address);
    ~TunDevice();

    TunDevice(const TunDevice &) = delete;
    TunDevice &operator=(const TunDevice &) = delete;

    [[nodiscard]] const std::string &name() const { return m_name; }
    bool readPacket(std::vector<uint8_t> &packet);
    bool writePacket(const uint8_t *packet, size_t size);

    // Testable descriptor helpers; production passes the non-blocking TUN fd.
    static bool ReadFromFd(int fd, std::vector<uint8_t> &packet);
    static bool WriteToFd(int fd, const uint8_t *packet, size_t size);

  private:
    int m_fd{-1};
    std::string m_name;
    std::vector<std::string> m_installedRoutes;
};

std::string Ipv4ToString(const std::array<uint8_t, 4> &address);

} // namespace lte::ue
