//
// This file is a part of UERANSIM project.
// Copyright (c) 2027 ALİ GÜNGÖR.
//
// https://github.com/aligungr/UERANSIM/
// See README, LICENSE, and CONTRIBUTING files for licensing details.
//

#include "tun.hpp"
#include "config.hpp"
#include <utils/libc_error.hpp>

namespace nr::ue::tun
{

int TunAllocate(const char *namePrefix, std::string &allocatedName, const std::string &nsName, bool useNamespace,
                std::string &error)
{
    try
    {
        // The name is returned by value, so there is no heap allocation to release on the
        // success path or on any of the throwing ones.
        return tun::AllocateTun(namePrefix != nullptr ? namePrefix : "", allocatedName, nsName, useNamespace);
    }
    catch (const LibError &e)
    {
        error = e.what();
        allocatedName.clear();
        return -1;
    }
}

bool TunConfigure(const std::string &tunName, const std::string &ipAddress, const std::string &netmask, int mtu,
                  const std::string &nsName, bool useNamespace, bool configureRouting, std::string &error)
{
    try
    {
        tun::ConfigureTun(tunName, ipAddress, netmask, mtu, nsName, useNamespace, configureRouting);
    }
    catch (const LibError &e)
    {
        error = e.what();
        return false;
    }

    return true;
}

bool TunCleanup(const std::string &tunName, const std::string &nsName, bool useNamespace, std::string &error)
{
    try
    {
        tun::CleanupTun(tunName, nsName, useNamespace);
    }
    catch (const LibError &e)
    {
        error = e.what();
        return false;
    }

    return true;
}

} // namespace nr::ue::tun
