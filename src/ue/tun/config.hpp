//
// This file is a part of UERANSIM project.
// Copyright (c) 2027 ALİ GÜNGÖR.
//
// https://github.com/aligungr/UERANSIM/
// See README, LICENSE, and CONTRIBUTING files for licensing details.
//

#pragma once

#include <string>

namespace nr::ue::tun
{

// Creates a TUN device named <ifPrefix><index>, or throws with the reason it could not. When
// useNamespace is set, the device is placed in a network namespace created by this very call;
// a namespace that already exists is refused and left untouched.
int AllocateTun(const std::string &ifPrefix, std::string &allocatedName, const std::string &nsName, bool useNamespace);

// Gives the device its address, MTU and, when asked, its route. Refuses a name it cannot
// verify rather than configuring whatever currently answers to it.
void ConfigureTun(const std::string &tunName, const std::string &ipAddr, const std::string &netmask, int mtu,
                  const std::string &nsName, bool useNamespace, bool configureRoute);

// Releases the namespace this invocation created for this device. A namespace somebody else
// owns is left alone, and calling this twice is harmless.
void CleanupTun(const std::string &tunName, const std::string &nsName, bool useNamespace);

} // namespace nr::ue::tun
