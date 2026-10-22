//
// This file is a part of UERANSIM project.
// Copyright (c) 2027 ALİ GÜNGÖR.
//
// https://github.com/aligungr/UERANSIM/
// See README, LICENSE, and CONTRIBUTING files for licensing details.
//

#pragma once

#include "types.hpp"

#include <atomic>

namespace lte::enb
{

int Run(const EnbConfig &config, const std::atomic_bool &shutdownRequested);

} // namespace lte::enb
