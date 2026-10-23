//
// This file is a part of UERANSIM project.
// Copyright (c) 2027 ALİ GÜNGÖR.
//
// https://github.com/aligungr/UERANSIM/
// See README, LICENSE, and CONTRIBUTING files for licensing details.
//

#pragma once

#include "types.hpp"

namespace lte::ue
{
Config ParseConfig(const std::string &yamlText);
Config LoadConfig(const std::string &path);
} // namespace lte::ue
