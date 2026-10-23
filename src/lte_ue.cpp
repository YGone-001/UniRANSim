//
// This file is a part of UERANSIM project.
// Copyright (c) 2027 ALİ GÜNGÖR.
//
// https://github.com/aligungr/UERANSIM/
// See README, LICENSE, and CONTRIBUTING files for licensing details.
//

#include <atomic>
#include <csignal>
#include <iostream>

#include <lte/ue/app.hpp>
#include <lte/ue/config.hpp>

namespace
{
std::atomic_bool g_shutdown{false};
void Signal(int) { g_shutdown = true; }
}

int main(int argc, char **argv)
{
    if (argc != 3 || (std::string(argv[1]) != "-c" && std::string(argv[1]) != "--config"))
    {
        std::cerr << "Usage: " << argv[0] << " -c <config-file>\n";
        return 1;
    }
    try
    {
        std::signal(SIGINT, Signal);
        std::signal(SIGTERM, Signal);
        return lte::ue::Run(lte::ue::LoadConfig(argv[2]), g_shutdown);
    }
    catch (const std::exception &e) { std::cerr << "ERROR: " << e.what() << std::endl; return 1; }
}
