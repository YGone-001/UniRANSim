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
#include <stdexcept>
#include <string>

#include <lte/enb/app.hpp>
#include <lte/enb/config.hpp>

namespace
{

std::atomic_bool g_shutdownRequested{false};

void HandleSignal(int)
{
    g_shutdownRequested = true;
}

void PrintUsage(const char *program)
{
    std::cout << "Usage: " << program << " -c <config-file>\n"
              << "LTE eNB S1 Setup simulator (S1AP over SCTP)\n";
}

} // namespace

int main(int argc, char **argv)
{
    std::string configPath;
    for (int i = 1; i < argc; ++i)
    {
        std::string argument = argv[i];
        if ((argument == "-c" || argument == "--config") && i + 1 < argc)
            configPath = argv[++i];
        else if (argument == "-h" || argument == "--help")
        {
            PrintUsage(argv[0]);
            return 0;
        }
        else
        {
            std::cerr << "ERROR: Unknown or incomplete option '" << argument << "'\n";
            PrintUsage(argv[0]);
            return 1;
        }
    }

    if (configPath.empty())
    {
        std::cerr << "ERROR: A configuration file is required\n";
        PrintUsage(argv[0]);
        return 1;
    }

    try
    {
        auto config = lte::enb::LoadConfig(configPath);
        std::signal(SIGINT, HandleSignal);
        std::signal(SIGTERM, HandleSignal);
        return lte::enb::Run(config, g_shutdownRequested);
    }
    catch (const std::exception &e)
    {
        std::cerr << "ERROR: " << e.what() << std::endl;
        return 1;
    }
}
