//
// This file is a part of UERANSIM project.
// Copyright (c) 2027 ALİ GÜNGÖR.
//
// https://github.com/aligungr/UERANSIM/
// See README, LICENSE, and CONTRIBUTING files for licensing details.
//

// A stand-in for the host, so that the shared TUN code can be driven through the dangerous
// situations it has to survive — an existing namespace, a replaced namespace, a failed
// creation, an unsafe name — without any of them being real. Every process the code would
// start is recorded instead of run, namespace identities are invented, and TUN devices are
// ordinary file descriptors that can be counted and closed. Nothing here reaches a shell, a
// real device or a real namespace.

#pragma once

#include <dirent.h>
#include <fcntl.h>
#include <unistd.h>

#include <functional>
#include <map>
#include <set>
#include <string>
#include <utility>
#include <vector>

#include <ue/tun/env.hpp>
#include <ue/tun/ownership.hpp>

namespace ue_tun_test
{

using nr::ue::tun::CommandArgs;
using nr::ue::tun::CommandResult;
using nr::ue::tun::NamespaceIdentity;
using nr::ue::tun::NamespacePresence;
using nr::ue::tun::NamespaceState;
using nr::ue::tun::TunEnvironment;

class FakeHost
{
  public:
    struct FakeNamespace
    {
        NamespacePresence presence{NamespacePresence::Present};
        NamespaceIdentity identity{};
        // What the namespace holds. Recorded only to prove that it is never consulted: a
        // namespace with nothing but loopback is not more disposable than any other.
        bool onlyLoopback{true};
    };

    FakeHost()
    {
        nr::ue::tun::ClearNamespaceRecordsForTesting();
        nr::ue::tun::SetTunEnvironmentForTesting(Env());
    }
    ~FakeHost()
    {
        nr::ue::tun::ClearNamespaceRecordsForTesting();
        nr::ue::tun::ResetTunEnvironmentForTesting();
    }
    FakeHost(const FakeHost &) = delete;
    FakeHost &operator=(const FakeHost &) = delete;

    // ---- state a test sets up ----

    std::set<std::string> interfaces;  // the interface names enumeration reports
    bool enumerationFails{false};      // enumeration reports a failure instead of names
    std::map<std::string, FakeNamespace> namespaces;
    bool namespaceStateUnreadable{false};  // every namespace reports 'Unknown'

    // ---- what the code under test did ----

    std::vector<CommandArgs> commands;
    std::vector<std::string> createdDevices;
    bool deviceCreationFails{false};

    // How the fake commands answer. A status of 0 is a success, anything else is a failure,
    // and 'commandFailsToStart' models a process that could not be run at all.
    int commandStatus{0};
    bool commandFailsToStart{false};
    std::string commandOutput;
    // Optional per-command answer. Return true to answer this command and stop there.
    std::function<bool(const CommandArgs &, CommandResult &)> onCommand;

    // ---- helpers ----

    // A namespace that exists, with its own identity.
    void AddNamespace(const std::string &name, uint64_t inode, bool onlyLoopback = true)
    {
        FakeNamespace ns;
        ns.presence = NamespacePresence::Present;
        ns.identity.known = true;
        ns.identity.device = 4;
        ns.identity.inode = inode;
        ns.onlyLoopback = onlyLoopback;
        namespaces[name] = ns;
    }

    [[nodiscard]] std::vector<CommandArgs> DeleteCommands() const
    {
        std::vector<CommandArgs> found;
        for (const auto &args : commands)
        {
            if (args.size() >= 3 && args[0] == "ip" && args[1] == "netns" && args[2] == "delete")
                found.push_back(args);
        }
        return found;
    }

    [[nodiscard]] int DeleteCount() const { return static_cast<int>(DeleteCommands().size()); }

    [[nodiscard]] std::vector<CommandArgs> CommandsNamed(const std::string &verb) const
    {
        std::vector<CommandArgs> found;
        for (const auto &args : commands)
        {
            for (const auto &arg : args)
            {
                if (arg == verb)
                {
                    found.push_back(args);
                    break;
                }
            }
        }
        return found;
    }

    // How many descriptors this process has open. Comparing the count before and after a
    // rejected call is what shows that nothing was left open.
    static int OpenFdCount()
    {
        DIR *dir = opendir("/proc/self/fd");
        if (dir == nullptr)
            return -1;
        int count = 0;
        while (readdir(dir) != nullptr)
            ++count;
        closedir(dir);
        return count;
    }

  private:
    TunEnvironment Env()
    {
        TunEnvironment env;

        env.enumerateInterfaces = [this](std::set<std::string> &names) {
            if (enumerationFails)
                return false;
            names = interfaces;
            return true;
        };

        env.readNamespaceState = [this](const std::string &name) {
            NamespaceState state;
            if (namespaceStateUnreadable)
            {
                state.presence = NamespacePresence::Unknown;
                return state;
            }
            const auto it = namespaces.find(name);
            if (it == namespaces.end())
            {
                state.presence = NamespacePresence::Absent;
                return state;
            }
            state.presence = it->second.presence;
            state.identity = it->second.identity;
            return state;
        };

        env.runCommand = [this](const CommandArgs &args) {
            commands.push_back(args);
            CommandResult result;
            if (onCommand && onCommand(args, result))
                return result;
            result.started = !commandFailsToStart;
            result.status = commandFailsToStart ? -1 : commandStatus;
            result.output = commandOutput;
            return result;
        };

        env.createTunDevice = [this](const std::string &name) {
            if (deviceCreationFails)
                return -1;
            createdDevices.push_back(name);
            // A real descriptor is handed out so that a leak shows up in the open count.
            return open("/dev/null", O_RDWR);
        };

        return env;
    }
};

} // namespace ue_tun_test
