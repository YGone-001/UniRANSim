//
// This file is a part of UERANSIM project.
// Copyright (c) 2027 ALİ GÜNGÖR.
//
// https://github.com/aligungr/UERANSIM/
// See README, LICENSE, and CONTRIBUTING files for licensing details.
//

#pragma once

#include <cstdint>
#include <functional>
#include <set>
#include <string>
#include <vector>

namespace nr::ue::tun
{

// A process invocation as an argument vector. The shared TUN code never builds a shell
// command line, so a namespace or interface name is always exactly one argument and can
// never change which program runs or how many arguments it sees.
using CommandArgs = std::vector<std::string>;

struct CommandResult
{
    bool started{false};  // false when the process could not be run at all
    int status{-1};       // the exit status of a process that did run
    std::string output;   // what the command wrote to stdout
};

// Whether a namespace exists at all. 'Unknown' is deliberately distinct from 'Absent': a
// namespace that cannot be inspected is treated as somebody else's rather than as free space.
enum class NamespacePresence
{
    Absent,
    Present,
    Unknown,
};

// The identity of one namespace instance. Linux gives every network namespace its own
// device and inode pair, so a namespace that is deleted and recreated under the same name
// gets a different identity here. An identity that cannot be read is never treated as a
// match, which is what makes a stale name harmless.
struct NamespaceIdentity
{
    bool known{false};
    uint64_t device{0};
    uint64_t inode{0};

    [[nodiscard]] bool Matches(const NamespaceIdentity &other) const
    {
        return known && other.known && device == other.device && inode == other.inode;
    }
};

struct NamespaceState
{
    NamespacePresence presence{NamespacePresence::Unknown};
    NamespaceIdentity identity{};
};

// Everything the shared TUN implementation asks of the outside world. Production fills this
// in with the real system calls; tests replace it to drive name selection, namespace
// ownership and cleanup decisions deterministically, without root, without a shell and
// without touching any real device or namespace.
struct TunEnvironment
{
    // Fills in the interface names currently visible. Returns false when enumeration fails.
    std::function<bool(std::set<std::string> &names)> enumerateInterfaces;
    // The state of one namespace name at this moment.
    std::function<NamespaceState(const std::string &name)> readNamespaceState;
    // Runs an argument vector without a shell.
    std::function<CommandResult(const CommandArgs &args)> runCommand;
    // Creates a TUN device with exactly this interface name and returns its file descriptor,
    // or -1 when the device could not be created.
    std::function<int(const std::string &name)> createTunDevice;
};

// The environment the shared TUN code is running against.
const TunEnvironment &TunEnv();

// Test seam. Installs a replacement environment; any slot left empty keeps its real
// implementation. Tests only.
void SetTunEnvironmentForTesting(const TunEnvironment &env);

// Test seam. Restores the real environment. Tests only.
void ResetTunEnvironmentForTesting();

} // namespace nr::ue::tun
