//
// This file is a part of UERANSIM project.
// Copyright (c) 2027 ALİ GÜNGÖR.
//
// https://github.com/aligungr/UERANSIM/
// See README, LICENSE, and CONTRIBUTING files for licensing details.
//

#include "env.hpp"

#include "naming.hpp"

#include <cerrno>
#include <cstring>
#include <fcntl.h>
#include <ifaddrs.h>
#include <linux/if_tun.h>
#include <net/if.h>
#include <sys/ioctl.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>

namespace nr::ue::tun
{
namespace
{

// A named network namespace is a bind mount under /var/run/netns. The object it exposes is an
// nsfs file whose device and inode identify the namespace instance itself, not just its name.
constexpr const char *NamespaceDir = "/var/run/netns/";

bool RealEnumerateInterfaces(std::set<std::string> &names)
{
    struct ifaddrs *addrs = nullptr;
    if (getifaddrs(&addrs) != 0)
        return false;
    // Nothing is allocated here, so the list is released on the only path out.
    for (struct ifaddrs *entry = addrs; entry != nullptr; entry = entry->ifa_next)
    {
        if (entry->ifa_name != nullptr)
            names.insert(entry->ifa_name);
    }
    freeifaddrs(addrs);
    return true;
}

NamespaceState RealReadNamespaceState(const std::string &name)
{
    NamespaceState state;
    struct stat st{};
    if (stat((std::string{NamespaceDir} + name).c_str(), &st) != 0)
    {
        state.presence = errno == ENOENT ? NamespacePresence::Absent : NamespacePresence::Unknown;
        return state;
    }
    state.presence = NamespacePresence::Present;
    state.identity.known = true;
    state.identity.device = static_cast<uint64_t>(st.st_dev);
    state.identity.inode = static_cast<uint64_t>(st.st_ino);
    return state;
}

CommandResult RealRunCommand(const CommandArgs &args)
{
    CommandResult result;
    if (args.empty())
        return result;

    int out[2];
    if (pipe(out) != 0)
        return result;

    const pid_t child = fork();
    if (child < 0)
    {
        close(out[0]);
        close(out[1]);
        return result;
    }

    if (child == 0)
    {
        // The child runs the program directly: there is no shell anywhere in this path, so an
        // argument can only ever be an argument.
        close(out[0]);
        if (dup2(out[1], STDOUT_FILENO) < 0)
            _exit(127);
        close(out[1]);

        std::vector<char *> argv;
        argv.reserve(args.size() + 1);
        for (const auto &arg : args)
            argv.push_back(const_cast<char *>(arg.c_str()));
        argv.push_back(nullptr);

        execvp(argv[0], argv.data());
        _exit(127);
    }

    close(out[1]);
    char buffer[512];
    ssize_t count;
    while ((count = read(out[0], buffer, sizeof(buffer))) > 0)
        result.output.append(buffer, static_cast<std::size_t>(count));
    close(out[0]);

    int status = 0;
    while (waitpid(child, &status, 0) < 0)
    {
        if (errno != EINTR)
            return result;
    }

    result.started = true;
    result.status = WIFEXITED(status) ? WEXITSTATUS(status) : -1;
    return result;
}

int RealCreateTunDevice(const std::string &name)
{
    ifreq ifr{};
    if (!CopyInterfaceName(ifr.ifr_name, sizeof(ifr.ifr_name), name))
    {
        errno = ENAMETOOLONG;
        return -1;
    }
    ifr.ifr_flags = IFF_TUN | IFF_NO_PI;

    const int fd = open("/dev/net/tun", O_RDWR);
    if (fd < 0)
        return -1;

    if (ioctl(fd, TUNSETIFF, &ifr) < 0)
    {
        const int saved = errno;
        close(fd);
        errno = saved;
        return -1;
    }

    // Exactly one name is asked for. A device that comes back under a different one is
    // refused rather than adopted under the name that was wanted.
    if (std::strncmp(ifr.ifr_name, name.c_str(), IFNAMSIZ) != 0)
    {
        close(fd);
        errno = EBUSY;
        return -1;
    }
    return fd;
}

TunEnvironment RealEnvironment()
{
    TunEnvironment env;
    env.enumerateInterfaces = RealEnumerateInterfaces;
    env.readNamespaceState = RealReadNamespaceState;
    env.runCommand = RealRunCommand;
    env.createTunDevice = RealCreateTunDevice;
    return env;
}

// Replaced only by tests, and only between test cases: production never touches this.
TunEnvironment &MutableEnv()
{
    static TunEnvironment env = RealEnvironment();
    return env;
}

} // namespace

const TunEnvironment &TunEnv()
{
    return MutableEnv();
}

void SetTunEnvironmentForTesting(const TunEnvironment &env)
{
    TunEnvironment merged = env;
    if (!merged.enumerateInterfaces)
        merged.enumerateInterfaces = RealEnvironment().enumerateInterfaces;
    if (!merged.readNamespaceState)
        merged.readNamespaceState = RealEnvironment().readNamespaceState;
    if (!merged.runCommand)
        merged.runCommand = RealEnvironment().runCommand;
    if (!merged.createTunDevice)
        merged.createTunDevice = RealEnvironment().createTunDevice;
    MutableEnv() = std::move(merged);
}

void ResetTunEnvironmentForTesting()
{
    MutableEnv() = RealEnvironment();
}

} // namespace nr::ue::tun
