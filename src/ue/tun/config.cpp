//
// This file is a part of UERANSIM project.
// Copyright (c) 2027 ALİ GÜNGÖR.
//
// https://github.com/aligungr/UERANSIM/
// See README, LICENSE, and CONTRIBUTING files for licensing details.
//

#include "config.hpp"

#include "env.hpp"
#include "naming.hpp"
#include "ownership.hpp"

#include <arpa/inet.h>
#include <cerrno>
#include <cstring>
#include <fstream>
#include <mutex>
#include <net/if.h>
#include <set>
#include <sstream>
#include <string>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <unistd.h>
#include <vector>

#include <lib/app/base_app.hpp>
#include <utils/libc_error.hpp>

#define ROUTING_TABLE_PREFIX "rt_"

// Guards the device and namespace work below. Held across blocking command executions, so it
// is not the same lock as the namespace registry, which must stay responsive during cleanup.
static std::mutex configMutex;
static int initialized = 0;

namespace nr::ue::tun
{
namespace
{

// A descriptor released on every path out of a function, including the throwing ones.
class ScopedFd
{
  public:
    explicit ScopedFd(int fd) : m_fd{fd} {}
    ~ScopedFd()
    {
        if (m_fd >= 0)
            ::close(m_fd);
    }
    ScopedFd(const ScopedFd &) = delete;
    ScopedFd &operator=(const ScopedFd &) = delete;
    [[nodiscard]] int get() const { return m_fd; }

  private:
    int m_fd;
};

// Command output and similar text kept short enough that a failure message stays readable.
std::string Bounded(const std::string &text)
{
    constexpr std::size_t limit = 200;
    if (text.size() <= limit)
        return text;
    return text.substr(0, limit) + "...";
}

// The command, for a diagnostic only. Every argument has already been checked to be a fixed
// literal or an accepted identifier, and no command is ever handed to a shell, so an
// argument cannot change what this describes.
std::string DescribeCommand(const CommandArgs &args)
{
    std::string text;
    for (const auto &arg : args)
    {
        if (!text.empty())
            text += ' ';
        text += arg;
    }
    return text;
}

// Runs an argument vector and returns its output, or throws with what went wrong. Nothing is
// passed through a shell here: each argument stays exactly one argument.
CommandResult RunRequired(const CommandArgs &args)
{
    const CommandResult result = TunEnv().runCommand(args);
    if (!result.started || result.status != 0)
        throw LibError("Command execution failed. The command was: " + DescribeCommand(args) +
                       ". The output is: '" + Bounded(result.output) + "'");
    return result;
}

bool IsIpv4Address(const std::string &value)
{
    in_addr addr{};
    return inet_pton(AF_INET, value.c_str(), &addr) == 1;
}

int NetmaskToPrefixLength(const std::string &netmask)
{
    in_addr addr{};
    if (inet_pton(AF_INET, netmask.c_str(), &addr) != 1)
        return -1;

    uint32_t mask = ntohl(addr.s_addr);
    int prefixLength = 0;
    bool zeroSeen = false;
    for (int bit = 31; bit >= 0; --bit)
    {
        bool set = (mask & (1u << bit)) != 0;
        if (set)
        {
            if (zeroSeen)
                return -1;
            ++prefixLength;
        }
        else
        {
            zeroSeen = true;
        }
    }

    return prefixLength;
}

void TunSetIpAndUp(const std::string &ifName, const std::string &ipAddr, const std::string &netmask, int mtu)
{
    ifreq ifr{};
    if (!CopyInterfaceName(ifr.ifr_name, sizeof(ifr.ifr_name), ifName))
        throw LibError("TUN configuration refused: the interface name is not usable.");

    const ScopedFd sock{socket(AF_INET, SOCK_DGRAM, 0)};
    if (sock.get() < 0)
        throw LibError("socket(AF_INET)", errno);

    sockaddr_in address{};
    address.sin_family = AF_INET;
    address.sin_addr.s_addr = inet_addr(ipAddr.c_str());
    memcpy(&ifr.ifr_addr, &address, sizeof(address));
    if (ioctl(sock.get(), SIOCSIFADDR, &ifr) < 0)
        throw LibError("ioctl(SIOCSIFADDR)", errno);

    sockaddr_in netmaskAddr{};
    netmaskAddr.sin_family = AF_INET;
    netmaskAddr.sin_addr.s_addr = inet_addr(netmask.c_str());
    memcpy(&ifr.ifr_netmask, &netmaskAddr, sizeof(netmaskAddr));
    if (ioctl(sock.get(), SIOCSIFNETMASK, &ifr) < 0)
        throw LibError("ioctl(SIOCSIFNETMASK)", errno);

    if (ioctl(sock.get(), SIOCGIFFLAGS, &ifr) < 0)
        throw LibError("ioctl(SIOCGIFFLAGS)", errno);

    // The interface flags and the MTU share a union in 'ifreq', so the flags read above are
    // saved before the MTU overwrites them and restored afterwards. Writing the MTU straight
    // over the flags and then raising IFF_UP would hand the kernel the MTU value as flags.
    const short flags = ifr.ifr_flags;

    ifr.ifr_mtu = mtu;
    if (ioctl(sock.get(), SIOCSIFMTU, &ifr) < 0)
        throw LibError("ioctl(SIOCSIFMTU)", errno);

    ifr.ifr_flags = flags | IFF_UP | IFF_RUNNING;
    if (ioctl(sock.get(), SIOCSIFFLAGS, &ifr) < 0)
        throw LibError("ioctl(SIOCSIFFLAGS)", errno);
}

void ConfigureRtTables(const std::string &tableName)
{
    std::ifstream ifs;
    ifs.open("/etc/iproute2/rt_tables");
    if (!ifs.is_open() || !ifs.good())
        throw LibError("Could not open '/etc/iproute2/rt_tables'");

    std::string line;

    bool found = false;
    std::set<int> nums;

    while (std::getline(ifs, line))
    {
        auto pos = line.find('#');
        if (pos != std::string::npos)
            line = line.substr(0, pos);
        if (line.length() == 0)
            continue;

        std::stringstream ss;
        ss << line;

        int num;
        ss >> num >> line;

        nums.insert(num);

        if (line == tableName)
            found = true;
    }

    ifs.close();

    if (!found)
    {
        int availableId = 1000;
        while (nums.count(availableId))
            availableId++;

        std::ofstream ofs;

        ofs.open("/etc/iproute2/rt_tables", std::ios_base::app);
        if (!ofs.is_open() || !ofs.good())
            throw LibError("Could not open '/etc/iproute2/rt_tables'");

        ofs << "\n" << availableId << "\t" << tableName << std::endl;
        ofs.close();
    }
}

void RemoveExistingIpRules(const std::string &ipAddr)
{
    const CommandResult listed = RunRequired({"ip", "rule", "list", "from", ipAddr});

    std::vector<CommandArgs> toRemove;
    std::stringstream ss{listed.output};
    std::string line;
    while (std::getline(ss, line))
    {
        if (line.empty())
            continue;

        // Parsed into separate words rather than scanned into fixed buffers: the table name
        // and address come back from a command, and an unbounded %s would overflow them.
        int num = 0;
        std::string colon, from, keyword, table;
        std::stringstream words{line};
        if (!(words >> num >> colon >> from >> keyword >> table) || colon != ":" || keyword != "lookup")
            throw LibError("ip rule list output could not be parsed");

        if (from == ipAddr)
            toRemove.push_back({"ip", "rule", "del", "from", from, "lookup", table});
    }

    for (const auto &args : toRemove)
        RunRequired(args);
}

void AddNewIpRules(const std::string &ipAddr, const std::string &tableName)
{
    RunRequired({"ip", "rule", "add", "from", ipAddr, "table", tableName});
}

bool IsFibTableExists(const std::string &tableName)
{
    const CommandResult listed = RunRequired({"ip", "route", "show", "table", "all"});

    std::stringstream ss{listed.output};
    std::string token;
    while (ss >> token)
    {
        if (token == "table")
        {
            ss >> token;
            if (token == tableName)
                return true;
        }
    }

    return false;
}

void RemoveExistingIpRoutes(const std::string &interfaceName, const std::string &tableName)
{
    if (!IsFibTableExists(tableName))
        return;

    const CommandResult listed = RunRequired({"ip", "route", "list", "table", tableName});

    std::vector<CommandArgs> toRemove;
    std::stringstream ss{listed.output};
    std::string line;
    while (std::getline(ss, line))
    {
        if (line.empty())
            continue;

        std::string keyword1, keyword2, dev, keyword3, keyword4;
        std::stringstream words{line};
        if (!(words >> keyword1 >> keyword2 >> dev >> keyword3 >> keyword4) || keyword1 != "default" ||
            keyword2 != "dev" || keyword3 != "scope" || keyword4 != "link")
            throw LibError("ip route list output could not be parsed");

        if (dev == interfaceName)
            toRemove.push_back({"ip", "route", "del", "default", "dev", dev, "table", tableName});
    }

    for (const auto &args : toRemove)
        RunRequired(args);
}

void AddIpRoutes(const std::string &interfaceName, const std::string &tableName)
{
    RunRequired({"ip", "route", "add", "default", "dev", interfaceName, "table", tableName});
}

// A namespace is configured only while this invocation can still prove that it created it.
// The name alone is not enough: if the namespace behind the name has been replaced,
// configuring it would silently adopt somebody else's.
void VerifyOwnedNamespace(const std::string &nsName)
{
    NamespaceRecord record;
    if (!FindNamespaceRecord(nsName, record) || record.ownership != NamespaceOwnership::CreatedHere)
        throw LibError("Network namespace '" + nsName + "' is not owned by this invocation; refusing to use it.");

    const NamespaceState now = TunEnv().readNamespaceState(nsName);
    if (now.presence != NamespacePresence::Present || !record.identity.Matches(now.identity))
        throw LibError("Network namespace '" + nsName +
                       "' is no longer the namespace this invocation created; refusing to use it.");
}

// Moves the freshly created device into a namespace created by this call. An existing
// namespace is refused and left exactly as it was: what it contains is never used to decide
// whether it is disposable, and it is never deleted to make room.
void PlaceInNewNamespace(const std::string &ifName, const std::string &nsName)
{
    const std::string nameError = NamespaceNameError(nsName);
    if (!nameError.empty())
        throw LibError("Network namespace could not be created: " + nameError + ".");

    const NamespaceState before = TunEnv().readNamespaceState(nsName);
    if (before.presence == NamespacePresence::Unknown)
        throw LibError("Network namespace '" + nsName +
                       "' could not be inspected, so this invocation cannot claim it; leaving it untouched.");
    if (before.presence == NamespacePresence::Present)
        throw LibError("Network namespace '" + nsName +
                       "' already exists and was not created by this invocation; leaving it untouched.");

    RunRequired({"ip", "netns", "add", nsName});

    const NamespaceState ours = TunEnv().readNamespaceState(nsName);
    RecordNamespace(nsName, NamespaceOwnership::CreatedHere, ours.identity);
    if (ours.presence != NamespacePresence::Present || !ours.identity.known)
        throw LibError("Network namespace '" + nsName +
                       "' could not be verified after it was created, so it is left in place rather than removed "
                       "under an identity that cannot be confirmed.");

    try
    {
        RunRequired({"ip", "netns", "exec", nsName, "ip", "link", "set", "lo", "up"});
        RunRequired({"ip", "link", "set", ifName, "netns", nsName});
        RunRequired({"ip", "netns", "exec", nsName, "ip", "link", "show", ifName});
    }
    catch (...)
    {
        // Roll back only what this invocation created, and only while it can still prove that
        // the name identifies that same namespace.
        (void)CleanupOwnedNamespace(nsName);
        throw;
    }
}

void InitializeTunHandling()
{
    if (initialized)
        return;

    // Reuse the framework's signal/exit handling instead of installing our own handlers, which would
    // otherwise override app::BaseSignalHandler. RunAtExit is the same mechanism proc_table uses.
    app::RunAtExit(CleanupAllOwnedNamespaces);
    initialized = 1;
}

} // namespace

int AllocateTun(const std::string &ifPrefix, std::string &allocatedName, const std::string &nsName, bool useNamespace)
{
    // acquire the configuration lock
    const std::lock_guard<std::mutex> lock(configMutex);

    if (useNamespace)
        InitializeTunHandling();

    const std::string prefixError = InterfacePrefixError(ifPrefix);
    if (!prefixError.empty())
        throw LibError("TUN interface could not be allocated: " + prefixError + ".");

    // Both names are settled before anything is created, so a rejected configuration cannot
    // leave a half-built device or namespace behind.
    if (useNamespace)
    {
        const std::string nameError = NamespaceNameError(nsName);
        if (!nameError.empty())
            throw LibError("Network namespace could not be created: " + nameError + ".");
    }

    std::set<std::string> existing;
    if (!TunEnv().enumerateInterfaces(existing))
        throw LibError("TUN interface could not be allocated: the existing interfaces could not be enumerated.");

    // The complete generated name is measured before it goes anywhere near a fixed buffer, and
    // a candidate that would not fit is skipped rather than cut down to size.
    const std::string ifName = NextInterfaceName(ifPrefix, existing);
    if (ifName.empty())
        throw LibError("TUN interface could not be allocated: every interface name the prefix '" + ifPrefix +
                       "' can produce within IFNAMSIZ is already in use.");

    const int fd = TunEnv().createTunDevice(ifName);
    if (fd < 0)
        throw LibError("TUN interface '" + ifName + "' could not be created.");

    if (useNamespace)
    {
        try
        {
            PlaceInNewNamespace(ifName, nsName);
        }
        catch (...)
        {
            close(fd);
            throw;
        }
    }

    allocatedName = ifName;
    return fd;
}

void ConfigureTun(const std::string &tunName, const std::string &ipAddr, const std::string &netmask, int mtu,
                  const std::string &nsName, bool useNamespace, bool configureRoute)
{
    // acquire the configuration lock
    const std::lock_guard<std::mutex> lock(configMutex);

    if (!IsUsableInterfaceName(tunName))
        throw LibError("TUN configuration refused: the interface name is not usable.");
    if (mtu <= 0)
        throw LibError("TUN configuration refused: the MTU must be positive.");
    if (!IsIpv4Address(ipAddr))
        throw LibError("TUN configuration refused: the IPv4 address is not usable.");
    const int prefixLength = NetmaskToPrefixLength(netmask);
    if (prefixLength < 0)
        throw LibError("TUN configuration refused: the netmask is not usable.");

    if (useNamespace)
    {
        const std::string nameError = NamespaceNameError(nsName);
        if (!nameError.empty())
            throw LibError("TUN configuration refused: " + nameError + ".");
        VerifyOwnedNamespace(nsName);

        RunRequired({"ip", "netns", "exec", nsName, "ip", "addr", "add", ipAddr + "/" + std::to_string(prefixLength),
                     "dev", tunName});
        RunRequired({"ip", "netns", "exec", nsName, "ip", "link", "set", tunName, "mtu", std::to_string(mtu)});
        RunRequired({"ip", "netns", "exec", nsName, "ip", "link", "set", tunName, "up"});
        if (configureRoute)
            RunRequired({"ip", "netns", "exec", nsName, "ip", "route", "replace", "default", "dev", tunName});
        return;
    }

    TunSetIpAndUp(tunName, ipAddr, netmask, mtu);
    if (configureRoute)
    {
        const std::string tableName = ROUTING_TABLE_PREFIX + tunName;

        ConfigureRtTables(tableName);
        RemoveExistingIpRules(ipAddr);
        AddNewIpRules(ipAddr, tableName);
        RemoveExistingIpRoutes(tunName, tableName);
        AddIpRoutes(tunName, tableName);
    }
}

void CleanupTun(const std::string &tunName, const std::string &nsName, bool useNamespace)
{
    const std::lock_guard<std::mutex> lock(configMutex);

    if (!useNamespace || nsName.empty())
        return;

    // Both names are checked before anything is attempted, so a name that cannot be an
    // identifier never reaches a command.
    if (!IsUsableInterfaceName(tunName))
        throw LibError("TUN cleanup refused: the interface name is not usable.");
    const std::string nameError = NamespaceNameError(nsName);
    if (!nameError.empty())
        throw LibError("TUN cleanup refused: " + nameError + ".");

    // No record means no ownership, and no ownership means no delete. A namespace somebody
    // else created is never registered here in the first place, so it is never reached.
    const CleanupOutcome outcome = CleanupOwnedNamespace(nsName);
    if (outcome == CleanupOutcome::DeleteFailed)
        throw LibError("Network namespace '" + nsName + "' could not be deleted.");
}

} // namespace nr::ue::tun
