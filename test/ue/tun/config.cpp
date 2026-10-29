//
// This file is a part of UERANSIM project.
// Copyright (c) 2027 ALİ GÜNGÖR.
//
// https://github.com/aligungr/UERANSIM/
// See README, LICENSE, and CONTRIBUTING files for licensing details.
//

#include <string>
#include <unistd.h>
#include <vector>

#include <ext/doctest/doctest.h>
#include <test/ue/tun/fake_environment.hpp>
#include <ue/tun/config.hpp>
#include <ue/tun/naming.hpp>
#include <ue/tun/ownership.hpp>
#include <utils/libc_error.hpp>

using nr::ue::tun::AllocateTun;
using nr::ue::tun::CleanupAllOwnedNamespaces;
using nr::ue::tun::CleanupTun;
using nr::ue::tun::CommandArgs;
using nr::ue::tun::CommandResult;
using nr::ue::tun::ConfigureTun;
using nr::ue::tun::FindNamespaceRecord;
using nr::ue::tun::NamespaceIdentity;
using nr::ue::tun::NamespaceOwnership;
using nr::ue::tun::NamespaceRecord;
using nr::ue::tun::NamespaceRecordCount;
using nr::ue::tun::RecordNamespace;

using ue_tun_test::FakeHost;

namespace
{

// Names chosen so that nothing here can be mistaken for a namespace on the laboratory host.
const std::string kOwned = "x12owned";
const std::string kExternal = "x12external";
const std::string kDevice = "x12tun";

NamespaceIdentity IdentityOf(uint64_t inode)
{
    NamespaceIdentity identity;
    identity.known = true;
    identity.device = 4;
    identity.inode = inode;
    return identity;
}

// Makes the named namespace appear at the moment the fake 'ip netns add' is recorded, which
// is when a real one would exist.
void AppearOnCreate(FakeHost &host, uint64_t inode = 9090)
{
    host.onCommand = [&host, inode](const CommandArgs &args, CommandResult &) {
        if (args.size() == 4 && args[0] == "ip" && args[1] == "netns" && args[2] == "add")
            host.AddNamespace(args[3], inode);
        return false;
    };
}

bool Contains(const CommandArgs &args, const std::string &value)
{
    for (const auto &arg : args)
    {
        if (arg == value)
            return true;
    }
    return false;
}

} // namespace

TEST_CASE("ue/tun/config: allocation picks the first free generated name and creates exactly one device")
{
    FakeHost host;
    host.interfaces = {"lo", "eno1", "x12tun0"};

    std::string name;
    const int fd = AllocateTun(kDevice, name, {}, false);
    CHECK(fd >= 0);
    CHECK(name == "x12tun1");
    CHECK(host.createdDevices == std::vector<std::string>{"x12tun1"});
    CHECK(host.commands.empty());  // no namespace work at all without a namespace
    CHECK(close(fd) == 0);
}

TEST_CASE("ue/tun/config: the historical LTE and NR prefixes still produce their historical names")
{
    FakeHost host;

    std::string name;
    int fd = AllocateTun("uniransim-lte", name, {}, false);
    REQUIRE(fd >= 0);
    CHECK(name == "uniransim-lte0");
    CHECK(close(fd) == 0);

    fd = AllocateTun("uesimtun", name, {}, false);
    REQUIRE(fd >= 0);
    CHECK(name == "uesimtun0");
    CHECK(close(fd) == 0);
}

TEST_CASE("ue/tun/config: an unusable prefix is refused before anything is created")
{
    FakeHost host;

    for (const std::string &prefix : {std::string{}, std::string(15, 'p'), std::string{"a b"}, std::string{"a;b"},
                                      std::string{"-abc"}, std::string{"a/b"}})
    {
        CAPTURE(prefix);
        std::string name;
        const int before = FakeHost::OpenFdCount();
        CHECK_THROWS_AS(AllocateTun(prefix, name, {}, false), LibError);
        CHECK(name.empty());
        CHECK(host.createdDevices.empty());
        CHECK(host.commands.empty());
        CHECK(FakeHost::OpenFdCount() == before);
    }
}

TEST_CASE("ue/tun/config: an exhausted prefix is refused without creating a device")
{
    FakeHost host;
    const std::string prefix = std::string(14, 'p');
    for (int i = 0; i <= 9; ++i)
        host.interfaces.insert(prefix + std::to_string(i));

    std::string name;
    const int before = FakeHost::OpenFdCount();
    CHECK_THROWS_AS(AllocateTun(prefix, name, {}, false), LibError);
    CHECK(host.createdDevices.empty());
    CHECK(host.commands.empty());
    CHECK(FakeHost::OpenFdCount() == before);

    // The refusal says which prefix ran out and why, without inventing a shorter name.
    try
    {
        AllocateTun(prefix, name, {}, false);
    }
    catch (const LibError &error)
    {
        const std::string message = error.what();
        CHECK(message.find(prefix) != std::string::npos);
        CHECK(message.find("IFNAMSIZ") != std::string::npos);
    }
}

TEST_CASE("ue/tun/config: an interface-enumeration failure is refused and creates nothing")
{
    FakeHost host;
    host.enumerationFails = true;

    std::string name;
    CHECK_THROWS_AS(AllocateTun(kDevice, name, {}, false), LibError);
    CHECK(name.empty());
    CHECK(host.createdDevices.empty());
    CHECK(host.commands.empty());
}

TEST_CASE("ue/tun/config: a failed device creation leaves nothing behind")
{
    FakeHost host;
    host.deviceCreationFails = true;

    std::string name;
    const int before = FakeHost::OpenFdCount();
    CHECK_THROWS_AS(AllocateTun(kDevice, name, {}, false), LibError);
    CHECK(host.commands.empty());
    CHECK(FakeHost::OpenFdCount() == before);
}

TEST_CASE("ue/tun/config: an existing namespace is rejected and left completely untouched")
{
    FakeHost host;
    host.AddNamespace(kExternal, 4242, /*onlyLoopback=*/true);

    std::string name;
    const int before = FakeHost::OpenFdCount();
    CHECK_THROWS_AS(AllocateTun(kDevice, name, kExternal, true), LibError);

    // The strongest form of the rule: nothing was run at all, so in particular no delete.
    CHECK(host.commands.empty());
    CHECK(host.DeleteCount() == 0);
    CHECK(host.namespaces.count(kExternal) == 1);
    CHECK(host.namespaces.at(kExternal).onlyLoopback);
    CHECK(NamespaceRecordCount() == 0);
    CHECK(FakeHost::OpenFdCount() == before);
}

TEST_CASE("ue/tun/config: an occupied namespace is rejected just like an empty one")
{
    FakeHost host;
    host.AddNamespace(kExternal, 4242, /*onlyLoopback=*/false);

    std::string name;
    CHECK_THROWS_AS(AllocateTun(kDevice, name, kExternal, true), LibError);
    CHECK(host.commands.empty());
    CHECK(host.namespaces.count(kExternal) == 1);
}

TEST_CASE("ue/tun/config: a namespace that cannot be inspected is left untouched")
{
    FakeHost host;
    host.namespaceStateUnreadable = true;

    std::string name;
    const int before = FakeHost::OpenFdCount();
    CHECK_THROWS_AS(AllocateTun(kDevice, name, kOwned, true), LibError);
    CHECK(host.commands.empty());
    CHECK(host.DeleteCount() == 0);
    CHECK(NamespaceRecordCount() == 0);
    CHECK(FakeHost::OpenFdCount() == before);
}

TEST_CASE("ue/tun/config: a namespace created for a new device is put on the books as created here")
{
    FakeHost host;
    AppearOnCreate(host);

    std::string name;
    const int fd = AllocateTun(kDevice, name, kOwned, true);
    REQUIRE(fd >= 0);
    CHECK(close(fd) == 0);

    NamespaceRecord record;
    REQUIRE(FindNamespaceRecord(kOwned, record));
    CHECK(record.ownership == NamespaceOwnership::CreatedHere);
    CHECK(record.identity.known);
    CHECK(host.createdDevices == std::vector<std::string>{name});
}

TEST_CASE("ue/tun/config: a failed setup after namespace creation rolls back only what this invocation created")
{
    FakeHost host;
    host.AddNamespace(kExternal, 4242);  // somebody else's namespace, must survive untouched
    host.onCommand = [&host](const CommandArgs &args, CommandResult &result) {
        if (args.size() == 4 && args[0] == "ip" && args[1] == "netns" && args[2] == "add")
        {
            host.AddNamespace(args[3], 9090);
            return false;
        }
        // The device move into the namespace is what fails.
        if (args.size() >= 2 && args[0] == "ip" && args[1] == "link")
        {
            result.started = true;
            result.status = 1;
            return true;
        }
        return false;
    };

    std::string name;
    const int before = FakeHost::OpenFdCount();
    CHECK_THROWS_AS(AllocateTun(kDevice, name, kOwned, true), LibError);

    // Exactly one delete, and it is the namespace this invocation made.
    const auto deletes = host.DeleteCommands();
    REQUIRE(deletes.size() == 1);
    CHECK(deletes[0] == CommandArgs{"ip", "netns", "delete", kOwned});
    CHECK(host.namespaces.count(kExternal) == 1);
    CHECK(NamespaceRecordCount() == 0);
    CHECK(FakeHost::OpenFdCount() == before);
}

TEST_CASE("ue/tun/config: a namespace whose creation fails is not registered and nothing is deleted")
{
    FakeHost host;
    host.commandStatus = 1;

    std::string name;
    const int before = FakeHost::OpenFdCount();
    CHECK_THROWS_AS(AllocateTun(kDevice, name, kOwned, true), LibError);
    CHECK(host.DeleteCount() == 0);
    CHECK(NamespaceRecordCount() == 0);
    CHECK(FakeHost::OpenFdCount() == before);
}

TEST_CASE("ue/tun/config: an unsafe namespace name is refused before any process is started")
{
    FakeHost host;

    const std::vector<std::string> unsafe = {
        std::string{"p6ns7; rm -rf /"}, std::string{"x`id`"},      std::string{"x$(id)"},
        std::string{"x | tee /etc/passwd"}, std::string{"x > /tmp/o"}, std::string{"x\ny"},
        std::string{"x\ty"},            std::string{"x y"},        std::string{"-x"},
        std::string{"/x"},              std::string{},             std::string(300, 'n'),
    };

    for (const auto &nsName : unsafe)
    {
        CAPTURE(nsName);
        std::string name;
        CHECK_THROWS_AS(AllocateTun(kDevice, name, nsName, true), LibError);
        // Nothing was run, nothing was created and nothing was registered.
        CHECK(host.commands.empty());
        CHECK(host.createdDevices.empty());
        CHECK(NamespaceRecordCount() == 0);
    }
}

TEST_CASE("ue/tun/config: a refused name is never echoed back and the message stays short")
{
    FakeHost host;
    const std::string hostile = std::string{"x; "} + std::string(4000, 'A');

    std::string name;
    try
    {
        AllocateTun(kDevice, name, hostile, true);
        FAIL("the hostile namespace name was accepted");
    }
    catch (const LibError &error)
    {
        const std::string message = error.what();
        CHECK(message.find(hostile) == std::string::npos);
        CHECK(message.size() < 300);
        CHECK_FALSE(message.empty());
    }
}

TEST_CASE("ue/tun/config: every command is an argument vector and a name cannot change its structure")
{
    FakeHost host;
    AppearOnCreate(host);

    std::string name;
    const int fd = AllocateTun(kDevice, name, kOwned, true);
    REQUIRE(fd >= 0);
    CHECK(close(fd) == 0);
    REQUIRE_FALSE(host.commands.empty());

    int mentionsDevice = 0;
    for (const auto &args : host.commands)
    {
        // An argument vector has a program and arguments. A shell command line would arrive
        // here as a single string, which is exactly what never happens.
        CHECK(args.size() >= 2);
        CHECK(args[0] == "ip");
        CHECK(args[0].find(' ') == std::string::npos);
        for (const auto &arg : args)
        {
            CHECK(arg.find(';') == std::string::npos);
            CHECK(arg.find('$') == std::string::npos);
            CHECK(arg.find('`') == std::string::npos);
            CHECK(arg.find('|') == std::string::npos);
            CHECK(arg.find('\n') == std::string::npos);
        }
        // The names are each one argument among several, never a fragment of a command.
        CHECK(Contains(args, kOwned));
        if (Contains(args, name))
            ++mentionsDevice;
    }
    CHECK(mentionsDevice > 0);
}

TEST_CASE("ue/tun/config: a simulated cleanup of an externally owned loopback-only namespace issues zero deletes")
{
    FakeHost host;
    host.AddNamespace(kExternal, 4242, /*onlyLoopback=*/true);

    // The strongest destruction-safety check there is: a namespace that is not ours, holding
    // nothing but loopback, is presented to cleanup repeatedly and not one delete is issued.
    CHECK_NOTHROW(CleanupTun(kDevice, kExternal, true));
    CHECK_NOTHROW(CleanupTun(kDevice, kExternal, true));
    CleanupAllOwnedNamespaces();

    CHECK(host.commands.empty());
    CHECK(host.DeleteCount() == 0);
    CHECK(host.namespaces.count(kExternal) == 1);
    CHECK(host.namespaces.at(kExternal).onlyLoopback);
}

TEST_CASE("ue/tun/config: cleanup deletes its own namespace once and is idempotent")
{
    FakeHost host;
    host.AddNamespace(kOwned, 9090);
    RecordNamespace(kOwned, NamespaceOwnership::CreatedHere, IdentityOf(9090));

    CHECK_NOTHROW(CleanupTun(kDevice, kOwned, true));
    CHECK_NOTHROW(CleanupTun(kDevice, kOwned, true));
    CleanupAllOwnedNamespaces();

    REQUIRE(host.DeleteCount() == 1);
    CHECK(host.DeleteCommands()[0] == CommandArgs{"ip", "netns", "delete", kOwned});
    CHECK(NamespaceRecordCount() == 0);
}

TEST_CASE("ue/tun/config: cleanup refuses an unusable name without running anything")
{
    FakeHost host;
    CHECK_THROWS_AS(CleanupTun("a b", kOwned, true), LibError);
    CHECK_THROWS_AS(CleanupTun(kDevice, "x; rm -rf /", true), LibError);
    CHECK(host.commands.empty());
}

TEST_CASE("ue/tun/config: a namespace that is no longer the one created is never configured")
{
    FakeHost host;
    host.AddNamespace(kOwned, 1111);
    RecordNamespace(kOwned, NamespaceOwnership::CreatedHere, IdentityOf(2222));

    CHECK_THROWS_AS(ConfigureTun(kDevice + "0", "10.45.0.2", "255.255.0.0", 1400, kOwned, true, true), LibError);
    CHECK(host.commands.empty());
}

TEST_CASE("ue/tun/config: configuration refuses a namespace this invocation does not own")
{
    FakeHost host;
    host.AddNamespace(kExternal, 4242);

    CHECK_THROWS_AS(ConfigureTun(kDevice + "0", "10.45.0.2", "255.255.0.0", 1400, kExternal, true, true), LibError);
    CHECK(host.commands.empty());
}

TEST_CASE("ue/tun/config: two lifetimes cannot both take the same namespace")
{
    FakeHost host;
    AppearOnCreate(host);

    std::string firstName;
    const int first = AllocateTun(kDevice, firstName, kOwned, true);
    REQUIRE(first >= 0);

    // The second lifetime sees the namespace as somebody else's and is refused outright.
    std::string secondName;
    CHECK_THROWS_AS(AllocateTun(kDevice, secondName, kOwned, true), LibError);
    CHECK(host.DeleteCount() == 0);
    CHECK(host.namespaces.count(kOwned) == 1);

    CHECK(close(first) == 0);
    CleanupTun(firstName, kOwned, true);
    CHECK(host.DeleteCount() == 1);
}

TEST_CASE("ue/tun/config: an unusable interface name is refused by the shared configuration entry point")
{
    FakeHost host;

    for (const std::string &name : {std::string{}, std::string(16, 'n'), std::string{"a b"}, std::string{"a;b"}})
    {
        CAPTURE(name);
        CHECK_THROWS_AS(ConfigureTun(name, "10.45.0.2", "255.255.0.0", 1400, {}, false, false), LibError);
        CHECK_THROWS_AS(CleanupTun(name, kOwned, true), LibError);
        CHECK(host.commands.empty());
    }
}

TEST_CASE("ue/tun/config: configuration refuses a bad address or netmask before touching anything")
{
    FakeHost host;

    CHECK_THROWS_AS(ConfigureTun(kDevice + "0", "not-an-address", "255.255.0.0", 1400, {}, false, false), LibError);
    CHECK_THROWS_AS(ConfigureTun(kDevice + "0", "10.45.0.2", "255.0.255.0", 1400, {}, false, false), LibError);
    CHECK_THROWS_AS(ConfigureTun(kDevice + "0", "10.45.0.2", "255.255.0.0", 0, {}, false, false), LibError);
    CHECK(host.commands.empty());
}

TEST_CASE("ue/tun/config: the LTE path allocates a device without creating or deleting any namespace")
{
    FakeHost host;
    host.interfaces = {"lo", "eno1", "ogstun", "ogstun1"};

    std::string name;
    const int fd = AllocateTun("uniransim-lte", name, {}, false);
    REQUIRE(fd >= 0);
    CHECK(name == "uniransim-lte0");
    CHECK(close(fd) == 0);

    // LTE never asks for a namespace, so no namespace work happens at all.
    CHECK(host.commands.empty());
    CHECK(host.DeleteCount() == 0);

    // Cleanup with no namespace is a no-op, whatever it is given.
    CHECK_NOTHROW(CleanupTun(name, {}, false));
    CHECK(host.commands.empty());
}
