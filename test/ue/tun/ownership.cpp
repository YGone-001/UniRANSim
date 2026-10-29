//
// This file is a part of UERANSIM project.
// Copyright (c) 2027 ALİ GÜNGÖR.
//
// https://github.com/aligungr/UERANSIM/
// See README, LICENSE, and CONTRIBUTING files for licensing details.
//

#include <string>

#include <ext/doctest/doctest.h>
#include <test/ue/tun/fake_environment.hpp>
#include <ue/tun/ownership.hpp>

using nr::ue::tun::CleanupAllOwnedNamespaces;
using nr::ue::tun::CleanupDecision;
using nr::ue::tun::CleanupOutcome;
using nr::ue::tun::CleanupOwnedNamespace;
using nr::ue::tun::ClearNamespaceRecordsForTesting;
using nr::ue::tun::CommandArgs;
using nr::ue::tun::DecideNamespaceCleanup;
using nr::ue::tun::FindNamespaceRecord;
using nr::ue::tun::NamespaceIdentity;
using nr::ue::tun::NamespaceOwnership;
using nr::ue::tun::NamespacePresence;
using nr::ue::tun::NamespaceRecord;
using nr::ue::tun::NamespaceRecordCount;
using nr::ue::tun::NamespaceState;
using nr::ue::tun::RecordNamespace;
using nr::ue::tun::TakeNamespaceRecord;

using ue_tun_test::FakeHost;

namespace
{

// Every name used here starts with 'x12' so it cannot be confused with a namespace that
// exists on the laboratory host.
const std::string kOwned = "x12owned";
const std::string kExternal = "x12external";
const std::string kReused = "x12reused";
const std::string kReplaced = "x12replaced";

NamespaceIdentity Identity(uint64_t inode)
{
    NamespaceIdentity identity;
    identity.known = true;
    identity.device = 4;
    identity.inode = inode;
    return identity;
}

NamespaceState StateAt(uint64_t inode, NamespacePresence presence = NamespacePresence::Present)
{
    NamespaceState state;
    state.presence = presence;
    state.identity = Identity(inode);
    return state;
}

} // namespace

TEST_CASE("ue/tun/ownership: a namespace this invocation created may be deleted")
{
    CHECK(DecideNamespaceCleanup({kOwned, NamespaceOwnership::CreatedHere, Identity(100)}, StateAt(100)) ==
          CleanupDecision::Delete);
}

TEST_CASE("ue/tun/ownership: a namespace that existed before the operation is never deleted")
{
    // On the books only because it was allowed to be used: the original owner is kept, so it
    // is never deleted here even though the name and the identity both match exactly.
    CHECK(DecideNamespaceCleanup({kReused, NamespaceOwnership::Reused, Identity(300)}, StateAt(300)) ==
          CleanupDecision::LeaveIntact);
    CHECK(DecideNamespaceCleanup({kReused, NamespaceOwnership::Reused, Identity(300)}, StateAt(300)) !=
          CleanupDecision::Delete);

    // Not on the books at all is handled before this point: a name with no record of having
    // been created here never reaches a delete.
    FakeHost host;
    host.AddNamespace(kExternal, 200);
    CHECK(CleanupOwnedNamespace(kExternal) == CleanupOutcome::NoRecord);
    CHECK(host.DeleteCount() == 0);
}

TEST_CASE("ue/tun/ownership: loopback-only status does not make a namespace disposable")
{
    FakeHost host;
    host.AddNamespace(kExternal, 4242, /*onlyLoopback=*/true);

    // The strongest form of the rule: an externally owned namespace holding nothing but
    // loopback is presented to cleanup, and not one delete command is issued for it.
    CHECK(CleanupOwnedNamespace(kExternal) == CleanupOutcome::NoRecord);
    CleanupAllOwnedNamespaces();
    CHECK(host.DeleteCount() == 0);
    CHECK(host.commands.empty());

    // And what it contains is never read to reach that decision.
    CHECK(host.namespaces.at(kExternal).onlyLoopback);
}

TEST_CASE("ue/tun/ownership: an occupied namespace is treated no differently from an empty one")
{
    FakeHost host;
    host.AddNamespace(kExternal, 4242, /*onlyLoopback=*/false);

    CHECK(CleanupOwnedNamespace(kExternal) == CleanupOutcome::NoRecord);
    CleanupAllOwnedNamespaces();
    CHECK(host.DeleteCount() == 0);
}

TEST_CASE("ue/tun/ownership: reusing a namespace never grants deletion rights")
{
    FakeHost host;
    host.AddNamespace(kReused, 5150);
    RecordNamespace(kReused, NamespaceOwnership::Reused, Identity(5150));

    CHECK(CleanupOwnedNamespace(kReused) == CleanupOutcome::NotOwned);
    CHECK(host.DeleteCount() == 0);
    // And it is gone from the books, so nothing retries later.
    CHECK(NamespaceRecordCount() == 0);
}

TEST_CASE("ue/tun/ownership: a namespace created here and then replaced is not deleted")
{
    FakeHost host;
    host.AddNamespace(kReplaced, 6260);  // a different instance than the one recorded
    RecordNamespace(kReplaced, NamespaceOwnership::CreatedHere, Identity(6000));

    CHECK(CleanupOwnedNamespace(kReplaced) == CleanupOutcome::Replaced);
    CHECK(host.DeleteCount() == 0);
    CHECK(host.namespaces.count(kReplaced) == 1);
}

TEST_CASE("ue/tun/ownership: a namespace whose identity cannot be established is left intact")
{
    FakeHost host;
    host.AddNamespace(kOwned, 7070);
    host.namespaces.at(kOwned).identity.known = false;
    RecordNamespace(kOwned, NamespaceOwnership::CreatedHere, Identity(7070));

    CHECK(CleanupOwnedNamespace(kOwned) == CleanupOutcome::Unverifiable);
    CHECK(host.DeleteCount() == 0);

    // The same holds when the whole namespace table cannot be read.
    ClearNamespaceRecordsForTesting();
    host.AddNamespace(kOwned, 7070);
    RecordNamespace(kOwned, NamespaceOwnership::CreatedHere, Identity(7070));
    host.namespaceStateUnreadable = true;
    CHECK(CleanupOwnedNamespace(kOwned) == CleanupOutcome::Unverifiable);
    CHECK(host.DeleteCount() == 0);
}

TEST_CASE("ue/tun/ownership: a created namespace is deleted exactly once and cleanup is idempotent")
{
    FakeHost host;
    host.AddNamespace(kOwned, 8080);
    RecordNamespace(kOwned, NamespaceOwnership::CreatedHere, Identity(8080));

    CHECK(CleanupOwnedNamespace(kOwned) == CleanupOutcome::Deleted);
    REQUIRE(host.DeleteCount() == 1);
    CHECK(host.DeleteCommands()[0] == CommandArgs{"ip", "netns", "delete", kOwned});

    // The record is consumed with the delete, so the second call does nothing at all.
    CHECK(CleanupOwnedNamespace(kOwned) == CleanupOutcome::NoRecord);
    CleanupAllOwnedNamespaces();
    CHECK(host.DeleteCount() == 1);
}

TEST_CASE("ue/tun/ownership: a namespace that is already gone needs no delete and leaves nothing behind")
{
    FakeHost host;
    RecordNamespace(kOwned, NamespaceOwnership::CreatedHere, Identity(9090));

    CHECK(CleanupOwnedNamespace(kOwned) == CleanupOutcome::AlreadyGone);
    CHECK(host.DeleteCount() == 0);
    CHECK(NamespaceRecordCount() == 0);
}

TEST_CASE("ue/tun/ownership: a failed delete is reported as a failure and never as a success")
{
    FakeHost host;
    host.AddNamespace(kOwned, 1010);
    RecordNamespace(kOwned, NamespaceOwnership::CreatedHere, Identity(1010));
    host.commandStatus = 1;

    CHECK(CleanupOwnedNamespace(kOwned) == CleanupOutcome::DeleteFailed);
    CHECK(host.DeleteCount() == 1);

    // A delete whose process could not even be started is a failure as well.
    ClearNamespaceRecordsForTesting();
    host.AddNamespace(kOwned, 1010);
    RecordNamespace(kOwned, NamespaceOwnership::CreatedHere, Identity(1010));
    host.commandFailsToStart = true;
    CHECK(CleanupOwnedNamespace(kOwned) == CleanupOutcome::DeleteFailed);
}

TEST_CASE("ue/tun/ownership: a stale registry entry cannot cause a later deletion")
{
    FakeHost host;
    // Recorded as created here, but the namespace behind the name has since been replaced.
    host.AddNamespace(kReplaced, 1111);
    RecordNamespace(kReplaced, NamespaceOwnership::CreatedHere, Identity(2222));

    // Shutdown cleanup runs over whatever is still on the books.
    CleanupAllOwnedNamespaces();

    CHECK(host.DeleteCount() == 0);
    CHECK(host.namespaces.count(kReplaced) == 1);
    CHECK(NamespaceRecordCount() == 0);
}

TEST_CASE("ue/tun/ownership: shutdown cleanup deletes only what this invocation created")
{
    FakeHost host;
    host.AddNamespace(kOwned, 3333);
    host.AddNamespace(kReused, 4444);
    host.AddNamespace(kReplaced, 5555);

    RecordNamespace(kOwned, NamespaceOwnership::CreatedHere, Identity(3333));
    RecordNamespace(kReused, NamespaceOwnership::Reused, Identity(4444));
    RecordNamespace(kReplaced, NamespaceOwnership::CreatedHere, Identity(6666));

    CleanupAllOwnedNamespaces();

    const auto deletes = host.DeleteCommands();
    REQUIRE(deletes.size() == 1);
    CHECK(deletes[0] == CommandArgs{"ip", "netns", "delete", kOwned});
    CHECK(host.namespaces.count(kReused) == 1);
    CHECK(host.namespaces.count(kReplaced) == 1);
}

TEST_CASE("ue/tun/ownership: a namespace whose creation failed is never put on the books")
{
    FakeHost host;
    // Nothing recorded, so nothing can be deleted later on the strength of a name alone.
    CHECK(NamespaceRecordCount() == 0);
    CHECK(CleanupOwnedNamespace(kOwned) == CleanupOutcome::NoRecord);
    CHECK(host.DeleteCount() == 0);
}

TEST_CASE("ue/tun/ownership: taking a record off the books is what makes a second cleanup harmless")
{
    FakeHost host;
    NamespaceRecord record;
    CHECK_FALSE(TakeNamespaceRecord(kOwned, record));

    RecordNamespace(kOwned, NamespaceOwnership::CreatedHere, Identity(7777));
    REQUIRE(TakeNamespaceRecord(kOwned, record));
    CHECK(record.name == kOwned);
    CHECK(record.ownership == NamespaceOwnership::CreatedHere);
    CHECK(record.identity.Matches(Identity(7777)));
    CHECK_FALSE(TakeNamespaceRecord(kOwned, record));
}

TEST_CASE("ue/tun/ownership: a record can be inspected without being consumed")
{
    FakeHost host;
    RecordNamespace(kOwned, NamespaceOwnership::CreatedHere, Identity(8888));

    NamespaceRecord first;
    REQUIRE(FindNamespaceRecord(kOwned, first));
    NamespaceRecord second;
    REQUIRE(FindNamespaceRecord(kOwned, second));
    CHECK(first.identity.Matches(second.identity));
    CHECK(NamespaceRecordCount() == 1);
}
