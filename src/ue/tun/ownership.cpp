//
// This file is a part of UERANSIM project.
// Copyright (c) 2027 ALİ GÜNGÖR.
//
// https://github.com/aligungr/UERANSIM/
// See README, LICENSE, and CONTRIBUTING files for licensing details.
//

#include "ownership.hpp"

#include "naming.hpp"

#include <mutex>
#include <utility>
#include <vector>

namespace nr::ue::tun
{
namespace
{

std::mutex &RegistryMutex()
{
    static std::mutex mutex;
    return mutex;
}

// The namespaces this invocation created and may therefore delete. A name is on this list
// only because the current invocation created it: an existing namespace is never added, so
// this list can never become a list of things to destroy that belong to someone else.
std::vector<NamespaceRecord> &Records()
{
    static std::vector<NamespaceRecord> records;
    return records;
}

// The one place a namespace is ever deleted. Everything else has to go through here, and
// every caller has already been told that the namespace is this invocation's own.
CleanupOutcome CleanupRecord(const NamespaceRecord &record)
{
    // A namespace that was only ever allowed to be used keeps its original owner. It is
    // reported as not ours rather than quietly deleted.
    if (record.ownership != NamespaceOwnership::CreatedHere)
        return CleanupOutcome::NotOwned;

    const NamespaceState now = TunEnv().readNamespaceState(record.name);
    if (now.presence == NamespacePresence::Absent)
        return CleanupOutcome::AlreadyGone;
    if (now.presence == NamespacePresence::Unknown)
        return CleanupOutcome::Unverifiable;

    if (DecideNamespaceCleanup(record, now) != CleanupDecision::Delete)
    {
        if (!record.identity.known || !now.identity.known)
            return CleanupOutcome::Unverifiable;
        return CleanupOutcome::Replaced;
    }

    const CommandResult result = TunEnv().runCommand({"ip", "netns", "delete", record.name});
    if (!result.started || result.status != 0)
        return CleanupOutcome::DeleteFailed;
    return CleanupOutcome::Deleted;
}

} // namespace

CleanupDecision DecideNamespaceCleanup(const NamespaceRecord &record, const NamespaceState &now)
{
    // Only a namespace this invocation created may be deleted at all.
    if (record.ownership != NamespaceOwnership::CreatedHere)
        return CleanupDecision::LeaveIntact;

    // Absent means there is nothing to delete. Unknown means ownership cannot be established,
    // and that fails closed: the namespace is left alone.
    if (now.presence != NamespacePresence::Present)
        return CleanupDecision::LeaveIntact;

    // A record holding a name is not proof. The name has to still identify the very namespace
    // that was created, so an identity that cannot be read is never accepted as a match.
    if (!record.identity.known || !now.identity.known)
        return CleanupDecision::LeaveIntact;
    if (!record.identity.Matches(now.identity))
        return CleanupDecision::LeaveIntact;

    return CleanupDecision::Delete;
}

void RecordNamespace(const std::string &name, NamespaceOwnership ownership, const NamespaceIdentity &identity)
{
    if (NamespaceNameError(name).empty() == false)
        return;

    const std::lock_guard<std::mutex> lock(RegistryMutex());
    for (const auto &record : Records())
    {
        if (record.name == name)
            return; // the first record is the one that counts
    }

    NamespaceRecord record;
    record.name = name;
    record.ownership = ownership;
    record.identity = identity;
    Records().push_back(std::move(record));
}

bool FindNamespaceRecord(const std::string &name, NamespaceRecord &record)
{
    const std::lock_guard<std::mutex> lock(RegistryMutex());
    for (const auto &existing : Records())
    {
        if (existing.name != name)
            continue;
        record = existing;
        return true;
    }
    return false;
}

bool TakeNamespaceRecord(const std::string &name, NamespaceRecord &record)
{
    const std::lock_guard<std::mutex> lock(RegistryMutex());
    for (std::size_t i = 0; i < Records().size(); ++i)
    {
        if (Records()[i].name != name)
            continue;
        record = std::move(Records()[i]);
        Records().erase(Records().begin() + static_cast<std::ptrdiff_t>(i));
        return true;
    }
    return false;
}

CleanupOutcome CleanupOwnedNamespace(const std::string &name)
{
    // The record is consumed whatever happens below, so a second cleanup call cannot issue a
    // second delete and a registry entry cannot linger to be acted on later.
    NamespaceRecord record;
    if (!TakeNamespaceRecord(name, record))
        return CleanupOutcome::NoRecord;
    return CleanupRecord(record);
}

void CleanupAllOwnedNamespaces()
{
    std::vector<NamespaceRecord> snapshot;
    {
        const std::lock_guard<std::mutex> lock(RegistryMutex());
        snapshot.swap(Records());
    }

    for (const auto &record : snapshot)
        (void)CleanupRecord(record);
}

int NamespaceRecordCount()
{
    const std::lock_guard<std::mutex> lock(RegistryMutex());
    return static_cast<int>(Records().size());
}

void ClearNamespaceRecordsForTesting()
{
    const std::lock_guard<std::mutex> lock(RegistryMutex());
    Records().clear();
}

} // namespace nr::ue::tun
