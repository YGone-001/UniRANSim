//
// This file is a part of UERANSIM project.
// Copyright (c) 2027 ALİ GÜNGÖR.
//
// https://github.com/aligungr/UERANSIM/
// See README, LICENSE, and CONTRIBUTING files for licensing details.
//

#pragma once

#include "env.hpp"

#include <string>

namespace nr::ue::tun
{

// Why a namespace name is on this invocation's books.
enum class NamespaceOwnership
{
    // Absent before, created by this invocation. The only kind that may ever be deleted.
    CreatedHere,
    // Somebody else created it and this invocation was only allowed to use it. It keeps its
    // original owner, so it is never deleted here.
    Reused,
};

struct NamespaceRecord
{
    std::string name;
    NamespaceOwnership ownership{NamespaceOwnership::CreatedHere};
    // The identity seen when the record was made. It is what turns a name into "this very
    // namespace": a name alone proves nothing once the namespace behind it can change.
    NamespaceIdentity identity{};
};

// What the cleanup path may do about a namespace.
enum class CleanupDecision
{
    Delete,
    LeaveIntact,
};

// What a cleanup attempt actually did. A refusal and a failure are reported as themselves so
// that a cleanup which did nothing is never presented as a cleanup that succeeded.
enum class CleanupOutcome
{
    Deleted,       // deleted: created here, and still the same namespace instance
    NoRecord,      // nothing on the books, so nothing this invocation may delete
    NotOwned,      // on the books, but not created by this invocation
    AlreadyGone,   // the name no longer identifies any namespace
    Replaced,      // the name now identifies a different namespace
    Unverifiable,  // ownership could not be established; left intact on purpose
    DeleteFailed,  // the delete command did not succeed; the namespace is left in place
};

// Decides whether a namespace may be deleted right now. A record alone is never enough: the
// namespace must have been created by this invocation and must still be the very same
// instance. Anything else is left intact, and a namespace whose identity cannot be
// established is left intact too — a preserved namespace is preferable to deleting one that
// belongs to somebody else.
CleanupDecision DecideNamespaceCleanup(const NamespaceRecord &record, const NamespaceState &now);

// Puts a namespace name on the books together with the ownership it actually has and the
// identity observed at that moment. An existing namespace is never recorded as created here.
void RecordNamespace(const std::string &name, NamespaceOwnership ownership, const NamespaceIdentity &identity);

// Copies out the record for this name without consuming it, so a caller can check ownership
// and identity without taking the namespace off the books. Returns false when there is none.
bool FindNamespaceRecord(const std::string &name, NamespaceRecord &record);

// Removes and returns the record for this name. Consuming the record is what makes a second
// cleanup call a no-op instead of a second delete. Returns false when there is none.
bool TakeNamespaceRecord(const std::string &name, NamespaceRecord &record);

// Deletes the namespace only when this invocation created it and it is still the same
// instance. Reports what happened, so a refused or failed delete is never claimed as a
// successful one.
CleanupOutcome CleanupOwnedNamespace(const std::string &name);

// Runs the same rule over every namespace on the books. Used for shutdown cleanup, so it
// deletes only what this invocation can still prove it created.
void CleanupAllOwnedNamespaces();

// How many namespace records are still on the books.
int NamespaceRecordCount();

// Test seam. Drops every record without deleting anything. Tests only.
void ClearNamespaceRecordsForTesting();

} // namespace nr::ue::tun
