//
// This file is a part of UERANSIM project.
// Copyright (c) 2027 ALİ GÜNGÖR.
//
// https://github.com/aligungr/UERANSIM/
// See README, LICENSE, and CONTRIBUTING files for licensing details.
//

#pragma once

#include <cstddef>
#include <net/if.h>
#include <set>
#include <string>

namespace nr::ue::tun
{

// The kernel stores an interface name in an IFNAMSIZ buffer together with its terminator, so
// the longest name that can be used is one character shorter. Every generated name is
// measured against this before it reaches any fixed-size buffer.
constexpr std::size_t MaxInterfaceNameLength = IFNAMSIZ - 1;

static_assert(MaxInterfaceNameLength + 1 == IFNAMSIZ,
              "an interface name must fit its buffer together with its terminator");

// The longest interface-name prefix that can still produce a name at all: at least one index
// digit has to fit next to it. This equals the longest prefix the LTE configuration parser
// accepts, so every prefix that was valid before is still valid here.
constexpr std::size_t MaxInterfacePrefixLength = MaxInterfaceNameLength - 1;

// Namespace names live in the filesystem, and the NR caller already refuses more than 255
// characters, so that remains the supported limit.
constexpr std::size_t MaxNamespaceNameLength = 255;

// Why this cannot be used as an interface-name prefix, or an empty string when it can. An
// empty prefix, a prefix too long to ever name an interface and a prefix holding anything
// outside the accepted identifier characters are all refused here, so no caller has to
// remember the rules and no prefix is silently rewritten into a different one.
std::string InterfacePrefixError(const std::string &prefix);

// Why this cannot be used as a namespace name, or an empty string when it can. The accepted
// grammar is deliberately narrow so that an unsafe name is rejected outright rather than
// rewritten into some other name that may already belong to a real namespace.
std::string NamespaceNameError(const std::string &name);

// Builds the namespace name for one PDU session out of parts that are each checked on their
// own before they are joined. A part that is not usable on its own is refused and named in
// 'error', and nothing is rewritten: turning an unsafe value into a different, shorter name
// could silently address a namespace that already exists and belongs to someone else.
//
// An absent or empty APN has always been written as the literal 'default', which stands in
// for a missing value rather than renaming anything configured. The result is returned as an
// empty string when it cannot be used.
std::string ComposeNamespaceName(const std::string &prefix, const std::string &identity, const std::string &apn,
                                 int psi, std::string &error);

// The first unused name of the form <prefix><index> that also fits a kernel interface name,
// or an empty string when no such candidate exists. A candidate that would not fit is
// skipped, never shortened: a shortened name would silently address a different interface.
// The prefix is expected to have passed InterfacePrefixError already.
std::string NextInterfaceName(const std::string &prefix, const std::set<std::string> &existing);

// Whether this can be used as an interface name at all: non-empty, no longer than the
// longest usable name, and made only of accepted identifier characters.
bool IsUsableInterfaceName(const std::string &name);

// Copies an interface name into a fixed kernel-sized buffer together with its terminator, or
// reports that it does not fit or is not usable. There is no truncating copy anywhere in the
// shared TUN code, so this is the only way a name reaches a fixed buffer.
bool CopyInterfaceName(char *dest, std::size_t destSize, const std::string &name);

} // namespace nr::ue::tun
