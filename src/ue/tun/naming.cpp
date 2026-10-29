//
// This file is a part of UERANSIM project.
// Copyright (c) 2027 ALİ GÜNGÖR.
//
// https://github.com/aligungr/UERANSIM/
// See README, LICENSE, and CONTRIBUTING files for licensing details.
//

#include "naming.hpp"

#include <cctype>
#include <cstring>

namespace nr::ue::tun
{
namespace
{

// How many generated names are tried for one prefix before it is called exhausted.
constexpr int MaxInterfaceCount = 1024;

// The accepted identifier characters: letters, digits, '_' and, after the first position,
// '-' and '.'. A leading '-' or '.' would read as a command-line option or a relative path,
// so those are refused rather than worked around. Anything else — whitespace, quotes,
// backticks, '$', ';', '|', '<', '>', newlines, control characters, '/' — is refused too,
// which is what keeps an identifier from ever becoming part of a command's structure.
bool IsIdentifierChar(char c, bool first)
{
    const auto u = static_cast<unsigned char>(c);
    if (std::isalnum(u) != 0 || c == '_')
        return true;
    return !first && (c == '-' || c == '.');
}

bool IsIdentifier(const std::string &value)
{
    for (std::size_t i = 0; i < value.size(); ++i)
    {
        if (!IsIdentifierChar(value[i], i == 0))
            return false;
    }
    return true;
}

} // namespace

std::string InterfacePrefixError(const std::string &prefix)
{
    if (prefix.empty())
        return "the interface name prefix is empty";
    if (prefix.size() > MaxInterfacePrefixLength)
        return "the interface name prefix is longer than " + std::to_string(MaxInterfacePrefixLength) +
               " characters, so no name generated from it would fit an interface name";
    if (!IsIdentifier(prefix))
        return "the interface name prefix contains an unsupported character";
    return {};
}

std::string NamespaceNameError(const std::string &name)
{
    if (name.empty())
        return "the namespace name is empty";
    if (name.size() > MaxNamespaceNameLength)
        return "the namespace name is longer than " + std::to_string(MaxNamespaceNameLength) + " characters";
    if (!IsIdentifier(name))
        return "the namespace name contains an unsupported character";
    return {};
}

std::string ComposeNamespaceName(const std::string &prefix, const std::string &identity, const std::string &apn,
                                 int psi, std::string &error)
{
    struct Part
    {
        const char *label;
        std::string value;
    };

    // An APN that carries no characters at all names no access point, and it has always been
    // written as 'default'. That is a fixed literal standing in for a missing value, not a
    // rewriting of whatever was configured: anything actually written down is still refused
    // below unless it is a usable identifier on its own.
    std::string apnPart = apn.empty() ? std::string{"default"} : apn;

    const Part parts[] = {
        {"the namespace name prefix", prefix},
        {"the subscriber identity", identity},
        {"the access point name", std::move(apnPart)},
    };

    std::string built;
    for (const auto &part : parts)
    {
        const std::string reason = NamespaceNameError(part.value);
        if (!reason.empty())
        {
            error = std::string(part.label) + " cannot be part of a namespace name: " + reason;
            return {};
        }
        if (!built.empty())
            built += '-';
        built += part.value;
    }

    // The PSI keeps the PDU sessions of one subscriber apart, even on the same access point.
    built += "-psi" + std::to_string(psi);

    const std::string reason = NamespaceNameError(built);
    if (!reason.empty())
    {
        error = "the namespace name cannot be used: " + reason;
        return {};
    }

    error.clear();
    return built;
}

std::string NextInterfaceName(const std::string &prefix, const std::set<std::string> &existing)
{
    for (int i = 0; i < MaxInterfaceCount; ++i)
    {
        std::string name = prefix + std::to_string(i);
        // A name that would not fit is skipped rather than cut down to size. Cutting it
        // would produce a shorter name that may already belong to another interface.
        if (name.size() > MaxInterfaceNameLength)
            continue;
        if (existing.count(name) == 0)
            return name;
    }
    return {};
}

bool IsUsableInterfaceName(const std::string &name)
{
    return !name.empty() && name.size() <= MaxInterfaceNameLength && IsIdentifier(name);
}

bool CopyInterfaceName(char *dest, std::size_t destSize, const std::string &name)
{
    if (dest == nullptr || destSize == 0 || name.size() >= destSize)
        return false;
    if (!IsUsableInterfaceName(name))
        return false;
    std::memcpy(dest, name.c_str(), name.size() + 1);
    return true;
}

} // namespace nr::ue::tun
