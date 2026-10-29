//
// This file is a part of UERANSIM project.
// Copyright (c) 2027 ALİ GÜNGÖR.
//
// https://github.com/aligungr/UERANSIM/
// See README, LICENSE, and CONTRIBUTING files for licensing details.
//

#include <cstring>
#include <set>
#include <string>
#include <vector>

#include <ext/doctest/doctest.h>
#include <ue/tun/naming.hpp>

using nr::ue::tun::ComposeNamespaceName;
using nr::ue::tun::CopyInterfaceName;
using nr::ue::tun::InterfacePrefixError;
using nr::ue::tun::IsUsableInterfaceName;
using nr::ue::tun::MaxInterfaceNameLength;
using nr::ue::tun::MaxInterfacePrefixLength;
using nr::ue::tun::MaxNamespaceNameLength;
using nr::ue::tun::NamespaceNameError;
using nr::ue::tun::NextInterfaceName;

namespace
{

// The longest prefix the LTE configuration parser accepts, which is also the longest one that
// can still produce a name at all.
std::string LongestPrefix()
{
    return std::string(MaxInterfacePrefixLength, 'p');
}

std::set<std::string> Names(const std::vector<std::string> &values)
{
    return std::set<std::string>(values.begin(), values.end());
}

} // namespace

TEST_CASE("ue/tun/naming: an empty interface prefix is refused")
{
    CHECK_FALSE(InterfacePrefixError("").empty());
}

TEST_CASE("ue/tun/naming: the historical LTE and NR prefixes are accepted")
{
    CHECK(InterfacePrefixError("uniransim-lte").empty());
    CHECK(InterfacePrefixError("uesimtun").empty());
}

TEST_CASE("ue/tun/naming: a prefix at the parser maximum produces the longest usable name exactly")
{
    const std::string prefix = LongestPrefix();
    REQUIRE(prefix.size() == MaxInterfacePrefixLength);
    CHECK(InterfacePrefixError(prefix).empty());

    const std::string name = NextInterfaceName(prefix, {});
    REQUIRE(name == prefix + "0");
    // The name fills the buffer right up to, but never past, the terminator.
    CHECK(name.size() == MaxInterfaceNameLength);

    char buffer[IFNAMSIZ];
    std::memset(buffer, 0xAB, sizeof(buffer));
    REQUIRE(CopyInterfaceName(buffer, sizeof(buffer), name));
    CHECK(std::string{buffer} == name);
    CHECK(buffer[name.size()] == '\0');
}

TEST_CASE("ue/tun/naming: a generated name never exceeds IFNAMSIZ - 1 for any accepted prefix")
{
    for (std::size_t length = 1; length <= MaxInterfacePrefixLength; ++length)
    {
        const std::string prefix(length, 'x');
        CAPTURE(length);
        CHECK(InterfacePrefixError(prefix).empty());

        // Walk the whole allocation sequence one prefix can produce and check every name it
        // hands back, right up to the point where it runs out.
        std::set<std::string> taken;
        for (int i = 0; i < 1024; ++i)
        {
            const std::string name = NextInterfaceName(prefix, taken);
            CAPTURE(i);
            if (name.empty())
                break;
            CHECK(name.size() <= MaxInterfaceNameLength);
            taken.insert(name);
        }
    }
}

TEST_CASE("ue/tun/naming: a prefix that fits index 9 but not index 10 still names index 9")
{
    const std::string prefix = LongestPrefix();
    const std::string forNine = prefix + "9";
    REQUIRE(forNine.size() == MaxInterfaceNameLength);

    // Index 9 is the last one that fits; index 10 would need one character more than the
    // kernel allows, so it is never produced and never cut down to size.
    CHECK(NextInterfaceName(prefix, Names({prefix + "0", prefix + "1", prefix + "2", prefix + "3", prefix + "4",
                                           prefix + "5", prefix + "6", prefix + "7", prefix + "8"})) == forNine);

    CHECK(NextInterfaceName(prefix, Names({prefix + "0", prefix + "1", prefix + "2", prefix + "3", prefix + "4",
                                           prefix + "5", prefix + "6", prefix + "7", prefix + "8", prefix + "9"}))
              .empty());
}

TEST_CASE("ue/tun/naming: a prefix longer than the parser maximum cannot name an interface")
{
    const std::string tooLong = std::string(MaxInterfacePrefixLength + 1, 'p');
    const std::string reason = InterfacePrefixError(tooLong);
    CHECK_FALSE(reason.empty());
    // The refusal is stated without echoing the offending input back.
    CHECK(reason.find(tooLong) == std::string::npos);
}

TEST_CASE("ue/tun/naming: existing names occupying indices 0 through 9 are skipped")
{
    std::vector<std::string> taken;
    for (int i = 0; i <= 9; ++i)
        taken.push_back("u" + std::to_string(i));
    CHECK(NextInterfaceName("u", Names(taken)) == "u10");
}

TEST_CASE("ue/tun/naming: existing names forcing index 10 or higher still produce a fitting name")
{
    const std::string prefix = "uniransim-lte";  // 13 characters, as the LTE default is
    std::vector<std::string> taken;
    for (int i = 0; i <= 9; ++i)
        taken.push_back(prefix + std::to_string(i));

    const std::string name = NextInterfaceName(prefix, Names(taken));
    REQUIRE(name == prefix + "10");
    CHECK(name.size() <= MaxInterfaceNameLength);
    CHECK(IsUsableInterfaceName(name));
}

TEST_CASE("ue/tun/naming: exhaustion of every safe candidate returns no name rather than a long one")
{
    std::set<std::string> taken;
    for (int i = 0; i < 1024; ++i)
        taken.insert("u" + std::to_string(i));

    CHECK(NextInterfaceName("u", taken).empty());
}

TEST_CASE("ue/tun/naming: a long prefix runs out at index 10 and reports nothing rather than overflowing")
{
    const std::string prefix = LongestPrefix();
    std::set<std::string> taken;
    for (int i = 0; i <= 9; ++i)
        taken.insert(prefix + std::to_string(i));

    CHECK(NextInterfaceName(prefix, taken).empty());
}

TEST_CASE("ue/tun/naming: a prefix holding shell syntax or separators is refused")
{
    const std::vector<std::string> illegal = {
        "a b",   "a;b",   "a`b",   "a$(b)",  "a|b",   "a>b",    "a<b",    "a'b",    "a\"b",  "a\\b",  "a/b",
        "a\nb",  "a\tb",  std::string{"a"} + '\0' + "b", std::string{"a"} + '\x01' + "b", "-abc", ".abc",
        "a:b",   "a*b",   "a?b",   "a[b]",   "a{b}",  "a~b",    "a!b",    "a&b",    "a#b",   "a%b",   "a=b",
        "a+b",   "a@b",
    };
    for (const auto &prefix : illegal)
    {
        CAPTURE(prefix);
        CHECK_FALSE(InterfacePrefixError(prefix).empty());
    }
}

TEST_CASE("ue/tun/naming: a namespace name holding shell syntax or separators is refused")
{
    const std::vector<std::string> illegal = {
        "p6ns7;x",   "p6ns7 x",   "p6ns7`x`",  "p6ns7$(x)", "p6ns7|x",   "p6ns7>x",  "p6ns7<x",  "p6ns7'x'",
        "p6ns7\"x\"", "p6ns7\\x", "p6ns7/x",   "p6ns7\nx",  "p6ns7\tx",  std::string{"p6ns7"} + '\0' + "x",
        std::string{"p6ns7"} + '\x01' + "x",   "-p6ns7",    ".p6ns7",    "p6ns7:x",  "p6ns7*x",  "p6ns7?x",
        "p6ns7~x",   "p6ns7!x",   "p6ns7&x",   "p6ns7#x",
    };
    for (const auto &name : illegal)
    {
        CAPTURE(name);
        CHECK_FALSE(NamespaceNameError(name).empty());
    }
}

TEST_CASE("ue/tun/naming: an empty or over-long namespace name is refused")
{
    CHECK_FALSE(NamespaceNameError("").empty());
    CHECK_FALSE(NamespaceNameError(std::string(MaxNamespaceNameLength + 1, 'n')).empty());
    CHECK(NamespaceNameError(std::string(MaxNamespaceNameLength, 'n')).empty());
    CHECK(NamespaceNameError("uesimtun-imsi460200000000007-internet-psi1").empty());
}

TEST_CASE("ue/tun/naming: a refused name is never rewritten into a different usable one")
{
    // The rule is reject, not repair: what comes back is a reason, never a cleaned-up name
    // that could happen to belong to a real namespace.
    for (const auto &name : {"p6ns7/x", "p6ns7 x", "p6ns7;x", "-p6ns7", ""})
    {
        CAPTURE(name);
        const std::string reason = NamespaceNameError(name);
        REQUIRE_FALSE(reason.empty());
        CHECK(reason.find("p6ns7-x") == std::string::npos);
    }
}

TEST_CASE("ue/tun/naming: an interface name is copied into a buffer only when it fits with its terminator")
{
    char buffer[IFNAMSIZ];

    std::memset(buffer, 0xAB, sizeof(buffer));
    REQUIRE(CopyInterfaceName(buffer, sizeof(buffer), std::string(MaxInterfaceNameLength, 'n')));
    CHECK(buffer[MaxInterfaceNameLength] == '\0');

    // One character too long: refused, and the destination is not touched at all.
    const std::string tooLong = std::string(MaxInterfaceNameLength + 1, 'n');
    std::memset(buffer, 0xAB, sizeof(buffer));
    CHECK_FALSE(CopyInterfaceName(buffer, sizeof(buffer), tooLong));
    for (char c : buffer)
        CHECK(c == static_cast<char>(0xAB));

    // A name with a character that cannot be an identifier is refused too.
    std::memset(buffer, 0xAB, sizeof(buffer));
    CHECK_FALSE(CopyInterfaceName(buffer, sizeof(buffer), "a b"));
    CHECK_FALSE(CopyInterfaceName(buffer, sizeof(buffer), "a;b"));
    CHECK_FALSE(CopyInterfaceName(buffer, sizeof(buffer), ""));
    for (char c : buffer)
        CHECK(c == static_cast<char>(0xAB));

    // A name that does not fit the buffer it is given is refused rather than cut to fit.
    char small[4];
    std::memset(small, 0xAB, sizeof(small));
    CHECK_FALSE(CopyInterfaceName(small, sizeof(small), "abcd"));
    CHECK_FALSE(CopyInterfaceName(nullptr, sizeof(buffer), "abc"));
    CHECK_FALSE(CopyInterfaceName(buffer, 0, "abc"));
}

TEST_CASE("ue/tun/naming: the same rules decide whether a name is usable at all")
{
    CHECK(IsUsableInterfaceName(std::string(MaxInterfaceNameLength, 'n')));
    CHECK_FALSE(IsUsableInterfaceName(std::string(MaxInterfaceNameLength + 1, 'n')));
    CHECK_FALSE(IsUsableInterfaceName(""));
    CHECK_FALSE(IsUsableInterfaceName("uniransim-lte with space"));
}

TEST_CASE("ue/tun/naming: a namespace name is composed the way it always has been")
{
    std::string error;
    // The name a laboratory configuration has produced up to now, unchanged.
    CHECK(ComposeNamespaceName("uniransim-nr", "460020000000007", "cmnet", 1, error) ==
          "uniransim-nr-460020000000007-cmnet-psi1");
    CHECK(error.empty());
    CHECK(ComposeNamespaceName("uesimtun", "460020000000008", "internet", 5, error) ==
          "uesimtun-460020000000008-internet-psi5");
    CHECK(error.empty());
}

TEST_CASE("ue/tun/naming: an access point that names nothing is written as the literal default")
{
    std::string error;
    // An absent or empty APN has never named anything, and it has always been written as
    // 'default'. That is the same name the old code produced, so nothing that used to work
    // stops working here.
    CHECK(ComposeNamespaceName("uniransim-nr", "460020000000007", "cmnet", 1, error) !=
          ComposeNamespaceName("uniransim-nr", "460020000000007", "", 1, error));
    CHECK(ComposeNamespaceName("uniransim-nr", "460020000000007", "", 1, error) ==
          "uniransim-nr-460020000000007-default-psi1");
    CHECK(error.empty());
}

TEST_CASE("ue/tun/naming: a composed name can never be a preserved laboratory namespace")
{
    std::string error;

    // 'p6ns7' and 'p6ns8' hold laboratory state that must never be addressed by name here.
    // A composed name always carries the separators between its parts, so it cannot collapse
    // onto either of them — even when the prefix is spelled exactly like one.
    const std::vector<std::string> prefixes = {"p6ns7", "p6ns8", "x", "", "uniransim-nr"};
    const std::vector<std::string> identities = {"p6ns7", "p6ns8", "460020000000007", "x"};
    const std::vector<std::string> apns = {"p6ns7", "p6ns8", "cmnet", "", "x"};

    for (const auto &prefix : prefixes)
    {
        for (const auto &identity : identities)
        {
            for (const auto &apn : apns)
            {
                for (int psi : {0, 1, 7, 8})
                {
                    const std::string name = ComposeNamespaceName(prefix, identity, apn, psi, error);
                    if (name.empty())
                        continue; // refused outright, which is safe too
                    CHECK(name != "p6ns7");
                    CHECK(name != "p6ns8");
                    // And the separators are always there, which is what makes the above true.
                    CHECK(name.find('-') != std::string::npos);
                    CHECK(NamespaceNameError(name).empty());
                }
            }
        }
    }
}

TEST_CASE("ue/tun/naming: an unsafe part is refused and named, never rewritten into another name")
{
    std::string error;

    for (const std::string &unsafe : {std::string{"p6ns7; rm -rf /"}, std::string{"x`id`"}, std::string{"x$(id)"},
                                      std::string{"p6ns7/x"}, std::string{"x y"}, std::string{"x\ny"},
                                      std::string(250, 'a')})
    {
        CAPTURE(unsafe);
        for (int which = 0; which < 3; ++which)
        {
            const std::string prefix = which == 0 ? unsafe : "uniransim-nr";
            const std::string identity = which == 1 ? unsafe : "460020000000007";
            const std::string apn = which == 2 ? unsafe : "cmnet";

            error.clear();
            const std::string name = ComposeNamespaceName(prefix, identity, apn, 1, error);
            // Nothing is produced, and nothing is silently turned into a shorter name that
            // could address somebody else's namespace.
            CHECK(name.empty());
            CHECK_FALSE(error.empty());
        }
    }
}

TEST_CASE("ue/tun/naming: a composition that would not fit is refused as a whole")
{
    std::string error;

    // Each part is a usable name on its own, but together they run past the limit.
    const std::string longIdentity(120, 'i');
    const std::string longApn(120, 'a');
    const std::string name = ComposeNamespaceName("uniransim-nr", longIdentity, longApn, 1, error);
    CHECK(name.empty());
    CHECK_FALSE(error.empty());

    // And the boundary itself is exact.
    std::string small = ComposeNamespaceName("x", "y", "z", 1, error);
    REQUIRE(small == "x-y-z-psi1");
    CHECK(NamespaceNameError(small).empty());
}

TEST_CASE("ue/tun/naming: no session identifier can add structure to a composed name")
{
    std::string error;

    for (int psi : {-1, 0, 1, 999999})
    {
        CAPTURE(psi);
        const std::string name = ComposeNamespaceName("uniransim-nr", "460020000000007", "cmnet", psi, error);
        if (name.empty())
        {
            CHECK_FALSE(error.empty());
            continue;
        }
        // Whatever the session number is, the result is still one identifier and nothing else.
        CHECK(NamespaceNameError(name).empty());
    }
}
