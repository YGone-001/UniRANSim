//
// This file is a part of UERANSIM project.
// Copyright (c) 2027 ALİ GÜNGÖR.
//
// https://github.com/aligungr/UERANSIM/
// See README, LICENSE, and CONTRIBUTING files for licensing details.
//
// Tracking area identity list parsing and membership. The list value is a
// concatenation of independently headed sub-lists, so these cases cover every
// sub-list form and the combinations a single-sub-list parser cannot read.

#include <ext/doctest/doctest.h>

#include <lte/ue/tai.hpp>

namespace
{

using lte::ue::ParseTaiList;
using lte::ue::SamePlmn;
using lte::ue::Tai;
using lte::ue::TaiListContains;
using lte::ue::TaiListError;

Tai T(const char *mcc, const char *mnc, uint16_t tac)
{
    return Tai{{mcc, mnc}, tac};
}

// The exact assignment a live Open5GS MME sent in Attach Accept: type 2 form,
// one PLMN 460/02 and one TAC 1.
std::vector<uint8_t> Open5gsSingleTai()
{
    return {0x40, 0x64, 0xF0, 0x20, 0x00, 0x01};
}

// Type 0 form: PLMN 460/02 with the TACs 1, 2 and 3 listed explicitly.
std::vector<uint8_t> ListedTacs()
{
    return {0x02, 0x64, 0xF0, 0x20, 0x00, 0x01, 0x00, 0x02, 0x00, 0x03};
}

// Type 1 form: PLMN 460/02 and a run of three consecutive TACs from 2. Only
// the first TAC is on the wire; the header carries the run length.
std::vector<uint8_t> ConsecutiveTacs()
{
    return {0x22, 0x64, 0xF0, 0x20, 0x00, 0x02};
}

// Type 2 form: three different PLMNs, one TAC each.
std::vector<uint8_t> SeveralPlmns()
{
    return {0x42, 0x64, 0xF0, 0x20, 0x00, 0x01, 0x64, 0xF0, 0x30, 0x00,
            0x02, 0x64, 0xF0, 0x40, 0x00, 0x03};
}

std::vector<Tai> Parse(const std::vector<uint8_t> &value)
{
    std::vector<Tai> parsed;
    REQUIRE(ParseTaiList(value, parsed));
    return parsed;
}

} // namespace

TEST_CASE("lte/tai: the live Open5GS single-TAI assignment authorizes exactly one tracking area")
{
    CHECK(TaiListError(Open5gsSingleTai()).empty());
    const auto parsed = Parse(Open5gsSingleTai());
    REQUIRE(parsed.size() == 1);
    CHECK(parsed[0] == T("460", "02", 1));
    CHECK(TaiListContains(parsed, T("460", "02", 1)));
    CHECK_FALSE(TaiListContains(parsed, T("460", "02", 2)));
    CHECK_FALSE(TaiListContains(parsed, T("460", "02", 0)));
    CHECK_FALSE(TaiListContains(parsed, T("460", "01", 1)));
    CHECK_FALSE(TaiListContains(parsed, T("310", "02", 1)));
}

TEST_CASE("lte/tai: a type 0 sub-list lists its tracking area codes explicitly")
{
    const auto parsed = Parse(ListedTacs());
    REQUIRE(parsed.size() == 3);
    CHECK(parsed[0] == T("460", "02", 1));
    CHECK(parsed[1] == T("460", "02", 2));
    CHECK(parsed[2] == T("460", "02", 3));
    // The codes are a set, not a progression: nothing between or beyond them
    // is authorized by listing them.
    CHECK_FALSE(TaiListContains(parsed, T("460", "02", 4)));
}

TEST_CASE("lte/tai: a type 1 sub-list covers the whole run of consecutive tracking area codes")
{
    // The run length lives in the header, so the value is the same six octets
    // whether it names one tracking area or many.
    CHECK(TaiListError(ConsecutiveTacs()).empty());
    const auto parsed = Parse(ConsecutiveTacs());
    REQUIRE(parsed.size() == 3);
    CHECK(parsed[0] == T("460", "02", 2));
    CHECK(parsed[1] == T("460", "02", 3));
    CHECK(parsed[2] == T("460", "02", 4));
    CHECK(TaiListContains(parsed, T("460", "02", 2)));
    CHECK(TaiListContains(parsed, T("460", "02", 3)));
    CHECK(TaiListContains(parsed, T("460", "02", 4)));
    CHECK_FALSE(TaiListContains(parsed, T("460", "02", 1)));
    CHECK_FALSE(TaiListContains(parsed, T("460", "02", 5)));
}

TEST_CASE("lte/tai: a type 2 sub-list pairs each tracking area with its own PLMN")
{
    const auto parsed = Parse(SeveralPlmns());
    REQUIRE(parsed.size() == 3);
    CHECK(parsed[0] == T("460", "02", 1));
    CHECK(parsed[1] == T("460", "03", 2));
    CHECK(parsed[2] == T("460", "04", 3));
    CHECK(TaiListContains(parsed, T("460", "03", 2)));
    CHECK_FALSE(TaiListContains(parsed, T("460", "02", 2)));
    CHECK_FALSE(TaiListContains(parsed, T("460", "03", 3)));
}

TEST_CASE("lte/tai: one value may concatenate several independently headed sub-lists")
{
    // Type 0 with two listed TACs, then a type 2 entry for a second PLMN. Each
    // sub-list brings its own header, so a parser that reads the value as one
    // list cannot make sense of it at all.
    const std::vector<uint8_t> value{0x01, 0x64, 0xF0, 0x20, 0x00, 0x01, 0x00, 0x02,
                                     0x40, 0x64, 0xF0, 0x30, 0x00, 0x07};
    const auto parsed = Parse(value);
    REQUIRE(parsed.size() == 3);
    CHECK(parsed[0] == T("460", "02", 1));
    CHECK(parsed[1] == T("460", "02", 2));
    CHECK(parsed[2] == T("460", "03", 7));
    CHECK(TaiListContains(parsed, T("460", "03", 7)));
    CHECK_FALSE(TaiListContains(parsed, T("460", "03", 8)));

    // A run of consecutive codes and a listed set may also appear together.
    const std::vector<uint8_t> mixed{0x21, 0x64, 0xF0, 0x20, 0x00, 0x0A, 0x01, 0x64,
                                     0xF0, 0x20, 0x00, 0x14, 0x00, 0x15};
    const auto mixedParsed = Parse(mixed);
    REQUIRE(mixedParsed.size() == 4);
    CHECK(mixedParsed[0] == T("460", "02", 10));
    CHECK(mixedParsed[1] == T("460", "02", 11));
    CHECK(mixedParsed[2] == T("460", "02", 20));
    CHECK(mixedParsed[3] == T("460", "02", 21));
}

TEST_CASE("lte/tai: all three sub-list forms agree when they name a single tracking area")
{
    const auto one = Parse({0x00, 0x64, 0xF0, 0x20, 0x00, 0x01});
    const auto run = Parse({0x20, 0x64, 0xF0, 0x20, 0x00, 0x01});
    const auto pair = Parse(Open5gsSingleTai());
    REQUIRE(one.size() == 1);
    REQUIRE(run.size() == 1);
    REQUIRE(pair.size() == 1);
    CHECK(one[0] == run[0]);
    CHECK(run[0] == pair[0]);
    CHECK(one[0] == T("460", "02", 1));
}

TEST_CASE("lte/tai: the header spare bit is ignored on receipt")
{
    // TS 24.007: spare bits are sent as zero and ignored by the receiver. The
    // type occupies two bits, so a spare bit must not shift the type reading.
    const std::vector<uint8_t> withSpare{0xC0, 0x64, 0xF0, 0x20, 0x00, 0x01};
    const auto parsed = Parse(withSpare);
    REQUIRE(parsed.size() == 1);
    CHECK(parsed[0] == T("460", "02", 1));
}

TEST_CASE("lte/tai: a reserved sub-list type is refused")
{
    // Type 3 is not defined. Reading the type as three bits would make this
    // look like a valid entry instead of the reserved value it is.
    const std::vector<uint8_t> reserved{0x60, 0x64, 0xF0, 0x20, 0x00, 0x01};
    CHECK_FALSE(TaiListError(reserved).empty());
    std::vector<Tai> parsed;
    CHECK_FALSE(ParseTaiList(reserved, parsed));
    CHECK(parsed.empty());
}

TEST_CASE("lte/tai: a truncated or inconsistent sub-list grants nothing")
{
    std::vector<Tai> parsed;
    const std::vector<std::vector<uint8_t>> malformed{
        {},                                    // no value at all
        {0x00},                                // header only
        {0x40, 0x64, 0xF0, 0x20},              // type 2 cut short
        {0x02, 0x64, 0xF0, 0x20, 0x00, 0x01},  // type 0 names three TACs, carries one
        {0x21, 0x64, 0xF0, 0x20, 0x00, 0x02, 0x00}, // a trailing octet starts a sub-list of its own
        {0x22, 0x64, 0xF0, 0x20, 0x00},        // type 1 is a fixed six octets
    };
    for (const auto &value : malformed)
    {
        CAPTURE(value.size());
        CHECK_FALSE(TaiListError(value).empty());
        CHECK_FALSE(ParseTaiList(value, parsed));
        // Refusing the value means refusing all of it: no partial grant.
        CHECK(parsed.empty());
    }

    // A valid sub-list followed by a broken one is refused whole, so the good
    // part cannot be used to smuggle in the bad one.
    const std::vector<uint8_t> partlyGood{0x40, 0x64, 0xF0, 0x20, 0x00, 0x01, 0x40, 0x64};
    CHECK_FALSE(TaiListError(partlyGood).empty());
    CHECK_FALSE(ParseTaiList(partlyGood, parsed));
    CHECK(parsed.empty());
}

TEST_CASE("lte/tai: a sub-list with an unencodable PLMN is refused")
{
    std::vector<Tai> parsed;
    // The PLMN carries BCD digits, so a nibble above 9 is not a digit. The
    // third octet's low nibble is the first MNC digit; the filler 0xF is only
    // tolerated in the position that marks a two-digit MNC.
    CHECK_FALSE(TaiListError({0x40, 0x6A, 0xF0, 0x20, 0x00, 0x01}).empty());
    CHECK_FALSE(ParseTaiList({0x40, 0x6A, 0xF0, 0x20, 0x00, 0x01}, parsed));
    CHECK_FALSE(TaiListError({0x40, 0x64, 0xF0, 0xFA, 0x00, 0x01}).empty());
    CHECK_FALSE(ParseTaiList({0x40, 0x64, 0xF0, 0xFA, 0x00, 0x01}, parsed));
    CHECK(parsed.empty());
}

TEST_CASE("lte/tai: a type 1 run may not overflow the tracking area code space")
{
    std::vector<Tai> parsed;
    // A run of two starting at 0xFFFF would reach 0x10000, which no tracking
    // area code can hold.
    CHECK_FALSE(TaiListError({0x21, 0x64, 0xF0, 0x20, 0xFF, 0xFF}).empty());
    CHECK_FALSE(ParseTaiList({0x21, 0x64, 0xF0, 0x20, 0xFF, 0xFF}, parsed));
    // A run of one ending exactly at 0xFFFF is fine.
    CHECK(TaiListError({0x20, 0x64, 0xF0, 0x20, 0xFF, 0xFF}).empty());
    const auto edge = Parse({0x20, 0x64, 0xF0, 0x20, 0xFF, 0xFF});
    REQUIRE(edge.size() == 1);
    CHECK(edge[0] == T("460", "02", 0xFFFF));
}

TEST_CASE("lte/tai: a tracking area list value is bounded")
{
    std::vector<Tai> parsed;
    // Sixteen type 2 sub-lists fill 96 octets and stay legal; one more takes
    // the value past the information element's limit.
    std::vector<uint8_t> tooLong;
    for (size_t i = 0; i < 17; ++i)
    {
        tooLong.push_back(0x40);
        tooLong.insert(tooLong.end(), {0x64, 0xF0, 0x20, 0x00, static_cast<uint8_t>(i + 1)});
    }
    CHECK(tooLong.size() == 102);
    CHECK_FALSE(TaiListError(tooLong).empty());
    CHECK_FALSE(ParseTaiList(tooLong, parsed));
    CHECK(parsed.empty());

    std::vector<uint8_t> atLimit;
    for (size_t i = 0; i < 16; ++i)
    {
        atLimit.push_back(0x40);
        atLimit.insert(atLimit.end(), {0x64, 0xF0, 0x20, 0x00, static_cast<uint8_t>(i + 1)});
    }
    CHECK(atLimit.size() == 96);
    CHECK(TaiListError(atLimit).empty());
    CHECK(Parse(atLimit).size() == 16);
}

TEST_CASE("lte/tai: a tracking area named twice authorizes nothing it did not already")
{
    // Nothing in the encoding forbids a sub-list from repeating itself, or one
    // value from naming the same tracking area through two different sub-list
    // forms, so such a list is accepted as written. What must not happen is the
    // repetition being read as a wider grant: the authorized set is the set of
    // distinct tracking areas, however often and in whatever shape they arrive.
    const std::vector<uint8_t> repeated{0x01, 0x64, 0xF0, 0x20, 0x00, 0x01, 0x00, 0x01};
    CHECK(TaiListError(repeated).empty());
    const auto parsed = Parse(repeated);
    REQUIRE(parsed.size() == 2);
    CHECK(parsed[0] == T("460", "02", 1));
    CHECK(parsed[1] == T("460", "02", 1));
    CHECK(TaiListContains(parsed, T("460", "02", 1)));
    CHECK_FALSE(TaiListContains(parsed, T("460", "02", 2)));
    CHECK_FALSE(TaiListContains(parsed, T("460", "01", 1)));

    // The same tracking area reached through a run of consecutive codes and
    // through an explicit listing is still one tracking area, not two.
    const std::vector<uint8_t> acrossForms{0x21, 0x64, 0xF0, 0x20, 0x00, 0x01,
                                           0x01, 0x64, 0xF0, 0x20, 0x00, 0x02, 0x00, 0x01};
    const auto mixed = Parse(acrossForms);
    REQUIRE(mixed.size() == 4);
    CHECK(mixed[0] == T("460", "02", 1));
    CHECK(mixed[1] == T("460", "02", 2));
    CHECK(mixed[2] == T("460", "02", 2));
    CHECK(mixed[3] == T("460", "02", 1));
    CHECK(TaiListContains(mixed, T("460", "02", 1)));
    CHECK(TaiListContains(mixed, T("460", "02", 2)));
    CHECK_FALSE(TaiListContains(mixed, T("460", "02", 3)));

    // Repetition still costs expansion budget, so one tracking area cannot be
    // repeated into the appearance of the whole code space. A type 1 run of
    // thirty-two occupies six octets whether or not any other sub-list already
    // covers the same codes.
    std::vector<uint8_t> atBudget;
    for (size_t i = 0; i < 8; ++i)
        atBudget.insert(atBudget.end(), {0x3F, 0x64, 0xF0, 0x20, 0x00, 0x01});
    CHECK(atBudget.size() == 48);
    CHECK(TaiListError(atBudget).empty());
    CHECK(Parse(atBudget).size() == 256);

    std::vector<uint8_t> inflated;
    for (size_t i = 0; i < 9; ++i)
        inflated.insert(inflated.end(), {0x3F, 0x64, 0xF0, 0x20, 0x00, 0x01});
    // Nine such runs all starting at TAC 1 would expand to 288 entries, well
    // inside the 98-octet wire limit and well outside the parsed bound.
    CHECK(inflated.size() == 54);
    CHECK_FALSE(TaiListError(inflated).empty());
    std::vector<Tai> parsedInflated;
    CHECK_FALSE(ParseTaiList(inflated, parsedInflated));
    CHECK(parsedInflated.empty());
}

TEST_CASE("lte/tai: PLMN identity comparison uses the encoded form")
{
    CHECK(SamePlmn({"460", "02"}, {"460", "02"}));
    CHECK_FALSE(SamePlmn({"460", "02"}, {"460", "03"}));
    CHECK_FALSE(SamePlmn({"460", "02"}, {"461", "02"}));
    // A two-digit and a three-digit MNC are different operators.
    CHECK_FALSE(SamePlmn({"460", "02"}, {"460", "002"}));
    // Something that is not a PLMN is never equal to anything, not even to
    // itself, because it cannot be placed on the wire at all.
    CHECK_FALSE(SamePlmn({"46", "02"}, {"46", "02"}));
    CHECK_FALSE(SamePlmn({"460", "0x"}, {"460", "0x"}));
    CHECK_FALSE(SamePlmn({"460", "0"}, {"460", "0"}));

    CHECK(T("460", "02", 1) == T("460", "02", 1));
    CHECK(T("460", "02", 1) != T("460", "02", 2));
    CHECK(T("460", "02", 1) != T("460", "03", 1));
}

TEST_CASE("lte/tai: an empty parsed list authorizes nothing")
{
    CHECK_FALSE(TaiListContains({}, T("460", "02", 1)));
    CHECK(TaiListContains({T("460", "02", 1)}, T("460", "02", 1)));
}
