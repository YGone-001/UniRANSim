//
// This file is a part of UERANSIM project.
// Copyright (c) 2027 ALİ GÜNGÖR.
//
// https://github.com/aligungr/UERANSIM/
// See README, LICENSE, and CONTRIBUTING files for licensing details.
//

// Tracking area identity and tracking area identity list, TS 24.301 9.9.3.32
// and 9.9.3.33.
//
// The TAI list information element is not a flat array of TAIs. Its value is a
// concatenation of independently headed sub-lists, and each sub-list header
// selects one of three different layouts. Membership therefore cannot be
// decided by walking the raw octets: the whole value has to be parsed and
// validated first, and only the resulting explicit TAIs may be consulted.

#pragma once

#include <array>
#include <cstdint>
#include <string>
#include <vector>

#include <lte/enb/types.hpp>

namespace lte::ue
{

// One tracking area identity: a PLMN and the TAC within it.
struct Tai
{
    enb::Plmn plmn;
    uint16_t tac{};
};

bool operator==(const Tai &left, const Tai &right);
bool operator!=(const Tai &left, const Tai &right);

// The three sub-list forms of the TS 24.301 9.9.3.33 TAI list value. The wire
// header octet is spare:1 | type:2 | num:5 counting from the most significant
// bit, and num is always one less than the number of tracking areas the
// sub-list carries. The spare bit is ignored on receipt per TS 24.007.
//
// The forms are named after the layouts below, which are the ones Open5GS
// builds in ogs_nas_tai_list_build and matches in mme_find_served_tai.
enum class TaiListForm : uint8_t
{
    // type 0: one PLMN followed by num+1 explicitly listed TACs, so the
    // sub-list occupies 1 + 3 + 2*(num+1) octets.
    OnePlmnListedTacs = 0,
    // type 1: one PLMN and a single TAC on the wire, in exactly 6 octets. The
    // num field does not count entries here: it extends that TAC into a run of
    // num+1 consecutive TACs starting at it.
    OnePlmnConsecutiveTacs = 1,
    // type 2: num+1 pairs of (PLMN, TAC) in 1 + 5*(num+1) octets, one TAC per
    // PLMN.
    SeveralPlmns = 2,
};

// Upper bound on a TAI list IE value. TS 24.301 9.9.3.33 caps the contents at
// 98 octets; anything longer is not a legal assignment.
inline constexpr size_t MaxTaiListValueLength = 98;

// Defensive bound on how many explicit TAIs one parsed list may expand to. A
// type 1 sub-list expands a single range, so the expanded count can exceed the
// number of on-wire TAIs. This is a work bound, not a protocol claim.
inline constexpr size_t MaxParsedTaiCount = 256;

// Returns an empty string when `value` is a well-formed TAI list information
// element value, and otherwise a description of the first defect found. The
// value is the IE contents only: no IEI and no length octet.
std::string TaiListError(const std::vector<uint8_t> &value);

// Parses `value` into the explicit tracking area identities it authorizes.
// Every sub-list is validated before anything is believed, so a partially
// valid or truncated value yields no TAIs at all rather than a partial grant.
// Returns true only when the whole value parsed and `out` was filled.
bool ParseTaiList(const std::vector<uint8_t> &value, std::vector<Tai> &out);

// True when `list` explicitly contains `tai`. An empty list contains nothing.
bool TaiListContains(const std::vector<Tai> &list, const Tai &tai);

// True when both PLMNs encode to the same three octets. A PLMN that cannot be
// encoded is never equal to anything.
bool SamePlmn(const enb::Plmn &left, const enb::Plmn &right);

} // namespace lte::ue
