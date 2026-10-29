//
// This file is a part of UERANSIM project.
// Copyright (c) 2027 ALİ GÜNGÖR.
//
// https://github.com/aligungr/UERANSIM/
// See README, LICENSE, and CONTRIBUTING files for licensing details.
//

// Tracking Area Update Accept atomicity. One Accept carries several
// independent assignments (update result, GUTI, tracking area list, periodic
// timer, bearer context status) and every one of them is validated before any
// of them is committed, so an Accept malformed in any element must leave the
// bearer set, the GUTI, the tracking areas and the pending procedure
// byte-identical to what they were.

#include <ext/doctest/doctest.h>

#include <array>
#include <cstdint>
#include <optional>
#include <ostream>
#include <vector>

#include <lte/tft.hpp>
#include <lte/ue/bearer_runtime.hpp>
#include <lte/ue/lifecycle.hpp>
#include <lte/ue/nas.hpp>

namespace
{
using lte::ue::DedicatedBearerRuntime;
using lte::ue::EcmState;
using lte::ue::EmmState;
using lte::ue::EpsBearerState;
using lte::ue::MobilityContext;
using lte::ue::PendingProcedure;
using lte::ue::Tai;

// --- identity and assignment fixtures --------------------------------------

// The working 11-octet EPS GUTI: identity type 0x06, M-TMSI 0x12345678.
std::array<uint8_t, 11> Guti()
{
    return {0xF6, 0x64, 0xF0, 0x20, 0x00, 0x01, 0x01, 0x12, 0x34, 0x56, 0x78};
}

// A second, distinguishable usable GUTI: other MME code, other M-TMSI.
std::array<uint8_t, 11> FreshGuti()
{
    return {0xF6, 0x64, 0xF0, 0x20, 0x00, 0x01, 0x02, 0x87, 0x65, 0x43, 0x21};
}

// Unusable: the identity-type bits name identity type 5, not a GUTI (6).
std::array<uint8_t, 11> WrongTypeGuti()
{
    return {0xF5, 0x64, 0xF0, 0x20, 0x00, 0x01, 0x01, 0x12, 0x34, 0x56, 0x78};
}

// Unusable: identity type is a GUTI but the M-TMSI is zero, so no paging
// identity can ever be derived from it.
std::array<uint8_t, 11> ZeroMtmsiGuti()
{
    return {0xF6, 0x64, 0xF0, 0x20, 0x00, 0x01, 0x01, 0x00, 0x00, 0x00, 0x00};
}

// The exact TAI list assignment a live Open5GS MME sent in Attach Accept:
// type 2 form, one PLMN 460/02 and one TAC 1.
std::vector<uint8_t> AssignedTaiList()
{
    return {0x40, 0x64, 0xF0, 0x20, 0x00, 0x01};
}

// Type 1 form, PLMN 460/02, a run of two consecutive TACs starting at 2.
std::vector<uint8_t> AssignedTaiListRange()
{
    return {0x21, 0x64, 0xF0, 0x20, 0x00, 0x02};
}

// Malformed: the type 2 sub-list header promises one (PLMN, TAC) pair in six
// octets but the value stops after two, so ParseTaiList refuses the whole
// value as truncated and authorizes no tracking area at all.
std::vector<uint8_t> MalformedTaiList()
{
    return {0x40, 0x64};
}

// EPS bearer context status bit N reports EBI N (TS 24.301 9.9.2.1).
constexpr uint16_t AllBearers = 0x00E0;  // default 5 + dedicated 6 and 7
constexpr uint16_t DropSeven = 0x0060;   // dedicated EBI 7 no longer exists
constexpr uint16_t DropDefault = 0x00C0; // the active default bearer is gone

lte::tft::PacketFilter Filter(uint8_t id, uint16_t port)
{
    lte::tft::PacketFilter filter;
    filter.identifier = id;
    filter.precedence = id;
    filter.direction = lte::tft::FilterDirection::UPLINK_ONLY;
    filter.hasProtocol = true;
    filter.protocol = 17;
    filter.hasLocalPort = true;
    filter.localPortLow = filter.localPortHigh = port;
    return filter;
}

DedicatedBearerRuntime Dedicated(uint8_t ebi, uint8_t qci, uint16_t port, std::vector<uint8_t> epsQos)
{
    DedicatedBearerRuntime bearer;
    bearer.ebi = ebi;
    bearer.linkedEbi = 5;
    bearer.qci = qci;
    bearer.epsQos = std::move(epsQos);
    bearer.tft.apply({lte::tft::OperationCode::CREATE_NEW, false, {Filter(0, port)}});
    return bearer;
}

// A registered UE with one default bearer (EBI 5) and two dedicated bearers
// (EBI 6 and 7), in the middle of a Normal Tracking Area Update.
struct Ue
{
    MobilityContext mobility;
    std::vector<DedicatedBearerRuntime> bearers;
};

Ue PendingUe()
{
    Ue ue;
    ue.mobility.ecm = EcmState::CONNECTED;
    ue.mobility.securityContextValid = true;
    ue.mobility.onAttachComplete(5, {10, 45, 0, 5}, Guti(), AssignedTaiList(), 0x30);
    ue.mobility.onUserPlaneReady();
    ue.bearers.push_back(Dedicated(6, 7, 7000, {7}));
    ue.bearers.push_back(Dedicated(7, 9, 8000, {9}));
    ue.mobility.startTau(false);
    return ue;
}

// --- snapshot / compare ----------------------------------------------------

struct BearerSnapshot
{
    uint8_t ebi{}, linkedEbi{}, qci{};
    bool accessReady{};
    std::vector<uint8_t> epsQos;
    std::vector<uint8_t> tft;

    bool operator==(const BearerSnapshot &other) const
    {
        return ebi == other.ebi && linkedEbi == other.linkedEbi && qci == other.qci &&
               accessReady == other.accessReady && epsQos == other.epsQos && tft == other.tft;
    }
    bool operator!=(const BearerSnapshot &other) const { return !(*this == other); }
};

// The complete trusted EPS state a rejected Accept must not be able to move.
struct StateSnapshot
{
    PendingProcedure pending{};
    std::optional<std::array<uint8_t, 11>> guti;
    std::vector<Tai> taiList;
    uint8_t t3412{}, defaultEbi{};
    EmmState emm{};
    EcmState ecm{};
    EpsBearerState bearer{};
    bool securityContextValid{};
    std::array<uint8_t, 4> assignedIpv4{};
    uint32_t accessGeneration{};
    std::vector<BearerSnapshot> bearers;

    bool operator==(const StateSnapshot &other) const
    {
        return pending == other.pending && guti == other.guti && taiList == other.taiList && t3412 == other.t3412 &&
               defaultEbi == other.defaultEbi && emm == other.emm && ecm == other.ecm && bearer == other.bearer &&
               securityContextValid == other.securityContextValid && assignedIpv4 == other.assignedIpv4 &&
               accessGeneration == other.accessGeneration && bearers == other.bearers;
    }
    bool operator!=(const StateSnapshot &other) const { return !(*this == other); }
};

std::ostream &operator<<(std::ostream &stream, const BearerSnapshot &bearer)
{
    stream << "{ebi=" << static_cast<int>(bearer.ebi) << ", linkedEbi=" << static_cast<int>(bearer.linkedEbi)
           << ", qci=" << static_cast<int>(bearer.qci) << ", accessReady=" << bearer.accessReady << "}";
    return stream;
}

std::ostream &operator<<(std::ostream &stream, const StateSnapshot &state)
{
    stream << "{pending=" << lte::ue::ToString(state.pending) << ", defaultEbi=" << static_cast<int>(state.defaultEbi)
           << ", t3412=" << static_cast<int>(state.t3412) << ", taiList=" << state.taiList.size()
           << ", guti=" << state.guti.has_value() << ", securityContextValid=" << state.securityContextValid
           << ", bearers=" << state.bearers.size() << "}";
    return stream;
}

StateSnapshot Snapshot(const MobilityContext &mobility, const std::vector<DedicatedBearerRuntime> &bearers)
{
    StateSnapshot state;
    state.pending = mobility.pending;
    state.guti = mobility.guti;
    state.taiList = mobility.taiList;
    state.t3412 = mobility.t3412;
    state.defaultEbi = mobility.defaultEbi;
    state.emm = mobility.emm;
    state.ecm = mobility.ecm;
    state.bearer = mobility.bearer;
    state.securityContextValid = mobility.securityContextValid;
    state.assignedIpv4 = mobility.assignedIpv4;
    state.accessGeneration = mobility.accessGeneration;
    for (const auto &bearer : bearers)
    {
        BearerSnapshot copy;
        copy.ebi = bearer.ebi;
        copy.linkedEbi = bearer.linkedEbi;
        copy.qci = bearer.qci;
        copy.accessReady = bearer.accessReady;
        copy.epsQos = bearer.epsQos;
        copy.tft = lte::tft::Encode({lte::tft::OperationCode::CREATE_NEW, false, bearer.tft.filters()});
        state.bearers.push_back(copy);
    }
    return state;
}
} // namespace

TEST_CASE("lte/tau_accept: a valid accept with full bearer retention commits every assignment")
{
    auto ue = PendingUe();
    const auto before = Snapshot(ue.mobility, ue.bearers);

    lte::ue::nas::TauAccept accept;
    accept.updateResult = 0;
    accept.t3412 = 0x21;
    accept.taiList = AssignedTaiListRange();
    accept.guti = FreshGuti();
    accept.bearerContextStatus = AllBearers;

    const auto result = lte::ue::ApplyTauAccept(ue.mobility, ue.bearers, accept);

    CHECK(result.releasedDedicated.empty());
    CHECK(result.completeRequired);
    REQUIRE(ue.bearers.size() == 2);

    // Every assignment landed and nothing else moved: new GUTI stored, the new
    // tracking area list stored already parsed as TACs 2 and 3, the new
    // periodic timer stored, the procedure completed, and both dedicated
    // bearers carried forward untouched.
    auto expected = before;
    expected.pending = PendingProcedure::NONE;
    expected.guti = FreshGuti();
    expected.taiList = std::vector<Tai>{{{"460", "02"}, 2}, {{"460", "02"}, 3}};
    expected.t3412 = 0x21;
    CHECK(Snapshot(ue.mobility, ue.bearers) == expected);

    std::vector<Tai> reparsed;
    REQUIRE(lte::ue::ParseTaiList(AssignedTaiListRange(), reparsed));
    CHECK(reparsed == ue.mobility.taiList);
}

TEST_CASE("lte/tau_accept: a valid accept that drops one dedicated bearer commits that and nothing else")
{
    auto ue = PendingUe();
    const auto before = Snapshot(ue.mobility, ue.bearers);

    lte::ue::nas::TauAccept accept;
    accept.updateResult = 0;
    accept.bearerContextStatus = DropSeven;

    const auto result = lte::ue::ApplyTauAccept(ue.mobility, ue.bearers, accept);

    CHECK(result.releasedDedicated == std::vector<uint8_t>{7});
    CHECK_FALSE(result.completeRequired); // no GUTI was carried
    REQUIRE(ue.bearers.size() == 1);
    CHECK(ue.bearers[0].ebi == 6);

    // Exactly one commitment: EBI 7 gone, procedure completed. The surviving
    // bearer and every assignment are byte-identical to before.
    auto expected = before;
    expected.pending = PendingProcedure::NONE;
    expected.bearers = std::vector<BearerSnapshot>{before.bearers[0]};
    CHECK(Snapshot(ue.mobility, ue.bearers) == expected);
}

TEST_CASE("lte/tau_accept: an unsupported update result cannot release a bearer the status would drop")
{
    auto ue = PendingUe();
    const auto before = Snapshot(ue.mobility, ue.bearers);

    lte::ue::nas::TauAccept accept;
    accept.updateResult = 1; // combined TA/LA update, refused outright
    accept.bearerContextStatus = DropSeven;

    CHECK_THROWS(lte::ue::ApplyTauAccept(ue.mobility, ue.bearers, accept));
    // The refusal happened before any reconciliation: EBI 7, which the status
    // would have dropped, is still in the live bearer set.
    CHECK(Snapshot(ue.mobility, ue.bearers) == before);
    REQUIRE(ue.bearers.size() == 2);
    CHECK(ue.bearers[1].ebi == 7);
}

TEST_CASE("lte/tau_accept: a malformed tracking area list cannot release a bearer the status would drop")
{
    auto ue = PendingUe();
    const auto before = Snapshot(ue.mobility, ue.bearers);

    lte::ue::nas::TauAccept accept;
    accept.updateResult = 0;
    accept.taiList = MalformedTaiList();
    accept.bearerContextStatus = DropSeven;

    CHECK_THROWS(lte::ue::ApplyTauAccept(ue.mobility, ue.bearers, accept));
    CHECK(Snapshot(ue.mobility, ue.bearers) == before);
    REQUIRE(ue.bearers.size() == 2);
    CHECK(ue.bearers[1].ebi == 7);
}

TEST_CASE("lte/tau_accept: an unusable new GUTI cannot change the bearer set either")
{
    auto ue = PendingUe();
    const auto before = Snapshot(ue.mobility, ue.bearers);

    // Both ways a GUTI can be unusable: wrong identity-type bits, and a zero
    // M-TMSI that could never yield a paging identity.
    for (const auto &unusable : {WrongTypeGuti(), ZeroMtmsiGuti()})
    {
        lte::ue::nas::TauAccept accept;
        accept.updateResult = 0;
        accept.guti = unusable;
        accept.bearerContextStatus = DropSeven;

        CHECK_THROWS(lte::ue::ApplyTauAccept(ue.mobility, ue.bearers, accept));
        CHECK(Snapshot(ue.mobility, ue.bearers) == before);
        REQUIRE(ue.bearers.size() == 2);
        CHECK(ue.bearers[1].ebi == 7);
    }
}

TEST_CASE("lte/tau_accept: a status that drops the default bearer changes nothing")
{
    auto ue = PendingUe();
    const auto before = Snapshot(ue.mobility, ue.bearers);

    lte::ue::nas::TauAccept accept;
    accept.updateResult = 0;
    accept.bearerContextStatus = DropDefault;

    // Losing the active default bearer is the end of the session, not a
    // reconciliation. The failure happens after the assignments were already
    // planned and before anything was committed.
    CHECK_THROWS(lte::ue::ApplyTauAccept(ue.mobility, ue.bearers, accept));
    CHECK(Snapshot(ue.mobility, ue.bearers) == before);
}

TEST_CASE("lte/tau_accept: a duplicate accept after a completed update is refused and changes nothing")
{
    auto ue = PendingUe();
    const auto before = Snapshot(ue.mobility, ue.bearers);

    lte::ue::nas::TauAccept first;
    first.updateResult = 0;
    first.t3412 = 0x21;
    first.taiList = AssignedTaiListRange();
    first.guti = FreshGuti();
    first.bearerContextStatus = AllBearers;
    REQUIRE(lte::ue::ApplyTauAccept(ue.mobility, ue.bearers, first).completeRequired);
    REQUIRE(ue.mobility.pending == PendingProcedure::NONE);

    const auto afterFirst = Snapshot(ue.mobility, ue.bearers);
    REQUIRE(afterFirst != before);

    // The procedure is over. A second Accept is not an update of the update:
    // it is a message the UE never asked for, and taking it would let one
    // replayed message rewrite the assignments behind the completed update.
    lte::ue::nas::TauAccept second;
    second.updateResult = 0;
    second.t3412 = 0x31;
    second.taiList = AssignedTaiList();
    second.guti = Guti();
    second.bearerContextStatus = AllBearers;

    CHECK_THROWS(lte::ue::ApplyTauAccept(ue.mobility, ue.bearers, second));
    CHECK(Snapshot(ue.mobility, ue.bearers) == afterFirst);
}

TEST_CASE("lte/tau_accept: a refused accept leaves the state a later legitimate accept can still commit")
{
    auto ue = PendingUe();
    const auto before = Snapshot(ue.mobility, ue.bearers);

    lte::ue::nas::TauAccept refused;
    refused.updateResult = 1;
    refused.bearerContextStatus = DropSeven;
    CHECK_THROWS(lte::ue::ApplyTauAccept(ue.mobility, ue.bearers, refused));
    CHECK(Snapshot(ue.mobility, ue.bearers) == before);

    // The refusal left the procedure pending and the context intact, so a
    // legitimate Accept now commits in full.
    lte::ue::nas::TauAccept accept;
    accept.updateResult = 0;
    accept.t3412 = 0x21;
    accept.taiList = AssignedTaiListRange();
    accept.guti = FreshGuti();
    accept.bearerContextStatus = AllBearers;

    const auto result = lte::ue::ApplyTauAccept(ue.mobility, ue.bearers, accept);
    CHECK(result.releasedDedicated.empty());
    CHECK(result.completeRequired);

    auto expected = before;
    expected.pending = PendingProcedure::NONE;
    expected.guti = FreshGuti();
    expected.taiList = std::vector<Tai>{{{"460", "02"}, 2}, {{"460", "02"}, 3}};
    expected.t3412 = 0x21;
    CHECK(Snapshot(ue.mobility, ue.bearers) == expected);
}

TEST_CASE("lte/tau_accept: a newly assigned GUTI requires a protected TAU Complete")
{
    // No GUTI carried: there is nothing new to acknowledge.
    {
        auto ue = PendingUe();
        lte::ue::nas::TauAccept accept;
        accept.updateResult = 0;
        accept.bearerContextStatus = AllBearers;
        CHECK_FALSE(lte::ue::ApplyTauAccept(ue.mobility, ue.bearers, accept).completeRequired);
    }
    // A usable GUTI: the update owes the network a protected TAU Complete
    // before the new identity is taken into use.
    {
        auto ue = PendingUe();
        lte::ue::nas::TauAccept accept;
        accept.updateResult = 0;
        accept.guti = FreshGuti();
        accept.bearerContextStatus = AllBearers;
        CHECK(lte::ue::ApplyTauAccept(ue.mobility, ue.bearers, accept).completeRequired);
    }
    // An unusable GUTI can never reach that outcome at all: it is refused
    // instead, so completeRequired can never come back true for one.
    {
        auto ue = PendingUe();
        const auto before = Snapshot(ue.mobility, ue.bearers);
        for (const auto &unusable : {WrongTypeGuti(), ZeroMtmsiGuti()})
        {
            lte::ue::nas::TauAccept accept;
            accept.updateResult = 0;
            accept.guti = unusable;
            accept.bearerContextStatus = DropSeven;
            CHECK_THROWS(lte::ue::ApplyTauAccept(ue.mobility, ue.bearers, accept));
            CHECK(Snapshot(ue.mobility, ue.bearers) == before);
        }
    }
}
