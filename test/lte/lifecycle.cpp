//
// This file is a part of UERANSIM project.
// Copyright (c) 2027 ALI GUNGOR.
//
// LTE EPS lifecycle, Detach, Service Request and TAU tests.

#include <ext/doctest/doctest.h>

#include <lte/ue/bearer_runtime.hpp>
#include <lte/ue/lifecycle.hpp>
#include <lte/ue/nas.hpp>
#include <lte/ue/security.hpp>

namespace
{
std::array<uint8_t, 11> Guti()
{
    return {0xF6, 0x64, 0xF0, 0x20, 0x00, 0x01, 0x01, 0x12, 0x34, 0x56, 0x78};
}

// The exact TAI list assignment a live Open5GS MME sent in Attach Accept:
// type 2 form, one PLMN 460/02 and one TAC 1.
std::vector<uint8_t> AssignedTaiList()
{
    return {0x40, 0x64, 0xF0, 0x20, 0x00, 0x01};
}

// A second, differently shaped but equally valid assignment: type 1 form,
// PLMN 460/02, a run of two consecutive TACs starting at 2.
std::vector<uint8_t> AssignedTaiListRange()
{
    return {0x21, 0x64, 0xF0, 0x20, 0x00, 0x02};
}

lte::ue::MobilityContext Registered()
{
    lte::ue::MobilityContext context;
    context.ecm = lte::ue::EcmState::CONNECTED;
    context.securityContextValid = true;
    context.onAttachComplete(5, {10, 45, 0, 5}, Guti(), AssignedTaiList(), 0x30);
    context.onUserPlaneReady();
    return context;
}
} // namespace

TEST_CASE("lte/lifecycle: S1 release retains registration and logical bearer but blocks data")
{
    auto context = Registered();
    context.enbTeid = 0x11111111;
    context.sgwTeid = 0x22222222;
    REQUIRE(context.canForwardUserPlane());
    context.onS1ContextReleased();
    CHECK(context.emm == lte::ue::EmmState::REGISTERED);
    CHECK(context.ecm == lte::ue::EcmState::IDLE);
    CHECK(context.bearer == lte::ue::EpsBearerState::SIGNALING_ESTABLISHED);
    CHECK_FALSE(context.canForwardUserPlane());
    CHECK_FALSE(context.enbTeid.has_value());
    CHECK_FALSE(context.sgwTeid.has_value());
    CHECK_NOTHROW(context.onS1ContextReleased());
}

TEST_CASE("lte/lifecycle: Service Request restores once and Detach clears all context")
{
    auto context = Registered();
    context.onS1ContextReleased();
    context.startServiceRequest();
    CHECK_THROWS(context.startServiceRequest());
    context.onServiceRestored();
    CHECK(context.canForwardUserPlane());
    CHECK_THROWS(context.onServiceRestored());
    context.startDetach();
    CHECK_FALSE(context.canForwardUserPlane());
    context.onDetachAccepted();
    CHECK(context.emm == lte::ue::EmmState::DEREGISTERED);
    CHECK(context.bearer == lte::ue::EpsBearerState::INACTIVE);
    CHECK_FALSE(context.guti.has_value());
    CHECK_THROWS(context.startDetach());
}

TEST_CASE("lte/lifecycle: normal and periodic TAU preserve bearer and update assigned context")
{
    auto context = Registered();
    context.startTau(false);
    context.onTauAccepted(0, std::nullopt, AssignedTaiListRange(), 0x21);
    REQUIRE(context.taiList.size() == 2);
    CHECK(context.taiList[0].tac == 2);
    CHECK(context.taiList[1].tac == 3);
    CHECK(context.t3412 == 0x21);
    CHECK(context.canForwardUserPlane());
    context.startTau(true);
    context.onTauAccepted(0, Guti(), std::nullopt, std::nullopt);
    CHECK(context.pending == lte::ue::PendingProcedure::NONE);
    // An absent element leaves the registered area untouched rather than
    // silently clearing it.
    REQUIRE(context.taiList.size() == 2);
}

TEST_CASE("lte/lifecycle: a TAU Accept cannot install an unparseable tracking area list")
{
    auto context = Registered();
    context.startTau(false);
    CHECK_THROWS(context.onTauAccepted(0, std::nullopt, std::vector<uint8_t>{0x40, 0x64}, 0x21));
    // The rejected assignment changed nothing: the previous list survives and
    // the procedure is still pending for a truthful retry.
    CHECK(context.taiList == std::vector<lte::ue::Tai>{{{"460", "02"}, 1}});
    CHECK(context.pending == lte::ue::PendingProcedure::TAU_NORMAL);
    CHECK_THROWS(context.onTauAccepted(0, std::nullopt, std::vector<uint8_t>{}, 0x21));
    CHECK(context.taiList == std::vector<lte::ue::Tai>{{{"460", "02"}, 1}});
}

TEST_CASE("lte/lifecycle: a duplicate Tracking Area Update Accept cannot reassign the registration")
{
    auto context = Registered();
    context.startTau(false);
    context.onTauAccepted(0, Guti(), AssignedTaiListRange(), 0x21);
    REQUIRE(context.pending == lte::ue::PendingProcedure::NONE);
    REQUIRE(context.taiList.size() == 2);
    const auto guti = context.guti;
    const auto taiList = context.taiList;

    // The procedure is over. A second Accept is not an update of the update: it
    // is a message the UE never asked for, and taking it would let one replayed
    // datagram rewrite the authorized tracking areas behind the registration's
    // back.
    CHECK_THROWS(context.onTauAccepted(0, Guti(), AssignedTaiList(), 0x30));
    CHECK(context.pending == lte::ue::PendingProcedure::NONE);
    CHECK(context.guti == guti);
    CHECK(context.taiList == taiList);
    CHECK(context.t3412 == 0x21);

    // The same holds once a periodic update has completed.
    auto periodic = Registered();
    periodic.startTau(true);
    periodic.onTauAccepted(0, std::nullopt, std::nullopt, 0x31);
    REQUIRE(periodic.pending == lte::ue::PendingProcedure::NONE);
    CHECK_THROWS(periodic.onTauAccepted(0, std::nullopt, AssignedTaiList(), 0x30));
    CHECK(periodic.pending == lte::ue::PendingProcedure::NONE);
    CHECK(periodic.t3412 == 0x31);
    CHECK(periodic.taiList == std::vector<lte::ue::Tai>{{{"460", "02"}, 1}});
}

TEST_CASE("lte/lifecycle: a Tracking Area Update Accept that is not an EPS-only update is refused")
{
    // TS 24.301 9.9.3.32: zero is the plain "TA updated" this procedure
    // performs. One announces a combined TA/LA update and two allocates an ISDN
    // number, neither of which this UE carries out; three to seven are reserved.
    // Recording any of them would report a CS-domain update that never took
    // place, so the accept is refused and the procedure is left pending for a
    // truthful retry rather than quietly completed.
    for (uint8_t result = 1; result <= 7; ++result)
    {
        CAPTURE(result);
        auto context = Registered();
        context.startTau(false);
        CHECK_THROWS(context.onTauAccepted(result, Guti(), AssignedTaiListRange(), 0x21));
        CHECK(context.pending == lte::ue::PendingProcedure::TAU_NORMAL);
        // Nothing was installed from the refused accept.
        CHECK(context.guti == Guti());
        CHECK(context.taiList == std::vector<lte::ue::Tai>{{{"460", "02"}, 1}});
        CHECK(context.t3412 == 0x30);
    }

    // The result is read out of the low three bits of its octet and the rest is
    // spare, so spare bits can neither hide a non-zero result nor invent one.
    // The decoder reports what the network said and leaves the refusal to the
    // procedure that would otherwise have to honour it.
    auto decoded = [](uint8_t octet) {
        const std::vector<uint8_t> wire{0x07, 0x49, octet, 0x5A, 0x31};
        return lte::ue::nas::DecodeDownlink(wire.data(), wire.size());
    };
    CHECK(decoded(0x00).tauAccept.updateResult == 0);
    CHECK(decoded(0xF8).tauAccept.updateResult == 0);
    CHECK(decoded(0x02).tauAccept.updateResult == 2);
    CHECK(decoded(0xFA).tauAccept.updateResult == 2);
    CHECK(decoded(0xFF).tauAccept.updateResult == 7);
    CHECK(decoded(0x00).tauAccept.t3412 == 0x31);
}

TEST_CASE("lte/lifecycle: a Tracking Area Update Reject ends only the update and not the registration")
{
    auto context = Registered();
    context.onS1ContextReleased();
    context.startTau(false);
    REQUIRE(context.pending == lte::ue::PendingProcedure::TAU_NORMAL);

    // A reject refuses this update; it does not deregister the UE. The EPS
    // registration, the security context, the subscriber identity and the
    // authorized tracking areas stand exactly as they did, so the UE is left
    // able to try again rather than silently falling back to a fresh Attach.
    context.onProcedureRejected();
    CHECK(context.pending == lte::ue::PendingProcedure::NONE);
    CHECK(context.emm == lte::ue::EmmState::REGISTERED);
    CHECK(context.ecm == lte::ue::EcmState::IDLE);
    CHECK(context.securityContextValid);
    CHECK(context.guti == Guti());
    CHECK(context.taiList == std::vector<lte::ue::Tai>{{{"460", "02"}, 1}});
    CHECK(context.defaultEbi == 5);
    CHECK(context.bearer == lte::ue::EpsBearerState::SIGNALING_ESTABLISHED);

    // A reject with nothing left to reject is itself refused rather than
    // becoming a second, unconditional reset of the state.
    CHECK_THROWS(context.onProcedureRejected());
    CHECK(context.pending == lte::ue::PendingProcedure::NONE);

    // The same holds for a rejected periodic update.
    auto periodic = Registered();
    periodic.startTau(true);
    REQUIRE(periodic.pending == lte::ue::PendingProcedure::TAU_PERIODIC);
    periodic.onProcedureRejected();
    CHECK(periodic.pending == lte::ue::PendingProcedure::NONE);
    CHECK(periodic.emm == lte::ue::EmmState::REGISTERED);
    CHECK(periodic.taiList == std::vector<lte::ue::Tai>{{{"460", "02"}, 1}});
}

TEST_CASE("lte/lifecycle: a malformed Attach Accept tracking area list cannot start a registration")
{
    lte::ue::MobilityContext context;
    context.ecm = lte::ue::EcmState::CONNECTED;
    context.securityContextValid = true;
    CHECK_THROWS(context.onAttachComplete(5, {10, 45, 0, 5}, Guti(), std::vector<uint8_t>{0x00, 0x01}, 0x30));
    CHECK(context.emm == lte::ue::EmmState::DEREGISTERED);
    CHECK(context.taiList.empty());
}

TEST_CASE("lte/lifecycle: arriving in a tracking area calls for a Normal TAU only outside the registered list")
{
    auto context = Registered();
    CHECK(lte::ue::EvaluateServingTai(context, {{"460", "02"}, 1}) == lte::ue::TauDecision::NO_CHANGE);
    CHECK(lte::ue::EvaluateServingTai(context, {{"460", "02"}, 2}) == lte::ue::TauDecision::NORMAL_TAU);
    CHECK(lte::ue::EvaluateServingTai(context, {{"460", "02"}, 0}) == lte::ue::TauDecision::NORMAL_TAU);
    CHECK(lte::ue::EvaluateServingTai(context, {{"460", "01"}, 1}) == lte::ue::TauDecision::NORMAL_TAU);

    // A range assignment authorizes every TAC it covers, not just the first.
    auto ranged = Registered();
    ranged.startTau(false);
    ranged.onTauAccepted(0, std::nullopt, AssignedTaiListRange(), 0x30);
    CHECK(lte::ue::EvaluateServingTai(ranged, {{"460", "02"}, 2}) == lte::ue::TauDecision::NO_CHANGE);
    CHECK(lte::ue::EvaluateServingTai(ranged, {{"460", "02"}, 3}) == lte::ue::TauDecision::NO_CHANGE);
    CHECK(lte::ue::EvaluateServingTai(ranged, {{"460", "02"}, 4}) == lte::ue::TauDecision::NORMAL_TAU);
}

TEST_CASE("lte/lifecycle: an unknown tracking area assignment fails closed instead of guessing")
{
    lte::ue::MobilityContext context;
    CHECK(lte::ue::EvaluateServingTai(context, {{"460", "02"}, 1}) == lte::ue::TauDecision::NOT_REGISTERED);

    auto registered = Registered();
    registered.taiList.clear();
    CHECK(lte::ue::EvaluateServingTai(registered, {{"460", "02"}, 1}) == lte::ue::TauDecision::NO_ASSIGNED_TAI);
    CHECK_THROWS(registered.startTau(false));

    registered = Registered();
    registered.securityContextValid = false;
    CHECK(lte::ue::EvaluateServingTai(registered, {{"460", "02"}, 2}) == lte::ue::TauDecision::NO_SECURITY);

    registered = Registered();
    registered.guti.reset();
    CHECK(lte::ue::EvaluateServingTai(registered, {{"460", "02"}, 2}) == lte::ue::TauDecision::NO_IDENTITY);

    registered = Registered();
    registered.startDetach();
    CHECK(lte::ue::EvaluateServingTai(registered, {{"460", "02"}, 2}) == lte::ue::TauDecision::PROCEDURE_PENDING);
}

TEST_CASE("lte/lifecycle: another tracking area already in the registered list needs no update")
{
    // A listed assignment names each authorized TAC explicitly, so arriving at
    // any of them is movement inside the registered area and not a reason to
    // update the network.
    auto context = Registered();
    context.startTau(false);
    context.onTauAccepted(0, std::nullopt,
                          std::vector<uint8_t>{0x02, 0x64, 0xF0, 0x20, 0x00, 0x01, 0x00, 0x02, 0x00, 0x07}, 0x30);
    CHECK(lte::ue::EvaluateServingTai(context, {{"460", "02"}, 1}) == lte::ue::TauDecision::NO_CHANGE);
    CHECK(lte::ue::EvaluateServingTai(context, {{"460", "02"}, 2}) == lte::ue::TauDecision::NO_CHANGE);
    CHECK(lte::ue::EvaluateServingTai(context, {{"460", "02"}, 7}) == lte::ue::TauDecision::NO_CHANGE);
    CHECK(lte::ue::EvaluateServingTai(context, {{"460", "02"}, 3}) == lte::ue::TauDecision::NORMAL_TAU);
    CHECK(lte::ue::EvaluateServingTai(context, {{"460", "02"}, 8}) == lte::ue::TauDecision::NORMAL_TAU);
}

TEST_CASE("lte/lifecycle: cell reselection is refused outside an idle registered state with no pending procedure")
{
    lte::ue::MobilityContext neverAttached;
    CHECK_THROWS(neverAttached.onCellReselected());

    // A UE in the middle of an access cannot leave the cell it is using.
    auto connected = Registered();
    CHECK_THROWS(connected.onCellReselected());

    // Nor may one leave while a procedure is pending over that access. A
    // dedicated bearer activation runs as a pending Service Request, so it is
    // covered by the same rule rather than by a special case.
    for (auto pending : {lte::ue::PendingProcedure::SERVICE_REQUEST, lte::ue::PendingProcedure::TAU_NORMAL,
                         lte::ue::PendingProcedure::TAU_PERIODIC, lte::ue::PendingProcedure::DETACH})
    {
        auto blocked = Registered();
        blocked.onS1ContextReleased();
        switch (pending)
        {
        case lte::ue::PendingProcedure::SERVICE_REQUEST: blocked.startServiceRequest(); break;
        case lte::ue::PendingProcedure::TAU_NORMAL: blocked.startTau(false); break;
        case lte::ue::PendingProcedure::TAU_PERIODIC: blocked.startTau(true); break;
        case lte::ue::PendingProcedure::DETACH: blocked.startDetach(); break;
        case lte::ue::PendingProcedure::NONE: break;
        }
        CHECK(blocked.pending == pending);
        CHECK_THROWS(blocked.onCellReselected());
    }

    auto idle = Registered();
    idle.onS1ContextReleased();
    CHECK_NOTHROW(idle.onCellReselected());
}

TEST_CASE("lte/lifecycle: cell reselection retires the old cell's access and keeps the registration")
{
    auto context = Registered();
    context.onS1ContextEstablished(41, 42);
    context.onBearerTransportEstablished(1001, 2001);
    context.accessGeneration = 7;
    context.onS1ContextReleased();
    // The ordinary release path already dropped these, so they are written back
    // to hold the contract to the stronger claim: whichever route reaches a
    // reselection, the identifiers of the cell being left never travel with it.
    context.enbUeS1apId = 41;
    context.mmeUeS1apId = 42;
    context.enbTeid = 1001;
    context.sgwTeid = 2001;

    const auto guti = context.guti;
    const auto taiList = context.taiList;
    const auto ipv4 = context.assignedIpv4;
    context.onCellReselected();

    CHECK_FALSE(context.enbUeS1apId.has_value());
    CHECK_FALSE(context.mmeUeS1apId.has_value());
    CHECK_FALSE(context.enbTeid.has_value());
    CHECK_FALSE(context.sgwTeid.has_value());
    CHECK(context.accessGeneration == 0);

    // The session is not the cell. Registration, security, subscriber identity,
    // authorized tracking areas, the PDN address and the logical bearer all
    // survive; only the access transport of the departed cell does not.
    CHECK(context.emm == lte::ue::EmmState::REGISTERED);
    CHECK(context.ecm == lte::ue::EcmState::IDLE);
    CHECK(context.bearer == lte::ue::EpsBearerState::SIGNALING_ESTABLISHED);
    CHECK(context.securityContextValid);
    CHECK(context.guti == guti);
    CHECK(context.taiList == taiList);
    CHECK(context.defaultEbi == 5);
    CHECK(context.assignedIpv4 == ipv4);
    CHECK(context.pending == lte::ue::PendingProcedure::NONE);
}

TEST_CASE("lte/bearer-runtime: the network bearer context status decides which contexts survive")
{
    using lte::ue::DedicatedBearerRuntime;
    DedicatedBearerRuntime six;
    six.ebi = 6;
    six.linkedEbi = 5;
    DedicatedBearerRuntime seven;
    seven.ebi = 7;
    seven.linkedEbi = 5;
    const std::vector<DedicatedBearerRuntime> bearers{six, seven};

    // Everything the UE still holds is still reported: nothing is released.
    auto all = lte::ue::ReconcileRetainedBearers(bearers, 0x00E0, 5);
    CHECK(all.retained.size() == 2);
    CHECK(all.released.empty());

    // The default survives but one dedicated context does not. The network's
    // view is authoritative, so exactly that one is released and the other is
    // carried forward instead of being dropped with it.
    auto partial = lte::ue::ReconcileRetainedBearers(bearers, 0x0060, 5);
    REQUIRE(partial.retained.size() == 1);
    CHECK(partial.retained[0].ebi == 6);
    CHECK(partial.released == std::vector<uint8_t>{7});

    // The default alone: every dedicated context is gone.
    auto none = lte::ue::ReconcileRetainedBearers(bearers, 0x0020, 5);
    CHECK(none.retained.empty());
    CHECK(none.released == std::vector<uint8_t>{6, 7});

    // Losing the default bearer is the end of the session, not a reconciliation.
    CHECK_THROWS(lte::ue::ReconcileRetainedBearers(bearers, 0x00C0, 5));
    // Only 5..15 are assignable, and a bit outside the sixteen the status
    // carries cannot be looked up at all.
    CHECK_THROWS(lte::ue::ReconcileRetainedBearers(bearers, 0xFFFF, 4));
    CHECK_THROWS(lte::ue::ReconcileRetainedBearers(bearers, 0xFFFF, 16));
    DedicatedBearerRuntime unassignable;
    unassignable.ebi = 4;
    unassignable.linkedEbi = 5;
    CHECK_THROWS(lte::ue::ReconcileRetainedBearers({unassignable}, 0xFFFF, 5));

    // The status the UE reports and the status it reads back use the same bit
    // convention, on both octets.
    const std::vector<uint8_t> tau{0x07, 0x49, 0x00, 0x5A, 0x31, 0x54, 0x02, 0x00, 0x02,
                                   0x50, 0x0B, 0xF6, 0x64, 0xF0, 0x20, 0x00, 0x01, 0x01,
                                   0x12, 0x34, 0x56, 0x78, 0x57, 0x02, 0x20, 0x81};
    const auto accepted = lte::ue::nas::DecodeDownlink(tau.data(), tau.size());
    REQUIRE(accepted.type == lte::ue::nas::DownlinkEmm::TAU_ACCEPT);
    REQUIRE(accepted.tauAccept.bearerContextStatus.has_value());
    CHECK(lte::ue::nas::EncodeEpsBearerContextStatus({5, 8, 15}) ==
          std::array<uint8_t, 2>{static_cast<uint8_t>(*accepted.tauAccept.bearerContextStatus & 0xFFU),
                                 static_cast<uint8_t>(*accepted.tauAccept.bearerContextStatus >> 8U)});

    DedicatedBearerRuntime eight;
    eight.ebi = 8;
    eight.linkedEbi = 5;
    DedicatedBearerRuntime fifteen;
    fifteen.ebi = 15;
    fifteen.linkedEbi = 5;
    auto high = lte::ue::ReconcileRetainedBearers({eight, fifteen}, *accepted.tauAccept.bearerContextStatus, 5);
    CHECK(high.retained.size() == 2);
    CHECK(high.released.empty());
}

TEST_CASE("lte/nas: Detach and TAU use GUTI, native KSI and exact EPS wire fields")
{
    CHECK(lte::ue::nas::EncodeDetachRequest(3, Guti(), false) ==
          std::vector<uint8_t>{0x07, 0x45, 0x31, 0x0B, 0xF6, 0x64, 0xF0, 0x20,
                               0x00, 0x01, 0x01, 0x12, 0x34, 0x56, 0x78});
    auto switchOff = lte::ue::nas::EncodeDetachRequest(3, Guti(), true);
    CHECK(switchOff[2] == 0x39);
    auto normal = lte::ue::nas::EncodeTauRequest(3, Guti(), {5}, false);
    auto periodic = lte::ue::nas::EncodeTauRequest(3, Guti(), {5}, true);
    CHECK(normal[0] == 0x07);
    CHECK(normal[1] == 0x48);
    CHECK(normal[2] == 0x30);
    CHECK(periodic[2] == 0x33);
    CHECK(std::vector<uint8_t>(normal.end() - 4, normal.end()) ==
          std::vector<uint8_t>{0x57, 0x02, 0x20, 0x00});
    auto ebiEight = lte::ue::nas::EncodeTauRequest(3, Guti(), {8}, false);
    CHECK(std::vector<uint8_t>(ebiEight.end() - 4, ebiEight.end()) ==
          std::vector<uint8_t>{0x57, 0x02, 0x00, 0x01});
    CHECK(lte::ue::nas::EncodeTauComplete() == std::vector<uint8_t>{0x07, 0x4A});
}

TEST_CASE("lte/nas: the EPS bearer context status reports every retained context")
{
    // TS 24.301 9.9.2.1: bit n of the first octet is EBI n for n in 0..7 and
    // bit n of the second is EBI n for n in 8..15.
    CHECK(lte::ue::nas::EncodeEpsBearerContextStatus({5}) == std::array<uint8_t, 2>{0x20, 0x00});
    CHECK(lte::ue::nas::EncodeEpsBearerContextStatus({8}) == std::array<uint8_t, 2>{0x00, 0x01});
    CHECK(lte::ue::nas::EncodeEpsBearerContextStatus({15}) == std::array<uint8_t, 2>{0x00, 0x80});

    // The default bearer plus a retained dedicated context are both reported;
    // reporting only the default would tell the network the dedicated context
    // no longer exists.
    CHECK(lte::ue::nas::EncodeEpsBearerContextStatus({5, 6}) == std::array<uint8_t, 2>{0x60, 0x00});
    CHECK(lte::ue::nas::EncodeEpsBearerContextStatus({6, 5}) == std::array<uint8_t, 2>{0x60, 0x00});
    CHECK(lte::ue::nas::EncodeEpsBearerContextStatus({5, 8, 15}) == std::array<uint8_t, 2>{0x20, 0x81});

    // Every assignable identity at once.
    std::vector<uint8_t> all;
    for (uint8_t ebi = 5; ebi <= 15; ++ebi)
        all.push_back(ebi);
    CHECK(lte::ue::nas::EncodeEpsBearerContextStatus(all) == std::array<uint8_t, 2>{0xE0, 0xFF});

    // An empty set, an identity outside the assignable range, or a repeated
    // identity is refused rather than quietly reported in a misleading way.
    CHECK_THROWS(lte::ue::nas::EncodeEpsBearerContextStatus({}));
    CHECK_THROWS(lte::ue::nas::EncodeEpsBearerContextStatus({4}));
    CHECK_THROWS(lte::ue::nas::EncodeEpsBearerContextStatus({16}));
    CHECK_THROWS(lte::ue::nas::EncodeEpsBearerContextStatus({5, 5}));

    // The same set reaches the TAU Request information element unchanged.
    auto request = lte::ue::nas::EncodeTauRequest(3, Guti(), {5, 8}, false);
    CHECK(std::vector<uint8_t>(request.end() - 4, request.end()) ==
          std::vector<uint8_t>{0x57, 0x02, 0x20, 0x01});
}

TEST_CASE("lte/nas: Detach Accept, TAU Accept and rejects are decoded defensively")
{
    const std::vector<uint8_t> detach{0x07, 0x46};
    CHECK(lte::ue::nas::DecodeDownlink(detach.data(), detach.size()).type ==
          lte::ue::nas::DownlinkEmm::DETACH_ACCEPT);
    std::vector<uint8_t> tau{0x07, 0x49, 0x00, 0x5A, 0x31, 0x54, 0x02, 0x00, 0x02,
                             0x50, 0x0B};
    const auto guti = Guti();
    tau.insert(tau.end(), guti.begin(), guti.end());
    tau.insert(tau.end(), {0x57, 0x02, 0x20, 0x00});
    auto accepted = lte::ue::nas::DecodeDownlink(tau.data(), tau.size());
    CHECK(accepted.type == lte::ue::nas::DownlinkEmm::TAU_ACCEPT);
    CHECK(accepted.tauAccept.t3412 == 0x31);
    CHECK(accepted.tauAccept.taiList == std::vector<uint8_t>{0, 2});
    CHECK(accepted.tauAccept.guti == guti);
    CHECK(accepted.tauAccept.bearerContextStatus == 0x20);
    const std::vector<uint8_t> rejected{0x07, 0x4B, 0x0B};
    CHECK(lte::ue::nas::DecodeDownlink(rejected.data(), rejected.size()).emmCause == 0x0B);
    CHECK_THROWS(lte::ue::nas::DecodeDownlink(detach.data(), 1));
}

TEST_CASE("lte/security: compact Service Request matches independent AES-CMAC fixture")
{
    lte::ue::SecurityContext context{};
    context.valid = context.keysDerived = context.securityActive = true;
    context.ksi = 3;
    context.integrity = lte::ue::IntegrityAlgorithm::EIA2;
    context.kNasInt = {0x2B, 0xD6, 0x45, 0x9F, 0x82, 0xC5, 0xB3, 0x00,
                       0x95, 0x2C, 0x49, 0x10, 0x48, 0x81, 0xFF, 0x48};
    context.ulNasCount = 0x0059B4;
    // Independently derived with AES-CMAC over
    // COUNT||BEARER/DIRECTION||0^24||{C7,74}: 6A9FD3BD...; short MAC=D3BD.
    const std::vector<uint8_t> expected{0xC7, 0x74, 0xD3, 0xBD};
    CHECK(lte::ue::nas::EncodeServiceRequest(context) == expected);
    CHECK_NOTHROW(lte::ue::nas::VerifyServiceRequest(context, expected.data(), expected.size(), 0x0059A0));
    auto corrupt = expected;
    corrupt.back() ^= 1;
    CHECK_THROWS(lte::ue::nas::VerifyServiceRequest(context, corrupt.data(), corrupt.size(), 0x0059A0));
    auto wrongKsi = expected;
    wrongKsi[1] ^= 0x20;
    CHECK_THROWS(lte::ue::nas::VerifyServiceRequest(context, wrongKsi.data(), wrongKsi.size(), 0x0059A0));
    CHECK_THROWS(lte::ue::nas::VerifyServiceRequest(context, expected.data(), expected.size(), 0x0059B5));
    context.securityActive = false;
    CHECK_THROWS(lte::ue::nas::EncodeServiceRequest(context));
}
