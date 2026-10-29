//
// This file is a part of UERANSIM project.
// Copyright (c) 2027 ALİ GÜNGÖR.
//
// https://github.com/aligungr/UERANSIM/
// See README, LICENSE, and CONTRIBUTING files for licensing details.
//

#include "lifecycle.hpp"

#include "paging.hpp"

namespace lte::ue
{

const char *ToString(EmmState state)
{
    return state == EmmState::REGISTERED ? "EMM_REGISTERED" : "EMM_DEREGISTERED";
}

const char *ToString(EcmState state)
{
    return state == EcmState::CONNECTED ? "ECM_CONNECTED" : "ECM_IDLE";
}

const char *ToString(EpsBearerState state)
{
    switch (state)
    {
    case EpsBearerState::INACTIVE: return "BEARER_INACTIVE";
    case EpsBearerState::SIGNALING_ESTABLISHED: return "BEARER_SIGNALING_ESTABLISHED";
    case EpsBearerState::USER_PLANE_READY: return "USER_PLANE_READY";
    }
    return "BEARER_UNKNOWN";
}

const char *ToString(PendingProcedure procedure)
{
    switch (procedure)
    {
    case PendingProcedure::NONE: return "NONE";
    case PendingProcedure::DETACH: return "DETACH_PENDING";
    case PendingProcedure::SERVICE_REQUEST: return "SERVICE_REQUEST_PENDING";
    case PendingProcedure::TAU_NORMAL: return "TAU_NORMAL_PENDING";
    case PendingProcedure::TAU_PERIODIC: return "TAU_PERIODIC_PENDING";
    }
    return "UNKNOWN_PENDING_PROCEDURE";
}

void MobilityContext::onAttachComplete(uint8_t ebi, const std::array<uint8_t, 4> &ipv4,
                                       std::optional<std::array<uint8_t, 11>> assignedGuti,
                                       const std::vector<uint8_t> &assignedTaiList, uint8_t periodicTimer)
{
    if (emm != EmmState::DEREGISTERED || ecm != EcmState::CONNECTED || ebi == 0 ||
        ipv4 == std::array<uint8_t, 4>{})
        throw LifecycleError("Invalid EPS Attach completion transition");
    // A registration with no readable authorized tracking areas is not a
    // registration this context can reason about later, so the assignment has
    // to parse in full before any of it is believed.
    std::vector<Tai> authorized;
    if (!ParseTaiList(assignedTaiList, authorized))
        throw LifecycleError("The Attach Accept tracking area list cannot be parsed");
    emm = EmmState::REGISTERED;
    bearer = EpsBearerState::SIGNALING_ESTABLISHED;
    pending = PendingProcedure::NONE;
    defaultEbi = ebi;
    assignedIpv4 = ipv4;
    guti = assignedGuti;
    taiList = std::move(authorized);
    t3412 = periodicTimer;
}

void MobilityContext::onS1ContextEstablished(uint32_t enbId, uint32_t mmeId)
{
    if (enbId == 0 || mmeId == 0)
        throw LifecycleError("S1AP identities must be non-zero");
    if (ecm == EcmState::CONNECTED && enbUeS1apId.has_value() && *enbUeS1apId != enbId)
        throw LifecycleError("Cannot replace an active S1AP UE context");
    ecm = EcmState::CONNECTED;
    enbUeS1apId = enbId;
    mmeUeS1apId = mmeId;
}

void MobilityContext::onBearerTransportEstablished(uint32_t localTeid, uint32_t remoteTeid)
{
    if (emm != EmmState::REGISTERED || ecm != EcmState::CONNECTED || defaultEbi == 0 ||
        localTeid == 0 || remoteTeid == 0)
        throw LifecycleError("Invalid EPS bearer transport establishment");
    enbTeid = localTeid;
    sgwTeid = remoteTeid;
    bearer = EpsBearerState::USER_PLANE_READY;
}

void MobilityContext::onUserPlaneReady()
{
    if (emm != EmmState::REGISTERED || ecm != EcmState::CONNECTED || defaultEbi == 0)
        throw LifecycleError("Invalid UE user-plane activation");
    bearer = EpsBearerState::USER_PLANE_READY;
}

void MobilityContext::onS1ContextReleased()
{
    if (ecm == EcmState::IDLE)
        return;
    ecm = EcmState::IDLE;
    enbUeS1apId.reset();
    mmeUeS1apId.reset();
    enbTeid.reset();
    sgwTeid.reset();
    if (emm == EmmState::REGISTERED && bearer != EpsBearerState::INACTIVE)
        bearer = EpsBearerState::SIGNALING_ESTABLISHED;
    else
        bearer = EpsBearerState::INACTIVE;
}

void MobilityContext::acceptAccessRelease(uint8_t ebi, uint32_t generation)
{
    if (emm != EmmState::REGISTERED || ebi != defaultEbi || generation == 0 ||
        generation != accessGeneration + 1U ||
        (ecm != EcmState::CONNECTED && pending != PendingProcedure::SERVICE_REQUEST))
        throw LifecycleError("Unexpected or stale access release");
    onS1ContextReleased();
    if (pending == PendingProcedure::SERVICE_REQUEST)
        pending = PendingProcedure::NONE;
    accessGeneration = generation;
}

void MobilityContext::validateAccessRestoration(uint8_t ebi, uint32_t generation, bool dedicated) const
{
    if (emm != EmmState::REGISTERED || !securityContextValid || generation == 0 || generation != accessGeneration ||
        ebi < 5 || ebi > 15 || (dedicated ? ebi == defaultEbi : ebi != defaultEbi))
        throw LifecycleError("Invalid bearer restoration identity or generation");
    if (dedicated)
    {
        // A dedicated bearer is restored on top of a default bearer that is
        // already back. A Tracking Area Update that is still outstanding does
        // not invalidate that restoration: it is answered by its own Accept and
        // nothing about the retained bearers is settled before then. Detach
        // and an unfinished Service Request still mean the default is not back.
        if (ecm != EcmState::CONNECTED || pending == PendingProcedure::DETACH ||
            pending == PendingProcedure::SERVICE_REQUEST)
            throw LifecycleError("Dedicated restoration precedes default service restoration");
    }
    else if (ecm != EcmState::IDLE ||
             (pending != PendingProcedure::SERVICE_REQUEST && pending != PendingProcedure::TAU_NORMAL &&
              pending != PendingProcedure::TAU_PERIODIC))
        // A restored access is only an answer to a procedure that asked for
        // one. A Tracking Area Update sent after a cell reselection is exactly
        // such a procedure, so the new cell's bearer transport is restored
        // while the Update is still waiting for its Accept.
        throw LifecycleError("Default restoration has no pending access procedure");
}

void MobilityContext::beginNewAttach()
{
    accessGeneration = 0;
}

void MobilityContext::onCellReselected()
{
    // A cell change in ECM-IDLE is not a new session and not a procedure: the
    // UE is between two accesses while continuing one registration.
    if (emm != EmmState::REGISTERED || ecm != EcmState::IDLE || pending != PendingProcedure::NONE)
        throw LifecycleError("Cell reselection requires an idle registered UE with no pending procedure");
    // The cell being left takes its S1AP identities, its access TEIDs and its
    // access generation with it. Presenting any of them at the target cell
    // would either reuse another cell's identifiers or use transport that no
    // longer exists.
    //
    // The new access epoch is numbered one rather than zero. Zero is the value
    // of "no epoch at all", and every generation-bound message — a release, a
    // restoration, a transport confirmation — is refused when it carries it, so
    // the first epoch of a reselected cell has to be a real one.
    enbUeS1apId.reset();
    mmeUeS1apId.reset();
    enbTeid.reset();
    sgwTeid.reset();
    accessGeneration = 1;
    // The logical default and dedicated bearers are still held by the network;
    // only their access transport is gone, which is what ECM-IDLE means.
    if (bearer != EpsBearerState::INACTIVE)
        bearer = EpsBearerState::SIGNALING_ESTABLISHED;
}

void MobilityContext::startServiceRequest()
{
    if (emm != EmmState::REGISTERED || ecm != EcmState::IDLE ||
        bearer != EpsBearerState::SIGNALING_ESTABLISHED || !securityContextValid || !guti.has_value() ||
        pending != PendingProcedure::NONE)
        throw LifecycleError("Service Request preconditions are not satisfied");
    pending = PendingProcedure::SERVICE_REQUEST;
}

void MobilityContext::onServiceRestored(uint32_t enbId, uint32_t mmeId, uint32_t localTeid, uint32_t remoteTeid)
{
    if (pending != PendingProcedure::SERVICE_REQUEST)
        throw LifecycleError("Unexpected Service Request restoration");
    onS1ContextEstablished(enbId, mmeId);
    onBearerTransportEstablished(localTeid, remoteTeid);
    pending = PendingProcedure::NONE;
}

void MobilityContext::onServiceRestored(bool userPlaneReady)
{
    if (pending != PendingProcedure::SERVICE_REQUEST || emm != EmmState::REGISTERED ||
        ecm != EcmState::IDLE || bearer != EpsBearerState::SIGNALING_ESTABLISHED)
        throw LifecycleError("Unexpected Service Request restoration");
    ecm = EcmState::CONNECTED;
    bearer = userPlaneReady ? EpsBearerState::USER_PLANE_READY : EpsBearerState::SIGNALING_ESTABLISHED;
    pending = PendingProcedure::NONE;
}

void MobilityContext::onTauAccessRestored(bool userPlaneReady)
{
    if (emm != EmmState::REGISTERED || ecm != EcmState::IDLE || bearer != EpsBearerState::SIGNALING_ESTABLISHED ||
        (pending != PendingProcedure::TAU_NORMAL && pending != PendingProcedure::TAU_PERIODIC))
        throw LifecycleError("Unexpected access restoration during a Tracking Area Update");
    ecm = EcmState::CONNECTED;
    bearer = userPlaneReady ? EpsBearerState::USER_PLANE_READY : EpsBearerState::SIGNALING_ESTABLISHED;
    // The Tracking Area Update stays pending. Only its Accept completes it, and
    // reporting the restored access as an accepted update would claim an
    // outcome that has not happened.
}

void MobilityContext::startDetach()
{
    if (emm != EmmState::REGISTERED || pending != PendingProcedure::NONE)
        throw LifecycleError("Detach requires an idle registered mobility procedure state");
    pending = PendingProcedure::DETACH;
}

void MobilityContext::onDetachAccepted()
{
    if (pending != PendingProcedure::DETACH)
        throw LifecycleError("Unexpected Detach Accept");
    *this = MobilityContext{};
}

void MobilityContext::startTau(bool periodic)
{
    if (emm != EmmState::REGISTERED || !securityContextValid || !guti.has_value() || taiList.empty() ||
        pending != PendingProcedure::NONE)
        throw LifecycleError("Tracking Area Update preconditions are not satisfied");
    pending = periodic ? PendingProcedure::TAU_PERIODIC : PendingProcedure::TAU_NORMAL;
}

MobilityContext::TauAcceptancePlan MobilityContext::planTauAccepted(
    uint8_t updateResult, std::optional<std::array<uint8_t, 11>> newGuti,
    std::optional<std::vector<uint8_t>> newTaiList, std::optional<uint8_t> newT3412) const
{
    if (pending != PendingProcedure::TAU_NORMAL && pending != PendingProcedure::TAU_PERIODIC)
        throw LifecycleError("Unexpected Tracking Area Update Accept");
    // TS 24.301 9.9.3.32: zero is the plain EPS "TA updated" this procedure
    // performs. Anything else reports a combined TA/LA update or a pre-Release
    // 8 ISDN allocation, none of which this UE carries out, so recording it
    // would claim a CS-domain update that never took place.
    if (updateResult != 0)
        throw LifecycleError("Unsupported non-EPS-only Tracking Area Update result");
    TauAcceptancePlan plan;
    // A newly assigned list is validated before it replaces the old one, so an
    // unreadable assignment can never shrink the registered area behind the
    // UE's back. The previous list survives an absent element untouched.
    if (newTaiList.has_value())
    {
        std::vector<Tai> authorized;
        if (!ParseTaiList(*newTaiList, authorized))
            throw LifecycleError("The Tracking Area Update Accept tracking area list cannot be parsed");
        plan.taiList = std::move(authorized);
    }
    if (newGuti.has_value())
    {
        // An identity that cannot yield an S-TMSI is not a GUTI this UE could
        // ever be paged under, so it is refused rather than stored as a
        // registration identity that no paging could ever reach.
        if (!STmsiFromGuti(*newGuti).has_value())
            throw LifecycleError("The Tracking Area Update Accept GUTI is not a usable EPS GUTI");
        plan.guti = *newGuti;
        plan.completeRequired = true;
    }
    if (newT3412.has_value())
        plan.t3412 = *newT3412;
    return plan;
}

void MobilityContext::commitTauAccepted(const TauAcceptancePlan &plan)
{
    if (plan.guti.has_value()) guti = *plan.guti;
    if (plan.taiList.has_value()) taiList = *plan.taiList;
    if (plan.t3412.has_value()) t3412 = *plan.t3412;
    pending = PendingProcedure::NONE;
}

void MobilityContext::onTauAccepted(uint8_t updateResult,
                                    std::optional<std::array<uint8_t, 11>> newGuti,
                                    std::optional<std::vector<uint8_t>> newTaiList,
                                    std::optional<uint8_t> newT3412)
{
    commitTauAccepted(planTauAccepted(updateResult, std::move(newGuti), std::move(newTaiList), newT3412));
}

void MobilityContext::onProcedureRejected()
{
    if (pending == PendingProcedure::NONE)
        throw LifecycleError("No mobility procedure is pending");
    pending = PendingProcedure::NONE;
}

bool MobilityContext::canForwardUserPlane() const
{
    return emm == EmmState::REGISTERED && ecm == EcmState::CONNECTED &&
           bearer == EpsBearerState::USER_PLANE_READY && pending != PendingProcedure::DETACH;
}

const char *ToString(TauDecision decision)
{
    switch (decision)
    {
    case TauDecision::NO_CHANGE: return "NO_CHANGE";
    case TauDecision::NORMAL_TAU: return "NORMAL_TAU";
    case TauDecision::NOT_REGISTERED: return "NOT_REGISTERED";
    case TauDecision::NO_SECURITY: return "NO_SECURITY";
    case TauDecision::NO_IDENTITY: return "NO_IDENTITY";
    case TauDecision::PROCEDURE_PENDING: return "PROCEDURE_PENDING";
    case TauDecision::NO_ASSIGNED_TAI: return "NO_ASSIGNED_TAI";
    }
    return "UNKNOWN_TAU_DECISION";
}

TauDecision EvaluateServingTai(const MobilityContext &context, const Tai &serving)
{
    if (context.emm != EmmState::REGISTERED)
        return TauDecision::NOT_REGISTERED;
    if (!context.securityContextValid)
        return TauDecision::NO_SECURITY;
    if (!context.guti.has_value())
        return TauDecision::NO_IDENTITY;
    if (context.pending != PendingProcedure::NONE)
        return TauDecision::PROCEDURE_PENDING;
    // Without an assigned list there is nothing to compare against. Treating
    // the absence of a list as "every tracking area is registered" would make
    // an unassigned UE permanently immune to a Normal TAU, and treating it as
    // "no tracking area is registered" would force one on every cell. Neither
    // is a reading of the assignment, so neither is taken.
    if (context.taiList.empty())
        return TauDecision::NO_ASSIGNED_TAI;
    return TaiListContains(context.taiList, serving) ? TauDecision::NO_CHANGE : TauDecision::NORMAL_TAU;
}

} // namespace lte::ue
