//
// This file is a part of UERANSIM project.
// Copyright (c) 2027 ALİ GÜNGÖR.
//
// https://github.com/aligungr/UERANSIM/
// See README, LICENSE, and CONTRIBUTING files for licensing details.
//

#include "lifecycle.hpp"

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
                                       std::vector<uint8_t> assignedTaiList, uint8_t periodicTimer)
{
    if (emm != EmmState::DEREGISTERED || ecm != EcmState::CONNECTED || ebi == 0 ||
        ipv4 == std::array<uint8_t, 4>{})
        throw LifecycleError("Invalid EPS Attach completion transition");
    emm = EmmState::REGISTERED;
    bearer = EpsBearerState::SIGNALING_ESTABLISHED;
    pending = PendingProcedure::NONE;
    defaultEbi = ebi;
    assignedIpv4 = ipv4;
    guti = assignedGuti;
    taiList = std::move(assignedTaiList);
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
        if (ecm != EcmState::CONNECTED || pending != PendingProcedure::NONE)
            throw LifecycleError("Dedicated restoration precedes default service restoration");
    }
    else if (pending != PendingProcedure::SERVICE_REQUEST || ecm != EcmState::IDLE)
        throw LifecycleError("Default restoration has no pending Service Request");
}

void MobilityContext::beginNewAttach()
{
    accessGeneration = 0;
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
    if (emm != EmmState::REGISTERED || !securityContextValid || !guti.has_value() ||
        pending != PendingProcedure::NONE)
        throw LifecycleError("Tracking Area Update preconditions are not satisfied");
    pending = periodic ? PendingProcedure::TAU_PERIODIC : PendingProcedure::TAU_NORMAL;
}

void MobilityContext::onTauAccepted(std::optional<std::array<uint8_t, 11>> newGuti,
                                    std::optional<std::vector<uint8_t>> newTaiList,
                                    std::optional<uint8_t> newT3412)
{
    if (pending != PendingProcedure::TAU_NORMAL && pending != PendingProcedure::TAU_PERIODIC)
        throw LifecycleError("Unexpected Tracking Area Update Accept");
    if (newGuti.has_value()) guti = *newGuti;
    if (newTaiList.has_value()) taiList = std::move(*newTaiList);
    if (newT3412.has_value()) t3412 = *newT3412;
    pending = PendingProcedure::NONE;
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

} // namespace lte::ue
