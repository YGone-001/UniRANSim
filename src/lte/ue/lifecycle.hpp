//
// This file is a part of UERANSIM project.
// Copyright (c) 2027 ALİ GÜNGÖR.
//
// https://github.com/aligungr/UERANSIM/
// See README, LICENSE, and CONTRIBUTING files for licensing details.
//
#pragma once

#include <array>
#include <cstdint>
#include <optional>
#include <stdexcept>
#include <vector>

#include "tai.hpp"

namespace lte::ue
{

enum class EmmState
{
    DEREGISTERED,
    REGISTERED
};

enum class EcmState
{
    IDLE,
    CONNECTED
};

enum class EpsBearerState
{
    INACTIVE,
    SIGNALING_ESTABLISHED,
    USER_PLANE_READY
};

enum class PendingProcedure
{
    NONE,
    DETACH,
    SERVICE_REQUEST,
    TAU_NORMAL,
    TAU_PERIODIC
};

const char *ToString(EmmState state);
const char *ToString(EcmState state);
const char *ToString(EpsBearerState state);
const char *ToString(PendingProcedure procedure);

class LifecycleError : public std::runtime_error
{
  public:
    using std::runtime_error::runtime_error;
};

// Long-lived single-UE EPS mobility context. S1AP identifiers and transport
// TEIDs belong to one ECM connection; the identity, PDN address and logical
// default bearer survive a normal transition to ECM-IDLE.
struct MobilityContext
{
    EmmState emm{EmmState::DEREGISTERED};
    EcmState ecm{EcmState::IDLE};
    EpsBearerState bearer{EpsBearerState::INACTIVE};
    PendingProcedure pending{PendingProcedure::NONE};

    bool securityContextValid{};
    std::optional<std::array<uint8_t, 11>> guti;
    // The tracking areas this UE is authorized to occupy. Only a fully parsed
    // and validated assignment ever reaches this field, so a malformed TAI
    // list cannot be stored and can never later be consulted as proof that a
    // tracking area code is authorized.
    std::vector<Tai> taiList;
    uint8_t t3412{};
    uint8_t defaultEbi{};
    uint32_t accessGeneration{};
    std::array<uint8_t, 4> assignedIpv4{};

    std::optional<uint32_t> enbUeS1apId;
    std::optional<uint32_t> mmeUeS1apId;
    std::optional<uint32_t> enbTeid;
    std::optional<uint32_t> sgwTeid;

    void onAttachComplete(uint8_t ebi, const std::array<uint8_t, 4> &ipv4,
                          std::optional<std::array<uint8_t, 11>> assignedGuti,
                          const std::vector<uint8_t> &assignedTaiList, uint8_t periodicTimer);
    void onS1ContextEstablished(uint32_t enbId, uint32_t mmeId);
    void onBearerTransportEstablished(uint32_t localTeid, uint32_t remoteTeid);
    void onUserPlaneReady();
    void onS1ContextReleased();
    void acceptAccessRelease(uint8_t ebi, uint32_t generation);
    void validateAccessRestoration(uint8_t ebi, uint32_t generation, bool dedicated) const;
    // A fresh Attach begins a new logical EPS session and a new radio
    // incarnation. The access-generation counter is shared with the eNB and
    // must restart on both sides at the same point, otherwise a later
    // legitimate S1 release reaches this UE already out of step.
    void beginNewAttach();
    // The UE has reselected a different cell while ECM-IDLE. The S1AP
    // identities, the access TEIDs and the access generation belong to the
    // cell being left and are retired here; the target cell allocates its own
    // and the old ones must never be presented there. The EPS registration,
    // security context, GUTI, tracking areas and logical EPS bearer identities
    // belong to the session rather than to any one cell, so they survive. The
    // access generation restarts alongside the target cell's own counter.
    void onCellReselected();
    void startServiceRequest();
    void onServiceRestored(bool userPlaneReady = true);
    void onServiceRestored(uint32_t enbId, uint32_t mmeId, uint32_t localTeid, uint32_t remoteTeid);
    void startDetach();
    void onDetachAccepted();
    void startTau(bool periodic);
    // Completes a Tracking Area Update. `updateResult` is the EPS update result
    // the Accept carried, and only "TA updated" is an EPS-only update this UE
    // performs: one announcing a combined TA/LA update or a pre-Release 8 ISDN
    // number allocation is refused here rather than recorded as an update that
    // never happened.
    void onTauAccepted(uint8_t updateResult,
                       std::optional<std::array<uint8_t, 11>> newGuti,
                       std::optional<std::vector<uint8_t>> newTaiList,
                       std::optional<uint8_t> newT3412);
    void onProcedureRejected();
    [[nodiscard]] bool canForwardUserPlane() const;
};

// Why a newly observed serving tracking area does or does not call for a
// Normal Tracking Area Update.
enum class TauDecision
{
    // The serving TAI is in the registered list. Moving within it is not, on
    // its own, a reason to update the network.
    NO_CHANGE,
    // The serving TAI is outside the registered list and the context can
    // support a Normal TAU.
    NORMAL_TAU,
    NOT_REGISTERED,
    NO_SECURITY,
    NO_IDENTITY,
    PROCEDURE_PENDING,
    // No tracking area list was ever assigned. Fail closed rather than treat
    // an unknown registration area as if it authorized this one.
    NO_ASSIGNED_TAI
};

const char *ToString(TauDecision decision);

// Decides whether arriving in `serving` calls for a Normal Tracking Area
// Update. This is purely a question about the registered tracking area list:
// it never fires on an application timer, and periodic TAU keeps its own
// distinct trigger. Malformed or absent assignment information yields
// NO_ASSIGNED_TAI instead of a guess.
TauDecision EvaluateServingTai(const MobilityContext &context, const Tai &serving);

} // namespace lte::ue
