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
    std::vector<uint8_t> taiList;
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
                          std::vector<uint8_t> assignedTaiList, uint8_t periodicTimer);
    void onS1ContextEstablished(uint32_t enbId, uint32_t mmeId);
    void onBearerTransportEstablished(uint32_t localTeid, uint32_t remoteTeid);
    void onUserPlaneReady();
    void onS1ContextReleased();
    void acceptAccessRelease(uint8_t ebi, uint32_t generation);
    void validateAccessRestoration(uint8_t ebi, uint32_t generation, bool dedicated) const;
    void startServiceRequest();
    void onServiceRestored(bool userPlaneReady = true);
    void onServiceRestored(uint32_t enbId, uint32_t mmeId, uint32_t localTeid, uint32_t remoteTeid);
    void startDetach();
    void onDetachAccepted();
    void startTau(bool periodic);
    void onTauAccepted(std::optional<std::array<uint8_t, 11>> newGuti,
                       std::optional<std::vector<uint8_t>> newTaiList,
                       std::optional<uint8_t> newT3412);
    void onProcedureRejected();
    [[nodiscard]] bool canForwardUserPlane() const;
};

} // namespace lte::ue
