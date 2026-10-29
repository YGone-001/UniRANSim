//
// This file is a part of UERANSIM project.
// Copyright (c) 2027 ALİ GÜNGÖR.
//
// https://github.com/aligungr/UERANSIM/
// See README, LICENSE, and CONTRIBUTING files for licensing details.
//

#include "app.hpp"

#include "lifecycle.hpp"
#include "bearer_runtime.hpp"
#include "nas.hpp"
#include "paging.hpp"
#include "radio_link.hpp"
#include "security.hpp"
#include "trigger.hpp"
#include "tun.hpp"

#include <algorithm>
#include <chrono>
#include <iomanip>
#include <iostream>
#include <memory>
#include <sstream>

#include <lte/ip_packet.hpp>
#include <lte/tft.hpp>

#include <lib/udp/server.hpp>

namespace lte::ue
{
namespace
{
void Log(const char *level, const std::string &message)
{
    std::cout << "[lte-ue] [" << level << "] " << message << std::endl;
}

void LogState(State state)
{
    Log("INFO", std::string("State=") + ToString(state));
}

void SendNas(udp::UdpServer &socket, const InetAddress &enb, uint32_t ueId, std::vector<uint8_t> nas)
{
    auto frame = link::Encode({link::MessageType::NAS_UPLINK, ueId, std::move(nas)});
    socket.Send(enb, frame.data(), frame.size());
}

void SendServiceRequest(udp::UdpServer &socket, const InetAddress &enb, uint32_t ueId,
                        const std::array<uint8_t, 11> &guti, const std::vector<uint8_t> &nas)
{
    if (nas.size() != 4)
        throw std::runtime_error("Compact Service Request NAS must be four octets");
    std::vector<uint8_t> payload;
    payload.reserve(9);
    payload.push_back(guti[6]);
    payload.insert(payload.end(), guti.begin() + 7, guti.end());
    payload.insert(payload.end(), nas.begin(), nas.end());
    auto frame = link::Encode({link::MessageType::SERVICE_REQUEST, ueId, std::move(payload)});
    socket.Send(enb, frame.data(), frame.size());
}

// Sends a security-protected NAS message and advances the uplink NAS COUNT.
void SendProtected(udp::UdpServer &socket, const InetAddress &enb, uint32_t ueId, SecurityContext &security,
                   bool newContext, const std::vector<uint8_t> &plain)
{
    auto protectedMessage = nas::Protect(security, true, newContext, plain);
    SendNas(socket, enb, ueId, std::move(protectedMessage));
    security.ulNasCount = (security.ulNasCount + 1U) & 0xFFFFFFU;
}

// Protected uplink NAS that continues an existing EPS session over a new S1
// connection at a reselected cell. The identity prefix is derived from the
// UE's own valid GUTI, so the target eNB can address the Initial UE Message
// without the UE presenting any identifier the source cell allocated.
void SendMobilityNas(udp::UdpServer &socket, const InetAddress &enb, uint32_t ueId,
                     const std::array<uint8_t, 11> &guti, const std::vector<uint8_t> &protectedNas)
{
    std::vector<uint8_t> payload;
    payload.reserve(5 + protectedNas.size());
    payload.push_back(guti[6]);
    payload.insert(payload.end(), guti.begin() + 7, guti.end());
    payload.insert(payload.end(), protectedNas.begin(), protectedNas.end());
    auto frame = link::Encode({link::MessageType::NAS_UPLINK_MOBILITY, ueId, std::move(payload)});
    socket.Send(enb, frame.data(), frame.size());
}

// Verifies and recovers a security-protected downlink NAS message, then records
// the accepted DL COUNT. An unverified message never reaches the caller.
std::vector<uint8_t> ReceiveProtected(SecurityContext &security, const std::vector<uint8_t> &message)
{
    return nas::ReceiveProtectedDownlink(security, message);
}
} // namespace

int Run(const Config &config, const std::atomic_bool &shutdownRequested)
{
    State state = State::DISCONNECTED;
    SecurityContext security{};
    MobilityContext mobility{};
    bool attachAcceptSeen = false;
    bool defaultBearerAccepted = false;
    uint8_t activeEbi = 0;
    std::array<uint8_t, 4> assignedIpv4{};
    std::unique_ptr<TunDevice> tun;
    // Dedicated EPS bearers accepted on top of the default bearer. Each keeps
    // its own TFT so an uplink packet is routed by what the network selected,
    // never by a heuristic.
    nas::EpsBearerConfiguration defaultConfiguration;
    std::vector<DedicatedBearerRuntime> dedicatedBearers;
    uint64_t dedicatedUplinkPackets = 0;
    uint64_t dedicatedDownlinkPackets = 0;
    uint64_t tunUplinkPackets = 0;
    uint64_t tunUplinkBytes = 0;
    uint64_t tunDownlinkPackets = 0;
    uint64_t tunDownlinkBytes = 0;
    uint64_t malformedDrops = 0;
    uint64_t bearerInactiveDrops = 0;
    // Packets generated while no usable access transport exists. They are
    // dropped, counted and never buffered and never rerouted to another bearer.
    uint64_t accessUnavailableDrops = 0;
    // Unexpected S1-MME association loss bookkeeping. The UE keeps its EPS
    // registration and logical bearers; only access transport is invalidated.
    uint64_t accessLosses = 0;
    RestorationTrigger restorationTrigger;
    int recoveryAttempts = 0;
    uint64_t recoveryRestorations = 0;
    uint64_t recoveryFailures = 0;
    auto recoveryDeadline = std::chrono::steady_clock::time_point::max();
    bool scenarioTriggered = false;
    bool idleReleaseRequested = false;
    std::vector<uint8_t> pendingWire;
    int procedureRetries = 0;
    auto procedureDeadline = std::chrono::steady_clock::time_point::max();
    // Network-triggered paging bookkeeping. Nothing here can make the UE send a
    // Service Request on its own: only an accepted page does.
    bool pagingWaitArmed = false;
    auto pagingDeadline = std::chrono::steady_clock::time_point::max();
    uint64_t pagingIndications = 0;
    uint64_t pagingMatched = 0;
    uint64_t pagingIgnored = 0;
    uint64_t pagingSuppressed = 0;
    uint64_t pagingServiceRequests = 0;
    uint64_t pagingRestorations = 0;
    uint64_t pagingRestorationFailures = 0;
    udp::UdpServer socket(config.link.localAddress, config.link.localPort);
    InetAddress enb(config.link.enbAddress, config.link.enbPort);
    const uint32_t ueId = config.ueId;
    mobility.ecm = EcmState::CONNECTED;
    state = State::CONNECTED_TO_ENB;
    LogState(state);
    Log("INFO", "LTE UE " + std::to_string(ueId) + " using subscriber IMSI ..." + config.imsi.substr(config.imsi.size() - 4));
    mobility.beginNewAttach();
    auto attach = nas::EncodeAttachRequest(config);
    SendNas(socket, enb, ueId, std::move(attach));
    state = State::ATTACH_REQUEST_SENT;
    LogState(state);
    state = State::AUTHENTICATION_PENDING;
    LogState(state);

    auto deadline = std::chrono::steady_clock::now() + std::chrono::milliseconds(config.link.timeoutMs);
    auto scenarioDeadline = std::chrono::steady_clock::time_point::max();
    uint8_t buffer[link::MaxDataPduSize + link::HeaderSize];
    while (!shutdownRequested && (mobility.emm == EmmState::REGISTERED || std::chrono::steady_clock::now() < deadline))
    {
        const auto now = std::chrono::steady_clock::now();
        if (mobility.emm == EmmState::REGISTERED && !scenarioTriggered && now >= scenarioDeadline)
        {
            scenarioTriggered = true;
            if (config.lifecycle.scenario == LifecycleScenario::SERVICE_REQUEST ||
                config.lifecycle.scenario == LifecycleScenario::PAGING ||
                config.lifecycle.scenario == LifecycleScenario::IDLE_RESELECTION)
            {
                auto request = link::Encode({link::MessageType::S1_CONTEXT_RELEASE_REQUEST, ueId,
                                             {mobility.defaultEbi}});
                socket.Send(enb, request.data(), request.size());
                idleReleaseRequested = true;
                procedureDeadline = now + std::chrono::milliseconds(config.lifecycle.procedureTimeoutMs);
                if (config.lifecycle.scenario == LifecycleScenario::PAGING)
                    Log("INFO", "Controlled idle trigger sent an S1 Context Release Request; the UE will wait "
                                "for a network paging indication instead of sending Service Request");
                else if (config.lifecycle.scenario == LifecycleScenario::IDLE_RESELECTION)
                    Log("INFO", "Controlled idle trigger sent an S1 Context Release Request; the UE will reselect "
                                "the configured target cell once it reaches ECM-IDLE");
                else
                    Log("INFO", "Controlled idle trigger sent a standards-based S1 Context Release Request");
            }
            else if (config.lifecycle.scenario == LifecycleScenario::DETACH)
            {
                mobility.startDetach();
                auto plain = nas::EncodeDetachRequest(security.ksi, *mobility.guti, config.lifecycle.switchOff);
                pendingWire = nas::Protect(security, true, false, plain);
                SendNas(socket, enb, ueId, pendingWire);
                security.ulNasCount = (security.ulNasCount + 1U) & 0xFFFFFFU;
                procedureDeadline = now + std::chrono::milliseconds(config.lifecycle.procedureTimeoutMs);
                Log("INFO", std::string("Protected EPS Detach Request sent; switch-off=") +
                                (config.lifecycle.switchOff ? "true" : "false"));
                if (config.lifecycle.switchOff)
                {
                    auto deleted = link::Encode({link::MessageType::EPS_SESSION_DELETED, ueId,
                        link::EncodeBearerRestoration(activeEbi, mobility.accessGeneration)});
                    socket.Send(enb, deleted.data(), deleted.size());
                    mobility.onDetachAccepted();
                    dedicatedBearers.clear();
                    defaultConfiguration = {};
                    security = SecurityContext{};
                    tun.reset();
                    Log("INFO", "Switch-off Detach completed without waiting for Detach Accept");
                    return 0;
                }
            }
            else if (config.lifecycle.scenario == LifecycleScenario::TAU_NORMAL ||
                     config.lifecycle.scenario == LifecycleScenario::TAU_PERIODIC)
            {
                const bool periodic = config.lifecycle.scenario == LifecycleScenario::TAU_PERIODIC;
                mobility.startTau(periodic);
                auto plain = nas::EncodeTauRequest(
                    security.ksi, *mobility.guti,
                    RetainedBearerIdentities(mobility.defaultEbi, dedicatedBearers), periodic);
                pendingWire = nas::Protect(security, true, false, plain);
                SendNas(socket, enb, ueId, pendingWire);
                security.ulNasCount = (security.ulNasCount + 1U) & 0xFFFFFFU;
                procedureDeadline = now + std::chrono::milliseconds(config.lifecycle.procedureTimeoutMs);
                Log("INFO", std::string("Protected ") + (periodic ? "periodic" : "normal") +
                                " Tracking Area Update Request sent");
            }
        }

        // A stop request always wins over a deadline inside the same turn, so a
        // shutdown is never reported as a failed procedure. The loop condition
        // is evaluated before these checks; the guard makes the precedence
        // explicit rather than depending on when the flag was set.
        if (!shutdownRequested && idleReleaseRequested && now >= procedureDeadline)
        {
            Log("ERROR", "Timed out waiting for the MME S1 Context Release Command/Complete flow");
            return 1;
        }

        if (!shutdownRequested && pagingWaitArmed && now >= pagingDeadline)
        {
            // The MME owns paging retries. This is a bounded laboratory wait, and
            // its expiry is an unresolved test condition, never paging success.
            Log("ERROR", "Timed out waiting for a network paging indication; no Service Request was sent");
            return 1;
        }

        // Access restoration after an unexpected S1-MME association loss. The
        // UE sends a genuine compact EPS Service Request under its existing NAS
        // security context and GUTI. It never re-Attaches silently and never
        // invents a network procedure; the MME decides whether the old EPS
        // context still exists.
        if (restorationTrigger.recoveryArmed() && mobility.emm == EmmState::REGISTERED &&
            mobility.ecm == EcmState::IDLE && mobility.pending == PendingProcedure::NONE && now >= recoveryDeadline)
        {
            if (recoveryAttempts >= config.lifecycle.recoveryMaxAttempts)
            {
                restorationTrigger.abandon();
                Log("ERROR", "Access recovery gave up after " + std::to_string(recoveryAttempts) +
                                " Service Request attempt(s); the UE remains registered and ECM-IDLE");
            }
            else if (restorationTrigger.tryTakeFromRecovery())
            {
                try
                {
                    mobility.startServiceRequest();
                    pendingWire = nas::EncodeServiceRequest(security);
                    SendServiceRequest(socket, enb, ueId, *mobility.guti, pendingWire);
                    security.ulNasCount = (security.ulNasCount + 1U) & 0xFFFFFFU;
                    ++recoveryAttempts;
                    procedureRetries = 0;
                    procedureDeadline = now + std::chrono::milliseconds(config.lifecycle.procedureTimeoutMs);
                    recoveryDeadline = now + std::chrono::milliseconds(config.lifecycle.recoveryRetryMs);
                    Log("INFO", "Compact EPS Service Request sent after unexpected S1 access loss (attempt " +
                                    std::to_string(recoveryAttempts) + ")");
                }
                catch (const std::exception &e)
                {
                    restorationTrigger.abandon();
                    Log("ERROR", std::string("Access recovery cannot start a Service Request: ") + e.what());
                }
            }
        }

        if (mobility.pending != PendingProcedure::NONE && !pendingWire.empty() && now >= procedureDeadline)
        {
            if (procedureRetries >= config.lifecycle.maxRetries)
            {
                const auto failed = restorationTrigger.takeFailed();
                if (failed == RestorationOwner::PAGING)
                {
                    ++pagingRestorationFailures;
                    Log("ERROR", "Paging-triggered service restoration failed after bounded retransmissions");
                }
                else if (failed == RestorationOwner::RECOVERY)
                {
                    // A bounded recovery outcome: the network never completed
                    // the restoration. The UE stays registered and ECM-IDLE and
                    // reports the failure instead of fabricating success.
                    ++recoveryFailures;
                    pendingWire.clear();
                    mobility.onProcedureRejected();
                    Log("ERROR", "Access recovery Service Request timed out after bounded retransmissions");
                    recoveryDeadline = now + std::chrono::milliseconds(config.lifecycle.recoveryRetryMs);
                    continue;
                }
                Log("ERROR", std::string(ToString(mobility.pending)) + " timed out after bounded retransmissions");
                return 1;
            }
            if (mobility.pending == PendingProcedure::SERVICE_REQUEST)
                SendServiceRequest(socket, enb, ueId, *mobility.guti, pendingWire);
            else if (mobility.emm == EmmState::REGISTERED && !mobility.mmeUeS1apId.has_value())
                // A retransmission of a procedure that is still opening an S1
                // connection has to leave by the same route the first one used.
                // Once the MME has assigned an identifier the ordinary uplink
                // NAS transport is the right route again.
                SendMobilityNas(socket, enb, ueId, *mobility.guti, pendingWire);
            else
                SendNas(socket, enb, ueId, pendingWire);
            ++procedureRetries;
            procedureDeadline = now + std::chrono::milliseconds(config.lifecycle.procedureTimeoutMs);
            Log("WARN", std::string("Retransmitted ") + ToString(mobility.pending) +
                            ", retry=" + std::to_string(procedureRetries));
        }

        if (tun)
        {
            // Bound each turn so continuous application traffic cannot starve
            // downlink radio-link processing.
            for (int packetBudget = 0; packetBudget < 16; ++packetBudget)
            {
                std::vector<uint8_t> packet;
                if (!tun->readPacket(packet))
                    break;
                try
                {
                    const auto ipv4 = ip::Validate(packet.data(), packet.size(),
                                                   static_cast<size_t>(config.tun.mtu));
                    if (ipv4.source != assignedIpv4)
                        throw ip::ValidationError("TUN uplink source does not match the assigned UE IPv4 address");
                    ++tunUplinkPackets;
                    tunUplinkBytes += packet.size();

                    // Access transport may be temporarily unavailable, for
                    // example after an unexpected S1-MME association loss. Such
                    // packets are dropped and counted: they are never buffered
                    // and never sent through an obsolete TEID.
                    if (!mobility.canForwardUserPlane())
                    {
                        ++accessUnavailableDrops;
                        continue;
                    }

                    // Select the bearer by the network-provided TFT. Ties are
                    // resolved by evaluation precedence, and no match falls
                    // back to the default bearer.
                    const auto selection = SelectUplinkBearer(activeEbi, dedicatedBearers, packet.data(), packet.size());
                    const uint8_t selectedEbi = selection.ebi;

                    std::vector<uint8_t> frame;
                    if (selectedEbi != activeEbi)
                    {
                        auto &selected = *std::find_if(dedicatedBearers.begin(), dedicatedBearers.end(),
                            [&](const auto &bearer) { return bearer.ebi == selectedEbi; });
                        if (!selected.accessReady)
                        {
                            ++bearerInactiveDrops;
                            ++selected.inactiveDrops;
                            continue; // bounded drop; keep the TFT and never fall back to default
                        }
                        std::vector<uint8_t> payload;
                        payload.reserve(packet.size() + 1);
                        payload.push_back(selectedEbi);
                        payload.insert(payload.end(), packet.begin(), packet.end());
                        frame = link::Encode({link::MessageType::DATA_UPLINK_BEARER, ueId, std::move(payload)});
                    }
                    else
                        frame = link::Encode({link::MessageType::DATA_UPLINK, ueId, std::move(packet)});

                    if (!socket.TrySend(enb, frame.data(), frame.size()))
                        Log("WARN", "LTE radio-link uplink send would block; packet dropped");
                    else if (selectedEbi != activeEbi)
                    {
                        ++dedicatedUplinkPackets;
                        ++std::find_if(dedicatedBearers.begin(), dedicatedBearers.end(),
                            [&](const auto &bearer) { return bearer.ebi == selectedEbi; })->uplinkPackets;
                    }
                }
                catch (const std::exception &e)
                {
                    ++malformedDrops;
                    Log("WARN", std::string("Dropped invalid LTE TUN uplink packet: ") + e.what());
                }
            }
        }

        InetAddress peer;
        int received = socket.Receive(buffer, sizeof(buffer), mobility.emm == EmmState::REGISTERED ? 50 : 250, peer);
        if (received <= 0)
            continue;
        if (peer != enb)
        {
            Log("WARN", "Ignoring LTE radio-link datagram from an unexpected endpoint");
            continue;
        }
        try
        {
            auto message = link::Decode(buffer, static_cast<size_t>(received));
            if (!link::IsDownlink(message.type) || message.ueId != ueId)
                throw link::DecodeError("Unexpected LTE radio-link routing fields");

            if (message.type == link::MessageType::BEARER_RELEASED)
            {
                if (mobility.emm != EmmState::REGISTERED || message.payload.size() != 1)
                    throw link::DecodeError("Malformed bearer release");
                const uint8_t releasedEbi = message.payload[0];
                if (releasedEbi == activeEbi)
                {
                    tun.reset();
                    dedicatedBearers.clear();
                    defaultConfiguration = {};
                    mobility.bearer = EpsBearerState::INACTIVE;
                    state = State::EPS_REGISTERED;
                    LogState(state);
                    Log("WARN", "Default bearer released; LTE TUN resources were closed");
                    continue;
                }
                const auto released = std::find_if(dedicatedBearers.begin(), dedicatedBearers.end(),
                                                   [releasedEbi](const DedicatedBearerRuntime &bearer) {
                                                       return bearer.ebi == releasedEbi;
                                                   });
                if (released == dedicatedBearers.end())
                    throw link::DecodeError("Bearer release names an unknown bearer");
                dedicatedBearers.erase(released);
                Log("INFO", "Dedicated EPS bearer " + std::to_string(releasedEbi) +
                                " released; default bearer and TUN retained");
                continue;
            }
            if (message.type == link::MessageType::S1_CONTEXT_RELEASED)
            {
                if (mobility.emm != EmmState::REGISTERED || message.payload[0] != activeEbi)
                    throw link::DecodeError("S1 context release does not match the registered bearer");
                const auto release = link::DecodeBearerRestoration(message.payload);
                const bool serviceAborted = mobility.pending == PendingProcedure::SERVICE_REQUEST;
                mobility.acceptAccessRelease(release.first, release.second);
                if (serviceAborted)
                    pendingWire.clear();
                for (auto &bearer : dedicatedBearers)
                    bearer.releaseAccessTransport();
                Log("INFO", "State=ECM_IDLE; EPS registration, security, GUTI, bearer and TUN retained");
                if (idleReleaseRequested)
                {
                    idleReleaseRequested = false;
                    if (config.lifecycle.scenario == LifecycleScenario::PAGING)
                    {
                        // The wait starts here, at the first ECM-IDLE turn, so its
                        // deadline measures the paging window alone. Arming it when
                        // the release request was sent would let a short pagingWaitMs
                        // expire in the middle of the release exchange and report a
                        // paging timeout for what is really a release failure.
                        pagingWaitArmed = true;
                        pagingDeadline = std::chrono::steady_clock::now() +
                                         std::chrono::milliseconds(config.lifecycle.pagingWaitMs);
                        // Network-triggered scenario: stay idle until the MME pages.
                        Log("INFO", "Waiting for a network paging indication; no Service Request is sent locally");
                    }
                    else if (config.lifecycle.scenario == LifecycleScenario::IDLE_RESELECTION)
                    {
                        if (!config.link.targetCell.has_value())
                            throw std::runtime_error(
                                "The idle-reselection scenario needs a configured enbLink.targetCell");
                        const auto &target = *config.link.targetCell;
                        const Tai serving{config.plmn, config.link.servingTac};
                        const Tai arriving{target.plmn, target.tac};
                        // The cell being left keeps its S1AP identities, its
                        // access TEIDs and its access generation. None of them
                        // may be presented at the target.
                        mobility.onCellReselected();
                        enb = InetAddress(target.radioAddress, target.radioPort);
                        Log("INFO", "ECM-IDLE cell reselection " + serving.plmn.toString() + "/" +
                                        std::to_string(serving.tac) + " -> " + arriving.plmn.toString() + "/" +
                                        std::to_string(arriving.tac) + " via " + target.radioAddress + ":" +
                                        std::to_string(target.radioPort));

                        // Whether the move calls for a Normal Tracking Area
                        // Update is decided from the registered tracking area
                        // list alone. Moving cells is not the trigger; moving
                        // out of the registered area is.
                        const auto decision = EvaluateServingTai(mobility, arriving);
                        if (decision == TauDecision::NO_CHANGE)
                        {
                            Log("INFO", std::string("Target tracking area is in the registered list (") +
                                            ToString(decision) + "); no Tracking Area Update is sent");
                        }
                        else if (decision == TauDecision::NORMAL_TAU)
                        {
                            mobility.startTau(false);
                            auto plain = nas::EncodeTauRequest(
                                security.ksi, *mobility.guti,
                                RetainedBearerIdentities(mobility.defaultEbi, dedicatedBearers), false);
                            pendingWire = nas::Protect(security, true, false, plain);
                            SendMobilityNas(socket, enb, ueId, *mobility.guti, pendingWire);
                            security.ulNasCount = (security.ulNasCount + 1U) & 0xFFFFFFU;
                            procedureRetries = 0;
                            procedureDeadline = std::chrono::steady_clock::now() +
                                                std::chrono::milliseconds(config.lifecycle.procedureTimeoutMs);
                            Log("INFO", "Protected Normal Tracking Area Update Request sent through the "
                                        "reselected cell");
                        }
                        else
                        {
                            throw std::runtime_error(
                                std::string("Cannot start a Normal Tracking Area Update after reselection: ") +
                                ToString(decision));
                        }
                    }
                    else
                    {
                        mobility.startServiceRequest();
                        pendingWire = nas::EncodeServiceRequest(security);
                        SendServiceRequest(socket, enb, ueId, *mobility.guti, pendingWire);
                        security.ulNasCount = (security.ulNasCount + 1U) & 0xFFFFFFU;
                        procedureRetries = 0;
                        procedureDeadline = std::chrono::steady_clock::now() +
                                            std::chrono::milliseconds(config.lifecycle.procedureTimeoutMs);
                        Log("INFO", "Compact EPS Service Request sent from ECM-IDLE");
                    }
                }
                continue;
            }
            if (message.type == link::MessageType::S1_ACCESS_LOST)
            {
                // INTERNAL simulator abstraction: the eNB lost its S1-MME SCTP
                // association and invalidated this UE's access transport. This
                // is deliberately not a UE Context Release procedure — no S1AP
                // message was exchanged and no NAS or RRC message is implied.
                if (mobility.emm != EmmState::REGISTERED || message.payload[0] != activeEbi)
                    throw link::DecodeError("S1 access loss does not match the registered bearer");
                const auto lost = link::DecodeBearerRestoration(message.payload);
                mobility.acceptAccessRelease(lost.first, lost.second);
                pendingWire.clear();
                for (auto &bearer : dedicatedBearers)
                    bearer.releaseAccessTransport();
                ++accessLosses;
                // Only the UE-initiated path is armed here. Network-initiated
                // Paging is left untouched and remains fully functional.
                restorationTrigger.onAccessLoss(config.lifecycle.recoveryDelayMs > 0 &&
                                                config.lifecycle.recoveryMaxAttempts > 0);
                recoveryAttempts = 0;
                recoveryDeadline = std::chrono::steady_clock::now() +
                                   std::chrono::milliseconds(config.lifecycle.recoveryDelayMs);
                Log("WARN", "S1 access transport lost unexpectedly; EPS registration, security, GUTI, "
                            "logical bearers, TFT and TUN retained");
                continue;
            }
            if (message.type == link::MessageType::PAGING_INDICATION)
            {
                ++pagingIndications;
                // Decoding is strict: a notification that is not exactly the
                // seven-octet S-TMSI||TAC frame never reaches the state machine.
                const auto notification =
                    link::DecodePagingNotification(message.payload.data(), message.payload.size());
                const auto match = EvaluatePaging(mobility, config.plmn, notification);
                if (match != PagingMatch::ACCEPTED)
                {
                    ++pagingIgnored;
                    Log("INFO", std::string("Paging indication ignored: ") + ToString(match));
                    continue;
                }

                // A duplicate or late page must not start a second Service
                // Request, consume a second NAS COUNT, nor erase a
                // UE-initiated restoration that is already in flight.
                if (!restorationTrigger.tryTakeFromPaging())
                {
                    ++pagingSuppressed;
                    Log("INFO", "Paging indication ignored: another trigger already owns the pending restoration");
                    continue;
                }
                ++pagingMatched;
                auto compact = RespondToPaging(mobility, config.plmn, notification, security);
                if (!compact.has_value())
                    throw std::runtime_error("Accepted paging produced no compact Service Request");
                pendingWire = std::move(*compact);
                SendServiceRequest(socket, enb, ueId, *mobility.guti, pendingWire);
                ++pagingServiceRequests;
                pagingWaitArmed = false;
                procedureRetries = 0;
                procedureDeadline = std::chrono::steady_clock::now() +
                                    std::chrono::milliseconds(config.lifecycle.procedureTimeoutMs);
                Log("INFO", "Paging identity matched (MMEC=" + std::to_string(notification.mmeCode) +
                                "); compact EPS Service Request sent for the network-triggered restoration");
                continue;
            }
            if (message.type == link::MessageType::S1_CONTEXT_RESTORED)
            {
                const auto restored = link::DecodeBearerRestoration(message.payload);
                mobility.validateAccessRestoration(restored.first, restored.second, false);
                mobility.onServiceRestored(tun != nullptr);
                pendingWire.clear();
                // Exactly one trigger owns a restoration. A page that won the
                // race against an armed recovery timer is a paging restoration
                // even though the timer had already been scheduled.
                switch (restorationTrigger.takeRestored())
                {
                case RestorationOwner::PAGING:
                    ++pagingRestorations;
                    Log("INFO", "Access restoration completed after a network paging indication");
                    break;
                case RestorationOwner::RECOVERY:
                    ++recoveryRestorations;
                    Log("INFO", "Access restoration completed after unexpected S1 access loss");
                    break;
                case RestorationOwner::NONE:
                    break;
                }
                if (tun)
                {
                    auto readyFrame = link::Encode({link::MessageType::BEARER_TRANSPORT_READY, ueId,
                        link::EncodeBearerRestoration(activeEbi, mobility.accessGeneration)});
                    socket.Send(enb, readyFrame.data(), readyFrame.size());
                    Log("INFO", "State=ECM_CONNECTED; existing EPS bearer transport and user plane restored");
                }
                else
                    Log("WARN", "State=ECM_CONNECTED; bearer signaling restored in control-plane-only mode");
                continue;
            }
            if (message.type == link::MessageType::DEDICATED_BEARER_RESTORED)
            {
                const auto restored = link::DecodeBearerRestoration(message.payload);
                auto bearer = std::find_if(dedicatedBearers.begin(), dedicatedBearers.end(),
                    [&](const auto &candidate) { return candidate.ebi == restored.first; });
                if (bearer == dedicatedBearers.end() || !tun)
                    throw link::DecodeError("Restoration has no logical dedicated bearer or TUN");
                auto candidate = *bearer;
                candidate.restoreAccess(mobility, restored.first, restored.second);
                auto ack = link::Encode({link::MessageType::BEARER_TRANSPORT_READY, ueId, message.payload});
                socket.Send(enb, ack.data(), ack.size());
                *bearer = std::move(candidate);
                Log("INFO", "Existing dedicated EBI=" + std::to_string(restored.first) +
                            " access restored; retained TFT and NAS security unchanged");
                continue;
            }
            if (message.type == link::MessageType::DATA_DOWNLINK)
            {
                if (!tun || !mobility.canForwardUserPlane())
                {
                    ++bearerInactiveDrops;
                    throw link::DecodeError("Downlink data arrived before TUN readiness");
                }
                const auto ipv4 = ip::Validate(message.payload.data(), message.payload.size(),
                                               static_cast<size_t>(config.tun.mtu));
                if (ipv4.destination != assignedIpv4)
                    throw ip::ValidationError("Downlink destination does not match the assigned UE IPv4 address");
                if (tun->writePacket(message.payload.data(), message.payload.size()))
                {
                    ++tunDownlinkPackets;
                    tunDownlinkBytes += message.payload.size();
                }
                continue;
            }

            if (message.type == link::MessageType::DATA_DOWNLINK_BEARER)
            {
                if (!tun || !mobility.canForwardUserPlane())
                {
                    ++bearerInactiveDrops;
                    throw link::DecodeError("Dedicated downlink data arrived before TUN readiness");
                }
                if (message.payload.size() < 2)
                    throw link::DecodeError("Malformed bearer-aware downlink frame");
                const uint8_t bearerEbi = message.payload[0];
                const auto bearer = std::find_if(dedicatedBearers.begin(), dedicatedBearers.end(),
                                                 [bearerEbi](const DedicatedBearerRuntime &candidate) {
                                                     return candidate.ebi == bearerEbi;
                                                 });
                if (bearer == dedicatedBearers.end() || !bearer->accessReady)
                {
                    ++bearerInactiveDrops;
                    throw link::DecodeError("Downlink names an unknown or access-inactive dedicated bearer");
                }

                std::vector<uint8_t> packet(message.payload.begin() + 1, message.payload.end());
                const auto ipv4 = ip::Validate(packet.data(), packet.size(),
                                               static_cast<size_t>(config.tun.mtu));
                if (ipv4.destination != assignedIpv4)
                    throw ip::ValidationError("Downlink destination does not match the assigned UE IPv4 address");
                if (tun->writePacket(packet.data(), packet.size()))
                {
                    ++tunDownlinkPackets;
                    ++dedicatedDownlinkPackets;
                    ++bearer->downlinkPackets;
                    tunDownlinkBytes += packet.size();
                }
                continue;
            }

            if (message.type != link::MessageType::NAS_DOWNLINK)
                throw link::DecodeError("Data/NAS direction mismatch");
            if (!security.securityActive)
            {
                // Only a Security Mode Command may arrive before the context is active.
                if (!nas::IsSecurityModeCommand(message.payload.data(), message.payload.size()))
                {
                    // Authentication Request is still plain EMM.
                    if (state == State::AUTHENTICATION_PENDING || state == State::AUTHENTICATION_RESPONSE_SENT ||
                        state == State::EPS_AKA_ACCEPTED)
                    {
                        if (state == State::EPS_AKA_ACCEPTED)
                            throw nas::DecodeError("Plain NAS received after EPS AKA acceptance");
                    }
                    else
                        throw nas::DecodeError("Unexpected plain NAS message before security activation");

                    auto request = nas::DecodeAuthenticationRequest(message.payload.data(), message.payload.size());
                    state = State::AUTHENTICATION_REQUEST_RECEIVED;
                    LogState(state);
                    auto result = nas::Authenticate(config, request);
                    if (result.failure != nas::AkaFailure::NONE)
                    {
                        state = State::AUTHENTICATION_FAILED;
                        LogState(state);
                        if (result.failure == nas::AkaFailure::MAC_FAILURE)
                        {
                            Log("ERROR",
                                "AUTN MAC verification failed; returning EPS Authentication Failure (MAC failure)");
                            SendNas(socket, enb, ueId, nas::EncodeAuthenticationFailureMac());
                        }
                        else if (result.failure == nas::AkaFailure::SYNCHRONIZATION_FAILURE)
                            Log("ERROR", "AUTN SQN is stale; AUTS resynchronization is unsupported, failing closed");
                        else
                            Log("ERROR", "Authentication Request processing failed");
                        return 1;
                    }
                    security = result.context;
                    // Record the exact UE security capability octets that went
                    // out in the Attach Request so the SMC replay check can use
                    // them (TS 24.301 5.4.3.3).
                    security.advertisedSecurityCapabilities.assign(config.networkCapability.begin(),
                                                                    config.networkCapability.end());
                    SendNas(socket, enb, ueId, nas::EncodeAuthenticationResponse(result.res));
                    state = State::AUTHENTICATION_RESPONSE_SENT;
                    LogState(state);
                    continue;
                }

                // Security Mode Command: header type 3, integrity protected with the
                // new context and not ciphered, so the IEs are readable in the clear.
                if (!security.valid)
                    throw nas::DecodeError("Security Mode Command received before a valid AKA response");
                auto parsed = nas::ParseProtectedHeader(message.payload.data(), message.payload.size());
                if (parsed.headerType != nas::SecurityHeaderType::INTEGRITY_PROTECTED_WITH_NEW_CONTEXT)
                    throw nas::DecodeError("Security Mode Command must use the new EPS security context header");
                auto command = nas::DecodeSecurityModeCommand(parsed.plain.data(), parsed.plain.size());
                nas::ValidateSecurityModeCommand(config, command, security);
                security.kNasInt = nas::DeriveKnasInt(security.kasme, security.integrity);
                security.kNasEnc = nas::DeriveKnasEnc(security.kasme, security.ciphering);
                security.keysDerived = true;
                // MAC verification is mandatory before the context becomes active.
                nas::UnprotectBody(security, false, parsed.headerType, parsed.sequenceNumber, parsed.mac,
                                   parsed.plain);
                security.dlNasCount = parsed.sequenceNumber;
                security.ulNasCount = 0;
                security.securityActive = true;
                mobility.securityContextValid = true;
                state = State::SECURITY_MODE_COMMAND_RECEIVED;
                LogState(state);
                Log("INFO", std::string("NAS security activated: ") + nas::ToString(security.integrity) + "/" +
                                nas::ToString(security.ciphering) + " KSI=" + std::to_string(security.ksi));
                state = State::NAS_SECURITY_ACTIVE;
                LogState(state);

                SendProtected(socket, enb, ueId, security, true,
                              nas::EncodeSecurityModeComplete(config, command.imeisvRequested));
                state = State::SECURITY_MODE_COMPLETE_SENT;
                LogState(state);
                continue;
            }

            // A network without a matching security context may return a plain
            // Service Reject. It can only fail a pending Service Request; it
            // never updates trusted mobility state. Every other downlink after
            // security activation must verify integrity.
            std::vector<uint8_t> plain;
            if (mobility.pending == PendingProcedure::SERVICE_REQUEST && message.payload.size() >= 3 &&
                message.payload[0] == 0x07 && message.payload[1] == 0x4E)
            {
                plain = message.payload;
                Log("WARN", "Received unprotected Service Reject while restoring a released context");
            }
            else
                plain = ReceiveProtected(security, message.payload);
            // Handle C9 here so a malformed optional IE still receives a
            // protected Reject using the authenticated EBI/PTI header.
            if (plain.size() >= 3 && (plain[0] & 15U) == 2 && plain[2] == 0xC9)
            {
                const uint8_t ebi = plain[0] >> 4U, pti = plain[1];
                uint8_t cause = 0;
                std::string error;
                nas::EpsBearerConfiguration *target = nullptr;
                nas::EpsBearerConfiguration candidate;
                try
                {
                    if (mobility.emm != EmmState::REGISTERED || mobility.ecm != EcmState::CONNECTED ||
                        mobility.pending != PendingProcedure::NONE)
                        throw nas::EsmError(101, "Bearer modification conflicts with mobility state");
                    const auto request = nas::DecodeModifyEpsBearerContextRequest(plain.data(), plain.size());
                    if (ebi == activeEbi)
                        target = &defaultConfiguration;
                    else
                        for (auto &bearer : dedicatedBearers)
                            if (bearer.ebi == ebi)
                                target = &bearer;
                    if (!target)
                        throw nas::EsmError(43, "Unknown EPS bearer");
                    candidate = *target;
                    nas::ApplyBearerModification(candidate, request);
                }
                catch (const nas::EsmError &e)
                {
                    cause = e.cause;
                    error = e.what();
                }
                catch (const std::bad_alloc &)
                {
                    cause = 26;
                    error = "Insufficient local resources";
                }
                if (cause)
                {
                    SendProtected(socket, enb, ueId, security, false,
                                  nas::EncodeModifyEpsBearerContextReject(ebi, pti, cause));
                    Log("WARN", "Modify EPS bearer rejected EBI=" + std::to_string(ebi) +
                                    " cause=" + std::to_string(cause) + ": " + error);
                }
                else
                {
                    SendProtected(socket, enb, ueId, security, false,
                                  nas::EncodeModifyEpsBearerContextAccept(ebi, pti));
                    *target = std::move(candidate);
                    Log("INFO", "Modify EPS bearer accepted EBI=" + std::to_string(ebi) +
                                    " PTI=" + std::to_string(pti) + " QCI=" + std::to_string(target->qci) +
                                    " filters=" + std::to_string(target->tft.size()) +
                                    " UL-COUNT-next=" + std::to_string(security.ulNasCount) +
                                    " DL-COUNT=" + std::to_string(security.dlNasCount));
                }
                continue;
            }
            auto downlink = nas::DecodeDownlink(plain.data(), plain.size());

            if (downlink.type == nas::DownlinkEmm::ACTIVATE_DEDICATED_EPS_BEARER_CONTEXT)
            {
                const auto &request = downlink.dedicatedBearer;
                try
                {
                    if (mobility.emm != EmmState::REGISTERED || mobility.ecm != EcmState::CONNECTED ||
                        mobility.pending != PendingProcedure::NONE)
                        throw nas::DecodeError("Dedicated bearer activation conflicts with mobility state");
                    if (request.linkedEpsBearerIdentity != activeEbi)
                        throw nas::DecodeError("Dedicated bearer references a different default bearer");
                    for (const auto &bearer : dedicatedBearers)
                    {
                        if (bearer.ebi == request.epsBearerIdentity)
                            throw nas::DecodeError("Dedicated bearer identity is already active");
                    }
                    if (dedicatedBearers.size() >= 7)
                        throw nas::DecodeError("Dedicated bearer capacity is exhausted");

                    DedicatedBearerRuntime bearer;
                    bearer.ebi = request.epsBearerIdentity;
                    bearer.qci = request.qci;
                    bearer.linkedEbi = request.linkedEpsBearerIdentity;
                    bearer.epsQos = {request.qci};
                    if (!request.tft.empty())
                        bearer.tft.apply(lte::tft::Decode(request.tft.data(), request.tft.size()));

                    dedicatedBearers.push_back(std::move(bearer));
                    SendProtected(socket, enb, ueId, security, false,
                                  nas::EncodeActivateDedicatedEpsBearerContextAccept(
                                      request.epsBearerIdentity, request.procedureTransactionId));

                    std::vector<uint8_t> activated{request.epsBearerIdentity};
                    auto activatedFrame =
                        link::Encode({link::MessageType::BEARER_ACTIVATED, ueId, std::move(activated)});
                    socket.Send(enb, activatedFrame.data(), activatedFrame.size());

                    Log("INFO", "Dedicated EPS bearer " + std::to_string(request.epsBearerIdentity) +
                                    " activated (QCI=" + std::to_string(request.qci) + ", linked-EBI=" +
                                    std::to_string(request.linkedEpsBearerIdentity) + ", filters=" +
                                    std::to_string(dedicatedBearers.back().tft.size()) + ")");
                }
                catch (const std::exception &e)
                {
                    // Reject with insufficient resources and keep every other
                    // bearer untouched; a failed activation must not disturb the
                    // default bearer.
                    SendProtected(socket, enb, ueId, security, false,
                                  nas::EncodeActivateDedicatedEpsBearerContextReject(
                                      request.epsBearerIdentity, request.procedureTransactionId, 26));
                    Log("WARN", std::string("Rejected dedicated EPS bearer activation: ") + e.what());
                }
                continue;
            }

            if (downlink.type == nas::DownlinkEmm::DEACTIVATE_EPS_BEARER_CONTEXT)
            {
                const auto &request = downlink.deactivateBearer;
                const auto bearer = std::find_if(dedicatedBearers.begin(), dedicatedBearers.end(),
                                                 [&request](const DedicatedBearerRuntime &candidate) {
                                                     return candidate.ebi == request.epsBearerIdentity;
                                                 });
                if (bearer == dedicatedBearers.end())
                    throw nas::DecodeError("Deactivation names an unknown dedicated bearer");
                dedicatedBearers.erase(bearer);
                SendProtected(socket, enb, ueId, security, false,
                              nas::EncodeDeactivateEpsBearerContextAccept(request.epsBearerIdentity,
                                                                          request.procedureTransactionId));
                Log("INFO", "Dedicated EPS bearer " + std::to_string(request.epsBearerIdentity) +
                                " deactivated; default bearer retained");
                continue;
            }

            if (downlink.type == nas::DownlinkEmm::DETACH_ACCEPT)
            {
                if (mobility.pending != PendingProcedure::DETACH)
                    throw nas::DecodeError("Unexpected EPS Detach Accept");
                auto deleted = link::Encode({link::MessageType::EPS_SESSION_DELETED, ueId,
                    link::EncodeBearerRestoration(activeEbi, mobility.accessGeneration)});
                socket.Send(enb, deleted.data(), deleted.size());
                mobility.onDetachAccepted();
                security = SecurityContext{};
                pendingWire.clear();
                tun.reset();
                dedicatedBearers.clear();
                defaultConfiguration = {};
                Log("INFO", "EPS Detach accepted; State=EMM_DEREGISTERED, bearer and TUN released");
                return 0;
            }
            if (downlink.type == nas::DownlinkEmm::SERVICE_REJECT)
            {
                mobility.onProcedureRejected();
                Log("ERROR", "EPS Service Request rejected, EMM cause=" + std::to_string(downlink.emmCause));
                return 1;
            }
            if (downlink.type == nas::DownlinkEmm::TAU_REJECT)
            {
                mobility.onProcedureRejected();
                Log("ERROR", "Tracking Area Update rejected, EMM cause=" + std::to_string(downlink.emmCause));
                return 1;
            }
            if (downlink.type == nas::DownlinkEmm::TAU_ACCEPT)
            {
                if (mobility.pending != PendingProcedure::TAU_NORMAL &&
                    mobility.pending != PendingProcedure::TAU_PERIODIC)
                    throw nas::DecodeError("Unexpected Tracking Area Update Accept");
                if (downlink.tauAccept.bearerContextStatus.has_value())
                {
                    // The network's status is authoritative. An EPS bearer
                    // context the UE still holds but the network no longer
                    // reports has been deactivated, so the UE must stop
                    // claiming it exists rather than carrying it forward.
                    const auto reconciliation = ReconcileRetainedBearers(
                        dedicatedBearers, *downlink.tauAccept.bearerContextStatus, mobility.defaultEbi);
                    for (const uint8_t ebi : reconciliation.released)
                        Log("INFO", "Dedicated EPS bearer " + std::to_string(ebi) +
                                        " was not retained by the network and is no longer active");
                    dedicatedBearers = reconciliation.retained;
                }
                mobility.onTauAccepted(downlink.tauAccept.updateResult, downlink.tauAccept.guti,
                                       downlink.tauAccept.taiList, downlink.tauAccept.t3412);
                pendingWire.clear();
                if (downlink.tauAccept.guti.has_value())
                    SendProtected(socket, enb, ueId, security, false, nas::EncodeTauComplete());
                Log("INFO", std::string("Tracking Area Update accepted; context preserved") +
                                (downlink.tauAccept.guti.has_value() ? "; TAU Complete sent for new GUTI" : ""));
                scenarioDeadline = std::chrono::steady_clock::time_point::max();
                continue;
            }

            if (downlink.type == nas::DownlinkEmm::ESM_INFORMATION_REQUEST)
            {
                state = State::ESM_INFORMATION_REQUEST_RECEIVED;
                LogState(state);
                SendProtected(socket, enb, ueId, security, false,
                              nas::EncodeEsmInformationResponse(downlink.esmInformationRequest.procedureTransactionId,
                                                               downlink.esmInformationRequest.apn));
                state = State::ESM_INFORMATION_RESPONSE_SENT;
                LogState(state);
                continue;
            }

            if (downlink.type == nas::DownlinkEmm::ATTACH_REJECT)
            {
                state = State::PROCEDURE_FAILED;
                LogState(state);
                Log("ERROR", "EPS Attach rejected by the MME, EMM cause=" + std::to_string(downlink.emmCause));
                return 1;
            }

            if (downlink.type != nas::DownlinkEmm::ATTACH_ACCEPT)
            {
                Log("WARN", "Ignoring unexpected protected EMM message type " +
                               std::to_string(downlink.messageType));
                continue;
            }

            if (!attachAcceptSeen)
            {
                attachAcceptSeen = true;
                state = State::ATTACH_ACCEPT_RECEIVED;
                LogState(state);
            }

            const auto &accept = downlink.attachAccept;
            if (!accept.bearer.has_value())
                throw nas::DecodeError("Attach Accept did not carry Activate Default EPS Bearer Context Request");
            if (defaultBearerAccepted)
                throw nas::DecodeError("Duplicate Activate Default EPS Bearer Context Request");
            defaultBearerAccepted = true;
            state = State::DEFAULT_BEARER_PENDING;
            LogState(state);
            Log("INFO", "Default EPS bearer: EBI=" + std::to_string(accept.bearer->epsBearerIdentity) +
                            " QCI=" + std::to_string(accept.bearer->qci) + " APN=" + accept.bearer->apn);

            auto esmAccept = nas::EncodeActivateDefaultEpsBearerContextAccept(
                accept.bearer->epsBearerIdentity, accept.bearer->procedureTransactionId);
            SendProtected(socket, enb, ueId, security, false, nas::EncodeAttachComplete(esmAccept));
            state = State::ATTACH_COMPLETE_SENT;
            LogState(state);
            state = State::EPS_REGISTERED;
            LogState(state);
            state = State::DEFAULT_BEARER_SIGNALING_COMPLETE;
            LogState(state);

            activeEbi = accept.bearer->epsBearerIdentity;
            defaultConfiguration.ebi = activeEbi;
            defaultConfiguration.qci = accept.bearer->qci;
            defaultConfiguration.epsQos = {accept.bearer->qci};
            assignedIpv4 = accept.bearer->pdnAddress;
            if (assignedIpv4 == std::array<uint8_t, 4>{})
                throw nas::DecodeError("Default bearer did not provide a supported non-zero IPv4 PDN address");
            mobility.onAttachComplete(activeEbi, assignedIpv4, accept.guti, accept.taiList, accept.t3412);
            mobility.securityContextValid = security.securityActive;
            {
                std::ostringstream taiText;
                for (size_t i = 0; i < mobility.taiList.size(); ++i)
                {
                    if (i != 0)
                        taiText << ',';
                    taiText << mobility.taiList[i].plmn.toString() << '/' << mobility.taiList[i].tac;
                }
                std::string sTmsiText = "none";
                if (mobility.guti.has_value())
                {
                    const auto derived = STmsiFromGuti(*mobility.guti);
                    if (derived.has_value())
                    {
                        std::ostringstream sTmsi;
                        sTmsi << "MMEC=" << static_cast<int>(derived->mmeCode) << " M-TMSI=0x" << std::hex
                              << std::uppercase << std::setw(8) << std::setfill('0') << derived->mTmsi;
                        sTmsiText = sTmsi.str();
                    }
                }
                Log("INFO", "Assigned EPS bearer EBI=" + std::to_string(activeEbi) + " IPv4=" +
                                Ipv4ToString(assignedIpv4) + " S-TMSI{" + sTmsiText + "} TAI-list=" +
                                taiText.str());
            }
            try { tun = std::make_unique<TunDevice>(config.tun, assignedIpv4); }
            catch (const std::exception &e)
            {
                if (config.tun.required) throw;
                Log("WARN", std::string("Control-plane-only mode: LTE TUN unavailable: ") + e.what());
            }
            if (tun)
            {
                state = State::TUN_READY;
                LogState(state);
                Log("INFO", "LTE TUN " + tun->name() + " configured with " + Ipv4ToString(assignedIpv4) +
                                "/32 MTU=" + std::to_string(config.tun.mtu) +
                                " explicit-routes=" + std::to_string(config.tun.routes.size()));

                std::vector<uint8_t> ready{activeEbi, assignedIpv4[0], assignedIpv4[1], assignedIpv4[2],
                                           assignedIpv4[3]};
                auto readyFrame = link::Encode({link::MessageType::BEARER_READY, ueId, std::move(ready)});
                if (!socket.TrySend(enb, readyFrame.data(), readyFrame.size()))
                    throw std::runtime_error("LTE bearer-ready frame could not be sent");
                state = State::USER_PLANE_ACTIVE;
                LogState(state);
                mobility.onUserPlaneReady();
            }
            scenarioDeadline = std::chrono::steady_clock::now() +
                               std::chrono::milliseconds(config.lifecycle.triggerAfterMs);
            Log("INFO", tun ? "EPS Attach complete; persistent IPv4 user plane is active"
                             : "EPS Attach complete; bearer signaling active without local user plane");
            continue;
        }
        catch (const nas::SecurityError &e)
        {
            if (mobility.emm == EmmState::REGISTERED)
            {
                ++malformedDrops;
                Log("WARN", std::string("Dropped unauthenticated/replayed NAS: ") + e.what());
                continue;
            }
            state = State::PROCEDURE_FAILED;
            LogState(state);
            Log("ERROR", std::string("NAS security failure: ") + e.what());
            return 1;
        }
        catch (const std::exception &e)
        {
            if (mobility.emm == EmmState::REGISTERED && state != State::DEFAULT_BEARER_SIGNALING_COMPLETE && state != State::TUN_READY)
            {
                ++malformedDrops;
                Log("WARN", std::string("Dropped invalid LTE radio-link message: ") + e.what());
                continue;
            }
            state = State::PROCEDURE_FAILED;
            LogState(state);
            Log("ERROR", e.what());
            return 1;
        }
    }
    if (!shutdownRequested && mobility.emm != EmmState::REGISTERED)
    {
        state = State::PROCEDURE_FAILED;
        LogState(state);
        Log("ERROR", "Timed out waiting for MME EPS Attach signaling");
        return 1;
    }
    if (pagingWaitArmed)
        // Reaching here with the wait still armed is only possible through the
        // stop request, so this is a shutdown and never a paging timeout.
        Log("INFO", "Paging wait abandoned at shutdown; no Service Request was sent");
    Log("INFO", "User-plane statistics: tun-ul=" + std::to_string(tunUplinkPackets) + "/" +
                    std::to_string(tunUplinkBytes) + " tun-dl=" + std::to_string(tunDownlinkPackets) + "/" +
                    std::to_string(tunDownlinkBytes) + " drops(malformed/inactive)=" +
                    std::to_string(malformedDrops) + "/" + std::to_string(bearerInactiveDrops));
    Log("INFO", "NAS security counts: UL-next=" + std::to_string(security.ulNasCount) +
                    " DL-last=" + std::to_string(security.dlNasCount));
    Log("INFO", "Paging statistics: indications=" + std::to_string(pagingIndications) +
                    " matched=" + std::to_string(pagingMatched) +
                    " ignored=" + std::to_string(pagingIgnored) +
                    " duplicate-trigger-suppressed=" + std::to_string(pagingSuppressed) +
                    " service-requests=" + std::to_string(pagingServiceRequests) +
                    " restorations=" + std::to_string(pagingRestorations) +
                    " restoration-failures=" + std::to_string(pagingRestorationFailures));
    Log("INFO", "Access-recovery statistics: losses=" + std::to_string(accessLosses) +
                    " restorations=" + std::to_string(recoveryRestorations) +
                    " failures=" + std::to_string(recoveryFailures) +
                    " attempts=" + std::to_string(recoveryAttempts) +
                    " access-unavailable-drops=" + std::to_string(accessUnavailableDrops) +
                    " dedicated-ul=" + std::to_string(dedicatedUplinkPackets) +
                    " dedicated-dl=" + std::to_string(dedicatedDownlinkPackets));
    tun.reset();
    Log("INFO", "LTE UE shutdown complete");
    return 0;
}
} // namespace lte::ue
