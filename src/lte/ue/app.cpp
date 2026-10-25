//
// This file is a part of UERANSIM project.
// Copyright (c) 2027 ALİ GÜNGÖR.
//
// https://github.com/aligungr/UERANSIM/
// See README, LICENSE, and CONTRIBUTING files for licensing details.
//

#include "app.hpp"

#include "lifecycle.hpp"
#include "nas.hpp"
#include "radio_link.hpp"
#include "security.hpp"
#include "tun.hpp"

#include <chrono>
#include <iostream>
#include <memory>

#include <lte/ip_packet.hpp>

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

// Verifies and recovers a security-protected downlink NAS message, then records
// the accepted DL COUNT. An unverified message never reaches the caller.
std::vector<uint8_t> ReceiveProtected(SecurityContext &security, const std::vector<uint8_t> &message)
{
    auto parsed = nas::ParseProtectedHeader(message.data(), message.size());
    auto plain =
        nas::UnprotectBody(security, false, parsed.headerType, parsed.sequenceNumber, parsed.mac, parsed.plain);
    if (nas::StartsNewContext(parsed.headerType))
        security.dlNasCount = parsed.sequenceNumber;
    else
        security.dlNasCount = nas::EstimateNasCount(security.dlNasCount, parsed.sequenceNumber);
    return plain;
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
    uint64_t tunUplinkPackets = 0;
    uint64_t tunUplinkBytes = 0;
    uint64_t tunDownlinkPackets = 0;
    uint64_t tunDownlinkBytes = 0;
    uint64_t malformedDrops = 0;
    uint64_t bearerInactiveDrops = 0;
    bool scenarioTriggered = false;
    bool idleReleaseRequested = false;
    std::vector<uint8_t> pendingWire;
    int procedureRetries = 0;
    auto procedureDeadline = std::chrono::steady_clock::time_point::max();
    udp::UdpServer socket(config.link.localAddress, config.link.localPort);
    InetAddress enb(config.link.enbAddress, config.link.enbPort);
    const uint32_t ueId = 1;
    mobility.ecm = EcmState::CONNECTED;
    state = State::CONNECTED_TO_ENB;
    LogState(state);
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
            if (config.lifecycle.scenario == LifecycleScenario::SERVICE_REQUEST)
            {
                auto request = link::Encode({link::MessageType::S1_CONTEXT_RELEASE_REQUEST, ueId,
                                             {mobility.defaultEbi}});
                socket.Send(enb, request.data(), request.size());
                idleReleaseRequested = true;
                procedureDeadline = now + std::chrono::milliseconds(config.lifecycle.procedureTimeoutMs);
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
                    mobility.onDetachAccepted();
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
                auto plain = nas::EncodeTauRequest(security.ksi, *mobility.guti, mobility.defaultEbi, periodic);
                pendingWire = nas::Protect(security, true, false, plain);
                SendNas(socket, enb, ueId, pendingWire);
                security.ulNasCount = (security.ulNasCount + 1U) & 0xFFFFFFU;
                procedureDeadline = now + std::chrono::milliseconds(config.lifecycle.procedureTimeoutMs);
                Log("INFO", std::string("Protected ") + (periodic ? "periodic" : "normal") +
                                " Tracking Area Update Request sent");
            }
        }

        if (idleReleaseRequested && now >= procedureDeadline)
        {
            Log("ERROR", "Timed out waiting for the MME S1 Context Release Command/Complete flow");
            return 1;
        }

        if (mobility.pending != PendingProcedure::NONE && !pendingWire.empty() && now >= procedureDeadline)
        {
            if (procedureRetries >= config.lifecycle.maxRetries)
            {
                Log("ERROR", std::string(ToString(mobility.pending)) + " timed out after bounded retransmissions");
                return 1;
            }
            if (mobility.pending == PendingProcedure::SERVICE_REQUEST)
                SendServiceRequest(socket, enb, ueId, *mobility.guti, pendingWire);
            else
                SendNas(socket, enb, ueId, pendingWire);
            ++procedureRetries;
            procedureDeadline = now + std::chrono::milliseconds(config.lifecycle.procedureTimeoutMs);
            Log("WARN", std::string("Retransmitted ") + ToString(mobility.pending) +
                            ", retry=" + std::to_string(procedureRetries));
        }

        if (tun && mobility.canForwardUserPlane())
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
                    auto frame = link::Encode({link::MessageType::DATA_UPLINK, ueId, std::move(packet)});
                    if (!socket.TrySend(enb, frame.data(), frame.size()))
                        Log("WARN", "LTE radio-link uplink send would block; packet dropped");
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
                if (mobility.emm != EmmState::REGISTERED || message.payload.size() != 1 || message.payload[0] != activeEbi)
                    throw link::DecodeError("Bearer release does not match the active default bearer");
                tun.reset();
                mobility.bearer = EpsBearerState::INACTIVE;
                state = State::EPS_REGISTERED;
                LogState(state);
                Log("WARN", "Default bearer released; LTE TUN resources were closed");
                continue;
            }
            if (message.type == link::MessageType::S1_CONTEXT_RELEASED)
            {
                if (mobility.emm != EmmState::REGISTERED || message.payload[0] != activeEbi)
                    throw link::DecodeError("S1 context release does not match the registered bearer");
                mobility.onS1ContextReleased();
                Log("INFO", "State=ECM_IDLE; EPS registration, security, GUTI, bearer and TUN retained");
                if (idleReleaseRequested)
                {
                    idleReleaseRequested = false;
                    mobility.startServiceRequest();
                    pendingWire = nas::EncodeServiceRequest(security);
                    SendServiceRequest(socket, enb, ueId, *mobility.guti, pendingWire);
                    security.ulNasCount = (security.ulNasCount + 1U) & 0xFFFFFFU;
                    procedureRetries = 0;
                    procedureDeadline = std::chrono::steady_clock::now() +
                                        std::chrono::milliseconds(config.lifecycle.procedureTimeoutMs);
                    Log("INFO", "Compact EPS Service Request sent from ECM-IDLE");
                }
                continue;
            }
            if (message.type == link::MessageType::S1_CONTEXT_RESTORED)
            {
                if (message.payload[0] != activeEbi)
                    throw link::DecodeError("Restored S1 context has the wrong EBI");
                mobility.onServiceRestored(tun != nullptr);
                pendingWire.clear();
                if (tun)
                {
                    std::vector<uint8_t> ready{activeEbi, assignedIpv4[0], assignedIpv4[1], assignedIpv4[2],
                                               assignedIpv4[3]};
                    auto readyFrame = link::Encode({link::MessageType::BEARER_READY, ueId, std::move(ready)});
                    socket.Send(enb, readyFrame.data(), readyFrame.size());
                    Log("INFO", "State=ECM_CONNECTED; existing EPS bearer transport and user plane restored");
                }
                else
                    Log("WARN", "State=ECM_CONNECTED; bearer signaling restored in control-plane-only mode");
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
            auto downlink = nas::DecodeDownlink(plain.data(), plain.size());

            if (downlink.type == nas::DownlinkEmm::DETACH_ACCEPT)
            {
                if (mobility.pending != PendingProcedure::DETACH)
                    throw nas::DecodeError("Unexpected EPS Detach Accept");
                mobility.onDetachAccepted();
                security = SecurityContext{};
                pendingWire.clear();
                tun.reset();
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
                if (downlink.tauAccept.updateResult != 0)
                    throw nas::DecodeError("Unsupported non-EPS-only Tracking Area Update result");
                if (downlink.tauAccept.bearerContextStatus.has_value() &&
                    ((*downlink.tauAccept.bearerContextStatus &
                      static_cast<uint16_t>(1U << mobility.defaultEbi)) == 0))
                    throw nas::DecodeError("Tracking Area Update Accept removed the active default bearer");
                mobility.onTauAccepted(downlink.tauAccept.guti, downlink.tauAccept.taiList,
                                       downlink.tauAccept.t3412);
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
            assignedIpv4 = accept.bearer->pdnAddress;
            if (assignedIpv4 == std::array<uint8_t, 4>{})
                throw nas::DecodeError("Default bearer did not provide a supported non-zero IPv4 PDN address");
            mobility.onAttachComplete(activeEbi, assignedIpv4, accept.guti, accept.taiList, accept.t3412);
            mobility.securityContextValid = security.securityActive;
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
    Log("INFO", "User-plane statistics: tun-ul=" + std::to_string(tunUplinkPackets) + "/" +
                    std::to_string(tunUplinkBytes) + " tun-dl=" + std::to_string(tunDownlinkPackets) + "/" +
                    std::to_string(tunDownlinkBytes) + " drops(malformed/inactive)=" +
                    std::to_string(malformedDrops) + "/" + std::to_string(bearerInactiveDrops));
    tun.reset();
    Log("INFO", "LTE UE shutdown complete");
    return 0;
}
} // namespace lte::ue
