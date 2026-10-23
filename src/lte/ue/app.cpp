//
// This file is a part of UERANSIM project.
// Copyright (c) 2027 ALİ GÜNGÖR.
//
// https://github.com/aligungr/UERANSIM/
// See README, LICENSE, and CONTRIBUTING files for licensing details.
//

#include "app.hpp"

#include "nas.hpp"
#include "radio_link.hpp"
#include "security.hpp"

#include <chrono>
#include <iostream>

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
    bool attachAcceptSeen = false;
    bool defaultBearerAccepted = false;
    udp::UdpServer socket(config.link.localAddress, config.link.localPort);
    InetAddress enb(config.link.enbAddress, config.link.enbPort);
    const uint32_t ueId = 1;
    state = State::CONNECTED_TO_ENB;
    LogState(state);
    auto attach = nas::EncodeAttachRequest(config);
    SendNas(socket, enb, ueId, std::move(attach));
    state = State::ATTACH_REQUEST_SENT;
    LogState(state);
    state = State::AUTHENTICATION_PENDING;
    LogState(state);

    auto deadline = std::chrono::steady_clock::now() + std::chrono::milliseconds(config.link.timeoutMs);
    uint8_t buffer[link::MaxNasPduSize + 8];
    while (!shutdownRequested && std::chrono::steady_clock::now() < deadline)
    {
        InetAddress peer;
        int received = socket.Receive(buffer, sizeof(buffer), 250, peer);
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
            if (message.type != link::MessageType::NAS_DOWNLINK || message.ueId != ueId)
                throw link::DecodeError("Unexpected LTE radio-link routing fields");

            if (!security.securityActive)
            {
                // Only a Security Mode Command may arrive before the context is active.
                if (!nas::IsSecurityModeCommand(message.nas.data(), message.nas.size()))
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

                    auto request = nas::DecodeAuthenticationRequest(message.nas.data(), message.nas.size());
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
                auto parsed = nas::ParseProtectedHeader(message.nas.data(), message.nas.size());
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

            // Security is active: every further downlink must verify.
            auto plain = ReceiveProtected(security, message.nas);
            auto downlink = nas::DecodeDownlink(plain.data(), plain.size());

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
            Log("INFO", "EPS Attach and default bearer signaling complete");
            return 0;
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
            state = State::PROCEDURE_FAILED;
            LogState(state);
            Log("ERROR", e.what());
            return 1;
        }
    }
    if (!shutdownRequested)
    {
        state = State::PROCEDURE_FAILED;
        LogState(state);
        Log("ERROR", "Timed out waiting for MME EPS Attach signaling");
        return 1;
    }
    Log("INFO", "LTE UE shutdown complete");
    return 0;
}
} // namespace lte::ue
