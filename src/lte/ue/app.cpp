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
    bool registered = false;
    uint8_t activeEbi = 0;
    std::array<uint8_t, 4> assignedIpv4{};
    std::unique_ptr<TunDevice> tun;
    uint64_t tunUplinkPackets = 0;
    uint64_t tunUplinkBytes = 0;
    uint64_t tunDownlinkPackets = 0;
    uint64_t tunDownlinkBytes = 0;
    uint64_t malformedDrops = 0;
    uint64_t bearerInactiveDrops = 0;
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
    uint8_t buffer[link::MaxDataPduSize + link::HeaderSize];
    while (!shutdownRequested && (registered || std::chrono::steady_clock::now() < deadline))
    {
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
        int received = socket.Receive(buffer, sizeof(buffer), registered ? 50 : 250, peer);
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
                if (!registered || message.payload.size() != 1 || message.payload[0] != activeEbi)
                    throw link::DecodeError("Bearer release does not match the active default bearer");
                tun.reset();
                state = State::EPS_REGISTERED;
                LogState(state);
                Log("WARN", "Default bearer released; LTE TUN resources were closed");
                continue;
            }
            if (message.type == link::MessageType::DATA_DOWNLINK)
            {
                if (!registered || !tun)
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
            auto plain = ReceiveProtected(security, message.payload);
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
            registered = true;
            state = State::DEFAULT_BEARER_SIGNALING_COMPLETE;
            LogState(state);

            activeEbi = accept.bearer->epsBearerIdentity;
            assignedIpv4 = accept.bearer->pdnAddress;
            if (assignedIpv4 == std::array<uint8_t, 4>{})
                throw nas::DecodeError("Default bearer did not provide a supported non-zero IPv4 PDN address");
            tun = std::make_unique<TunDevice>(config.tun, assignedIpv4);
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
            Log("INFO", "EPS Attach complete; persistent IPv4 user plane is active");
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
            if (registered && state != State::DEFAULT_BEARER_SIGNALING_COMPLETE && state != State::TUN_READY)
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
    if (!shutdownRequested && !registered)
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
