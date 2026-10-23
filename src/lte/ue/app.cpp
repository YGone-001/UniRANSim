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
} // namespace

int Run(const Config &config, const std::atomic_bool &shutdownRequested)
{
    State state = State::DISCONNECTED;
    SecurityContext security{};
    udp::UdpServer socket(config.link.localAddress, config.link.localPort);
    InetAddress enb(config.link.enbAddress, config.link.enbPort);
    const uint32_t ueId = 1;
    state = State::CONNECTED_TO_ENB;
    LogState(state);
    auto attach = nas::EncodeAttachRequest(config);
    auto frame = link::Encode({link::MessageType::NAS_UPLINK, ueId, std::move(attach)});
    socket.Send(enb, frame.data(), frame.size());
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
        if (received <= 0) continue;
        if (peer != enb) { Log("WARN", "Ignoring LTE radio-link datagram from an unexpected endpoint"); continue; }
        try
        {
            auto message = link::Decode(buffer, static_cast<size_t>(received));
            if (message.type != link::MessageType::NAS_DOWNLINK || message.ueId != ueId)
                throw link::DecodeError("Unexpected LTE radio-link routing fields");
            if (nas::IsSecurityModeCommand(message.nas.data(), message.nas.size()))
            {
                if (!security.valid) throw nas::DecodeError("Security Mode Command received before a valid AKA response");
                state = State::EPS_AKA_ACCEPTED;
                LogState(state);
                Log("INFO", "MME sent Security Mode Command: EPS AKA accepted; EPS Attach remains incomplete by design");
                return 0;
            }
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
                    Log("ERROR", "AUTN MAC verification failed; returning EPS Authentication Failure (MAC failure)");
                    auto failure = link::Encode({link::MessageType::NAS_UPLINK, ueId, nas::EncodeAuthenticationFailureMac()});
                    socket.Send(enb, failure.data(), failure.size());
                }
                else if (result.failure == nas::AkaFailure::SYNCHRONIZATION_FAILURE)
                    Log("ERROR", "AUTN SQN is stale; AUTS resynchronization is unsupported, failing closed");
                else Log("ERROR", "Authentication Request processing failed");
                return 1;
            }
            security = result.context;
            auto response = link::Encode({link::MessageType::NAS_UPLINK, ueId, nas::EncodeAuthenticationResponse(result.res)});
            socket.Send(enb, response.data(), response.size());
            state = State::AUTHENTICATION_RESPONSE_SENT;
            LogState(state);
        }
        catch (const std::exception &e)
        {
            state = State::AUTHENTICATION_FAILED;
            LogState(state);
            Log("ERROR", e.what());
            return 1;
        }
    }
    if (!shutdownRequested) { Log("ERROR", "Timed out waiting for MME authentication signaling"); return 1; }
    Log("INFO", "LTE UE shutdown complete");
    return 0;
}
} // namespace lte::ue
