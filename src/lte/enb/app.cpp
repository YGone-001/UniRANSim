//
// This file is a part of UERANSIM project.
// Copyright (c) 2027 ALİ GÜNGÖR.
//
// https://github.com/aligungr/UERANSIM/
// See README, LICENSE, and CONTRIBUTING files for licensing details.
//

#include "app.hpp"
#include "codec.hpp"

#include <algorithm>
#include <chrono>
#include <cstring>
#include <iomanip>
#include <iostream>
#include <sstream>
#include <thread>

#include <lib/sctp/sctp.hpp>
#include <lib/udp/server.hpp>
#include <lte/ue/radio_link.hpp>

namespace lte::enb
{

namespace
{

using Clock = std::chrono::steady_clock;

void Log(const char *level, const std::string &message)
{
    std::cout << "[lte-enb] [" << level << "] " << message << std::endl;
}

std::string Hex(uint32_t value, int width)
{
    std::ostringstream stream;
    stream << "0x" << std::uppercase << std::hex << std::setfill('0') << std::setw(width) << value;
    return stream.str();
}

class Handler : public sctp::ISctpHandler
{
  public:
    void onAssociationSetup(int associationId, int inStreams, int outStreams) override
    {
        associationUp = true;
        outboundStreams = outStreams;
        Log("INFO", "SCTP association established (association=" + std::to_string(associationId) +
                        ", inbound-streams=" + std::to_string(inStreams) +
                        ", outbound-streams=" + std::to_string(outStreams) + ")");
    }

    void onAssociationShutdown() override
    {
        associationLost = true;
        Log("WARN", "SCTP association shutdown received");
    }

    void onConnectionReset() override
    {
        associationLost = true;
        Log("WARN", "SCTP connection reset");
    }

    void onMessage(const uint8_t *buffer, size_t length, uint16_t stream) override
    {
        message.assign(buffer, buffer + length);
        messageStream = stream;
    }

    void onUnhandledNotification() override
    {
        Log("WARN", "Unhandled SCTP notification received");
    }

    bool associationUp{};
    bool associationLost{};
    std::vector<uint8_t> message;
    uint16_t messageStream{};
    int outboundStreams{1};
};

uint16_t UeStream(const Handler &handler, uint32_t enbUeId)
{
    // Stream zero carries non-UE S1AP such as S1 Setup. Keep UE signalling on a
    // negotiated non-zero stream when the peer made one available.
    if (handler.outboundStreams <= 1)
        return 0;
    return static_cast<uint16_t>(1U + ((enbUeId - 1U) % static_cast<uint32_t>(handler.outboundStreams - 1)));
}

bool InterruptibleDelay(int milliseconds, const std::atomic_bool &shutdownRequested)
{
    auto deadline = Clock::now() + std::chrono::milliseconds(milliseconds);
    while (!shutdownRequested && Clock::now() < deadline)
        std::this_thread::sleep_for(std::chrono::milliseconds(100));
    return !shutdownRequested;
}

void LogServedGummeis(const s1ap::SetupOutcome &outcome)
{
    for (size_t i = 0; i < outcome.servedGummeis.size(); ++i)
    {
        const auto &item = outcome.servedGummeis[i];
        std::ostringstream stream;
        stream << "ServedGUMMEIs[" << i << "]: PLMN=";
        for (size_t j = 0; j < item.plmns.size(); ++j)
            stream << (j == 0 ? "" : ",") << item.plmns[j].toString();
        stream << " group-id=";
        for (size_t j = 0; j < item.groupIds.size(); ++j)
            stream << (j == 0 ? "" : ",") << Hex(item.groupIds[j], 4);
        stream << " mme-code=";
        for (size_t j = 0; j < item.mmeCodes.size(); ++j)
            stream << (j == 0 ? "" : ",") << Hex(item.mmeCodes[j], 2);
        Log("INFO", stream.str());
    }
}

} // namespace

int Run(const EnbConfig &config, const std::atomic_bool &shutdownRequested)
{
    Log("INFO", "LTE eNB identity: PLMN=" + config.plmn.toString() + " eNB-ID=" + Hex(config.enbId, 5) +
                    " TAC=" + Hex(config.tac, 4));
    Log("INFO", "S1-MME endpoint: local=" + config.localAddress + " remote=" + config.mmeAddress + ":" +
                    std::to_string(config.mmePort) + " PPID=18");

    const auto setupRequest = s1ap::EncodeS1SetupRequest(config);
    ConnectionStateMachine state;
    int requestedBackoffMs = 0;

    for (int attempt = 1; attempt <= config.retry.maxAttempts && !shutdownRequested; ++attempt)
    {
        if (attempt > 1)
        {
            int delay = std::max(config.retry.delayMs, requestedBackoffMs);
            Log("INFO", "Retry " + std::to_string(attempt) + "/" + std::to_string(config.retry.maxAttempts) +
                            " after " + std::to_string(delay) + " ms");
            if (!InterruptibleDelay(delay, shutdownRequested))
                break;
        }
        requestedBackoffMs = 0;
        state.transition(ConnectionEvent::CONNECT_STARTED);
        Log("INFO", "State=" + std::string(ToString(state.state())) + ", connecting to MME");

        try
        {
            sctp::SctpClient client(sctp::PayloadProtocolId::S1AP, config.localAddress, config.retry.connectMaxAttempts,
                                    config.retry.connectTimeoutMs);
            client.bind(config.localAddress, 0);
            client.connect(config.mmeAddress, config.mmePort);
            if (!state.transition(ConnectionEvent::SCTP_CONNECTED))
                throw std::runtime_error("Invalid state transition after SCTP connect");
            Log("INFO", "State=" + std::string(ToString(state.state())));

            Handler handler;
            // Drain the COMM_UP notification when the kernel queued one. connect() itself has already completed the
            // one-to-one SCTP association, so absence of a duplicate notification is not a failure.
            client.receiveFor(&handler, 100);
            if (handler.associationLost)
                throw sctp::SctpError("SCTP association was lost before S1 Setup");

            client.send(0, setupRequest);
            if (!state.transition(ConnectionEvent::SETUP_REQUEST_SENT))
                throw std::runtime_error("Duplicate or invalid S1 Setup Request transition");
            Log("INFO", "S1 Setup Request sent on SCTP stream 0 (" + std::to_string(setupRequest.size()) +
                            " bytes), State=" + ToString(state.state()));

            auto deadline = Clock::now() + std::chrono::milliseconds(config.retry.responseTimeoutMs);
            bool attemptComplete = false;
            while (!shutdownRequested && Clock::now() < deadline && !attemptComplete)
            {
                int remaining = static_cast<int>(
                    std::chrono::duration_cast<std::chrono::milliseconds>(deadline - Clock::now()).count());
                client.receiveFor(&handler, std::max(0, std::min(remaining, 500)));
                if (handler.associationLost)
                    throw sctp::SctpError("SCTP association lost while S1 Setup was pending");
                if (handler.message.empty())
                    continue;
                if (handler.messageStream != 0)
                    throw s1ap::CodecError("S1 Setup outcome arrived on a UE-associated SCTP stream");

                auto outcome = s1ap::DecodeS1SetupOutcome(handler.message.data(), handler.message.size());
                handler.message.clear();
                if (outcome.type == s1ap::OutcomeType::RESPONSE)
                {
                    Log("INFO", "Valid S1 Setup Response received");
                    LogServedGummeis(outcome);
                    Log("INFO", "Relative MME Capacity=" + std::to_string(*outcome.relativeMmeCapacity));
                    if (outcome.mmeName.has_value())
                        Log("INFO", "MME name=" + *outcome.mmeName);
                    if (outcome.diagnosticsPresent)
                        Log("WARN", "S1 Setup Response includes CriticalityDiagnostics");
                    state.transition(ConnectionEvent::SETUP_ACCEPTED);
                    Log("INFO", "S1 Setup accepted, State=" + std::string(ToString(state.state())));

                    udp::UdpServer ueLink(config.ueLinkAddress, config.ueLinkPort);
                    Log("INFO", "LTE UE radio-link listening on " + config.ueLinkAddress + ":" +
                                    std::to_string(config.ueLinkPort));
                    std::optional<InetAddress> uePeer;
                    std::optional<s1ap::UeContext> ueContext;
                    uint8_t radioBuffer[lte::ue::link::MaxNasPduSize + 8];
                    while (!shutdownRequested && !handler.associationLost)
                    {
                        // Keep both transports responsive without assuming SCTP stream zero for UE traffic.
                        client.receiveFor(&handler, 50);
                        if (!handler.message.empty())
                        {
                            try
                            {
                                auto downlink = s1ap::DecodeDownlinkNasTransport(handler.message.data(), handler.message.size());
                                handler.message.clear();
                                if (!ueContext.has_value() || !uePeer.has_value() ||
                                    downlink.enbUeS1apId != ueContext->enbUeS1apId)
                                    throw s1ap::CodecError("Downlink NAS Transport does not match the active UE context");
                                if (ueContext->mmeUeS1apId.has_value() &&
                                    *ueContext->mmeUeS1apId != downlink.mmeUeS1apId)
                                    throw s1ap::CodecError("MME-UE-S1AP-ID changed for the active UE context");
                                ueContext->mmeUeS1apId = downlink.mmeUeS1apId;
                                auto radio = lte::ue::link::Encode({lte::ue::link::MessageType::NAS_DOWNLINK,
                                                                    ueContext->enbUeS1apId, std::move(downlink.nasPdu)});
                                ueLink.Send(*uePeer, radio.data(), radio.size());
                                Log("INFO", "Forwarded Downlink NAS Transport to LTE UE");
                            }
                            catch (const std::exception &e)
                            {
                                Log("WARN", std::string("Rejected post-setup S1AP message on stream ") +
                                                std::to_string(handler.messageStream) + ": " + e.what());
                                handler.message.clear();
                            }
                        }

                        InetAddress peer;
                        int radioLength = ueLink.Receive(radioBuffer, sizeof(radioBuffer), 50, peer);
                        if (radioLength <= 0)
                            continue;
                        try
                        {
                            auto radio = lte::ue::link::Decode(radioBuffer, static_cast<size_t>(radioLength));
                            if (radio.type != lte::ue::link::MessageType::NAS_UPLINK || radio.ueId != 1)
                                throw lte::ue::link::DecodeError("Unsupported LTE UE radio-link identity or direction");
                            if (!uePeer.has_value())
                                uePeer = peer;
                            else if (*uePeer != peer)
                                throw lte::ue::link::DecodeError("A second LTE UE endpoint is not supported");
                            if (!ueContext.has_value())
                            {
                                ueContext = s1ap::UeContext{radio.ueId, std::nullopt};
                                auto initial = s1ap::EncodeInitialUeMessage(config, ueContext->enbUeS1apId, radio.nas);
                                client.send(UeStream(handler, ueContext->enbUeS1apId), initial);
                                Log("INFO", "Initial UE Message sent for LTE UE 1");
                            }
                            else
                            {
                                auto uplink = s1ap::EncodeUplinkNasTransport(config, *ueContext, radio.nas);
                                client.send(UeStream(handler, ueContext->enbUeS1apId), uplink);
                                Log("INFO", "Uplink NAS Transport sent for LTE UE 1");
                            }
                        }
                        catch (const std::exception &e)
                        {
                            Log("WARN", std::string("Rejected LTE UE radio-link datagram: ") + e.what());
                        }
                    }
                    if (handler.associationLost)
                    {
                        state.transition(ConnectionEvent::CONNECTION_LOST);
                        Log("WARN", "Connection disconnected, State=" + std::string(ToString(state.state())));
                    }
                    Log("INFO", "LTE eNB shutdown complete");
                    return shutdownRequested ? 0 : 1;
                }

                state.transition(ConnectionEvent::SETUP_REJECTED);
                std::string rejection = "S1 Setup rejected: cause=" + outcome.causeCategory + "/" + outcome.causeText +
                                        " (" + std::to_string(outcome.causeValue) + ")";
                if (outcome.timeToWaitSeconds.has_value())
                {
                    rejection += ", TimeToWait=" + std::to_string(*outcome.timeToWaitSeconds) + "s";
                    requestedBackoffMs = *outcome.timeToWaitSeconds * 1000;
                }
                if (outcome.diagnosticsPresent)
                    rejection += ", CriticalityDiagnostics present";
                Log("ERROR", rejection + ", State=" + ToString(state.state()));
                attemptComplete = true;
            }

            if (!attemptComplete && !shutdownRequested)
            {
                state.transition(ConnectionEvent::SETUP_REJECTED);
                Log("ERROR", "Timed out waiting for S1 Setup Response, State=" + std::string(ToString(state.state())));
            }
        }
        catch (const std::exception &e)
        {
            state.transition(ConnectionEvent::CONNECTION_LOST);
            Log("ERROR",
                std::string("S1 connection attempt failed: ") + e.what() + ", State=" + ToString(state.state()));
        }
    }

    if (shutdownRequested)
    {
        Log("INFO", "LTE eNB shutdown complete");
        return 0;
    }
    Log("ERROR", "S1 Setup did not complete after " + std::to_string(config.retry.maxAttempts) + " attempts");
    return 1;
}

} // namespace lte::enb
