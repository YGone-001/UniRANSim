//
// This file is a part of UERANSIM project.
// Copyright (c) 2027 ALİ GÜNGÖR.
//
// https://github.com/aligungr/UERANSIM/
// See README, LICENSE, and CONTRIBUTING files for licensing details.
//

#include "app.hpp"
#include "codec.hpp"
#include "multiplexer.hpp"

#include <algorithm>
#include <chrono>
#include <iomanip>
#include <iostream>
#include <sstream>
#include <thread>

#include <lib/sctp/sctp.hpp>

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

class Handler final : public sctp::ISctpHandler, public IS1apSender
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

    void sendS1ap(uint16_t stream, const std::vector<uint8_t> &pdu) override
    {
        client.send(stream, pdu);
    }

    sctp::SctpClient &client;
    bool associationUp{};
    bool associationLost{};
    std::vector<uint8_t> message;
    uint16_t messageStream{};
    int outboundStreams{1};

    explicit Handler(sctp::SctpClient &owner) : client(owner)
    {
    }
};

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
    Log("INFO", "Serving up to " + std::to_string(config.maxUes) + " concurrent LTE UEs");

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

            Handler handler(client);
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

                    EnbMultiplexer multiplexer(config, handler);
                    multiplexer.setOutboundStreams(handler.outboundStreams);
                    Log("INFO", "LTE UE radio-link listening on " + config.ueLinkAddress + ":" +
                                    std::to_string(config.ueLinkPort));
                    Log("INFO", "Shared eNB S1-U GTP-U endpoint bound to " + config.s1uAddress + ":" +
                                    std::to_string(config.s1uPort));
                    while (!shutdownRequested && !handler.associationLost)
                    {
                        // Keep the shared SCTP association responsive; every
                        // received message is routed by the multiplexer to the
                        // matching UE context only.
                        client.receiveFor(&handler, 20);
                        if (!handler.message.empty())
                        {
                            multiplexer.handleS1ap(handler.message.data(), handler.message.size(),
                                                  handler.messageStream);
                            handler.message.clear();
                        }
                        multiplexer.poll(16, 16);
                    }
                    multiplexer.shutdown();
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
