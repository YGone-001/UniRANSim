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
#include "recovery.hpp"

#include <algorithm>
#include <chrono>
#include <fstream>
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

std::string Trim(const std::string &text)
{
    const auto first = text.find_first_not_of(" \t\r\n");
    if (first == std::string::npos)
        return {};
    const auto last = text.find_last_not_of(" \t\r\n");
    return text.substr(first, last - first + 1U);
}

// Association-scoped S1AP endpoint. It lives exactly as long as one SCTP
// association and is bound to the multiplexer only for that association's
// epoch, so a handler left behind by a previous epoch can never transmit.
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

// Opt-in, one-shot S1 failure injection for the test-owned eNB.
//
// The mechanism does not exist at all unless a control file is configured, so
// an ordinary deployment has no injection code path. It never touches the live
// EPC, never uses a firewall and never kills a process: it only invalidates the
// simulator's own SCTP association.
class FailureInjector
{
  public:
    enum class Command
    {
        NONE,
        // Tear the association down immediately.
        LOSS,
        // Drop the next S1AP PDU the eNB would have sent and tear the
        // association down instead. Deterministically produces an in-flight
        // interruption, e.g. during Initial Context Setup.
        LOSS_BEFORE_S1AP_RESPONSE
    };

    explicit FailureInjector(const FailureInjectionConfig &config) : m_config(config)
    {
        if (m_config.controlFile.empty())
            Log("INFO", "S1 failure injection is disabled (no control file configured)");
        else
            Log("INFO", "S1 failure injection armed; control file=" + m_config.controlFile);
    }

    Command poll()
    {
        if (m_config.controlFile.empty())
            return Command::NONE;
        const auto now = Clock::now();
        if (now < m_nextPoll)
            return Command::NONE;
        m_nextPoll = now + std::chrono::milliseconds(m_config.pollIntervalMs);

        std::ifstream input(m_config.controlFile);
        if (!input.is_open())
            return Command::NONE;
        std::string line;
        std::getline(input, line);
        input.close();
        // One-shot: the command is consumed so it cannot fire twice.
        std::ofstream(m_config.controlFile, std::ios::trunc).close();

        const std::string command = Trim(line);
        if (command.empty())
            return Command::NONE;
        if (command == "loss")
            return Command::LOSS;
        if (command == "loss-before-s1ap-response")
            return Command::LOSS_BEFORE_S1AP_RESPONSE;
        Log("WARN", "Unknown S1 failure-injection command ignored: " + command);
        return Command::NONE;
    }

  private:
    FailureInjectionConfig m_config;
    Clock::time_point m_nextPoll{};
};

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

void LogRecoveryCounters(const RecoveryCounters &counters)
{
    Log("INFO", "S1 recovery statistics: associations-established=" +
                    std::to_string(counters.associationsEstablished) +
                    " unexpected-losses=" + std::to_string(counters.unexpectedAssociationLosses) +
                    " injected-losses=" + std::to_string(counters.injectedAssociationLosses) +
                    " access-invalidations=" + std::to_string(counters.accessInvalidations) +
                    " ues-affected=" + std::to_string(counters.activeUesAffectedByLoss) +
                    " bearers-retained=" + std::to_string(counters.logicalBearersRetained) +
                    " teids-invalidated=" + std::to_string(counters.localTeidsInvalidated) +
                    " reconnect(attempts/success/failure)=" + std::to_string(counters.reconnectAttempts) + "/" +
                    std::to_string(counters.reconnectSuccesses) + "/" + std::to_string(counters.reconnectFailures) +
                    " s1-setup-failures=" + std::to_string(counters.s1SetupFailures) +
                    " ue-restorations(success/failure)=" + std::to_string(counters.successfulUeRestorations) + "/" +
                    std::to_string(counters.failedUeRestorations) +
                    " rejected(stale-messages/sender/unbound)=" + std::to_string(counters.staleMessagesRejected) + "/" +
                    std::to_string(counters.staleSenderRejects) + "/" + std::to_string(counters.unboundSenderRejects));
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

    // Long-lived eNB runtime. The simulated-radio endpoint, the shared S1-U
    // GTP-U socket and the whole per-UE registry survive every SCTP
    // association epoch; only the association itself is recreated.
    EnbMultiplexer multiplexer(config);
    Log("INFO", "LTE UE radio-link listening on " + config.ueLinkAddress + ":" + std::to_string(config.ueLinkPort));
    Log("INFO", "Shared eNB S1-U GTP-U endpoint bound to " + config.s1uAddress + ":" + std::to_string(config.s1uPort));

    FailureInjector injector(config.failureInjection);

    int requestedBackoffMs = 0;
    int initialAttempts = 0;
    int recoveryAttempts = 0;
    bool establishedOnce = false;
    bool shutdownInterrupted = false;

    for (;;)
    {
        if (shutdownRequested)
            break;

        if (establishedOnce)
        {
            if (config.recovery.maxAttempts > 0 && recoveryAttempts >= config.recovery.maxAttempts)
            {
                Log("ERROR", "S1 recovery did not complete after " + std::to_string(recoveryAttempts) +
                                " reconnect attempt(s)");
                LogRecoveryCounters(multiplexer.recoveryCounters());
                return 1;
            }
            ++recoveryAttempts;
            ++multiplexer.recoveryCounters().reconnectAttempts;
            state.transition(ConnectionEvent::RECOVERY_STARTED);
            const int delay = RecoveryBackoffMs(config.recovery, recoveryAttempts, requestedBackoffMs);
            Log("INFO", "State=" + std::string(ToString(state.state())) + ", reconnect attempt " +
                            std::to_string(recoveryAttempts) +
                            (config.recovery.maxAttempts > 0 ? "/" + std::to_string(config.recovery.maxAttempts) : "") +
                            " after " + std::to_string(delay) + " ms");
            if (!InterruptibleDelay(delay, shutdownRequested))
            {
                shutdownInterrupted = true;
                break;
            }
        }
        else
        {
            ++initialAttempts;
            if (initialAttempts > config.retry.maxAttempts)
                break;
            if (initialAttempts > 1)
            {
                const int delay = std::max(config.retry.delayMs, requestedBackoffMs);
                Log("INFO", "Retry " + std::to_string(initialAttempts) + "/" + std::to_string(config.retry.maxAttempts) +
                                " after " + std::to_string(delay) + " ms");
                if (!InterruptibleDelay(delay, shutdownRequested))
                {
                    shutdownInterrupted = true;
                    break;
                }
            }
            state.transition(ConnectionEvent::CONNECT_STARTED);
            Log("INFO", "State=" + std::string(ToString(state.state())) + ", connecting to MME");
        }
        requestedBackoffMs = 0;

        try
        {
            sctp::SctpClient client(sctp::PayloadProtocolId::S1AP, config.localAddress,
                                    config.retry.connectMaxAttempts, config.retry.connectTimeoutMs);
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

                    // A successful S1 Setup authorizes a new association
                    // epoch. Only now may UE-associated signalling flow.
                    const uint32_t epoch = multiplexer.bindAssociation(handler, handler.outboundStreams);
                    Log("INFO", "S1 association epoch=" + std::to_string(epoch) +
                                    ", outbound-streams=" + std::to_string(handler.outboundStreams));
                    if (establishedOnce)
                        ++multiplexer.recoveryCounters().reconnectSuccesses;
                    establishedOnce = true;
                    attemptComplete = true;

                    // Serve this association until it is lost or the process is
                    // asked to stop. The multiplexer keeps running either way.
                    while (!shutdownRequested && !handler.associationLost)
                    {
                        FailureInjector::Command command = injector.poll();
                        if (command == FailureInjector::Command::LOSS)
                        {
                            Log("WARN", "S1 failure injection: association loss requested by the control file");
                            handler.associationLost = true;
                            break;
                        }
                        if (command == FailureInjector::Command::LOSS_BEFORE_S1AP_RESPONSE)
                        {
                            Log("WARN", "S1 failure injection: armed to interrupt the next S1AP response");
                            multiplexer.armLossBeforeNextS1apSend();
                        }

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

                        if (multiplexer.injectionTriggered())
                        {
                            Log("WARN", "S1 failure injection: an in-flight S1AP procedure was interrupted");
                            handler.associationLost = true;
                            break;
                        }
                    }

                    const bool stopping = shutdownRequested;
                    // Access transport of every affected UE is invalidated and
                    // the association sender is detached before anything else.
                    const size_t affected = multiplexer.invalidateAccess();
                    if (handler.associationLost && !stopping)
                    {
                        ++multiplexer.recoveryCounters().unexpectedAssociationLosses;
                        state.transition(ConnectionEvent::CONNECTION_LOST);
                        Log("WARN", "Connection disconnected after invalidating access of " +
                                        std::to_string(affected) + " LTE UE(s), State=" +
                                        std::string(ToString(state.state())));
                        LogRecoveryCounters(multiplexer.recoveryCounters());
                        continue;
                    }
                    state.transition(ConnectionEvent::SHUTDOWN_REQUESTED);
                    Log("INFO", "LTE eNB shutdown complete");
                    multiplexer.shutdown();
                    LogRecoveryCounters(multiplexer.recoveryCounters());
                    return 0;
                }

                state.transition(ConnectionEvent::SETUP_REJECTED);
                ++multiplexer.recoveryCounters().s1SetupFailures;
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
                ++multiplexer.recoveryCounters().s1SetupFailures;
                Log("ERROR", "Timed out waiting for S1 Setup Response, State=" + std::string(ToString(state.state())));
            }
        }
        catch (const std::exception &e)
        {
            // invalidateAccess detaches the sender first, so nothing produced
            // during the cleanup can still reach the failed association.
            const size_t affected = multiplexer.invalidateAccess();
            state.transition(ConnectionEvent::CONNECTION_LOST);
            if (establishedOnce)
            {
                ++multiplexer.recoveryCounters().unexpectedAssociationLosses;
                ++multiplexer.recoveryCounters().reconnectFailures;
                Log("WARN", "S1 connection failed after invalidating access of " + std::to_string(affected) +
                                " LTE UE(s): " + e.what() + ", State=" + ToString(state.state()));
            }
            else
                Log("ERROR", std::string("S1 connection attempt failed: ") + e.what() + ", State=" +
                                 ToString(state.state()));
        }
    }

    if (shutdownInterrupted || shutdownRequested)
    {
        state.transition(ConnectionEvent::SHUTDOWN_REQUESTED);
        multiplexer.invalidateAccess();
        multiplexer.shutdown();
        Log("INFO", "LTE eNB shutdown complete");
        LogRecoveryCounters(multiplexer.recoveryCounters());
        return 0;
    }
    Log("ERROR", "S1 Setup did not complete after " + std::to_string(config.retry.maxAttempts) + " attempts");
    multiplexer.shutdown();
    LogRecoveryCounters(multiplexer.recoveryCounters());
    return 1;
}

} // namespace lte::enb
