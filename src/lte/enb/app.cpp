//
// This file is a part of UERANSIM project.
// Copyright (c) 2027 ALİ GÜNGÖR.
//
// https://github.com/aligungr/UERANSIM/
// See README, LICENSE, and CONTRIBUTING files for licensing details.
//

#include "app.hpp"
#include "codec.hpp"
#include "gtpu.hpp"
#include "user_plane.hpp"

#include <algorithm>
#include <chrono>
#include <cstdio>
#include <cstring>
#include <iomanip>
#include <iostream>
#include <memory>
#include <sstream>
#include <thread>

#include <lte/ip_packet.hpp>

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

std::array<uint8_t, 4> ParseIpv4(const std::string &address)
{
    unsigned a = 0, b = 0, c = 0, d = 0;
    char extra = 0;
    if (std::sscanf(address.c_str(), "%u.%u.%u.%u%c", &a, &b, &c, &d, &extra) != 4 || a > 255 || b > 255 || c > 255 ||
        d > 255)
        throw std::runtime_error("S1-U address must be an IPv4 literal: " + address);
    return {static_cast<uint8_t>(a), static_cast<uint8_t>(b), static_cast<uint8_t>(c), static_cast<uint8_t>(d)};
}

std::array<uint8_t, 4> TeidToBytes(uint32_t teid)
{
    return {static_cast<uint8_t>((teid >> 24U) & 0xFFU), static_cast<uint8_t>((teid >> 16U) & 0xFFU),
            static_cast<uint8_t>((teid >> 8U) & 0xFFU), static_cast<uint8_t>(teid & 0xFFU)};
}

// One default EPS bearer's S1-U socket, mapping and counters.
struct UserPlaneCounters
{
    uint64_t simulatedUplinkPackets{};
    uint64_t simulatedUplinkBytes{};
    uint64_t simulatedDownlinkPackets{};
    uint64_t simulatedDownlinkBytes{};
    uint64_t s1uUplinkPackets{};
    uint64_t s1uUplinkBytes{};
    uint64_t s1uDownlinkPackets{};
    uint64_t s1uDownlinkBytes{};
    uint64_t malformedDrops{};
    uint64_t invalidTeidDrops{};
    uint64_t unexpectedPeerDrops{};
    uint64_t bearerInactiveDrops{};
};

uint32_t TeidFromBytes(const std::array<uint8_t, 4> &value)
{
    return (static_cast<uint32_t>(value[0]) << 24U) | (static_cast<uint32_t>(value[1]) << 16U) |
           (static_cast<uint32_t>(value[2]) << 8U) | value[3];
}

std::string Ipv4ToString(const std::array<uint8_t, 4> &address)
{
    return std::to_string(address[0]) + "." + std::to_string(address[1]) + "." +
           std::to_string(address[2]) + "." + std::to_string(address[3]);
}

bool IsLoopback(const std::array<uint8_t, 4> &address)
{
    return address[0] == 127;
}

struct GtpuBearer
{
    std::unique_ptr<udp::UdpServer> socket;
    DefaultBearerContext context;
    std::string localAddress;
    uint16_t localPort{};
    uint32_t localTeid{};
    uint8_t erabId{};
    InetAddress sgwPeer;
    UserPlaneCounters counters;

    ~GtpuBearer()
    {
        release();
    }

    void establish(const EnbConfig &config, const s1ap::ErabToBeSetupItem &item, uint32_t ueId)
    {
        if (context.signalingEstablished())
            throw std::runtime_error("A default EPS bearer is already established for this UE");
        if (config.s1uAddress.empty() || config.s1uAddress == "0.0.0.0")
            throw std::runtime_error("The advertised eNB S1-U address must be a concrete local IPv4 address");
        if (config.s1uAddress.rfind("127.", 0) == 0 && !config.allowLoopbackS1u)
            throw std::runtime_error(
                "Loopback S1-U requires s1u.allowLoopback=true after verifying a shared network namespace");

        localAddress = config.s1uAddress;
        localPort = config.s1uPort;
        socket = std::make_unique<udp::UdpServer>(localAddress, localPort);
        localTeid = AllocateLocalTeid();
        erabId = item.erabId;
        const uint32_t sgwTeid = TeidFromBytes(item.gtpTeid);
        context.establish({item.erabId, item.qci, ueId, item.transportLayerAddress, sgwTeid, localTeid});
        sgwPeer = InetAddress(Ipv4ToString(item.transportLayerAddress), 2152);

        if (localAddress.rfind("127.", 0) == 0 && !IsLoopback(item.transportLayerAddress))
            Log("WARN", "Explicit loopback S1-U override is active with a non-loopback SGW-U peer");

        Log("INFO", "Established default bearer: E-RAB/EBI=" + std::to_string(erabId) +
                        " QCI=" + std::to_string(item.qci) + " eNB=" + localAddress + ":" +
                        std::to_string(localPort) + " eNB-TEID=" + Hex(localTeid, 8) +
                        " SGW-U=" + sgwPeer.toString() + " SGW-TEID=" + Hex(sgwTeid, 8));
    }

    void activate(uint32_t ueId, const std::vector<uint8_t> &payload)
    {
        if (payload.size() != 5)
            throw BearerError("Malformed bearer-ready payload");
        std::array<uint8_t, 4> ipv4{{payload[1], payload[2], payload[3], payload[4]}};
        context.activateUe(ueId, payload[0], ipv4);
        Log("INFO", "S1-U user plane ready for UE IPv4 " + Ipv4ToString(ipv4));
    }

    void forwardUplink(uint32_t ueId, const std::vector<uint8_t> &packet)
    {
        if (!context.active())
        {
            ++counters.bearerInactiveDrops;
            throw BearerError("Uplink data received before bearer readiness");
        }
        try
        {
            context.validateUplink(ueId, packet.data(), packet.size());
        }
        catch (const std::exception &)
        {
            ++counters.malformedDrops;
            throw;
        }
        ++counters.simulatedUplinkPackets;
        counters.simulatedUplinkBytes += packet.size();
        auto datagram = gtpu::EncodeTPdu(context.parameters().sgwTeid, packet.data(), packet.size());
        if (socket->TrySend(sgwPeer, datagram.data(), datagram.size()))
        {
            ++counters.s1uUplinkPackets;
            counters.s1uUplinkBytes += packet.size();
        }
    }

    void receiveDownlink(udp::UdpServer &ueLink, const std::optional<InetAddress> &uePeer)
    {
        if (!socket)
            return;

        uint8_t buffer[65536];
        InetAddress peer;
        const int received = socket->Receive(buffer, sizeof(buffer), 0, peer);
        if (received <= 0)
            return;
        if (peer != sgwPeer)
        {
            ++counters.unexpectedPeerDrops;
            Log("WARN", "Dropped S1-U datagram from unexpected peer " + peer.toString());
            return;
        }

        gtpu::Packet packet;
        try
        {
            packet = gtpu::Decode(buffer, static_cast<size_t>(received));
        }
        catch (const std::exception &e)
        {
            ++counters.malformedDrops;
            Log("WARN", std::string("Dropped malformed S1-U datagram: ") + e.what());
            return;
        }

        if (packet.messageType == gtpu::EchoRequest)
        {
            if (!packet.sequenceNumber.has_value())
            {
                ++counters.malformedDrops;
                Log("WARN", "Dropped GTP-U Echo Request without a sequence number");
                return;
            }
            auto response = gtpu::EncodeEchoResponse(*packet.sequenceNumber);
            socket->TrySend(sgwPeer, response.data(), response.size());
            return;
        }
        if (packet.messageType == gtpu::EchoResponse)
            return;

        if (!context.active() || !uePeer.has_value())
        {
            ++counters.bearerInactiveDrops;
            return;
        }
        if (packet.teid != context.parameters().localTeid)
        {
            ++counters.invalidTeidDrops;
            Log("WARN", "Dropped S1-U T-PDU with unknown/stale TEID " + Hex(packet.teid, 8));
            return;
        }
        try
        {
            context.validateDownlink(packet.teid, packet.payload.data(), packet.payload.size());
        }
        catch (const std::exception &e)
        {
            ++counters.malformedDrops;
            Log("WARN", std::string("Dropped invalid downlink IPv4 packet: ") + e.what());
            return;
        }

        ++counters.s1uDownlinkPackets;
        counters.s1uDownlinkBytes += packet.payload.size();
        auto frame = lte::ue::link::Encode(
            {lte::ue::link::MessageType::DATA_DOWNLINK, context.parameters().ueId, std::move(packet.payload)});
        const size_t ipBytes = frame.size() - lte::ue::link::HeaderSize;
        if (ueLink.TrySend(*uePeer, frame.data(), frame.size()))
        {
            ++counters.simulatedDownlinkPackets;
            counters.simulatedDownlinkBytes += ipBytes;
        }
    }

    void release()
    {
        if (!context.signalingEstablished() && !socket)
            return;
        Log("INFO", "User-plane statistics: radio-ul=" + std::to_string(counters.simulatedUplinkPackets) +
                        "/" + std::to_string(counters.simulatedUplinkBytes) +
                        " radio-dl=" + std::to_string(counters.simulatedDownlinkPackets) +
                        "/" + std::to_string(counters.simulatedDownlinkBytes) +
                        " s1u-ul=" + std::to_string(counters.s1uUplinkPackets) +
                        "/" + std::to_string(counters.s1uUplinkBytes) +
                        " s1u-dl=" + std::to_string(counters.s1uDownlinkPackets) +
                        "/" + std::to_string(counters.s1uDownlinkBytes) +
                        " drops(malformed/teid/peer/inactive)=" + std::to_string(counters.malformedDrops) + "/" +
                        std::to_string(counters.invalidTeidDrops) + "/" + std::to_string(counters.unexpectedPeerDrops) +
                        "/" + std::to_string(counters.bearerInactiveDrops));
        context.release();
        socket.reset();
        localTeid = 0;
        Log("INFO", "Released S1-U resources for E-RAB " + std::to_string(erabId));
    }
};

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
                    uint32_t nextEnbUeS1apId = 1;
                    constexpr uint32_t RadioUeId = 1;
                    GtpuBearer defaultBearer;
                    uint8_t radioBuffer[lte::ue::link::MaxDataPduSize + lte::ue::link::HeaderSize];
                    while (!shutdownRequested && !handler.associationLost)
                    {
                        // Keep both transports responsive without assuming SCTP stream zero for UE traffic.
                        client.receiveFor(&handler, 20);
                        if (!handler.message.empty())
                        {
                            try
                            {
                                const auto *message = handler.message.data();
                                const size_t messageLength = handler.message.size();
                                auto pdu = s1ap::ProbeS1apPdu(message, messageLength);
                                if (pdu.kind == s1ap::S1apPdu::Kind::INITIATING &&
                                    pdu.procedureCode == 9)
                                {
                                    auto request =
                                        s1ap::DecodeInitialContextSetupRequest(message, messageLength);
                                    handler.message.clear();
                                    if (!ueContext.has_value() || !uePeer.has_value() ||
                                        request.enbUeS1apId != ueContext->enbUeS1apId)
                                        throw s1ap::CodecError(
                                            "Initial Context Setup Request does not match the active UE context");
                                    if (ueContext->mmeUeS1apId.has_value() &&
                                        *ueContext->mmeUeS1apId != request.mmeUeS1apId)
                                        throw s1ap::CodecError("MME-UE-S1AP-ID changed for the active UE context");
                                    ueContext->mmeUeS1apId = request.mmeUeS1apId;
                                    if (request.erabs.size() != 1)
                                        throw s1ap::CodecError(
                                            "This LTE eNB establishes exactly one default EPS E-RAB");
                                    const auto &erab = request.erabs.front();
                                    // The simulated radio identity is stable across S1 releases;
                                    // fresh eNB-UE-S1AP-IDs must never leak into data-link routing.
                                    defaultBearer.establish(config, erab, RadioUeId);
                                    s1ap::ErabSetupItem setup{erab.erabId, ParseIpv4(defaultBearer.localAddress),
                                                              TeidToBytes(defaultBearer.localTeid)};
                                    auto response = s1ap::EncodeInitialContextSetupResponse(
                                        request.mmeUeS1apId, request.enbUeS1apId, {setup});
                                    client.send(UeStream(handler, ueContext->enbUeS1apId), response);
                                    Log("INFO", "Initial Context Setup Response sent with eNB S1-U TEID=" +
                                                    Hex(defaultBearer.localTeid, 8));
                                    if (erab.nasPduPresent)
                                    {
                                        auto radio = lte::ue::link::Encode(
                                            {lte::ue::link::MessageType::NAS_DOWNLINK, RadioUeId,
                                             erab.nasPdu});
                                        ueLink.Send(*uePeer, radio.data(), radio.size());
                                        Log("INFO", "Forwarded Initial Context Setup NAS-PDU to LTE UE");
                                    }
                                    else
                                    {
                                        auto restored = lte::ue::link::Encode(
                                            {lte::ue::link::MessageType::S1_CONTEXT_RESTORED, RadioUeId,
                                             {defaultBearer.erabId}});
                                        ueLink.Send(*uePeer, restored.data(), restored.size());
                                        Log("INFO", "Signalled restored S1 context and E-RAB transport to LTE UE");
                                    }
                                }
                                else if (pdu.kind == s1ap::S1apPdu::Kind::INITIATING &&
                                         pdu.procedureCode == 11)
                                {
                                    auto downlink =
                                        s1ap::DecodeDownlinkNasTransport(message, messageLength);
                                    handler.message.clear();
                                    if (!ueContext.has_value() || !uePeer.has_value() ||
                                        downlink.enbUeS1apId != ueContext->enbUeS1apId)
                                        throw s1ap::CodecError(
                                            "Downlink NAS Transport does not match the active UE context");
                                    if (ueContext->mmeUeS1apId.has_value() &&
                                        *ueContext->mmeUeS1apId != downlink.mmeUeS1apId)
                                        throw s1ap::CodecError("MME-UE-S1AP-ID changed for the active UE context");
                                    ueContext->mmeUeS1apId = downlink.mmeUeS1apId;
                                    auto radio = lte::ue::link::Encode({lte::ue::link::MessageType::NAS_DOWNLINK,
                                                                        RadioUeId,
                                                                        std::move(downlink.nasPdu)});
                                    ueLink.Send(*uePeer, radio.data(), radio.size());
                                    Log("INFO", "Forwarded Downlink NAS Transport to LTE UE");
                                }
                                else if (pdu.kind == s1ap::S1apPdu::Kind::INITIATING &&
                                         pdu.procedureCode == 23)
                                {
                                    auto command =
                                        s1ap::DecodeUeContextReleaseCommand(message, messageLength);
                                    handler.message.clear();
                                    Log("INFO", "UE Context Release Command received: cause=" +
                                                    command.causeCategory + "/" +
                                                    std::to_string(command.causeValue));
                                    if (ueContext.has_value() && command.enbUeS1apId.has_value() &&
                                        *command.enbUeS1apId != ueContext->enbUeS1apId)
                                        throw s1ap::CodecError(
                                            "UE Context Release does not match the active UE context");
                                    uint32_t mmeId = command.mmeUeS1apId;
                                    uint32_t enbId = command.enbUeS1apId.value_or(
                                        ueContext.has_value() ? ueContext->enbUeS1apId : 0U);
                                    if (uePeer.has_value() && defaultBearer.context.signalingEstablished())
                                    {
                                        auto released = lte::ue::link::Encode(
                                            {lte::ue::link::MessageType::S1_CONTEXT_RELEASED, RadioUeId,
                                             {defaultBearer.erabId}});
                                        ueLink.TrySend(*uePeer, released.data(), released.size());
                                    }
                                    defaultBearer.release();
                                    auto complete = s1ap::EncodeUeContextReleaseComplete(mmeId, enbId);
                                    client.send(UeStream(handler, enbId), complete);
                                    Log("INFO", "UE Context Release Complete sent");
                                    ueContext.reset();
                                }
                                else
                                {
                                    throw s1ap::CodecError("Unexpected S1AP procedure code " +
                                                           std::to_string(pdu.procedureCode));
                                }
                            }
                            catch (const std::exception &e)
                            {
                                Log("WARN", std::string("Rejected post-setup S1AP message on stream ") +
                                                std::to_string(handler.messageStream) + ": " + e.what());
                                handler.message.clear();
                            }
                        }

                        InetAddress peer;
                        int radioLength = ueLink.Receive(radioBuffer, sizeof(radioBuffer), 20, peer);
                        if (radioLength > 0)
                        {
                            try
                            {
                                auto radio = lte::ue::link::Decode(radioBuffer, static_cast<size_t>(radioLength));
                                if (!lte::ue::link::IsUplink(radio.type) || radio.ueId != RadioUeId)
                                    throw lte::ue::link::DecodeError("Unsupported LTE UE radio-link identity or direction");
                                if (!uePeer.has_value())
                                {
                                    if (radio.type != lte::ue::link::MessageType::NAS_UPLINK)
                                        throw lte::ue::link::DecodeError("Data arrived before an LTE UE NAS context");
                                    uePeer = peer;
                                }
                                else if (*uePeer != peer)
                                    throw lte::ue::link::DecodeError("A second LTE UE endpoint is not supported");

                                if (radio.type == lte::ue::link::MessageType::S1_CONTEXT_RELEASE_REQUEST)
                                {
                                    if (!ueContext.has_value() || !ueContext->mmeUeS1apId.has_value() ||
                                        !defaultBearer.context.signalingEstablished() || radio.payload[0] != defaultBearer.erabId)
                                        throw lte::ue::link::DecodeError(
                                            "S1 release request does not match an active registered UE context");
                                    auto request = s1ap::EncodeUeContextReleaseRequest(
                                        *ueContext->mmeUeS1apId, ueContext->enbUeS1apId);
                                    client.send(UeStream(handler, ueContext->enbUeS1apId), request);
                                    Log("INFO", "UE Context Release Request sent: cause=radioNetwork/user-inactivity");
                                }
                                else if (radio.type == lte::ue::link::MessageType::SERVICE_REQUEST &&
                                         ueContext.has_value())
                                    throw lte::ue::link::DecodeError(
                                        "Duplicate Service Request cannot replace a pending or active S1 context");
                                else if (radio.type == lte::ue::link::MessageType::BEARER_READY)
                                    defaultBearer.activate(radio.ueId, radio.payload);
                                else if (radio.type == lte::ue::link::MessageType::DATA_UPLINK)
                                    defaultBearer.forwardUplink(radio.ueId, radio.payload);
                                else if (!ueContext.has_value())
                                {
                                    if (radio.type != lte::ue::link::MessageType::NAS_UPLINK &&
                                        radio.type != lte::ue::link::MessageType::SERVICE_REQUEST)
                                        throw lte::ue::link::DecodeError(
                                            "Only NAS may establish a fresh LTE S1 UE context");
                                    const uint32_t enbUeId = nextEnbUeS1apId++;
                                    if (nextEnbUeS1apId == 0 || nextEnbUeS1apId > 0xFFFFFFU)
                                        nextEnbUeS1apId = 1;
                                    ueContext = s1ap::UeContext{enbUeId, std::nullopt};
                                    std::vector<uint8_t> nasPdu = radio.payload;
                                    std::optional<s1ap::STmsi> sTmsi;
                                    if (radio.type == lte::ue::link::MessageType::SERVICE_REQUEST)
                                    {
                                        const uint32_t mTmsi = (static_cast<uint32_t>(radio.payload[1]) << 24U) |
                                                               (static_cast<uint32_t>(radio.payload[2]) << 16U) |
                                                               (static_cast<uint32_t>(radio.payload[3]) << 8U) |
                                                               radio.payload[4];
                                        sTmsi = s1ap::STmsi{radio.payload[0], mTmsi};
                                        nasPdu.assign(radio.payload.begin() + 5, radio.payload.end());
                                    }
                                    auto initial = s1ap::EncodeInitialUeMessage(
                                        config, ueContext->enbUeS1apId, nasPdu, sTmsi);
                                    client.send(UeStream(handler, ueContext->enbUeS1apId), initial);
                                    Log("INFO", "Initial UE Message sent for LTE UE 1 with fresh eNB-UE-S1AP-ID=" +
                                                    std::to_string(enbUeId));
                                }
                                else
                                {
                                    auto uplink = s1ap::EncodeUplinkNasTransport(config, *ueContext, radio.payload);
                                    client.send(UeStream(handler, ueContext->enbUeS1apId), uplink);
                                    Log("INFO", "Uplink NAS Transport sent for LTE UE 1");
                                }
                            }
                            catch (const std::exception &e)
                            {
                                Log("WARN", std::string("Rejected LTE UE radio-link datagram: ") + e.what());
                            }
                        }
                        defaultBearer.receiveDownlink(ueLink, uePeer);
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
