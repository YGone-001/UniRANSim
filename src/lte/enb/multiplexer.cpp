//
// This file is a part of UERANSIM project.
// Copyright (c) 2027 ALİ GÜNGÖR.
//
// https://github.com/aligungr/UERANSIM/
// See README, LICENSE, and CONTRIBUTING files for licensing details.
//

#include "multiplexer.hpp"

#include "codec.hpp"

#include <iomanip>
#include <iostream>
#include <sstream>
#include <stdexcept>
#include <utility>

namespace lte::enb
{

namespace
{

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

bool IsLoopback(const std::array<uint8_t, 4> &address)
{
    return address[0] == 127;
}

std::string Describe(const EnbUeEntry &entry)
{
    std::ostringstream stream;
    stream << "LTE UE " << entry.radioUeId << " (eNB-UE-S1AP-ID=" << entry.enbUeS1apId
           << ", MME-UE-S1AP-ID=" << entry.mmeUeS1apId << ", " << ToString(entry.s1) << ")";
    return stream.str();
}

} // namespace

EnbMultiplexer::EnbMultiplexer(const EnbConfig &config, IS1apSender &sender)
    : m_config(config), m_sender(sender), m_ueLink(config.ueLinkAddress, config.ueLinkPort),
      m_registry(static_cast<size_t>(config.maxUes)), m_s1u(config.s1uAddress, config.s1uPort, config.allowLoopbackS1u,
                                                           m_registry, m_ueLink)
{
}

void EnbMultiplexer::setOutboundStreams(int outboundStreams)
{
    if (outboundStreams < 1)
        throw std::runtime_error("The negotiated outbound SCTP stream count must be at least one");
    m_outboundStreams = outboundStreams;
}

void EnbMultiplexer::poll(int radioBudget, int s1uBudget)
{
    uint8_t buffer[lte::ue::link::MaxDataPduSize + lte::ue::link::HeaderSize];
    for (int budget = radioBudget; budget > 0; --budget)
    {
        InetAddress peer;
        const int length = m_ueLink.Receive(buffer, sizeof(buffer), 0, peer);
        if (length <= 0)
            break;
        handleRadioFrame(buffer, static_cast<size_t>(length), peer);
    }
    m_s1u.poll(s1uBudget);
}

void EnbMultiplexer::handleS1ap(const uint8_t *data, size_t size, uint16_t stream)
{
    try
    {
        const auto pdu = s1ap::ProbeS1apPdu(data, size);
        if (pdu.kind == s1ap::S1apPdu::Kind::INITIATING && pdu.procedureCode == 9)
            onInitialContextSetupRequest(data, size);
        else if (pdu.kind == s1ap::S1apPdu::Kind::INITIATING && pdu.procedureCode == 11)
            onDownlinkNasTransport(data, size);
        else if (pdu.kind == s1ap::S1apPdu::Kind::INITIATING && pdu.procedureCode == 23)
            onUeContextReleaseCommand(data, size);
        else
            throw s1ap::CodecError("Unexpected S1AP procedure code " + std::to_string(pdu.procedureCode));
    }
    catch (const std::exception &e)
    {
        // A rejected UE-specific message never endangers the shared
        // association or the contexts of the other UEs.
        Log("WARN", std::string("Rejected post-setup S1AP message on stream ") + std::to_string(stream) + ": " +
                       e.what());
    }
}

void EnbMultiplexer::onInitialContextSetupRequest(const uint8_t *data, size_t size)
{
    auto request = s1ap::DecodeInitialContextSetupRequest(data, size);
    auto *entry = m_registry.findByEnbUeS1apId(request.enbUeS1apId);
    if (entry == nullptr)
        throw s1ap::CodecError("Initial Context Setup Request references an unknown eNB-UE-S1AP-ID");
    if (entry->s1 != UeS1State::CONTEXT_PENDING)
        throw s1ap::CodecError("Initial Context Setup Request does not match a pending S1 UE context");
    if (entry->mmeUeS1apId != 0 && entry->mmeUeS1apId != request.mmeUeS1apId)
        throw s1ap::CodecError("MME-UE-S1AP-ID changed for the active UE context");
    if (const auto *owner = m_registry.findByMmeUeS1apId(request.mmeUeS1apId); owner != nullptr && owner != entry)
        throw s1ap::CodecError("MME-UE-S1AP-ID is already owned by another UE context");
    if (entry->bearer.signalingEstablished())
        throw BearerError("A default EPS bearer is already established for this UE");
    if (request.erabs.size() != 1)
        throw s1ap::CodecError("This LTE eNB establishes exactly one default EPS E-RAB");

    m_registry.setMmeUeS1apId(*entry, request.mmeUeS1apId);
    const auto &erab = request.erabs.front();
    const uint32_t localTeid = m_registry.allocateLocalTeid();
    const uint32_t sgwTeid = TeidFromBytes(erab.gtpTeid);
    // The simulated radio identity is stable across S1 releases; fresh eNB
    // UE S1AP IDs and TEIDs must never leak into data-link routing.
    entry->bearer.establish(
        {erab.erabId, erab.qci, entry->radioUeId, erab.transportLayerAddress, sgwTeid, localTeid});
    m_registry.bindLocalTeid(*entry, localTeid);
    entry->sgwPeer = InetAddress(Ipv4ToString(erab.transportLayerAddress), 2152);
    entry->s1 = UeS1State::CONTEXT_ESTABLISHED;

    s1ap::ErabSetupItem setup{erab.erabId, ParseIpv4(m_config.s1uAddress), TeidToBytes(localTeid)};
    auto response =
        s1ap::EncodeInitialContextSetupResponse(request.mmeUeS1apId, request.enbUeS1apId, {setup});
    m_sender.sendS1ap(streamFor(*entry), response);
    Log("INFO", "Established default bearer for " + Describe(*entry) + ": E-RAB/EBI=" + std::to_string(erab.erabId) +
                    " QCI=" + std::to_string(erab.qci) + " eNB=" + m_config.s1uAddress + ":" +
                    std::to_string(m_config.s1uPort) + " eNB-TEID=" + Hex(localTeid, 8) + " SGW-U=" +
                    entry->sgwPeer.toString() + " SGW-TEID=" + Hex(sgwTeid, 8));

    if (m_config.s1uAddress.rfind("127.", 0) == 0 && !IsLoopback(erab.transportLayerAddress))
        Log("WARN", "Explicit loopback S1-U override is active with a non-loopback SGW-U peer");

    if (erab.nasPduPresent)
    {
        sendRadio(*entry, lte::ue::link::MessageType::NAS_DOWNLINK, erab.nasPdu);
        Log("INFO", "Forwarded Initial Context Setup NAS-PDU to " + Describe(*entry));
    }
    else
    {
        sendRadio(*entry, lte::ue::link::MessageType::S1_CONTEXT_RESTORED, {erab.erabId});
        Log("INFO", "Signalled restored S1 context and E-RAB transport to " + Describe(*entry));
    }
}

void EnbMultiplexer::onDownlinkNasTransport(const uint8_t *data, size_t size)
{
    auto downlink = s1ap::DecodeDownlinkNasTransport(data, size);
    auto *entry = m_registry.findByEnbUeS1apId(downlink.enbUeS1apId);
    if (entry == nullptr)
        throw s1ap::CodecError("Downlink NAS Transport references an unknown or released eNB-UE-S1AP-ID");
    if (entry->mmeUeS1apId != 0 && entry->mmeUeS1apId != downlink.mmeUeS1apId)
        throw s1ap::CodecError("MME-UE-S1AP-ID changed for the active UE context");
    if (const auto *owner = m_registry.findByMmeUeS1apId(downlink.mmeUeS1apId); owner != nullptr && owner != entry)
        throw s1ap::CodecError("MME-UE-S1AP-ID is already owned by another UE context");
    if (!entry->s1Active())
        throw s1ap::CodecError("Downlink NAS Transport does not match an active S1 UE context");
    m_registry.setMmeUeS1apId(*entry, downlink.mmeUeS1apId);

    sendRadio(*entry, lte::ue::link::MessageType::NAS_DOWNLINK, std::move(downlink.nasPdu));
    Log("INFO", "Forwarded Downlink NAS Transport to " + Describe(*entry));
}

void EnbMultiplexer::onUeContextReleaseCommand(const uint8_t *data, size_t size)
{
    auto command = s1ap::DecodeUeContextReleaseCommand(data, size);
    Log("INFO", "UE Context Release Command received: cause=" + command.causeCategory + "/" +
                    std::to_string(command.causeValue));

    EnbUeEntry *entry;
    if (command.enbUeS1apId.has_value())
    {
        entry = m_registry.findByEnbUeS1apId(*command.enbUeS1apId);
        if (entry == nullptr)
            throw s1ap::CodecError("UE Context Release references an unknown or released eNB-UE-S1AP-ID");
        if (entry->mmeUeS1apId != 0 && entry->mmeUeS1apId != command.mmeUeS1apId)
            throw s1ap::CodecError("UE Context Release does not match the UE context identity pair");
    }
    else
    {
        // Signalling-based release carries only the MME-UE-S1AP-ID; the
        // target UE resolves from the registry instead of a guess.
        entry = m_registry.findByMmeUeS1apId(command.mmeUeS1apId);
        if (entry == nullptr)
            throw s1ap::CodecError("UE Context Release references an unknown or released MME-UE-S1AP-ID");
    }

    const uint32_t mmeId = command.mmeUeS1apId;
    const uint32_t enbId = entry->enbUeS1apId;
    const uint8_t erabId = entry->bearer.parameters().erabId;
    const uint32_t radioUeId = entry->radioUeId;
    if (entry->bearer.signalingEstablished())
        sendRadio(*entry, lte::ue::link::MessageType::S1_CONTEXT_RELEASED, {erabId});
    m_registry.releaseS1(*entry);
    Log("INFO", "Released S1 context of LTE UE " + std::to_string(radioUeId) + " (eNB-UE-S1AP-ID=" +
                    std::to_string(enbId) + ", MME-UE-S1AP-ID=" + std::to_string(mmeId) +
                    "); its TEID mapping was invalidated");
    auto complete = s1ap::EncodeUeContextReleaseComplete(mmeId, enbId);
    m_sender.sendS1ap(SctpStreamForUe(m_outboundStreams, enbId), complete);
    Log("INFO", "UE Context Release Complete sent for eNB-UE-S1AP-ID=" + std::to_string(enbId));
}

void EnbMultiplexer::handleRadioFrame(const uint8_t *data, size_t size, const InetAddress &peer)
{
    try
    {
        auto radio = lte::ue::link::Decode(data, size);
        if (!lte::ue::link::IsUplink(radio.type))
            throw lte::ue::link::DecodeError("Unexpected LTE radio-link direction");

        auto *entry = m_registry.find(radio.ueId);
        if (entry != nullptr && entry->peer != peer)
            throw lte::ue::link::DecodeError("LTE radio-link datagram from an endpoint that does not own this UE identity");
        if (entry == nullptr)
        {
            if (m_registry.findByPeer(peer) != nullptr)
                throw lte::ue::link::DecodeError("A radio endpoint may not claim another active UE identity");
            if (radio.type != lte::ue::link::MessageType::NAS_UPLINK &&
                radio.type != lte::ue::link::MessageType::SERVICE_REQUEST)
                throw lte::ue::link::DecodeError("Data arrived before an LTE UE NAS context");
            entry = &m_registry.registerPeer(radio.ueId, peer);
        }

        if (radio.type == lte::ue::link::MessageType::S1_CONTEXT_RELEASE_REQUEST)
        {
            if (!entry->s1Active() || !entry->bearer.signalingEstablished() || entry->mmeUeS1apId == 0 ||
                radio.payload[0] != entry->bearer.parameters().erabId)
                throw lte::ue::link::DecodeError("S1 release request does not match an active registered UE context");
            auto request = s1ap::EncodeUeContextReleaseRequest(entry->mmeUeS1apId, entry->enbUeS1apId);
            m_sender.sendS1ap(streamFor(*entry), request);
            Log("INFO", "UE Context Release Request sent for " + Describe(*entry) +
                            ": cause=radioNetwork/user-inactivity");
        }
        else if (radio.type == lte::ue::link::MessageType::SERVICE_REQUEST)
        {
            if (entry->s1Active())
                throw lte::ue::link::DecodeError("Duplicate Service Request cannot replace a pending or active S1 context");
            const uint32_t mTmsi = (static_cast<uint32_t>(radio.payload[1]) << 24U) |
                                   (static_cast<uint32_t>(radio.payload[2]) << 16U) |
                                   (static_cast<uint32_t>(radio.payload[3]) << 8U) | radio.payload[4];
            std::vector<uint8_t> nasPdu(radio.payload.begin() + 5, radio.payload.end());
            startInitialUeMessage(*entry, std::move(nasPdu), s1ap::STmsi{radio.payload[0], mTmsi});
        }
        else if (radio.type == lte::ue::link::MessageType::NAS_UPLINK)
        {
            if (entry->s1Active())
            {
                if (entry->mmeUeS1apId == 0)
                    throw lte::ue::link::DecodeError(
                        "Uplink NAS cannot be routed before the MME assigned an MME-UE-S1AP-ID");
                auto uplink =
                    s1ap::EncodeUplinkNasTransport(m_config, {entry->enbUeS1apId, entry->mmeUeS1apId}, radio.payload);
                m_sender.sendS1ap(streamFor(*entry), uplink);
                Log("INFO", "Uplink NAS Transport sent for " + Describe(*entry));
            }
            else
            {
                startInitialUeMessage(*entry, std::move(radio.payload), std::nullopt);
            }
        }
        else if (radio.type == lte::ue::link::MessageType::BEARER_READY)
            onBearerReady(*entry, radio.payload);
        else if (radio.type == lte::ue::link::MessageType::DATA_UPLINK)
        {
            m_s1u.forwardUplink(*entry, radio.payload.data(), radio.payload.size());
        }
        else
            throw lte::ue::link::DecodeError("Unsupported LTE radio-link message for an active UE");
    }
    catch (const std::exception &e)
    {
        Log("WARN", std::string("Rejected LTE UE radio-link datagram: ") + e.what());
    }
}

void EnbMultiplexer::onBearerReady(EnbUeEntry &entry, const std::vector<uint8_t> &payload)
{
    if (payload.size() != 5)
        throw lte::ue::link::DecodeError("Malformed bearer-ready payload");
    const std::array<uint8_t, 4> ipv4{{payload[1], payload[2], payload[3], payload[4]}};
    entry.bearer.activateUe(entry.radioUeId, payload[0], ipv4);
    entry.s1 = UeS1State::BEARER_ACTIVE;
    Log("INFO", "S1-U user plane ready for LTE UE " + std::to_string(entry.radioUeId) + " IPv4 " +
                    Ipv4ToString(ipv4));
}

void EnbMultiplexer::startInitialUeMessage(EnbUeEntry &entry, std::vector<uint8_t> nasPdu,
                                           std::optional<s1ap::STmsi> sTmsi)
{
    const uint32_t enbUeId = m_registry.allocateEnbUeS1apId();
    m_registry.bindEnbUeS1apId(entry, enbUeId);
    entry.s1 = UeS1State::CONTEXT_PENDING;
    auto initial = s1ap::EncodeInitialUeMessage(m_config, enbUeId, nasPdu, sTmsi);
    m_sender.sendS1ap(SctpStreamForUe(m_outboundStreams, enbUeId), initial);
    Log("INFO", "Initial UE Message sent for LTE UE " + std::to_string(entry.radioUeId) +
                    " with fresh eNB-UE-S1AP-ID=" + std::to_string(enbUeId));
}

void EnbMultiplexer::sendRadio(EnbUeEntry &entry, lte::ue::link::MessageType type, std::vector<uint8_t> payload)
{
    auto frame = lte::ue::link::Encode({type, entry.radioUeId, std::move(payload)});
    m_ueLink.Send(entry.peer, frame.data(), frame.size());
}

uint16_t EnbMultiplexer::streamFor(const EnbUeEntry &entry) const
{
    return SctpStreamForUe(m_outboundStreams, entry.enbUeS1apId);
}

UeRegistry &EnbMultiplexer::registry()
{
    return m_registry;
}

const UeRegistry &EnbMultiplexer::registry() const
{
    return m_registry;
}

InetAddress EnbMultiplexer::ueLinkAddress() const
{
    return m_ueLink.LocalAddress();
}

InetAddress EnbMultiplexer::s1uAddress() const
{
    return m_s1u.localAddress();
}

void EnbMultiplexer::shutdown()
{
    for (auto *entry : m_registry.all())
    {
        Log("INFO", "User-plane statistics for LTE UE " + std::to_string(entry->radioUeId) +
                        ": radio-ul=" + std::to_string(entry->counters.simulatedUplinkPackets) + "/" +
                        std::to_string(entry->counters.simulatedUplinkBytes) +
                        " radio-dl=" + std::to_string(entry->counters.simulatedDownlinkPackets) + "/" +
                        std::to_string(entry->counters.simulatedDownlinkBytes) +
                        " s1u-ul=" + std::to_string(entry->counters.s1uUplinkPackets) + "/" +
                        std::to_string(entry->counters.s1uUplinkBytes) +
                        " s1u-dl=" + std::to_string(entry->counters.s1uDownlinkPackets) + "/" +
                        std::to_string(entry->counters.s1uDownlinkBytes) +
                        " drops(malformed/teid/peer/inactive)=" + std::to_string(entry->counters.malformedDrops) +
                        "/" + std::to_string(entry->counters.invalidTeidDrops) + "/" +
                        std::to_string(entry->counters.unexpectedPeerDrops) + "/" +
                        std::to_string(entry->counters.bearerInactiveDrops));
        m_registry.releaseS1(*entry);
    }
    Log("INFO", "Shared S1-U endpoint statistics: echo=" + std::to_string(m_s1u.counters().echoRequests) +
                    " drops(malformed/unknown-teid)=" + std::to_string(m_s1u.counters().malformedDrops) + "/" +
                    std::to_string(m_s1u.counters().unknownTeidDrops));
}

} // namespace lte::enb
