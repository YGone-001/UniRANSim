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

// Compact hex of a received S1AP Paging PDU. A Paging message carries the
// paging identity but no NAS security material, so recording it is safe and it
// is the only way to diff an MME encoding against the local decoder.
std::string ToHex(const uint8_t *data, size_t size)
{
    std::ostringstream stream;
    stream << std::uppercase << std::hex << std::setfill('0');
    for (size_t i = 0; i < size; ++i)
        stream << std::setw(2) << static_cast<int>(data[i]);
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
        else if (pdu.kind == s1ap::S1apPdu::Kind::INITIATING && pdu.procedureCode == 5)
            onErabSetupRequest(data, size);
        else if (pdu.kind == s1ap::S1apPdu::Kind::INITIATING && pdu.procedureCode == 7)
            onErabReleaseCommand(data, size);
        else if (pdu.kind == s1ap::S1apPdu::Kind::INITIATING && pdu.procedureCode == 10)
            onPaging(data, size, stream);
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

void EnbMultiplexer::onPaging(const uint8_t *data, size_t size, uint16_t stream)
{
    ++m_paging.received;
    if (stream != 0)
    {
        // TS 36.412: non-UE-associated S1AP signalling uses stream identifier
        // zero. A page that claims to belong to a UE-associated stream is never
        // attached to an active UE context.
        ++m_paging.invalid;
        throw s1ap::CodecError("S1AP Paging arrived on a UE-associated SCTP stream");
    }

    s1ap::PagingMessage page;
    try
    {
        page = s1ap::DecodePaging(data, size);
    }
    catch (const std::exception &e)
    {
        ++m_paging.invalid;
        Log("WARN", std::string("Rejected S1AP Paging PDU (") + std::to_string(size) + " bytes): " + e.what() +
                        " raw=" + ToHex(data, size));
        throw;
    }
    ++m_paging.valid;

    if (page.cnDomain != 0)
    {
        // CS-domain paging never targets an EPS bearer.
        ++m_paging.csDomainIgnored;
        Log("INFO", "Ignoring S1AP Paging for the circuit-switched domain");
        return;
    }
    if (page.identity != s1ap::PagingMessage::Identity::S_TMSI)
    {
        // Never echo an IMSI page: it carries a permanent subscriber identity.
        ++m_paging.unsupportedIdentity;
        Log("WARN", "Ignoring S1AP Paging addressed by IMSI (identity redacted): this phase pages only by S-TMSI");
        return;
    }
    // A Paging PDU with an S-TMSI carries no permanent subscriber identity and
    // no NAS security material, so it is safe to record verbatim.
    Log("INFO", "Accepted S1AP Paging PDU (" + std::to_string(size) + " bytes): " + ToHex(data, size));
    if (!servesPagingTai(page.taiList))
    {
        ++m_paging.filteredByTac;
        Log("INFO", "Ignoring S1AP Paging: its TAI list does not include the served tracking area " +
                        m_config.plmn.toString() + "/TAC=" + std::to_string(m_config.tac));
        return;
    }

    // A real eNB broadcasts the page over its cell. This software radio link
    // has no broadcast medium and the eNB holds no UE NAS identity, so the
    // notification is delivered to the bounded set of retained idle radio
    // endpoints and each UE matches its own S-TMSI. Active contexts are not
    // touched: an ECM-CONNECTED UE simply has no page to answer.
    size_t notified = 0;
    size_t idle = 0;
    for (auto *entry : m_registry.all())
    {
        if (entry->s1 != UeS1State::IDLE_RETAINED)
            continue;
        ++idle;
        if (idle > static_cast<size_t>(m_config.maxUes))
            break;
        const std::vector<uint8_t> payload = lte::ue::link::EncodePagingNotification(
            {page.sTmsi.mmeCode, page.sTmsi.mTmsi, m_config.tac});
        auto frame =
            lte::ue::link::Encode({lte::ue::link::MessageType::PAGING_INDICATION, entry->radioUeId, payload});
        if (m_ueLink.TrySend(entry->peer, frame.data(), frame.size()))
        {
            ++notified;
            ++entry->pagingNotifications;
            ++m_paging.notificationsDelivered;
        }
        else
        {
            ++m_paging.notificationFailures;
            Log("WARN", "Simulated paging notification to LTE UE " + std::to_string(entry->radioUeId) +
                            " would block and was dropped");
        }
    }

    std::ostringstream stream2;
    stream2 << "S1AP Paging: MMEC=0x" << std::uppercase << std::hex << std::setfill('0') << std::setw(2)
            << static_cast<int>(page.sTmsi.mmeCode) << " M-TMSI=0x" << std::setw(8) << page.sTmsi.mTmsi
            << std::dec << " TAI=" << m_config.plmn.toString() << "/TAC=" << page.taiList.front().tac
            << " CN=ps-domain UE-identity-index=" << page.ueIdentityIndexValue << "; notified " << notified
            << " of " << idle << " retained idle UE(s)";
    Log("INFO", stream2.str());
}

bool EnbMultiplexer::servesPagingTai(const std::vector<s1ap::Tai> &taiList) const
{
    for (const auto &tai : taiList)
    {
        if (tai.tac == m_config.tac && tai.plmn.mcc == m_config.plmn.mcc && tai.plmn.mnc == m_config.plmn.mnc)
            return true;
    }
    return false;
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

void EnbMultiplexer::onErabSetupRequest(const uint8_t *data, size_t size)
{
    auto request = s1ap::DecodeErabSetupRequest(data, size);
    auto *entry = m_registry.findByEnbUeS1apId(request.enbUeS1apId);
    if (entry == nullptr)
        throw s1ap::CodecError("E-RAB Setup Request references an unknown or released eNB-UE-S1AP-ID");
    if (entry->mmeUeS1apId != request.mmeUeS1apId)
        throw s1ap::CodecError("E-RAB Setup Request does not match the UE context identity pair");
    if (!entry->s1Active())
        throw s1ap::CodecError("E-RAB Setup Request does not match an active S1 UE context");
    if (!entry->bearer.signalingEstablished())
        throw BearerError("A dedicated E-RAB requires an established default bearer");

    std::vector<s1ap::ErabSetupItem> established;
    std::vector<s1ap::ErabFailedItem> failed;

    for (const auto &erab : request.erabs)
    {
        try
        {
            BearerParameters parameters{};
            parameters.erabId = erab.erabId;
            parameters.qci = erab.qci;
            parameters.ueId = entry->radioUeId;
            parameters.sgwAddress = erab.transportLayerAddress;
            parameters.sgwTeid = TeidFromBytes(erab.gtpTeid);
            parameters.localTeid = m_registry.allocateLocalTeid();
            // A dedicated bearer always belongs to the PDN of this UE's default
            // bearer; the network does not send the link and must not be guessed.
            parameters.linkedDefaultEbi = entry->bearer.parameters().erabId;

            auto &bearer = m_registry.addDedicatedBearer(*entry, parameters);
            m_registry.bindLocalTeid(*entry, bearer, parameters.localTeid);

            established.push_back(
                {erab.erabId, ParseIpv4(m_config.s1uAddress), TeidToBytes(parameters.localTeid)});
            Log("INFO", "Established dedicated E-RAB " + std::to_string(erab.erabId) + " for " + Describe(*entry) +
                            ": QCI=" + std::to_string(erab.qci) + " eNB-TEID=" + Hex(parameters.localTeid, 8) +
                            " SGW-TEID=" + Hex(parameters.sgwTeid, 8) +
                            " linked-EBI=" + std::to_string(parameters.linkedDefaultEbi));

            // The protected NAS activation request travels to the UE unchanged.
            // The eNB holds no NAS keys and must not interpret it.
            if (erab.nasPduPresent)
                sendRadio(*entry, lte::ue::link::MessageType::NAS_DOWNLINK, erab.nasPdu);
        }
        catch (const std::exception &e)
        {
            failed.push_back({erab.erabId, "radioNetwork", 0});
            Log("WARN", "Failed to establish dedicated E-RAB " + std::to_string(erab.erabId) + ": " + e.what());
        }
    }

    if (established.empty())
        throw BearerError("No requested dedicated E-RAB could be established");

    auto response = s1ap::EncodeErabSetupResponse(request.mmeUeS1apId, request.enbUeS1apId, established, failed);
    m_sender.sendS1ap(streamFor(*entry), response);
}

void EnbMultiplexer::onErabReleaseCommand(const uint8_t *data, size_t size)
{
    auto command = s1ap::DecodeErabReleaseCommand(data, size);
    auto *entry = m_registry.findByEnbUeS1apId(command.enbUeS1apId);
    if (entry == nullptr)
        throw s1ap::CodecError("E-RAB Release Command references an unknown or released eNB-UE-S1AP-ID");
    if (entry->mmeUeS1apId != command.mmeUeS1apId)
        throw s1ap::CodecError("E-RAB Release Command does not match the UE context identity pair");

    for (auto erabId : command.erabIds)
    {
        // Releasing the default bearer is a PDN teardown, not an E-RAB release;
        // treating it as one would leave the UE registered with no user plane.
        if (entry->bearer.parameters().erabId == erabId)
            throw BearerError("The default bearer cannot be released by an E-RAB Release Command");
        m_registry.releaseBearer(*entry, erabId);
        Log("INFO", "Released dedicated E-RAB " + std::to_string(erabId) + " for " + Describe(*entry));
    }

    if (command.nasPduPresent)
    {
        // The network deactivates the bearer through NAS. Forwarding the
        // protected message lets the UE apply its own ESM state machine and
        // answer with the matching deactivate accept.
        sendRadio(*entry, lte::ue::link::MessageType::NAS_DOWNLINK, command.nasPdu);
    }
    else
    {
        for (auto erabId : command.erabIds)
            sendRadio(*entry, lte::ue::link::MessageType::BEARER_RELEASED, {erabId});
    }

    auto response = s1ap::EncodeErabReleaseResponse(command.mmeUeS1apId, command.enbUeS1apId, command.erabIds);
    m_sender.sendS1ap(streamFor(*entry), response);
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
        else if (radio.type == lte::ue::link::MessageType::DATA_UPLINK_BEARER)
        {
            if (radio.payload.size() < 2)
                throw lte::ue::link::DecodeError("Malformed bearer-aware uplink frame");
            BearerContext *bearer = m_registry.findBearer(*entry, radio.payload[0]);
            if (bearer == nullptr || bearer->kind() != BearerKind::DEDICATED)
                throw lte::ue::link::DecodeError("Uplink names an unknown or released dedicated bearer");
            m_s1u.forwardUplink(*entry, *bearer, radio.payload.data() + 1, radio.payload.size() - 1);
        }
        else if (radio.type == lte::ue::link::MessageType::BEARER_ACTIVATED)
        {
            if (radio.payload.size() != 1)
                throw lte::ue::link::DecodeError("Malformed bearer activation confirmation");
            BearerContext *bearer = m_registry.findBearer(*entry, radio.payload[0]);
            if (bearer == nullptr || bearer->kind() != BearerKind::DEDICATED)
                throw lte::ue::link::DecodeError("Activation names an unknown dedicated bearer");
            // The UE shares the PDN address of its default bearer, so a
            // dedicated bearer becomes forwardable only after this confirmation.
            bearer->activateUe(entry->radioUeId, radio.payload[0], entry->bearer.ueIpv4());
            Log("INFO", "Dedicated EPS bearer " + std::to_string(radio.payload[0]) +
                            " ready for forwarding on LTE UE " + std::to_string(entry->radioUeId));
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

const PagingCounters &EnbMultiplexer::pagingCounters() const
{
    return m_paging;
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
    Log("INFO", "S1AP Paging statistics: received=" + std::to_string(m_paging.received) +
                    " valid=" + std::to_string(m_paging.valid) + " invalid=" + std::to_string(m_paging.invalid) +
                    " cs-domain=" + std::to_string(m_paging.csDomainIgnored) +
                    " imsi-unsupported=" + std::to_string(m_paging.unsupportedIdentity) +
                    " tac-filtered=" + std::to_string(m_paging.filteredByTac) +
                    " notified=" + std::to_string(m_paging.notificationsDelivered) +
                    " notify-failures=" + std::to_string(m_paging.notificationFailures));
}

} // namespace lte::enb
