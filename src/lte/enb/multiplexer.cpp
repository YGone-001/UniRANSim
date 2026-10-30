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
#include <set>
#include <algorithm>
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

std::string Describe(const EnbUeEntry &entry)
{
    std::ostringstream stream;
    stream << "LTE UE " << entry.radioUeId << " (eNB-UE-S1AP-ID=" << entry.enbUeS1apId
           << ", MME-UE-S1AP-ID=" << entry.mmeUeS1apId << ", " << ToString(entry.s1) << ")";
    return stream.str();
}

} // namespace

EnbMultiplexer::EnbMultiplexer(const EnbConfig &config, IS1apSender &sender)
    : m_config(config), m_ueLink(config.ueLinkAddress, config.ueLinkPort),
      m_registry(static_cast<size_t>(config.maxUes)), m_s1u(config.s1uAddress, config.s1uPort, config.allowLoopbackS1u,
                                                           m_registry, m_ueLink)
{
    bindAssociation(sender, 1);
}

EnbMultiplexer::EnbMultiplexer(const EnbConfig &config)
    : m_config(config), m_ueLink(config.ueLinkAddress, config.ueLinkPort),
      m_registry(static_cast<size_t>(config.maxUes)), m_s1u(config.s1uAddress, config.s1uPort, config.allowLoopbackS1u,
                                                           m_registry, m_ueLink)
{
}

void S1apSenderBinding::bind(IS1apSender &sender, uint32_t epoch)
{
    if (epoch == 0)
        throw std::runtime_error("An association epoch must be non-zero");
    m_sender = &sender;
    m_epoch = epoch;
}

void S1apSenderBinding::unbind(uint32_t epoch)
{
    if (m_sender == nullptr || m_epoch != epoch)
        return;
    m_sender = nullptr;
}

bool S1apSenderBinding::send(uint32_t epoch, uint16_t stream, const std::vector<uint8_t> &pdu)
{
    if (m_sender == nullptr)
    {
        ++m_unboundRejects;
        return false;
    }
    if (m_epoch != epoch)
    {
        ++m_staleRejects;
        return false;
    }
    m_sender->sendS1ap(stream, pdu);
    return true;
}

uint32_t EnbMultiplexer::bindAssociation(IS1apSender &sender, int outboundStreams)
{
    if (m_sender.bound())
        throw std::runtime_error("An SCTP association is already bound");
    // Wraparound is handled explicitly: zero is never a valid epoch, so a
    // counter that rolls over skips it instead of colliding with "unbound".
    if (++m_nextAssociationEpoch == 0)
        ++m_nextAssociationEpoch;
    m_associationEpoch = m_nextAssociationEpoch;
    m_sender.bind(sender, m_associationEpoch);
    setOutboundStreams(outboundStreams);
    m_injectionTriggered = false;
    ++m_recovery.associationsEstablished;
    return m_associationEpoch;
}

void EnbMultiplexer::unbindAssociation()
{
    if (m_associationEpoch != 0)
        m_sender.unbind(m_associationEpoch);
    m_associationEpoch = 0;
}

bool EnbMultiplexer::associationBound() const
{
    return m_sender.bound();
}

uint32_t EnbMultiplexer::associationEpoch() const
{
    return m_associationEpoch;
}

uint32_t EnbMultiplexer::nextAssociationEpoch() const
{
    uint32_t next = m_nextAssociationEpoch + 1U;
    return next == 0 ? 1U : next;
}

bool EnbMultiplexer::sendS1ap(uint16_t stream, const std::vector<uint8_t> &pdu)
{
    if (m_injectionArmed)
    {
        // One-shot deterministic interruption: the PDU is dropped and the
        // caller tears the association down instead of transmitting.
        m_injectionArmed = false;
        m_injectionTriggered = true;
        // The interruption has now actually happened, so it is counted once as
        // an injected loss and the association-loss event it causes is not
        // counted a second time as unexpected.
        noteInjectedAssociationLoss();
        return false;
    }
    const bool sent = m_sender.send(m_associationEpoch, stream, pdu);
    if (!sent)
    {
        if (m_sender.bound())
            ++m_recovery.staleSenderRejects;
        else
            ++m_recovery.unboundSenderRejects;
    }
    return sent;
}

void EnbMultiplexer::armLossBeforeNextS1apSend()
{
    m_injectionArmed = true;
}

bool EnbMultiplexer::injectionTriggered() const
{
    return m_injectionTriggered;
}

bool EnbMultiplexer::injectionArmed() const
{
    return m_injectionArmed;
}

void EnbMultiplexer::clearInjection()
{
    m_injectionArmed = false;
    m_injectionTriggered = false;
}

void EnbMultiplexer::noteInjectedAssociationLoss()
{
    ++m_recovery.injectedAssociationLosses;
    m_injectedLossPending = true;
}

bool EnbMultiplexer::takeInjectedAssociationLoss()
{
    const bool injected = m_injectedLossPending;
    m_injectedLossPending = false;
    return injected;
}

void EnbMultiplexer::classifyAssociationLoss(bool stopping, bool established)
{
    // The mark is consumed on every teardown, including one that counts
    // nothing, so a mark left by a consumed command can never be applied to a
    // later and unrelated failure.
    const bool injected = takeInjectedAssociationLoss();
    if (!established || stopping || injected)
        return;
    ++m_recovery.unexpectedAssociationLosses;
}

size_t EnbMultiplexer::invalidateAccess()
{
    // An unexpected association loss is not a 3GPP UE Context Release
    // procedure. No S1AP message is fabricated here; the simulated UEs are
    // told only through the internal S1_ACCESS_LOST software-radio indication,
    // which is explicitly not a NAS or RRC message.
    //
    // Detaching the sender first guarantees that nothing generated during this
    // cleanup can still reach the failed association, and that a later
    // reconnection binds a brand-new epoch instead of reviving this one.
    unbindAssociation();
    m_accessInvalidatedAt = std::chrono::steady_clock::now();
    ++m_recovery.accessInvalidations;

    size_t affected = 0;
    for (auto *entry : m_registry.all())
    {
        if (!entry->s1Active())
            continue;
        // A context that never reached bearer-active was mid-procedure: the
        // association died before it could be completed, so the attempt failed.
        if (entry->s1 == UeS1State::CONTEXT_PENDING)
            ++m_recovery.failedUeRestorations;
        const uint8_t defaultEbi = entry->bearer.parameters().erabId;
        const size_t bearers = (entry->bearer.logicalExists() ? 1U : 0U) + entry->dedicatedBearers.size();
        ++affected;
        ++m_recovery.activeUesAffectedByLoss;
        m_recovery.logicalBearersRetained += bearers;
        for (const auto &bearer : entry->dedicatedBearers)
            if (bearer.parameters().localTeid != 0)
                ++m_recovery.localTeidsInvalidated;
        if (entry->bearer.parameters().localTeid != 0)
            ++m_recovery.localTeidsInvalidated;

        m_registry.releaseS1(*entry);
        try
        {
            // Generation-bound: the payload carries the new access generation,
            // so a late or duplicated notification is rejected by the UE.
            sendRadio(*entry, lte::ue::link::MessageType::S1_ACCESS_LOST,
                      lte::ue::link::EncodeBearerRestoration(defaultEbi, entry->accessGeneration));
        }
        catch (const std::exception &e)
        {
            // One unreachable simulated radio peer must not block the cleanup
            // of the other UEs.
            Log("WARN", std::string("Access-loss notification failed for LTE UE ") +
                            std::to_string(entry->radioUeId) + ": " + e.what());
        }
    }
    return affected;
}

uint64_t EnbMultiplexer::restorationLatencyMs() const
{
    return m_restorationLatencyMs;
}

const RecoveryCounters &EnbMultiplexer::recoveryCounters() const
{
    return m_recovery;
}

RecoveryCounters &EnbMultiplexer::recoveryCounters()
{
    return m_recovery;
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
        else if (pdu.kind == s1ap::S1apPdu::Kind::INITIATING && pdu.procedureCode == 6)
            onErabModifyRequest(data, size);
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
        ++m_recovery.staleMessagesRejected;
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
    catch (const std::exception &)
    {
        // A malformed Paging PDU can carry a permanent subscriber identity in
        // its APER octets, and neither those octets nor an unchecked decoder
        // message derived from them may reach an ordinary log. Only the fact of
        // the rejection, its length and a fixed category are recorded here, and
        // the exception handed on to the shared S1AP dispatcher is a fixed
        // allowlisted reason rather than the decoder's message, so the
        // dispatcher's own rejection line cannot echo untrusted input either.
        ++m_paging.invalid;
        Log("WARN", "Rejected S1AP Paging PDU (" + std::to_string(size) +
                        " bytes): category=aper-decode; raw payload withheld");
        throw s1ap::CodecError("S1AP Paging PDU rejected during APER decode");
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
    // Only the decoded identity is recorded, never the raw APER octets: an
    // ignore-criticality information element that this decoder does not inspect
    // could still carry a permanent subscriber identity in its bytes.
    if (!servesPagingTai(page.taiList))
    {
        ++m_paging.filteredByTac;
        std::ostringstream filtered;
        filtered << "Ignoring S1AP Paging for M-TMSI=0x" << std::uppercase << std::hex << std::setfill('0')
                 << std::setw(8) << page.sTmsi.mTmsi << std::dec
                 << ": its TAI list does not include the served tracking area " << m_config.plmn.toString()
                 << "/TAC=" << m_config.tac;
        Log("INFO", filtered.str());
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
        // One unusable radio endpoint must never cost the other idle UEs their
        // page, so a send that fails or cannot even be attempted is confined to
        // this entry and the fanout continues.
        bool delivered = false;
        try
        {
            delivered = m_ueLink.TrySend(entry->peer, frame.data(), frame.size());
        }
        catch (const std::exception &)
        {
            delivered = false;
        }
        if (delivered)
        {
            ++notified;
            ++entry->pagingNotifications;
            ++m_paging.notificationsDelivered;
        }
        else
        {
            ++m_paging.notificationFailures;
            Log("WARN", "Simulated paging notification to LTE UE " + std::to_string(entry->radioUeId) +
                            " was dropped; the remaining retained idle UEs are still notified");
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
    // Decode and ownership checks precede any assignment or TEID indexing.
    auto fail = [&](const std::string &category, int value) {
        sendS1ap(streamFor(*entry), s1ap::EncodeInitialContextSetupFailure(
            request.mmeUeS1apId, request.enbUeS1apId, category, value));
    };
    std::set<uint8_t> seen;
    for (const auto &item : request.erabs)
        if (!seen.insert(item.erabId).second)
        {
            fail("radioNetwork", 31); // multiple-E-RAB-ID-instances
            return;
        }
    const bool restoring = entry->bearer.logicalExists();
    const bool declared = entry->declaredBearers.has_value();
    // A Service Request is a resume: the bearers it restores are ones the UE's
    // own NAS has already confirmed and only their transport is new. On a cell
    // the UE reached by Tracking Area Update this eNB holds none of them,
    // because the Update established no bearer here, and ECM-IDLE has since
    // dropped the access transport and with it the declaration. The MME is the
    // one still holding the bearers, so nothing but this says the session being
    // set up is that session and not a new one.
    const bool resuming = entry->sessionRetained;
    // Whether the transport being set up is a restoration the UE confirms
    // rather than a new bearer it accepts. Which E-RAB plays which role is
    // still decided by `restoring` and `declared` alone: a resumed session this
    // cell holds nothing of and that named no inventory leaves those roles
    // unknowable, and they are not guessed off the network's list.
    const bool restoringTransport = restoring || declared || resuming;
    // A mobility uplink onto a cell that has never seen this session's Attach
    // has to say which E-RAB is which. Without that the E-RAB list of an
    // Initial Context Setup Request names only identifiers and QoS and marks no
    // roles, so on such a target the roles could only be guessed from QCI or
    // from the order of that list. Nothing is set up rather than guessed.
    if (entry->mobilityBootstrap && !restoring && !declared)
    {
        fail("radioNetwork", 25);
        return;
    }
    // A declaration that contradicts the logical bearer contexts this eNB still
    // holds is not a description of this session, and neither side of the
    // contradiction is believed.
    if (declared && restoring && entry->declaredBearers->defaultEbi != entry->bearer.parameters().erabId)
    {
        fail("radioNetwork", 25);
        return;
    }
    // Initial Attach has one provisional default candidate; BEARER_READY must
    // confirm its identity against the UE's validated NAS. No NAS is decrypted
    // here. Multiple unknown roles cannot be inferred from order or QCI.
    if ((!restoring && !declared && request.erabs.size() != 1) || entry->bearer.signalingEstablished() ||
        (restoring && !entry->bearer.logicalConfirmed()))
    {
        fail("radioNetwork", 29);
        return;
    }
    auto candidate = *entry;
    // Which E-RAB plays which role is decided before any of them is touched,
    // and it is never decided by the order of the network's list: a dedicated
    // bearer is defined on top of its default bearer, so the default is
    // established first whatever order the MME listed its E-RABs in. Each
    // outcome is recorded against the requested item, so the response still
    // reports the E-RABs in the order the MME sent them.
    const uint8_t defaultEbi = declared ? entry->declaredBearers->defaultEbi
                              : restoring ? entry->bearer.parameters().erabId
                                          : request.erabs.front().erabId;
    std::vector<size_t> order;
    order.reserve(request.erabs.size());
    for (size_t index = 0; index < request.erabs.size(); ++index)
        if (request.erabs[index].erabId == defaultEbi)
            order.push_back(index);
    for (size_t index = 0; index < request.erabs.size(); ++index)
        if (request.erabs[index].erabId != defaultEbi)
            order.push_back(index);
    std::vector<std::optional<s1ap::ErabSetupItem>> establishedAt(request.erabs.size());
    std::vector<std::optional<s1ap::ErabFailedItem>> failedAt(request.erabs.size());
    std::vector<s1ap::ErabSetupItem> established;
    std::vector<s1ap::ErabFailedItem> failed;
    established.reserve(8);
    failed.reserve(request.erabs.size());
    size_t establishedCount = 0;
    bool defaultEstablished = false;
    bool nonGbrEstablished = false;
    for (const size_t index : order)
    {
        const auto &erab = request.erabs[index];
        const ErabQos qos{erab.qci, erab.priorityLevel, erab.preemptionCapability,
                          erab.preemptionVulnerability, erab.gbr};
        auto *bearer = m_registry.findBearer(candidate, erab.erabId);
        // A declaration names the roles where one exists, the retained contexts
        // name them where this eNB already holds them, and an Initial Attach has
        // exactly one candidate, which is the default bearer of the new session
        // and is confirmed later against the UE's validated NAS.
        bool dedicatedRole = false;
        if (declared)
        {
            const auto &inventory = *entry->declaredBearers;
            if (erab.erabId == inventory.defaultEbi)
                dedicatedRole = false;
            else if (std::find(inventory.dedicatedEbis.begin(), inventory.dedicatedEbis.end(), erab.erabId) !=
                     inventory.dedicatedEbis.end())
                dedicatedRole = true;
            else
            {
                // The network offered a bearer this UE never confirmed. Neither
                // the offer nor the claim can make it true on its own, so it is
                // not established for this UE.
                failedAt[index] = s1ap::ErabFailedItem{erab.erabId, "radioNetwork", 30};
                continue;
            }
        }
        else if (restoring)
            dedicatedRole = bearer != nullptr && bearer->kind() == BearerKind::DEDICATED;
        if (erab.erabId < 5 || erab.erabId > 15 || (restoring && bearer == nullptr))
        {
            failedAt[index] = s1ap::ErabFailedItem{erab.erabId, "radioNetwork", 30};
            continue;
        }
        if (establishedCount >= 8)
        {
            failedAt[index] = s1ap::ErabFailedItem{erab.erabId, "radioNetwork", 25};
            continue;
        }
        if (!qos.valid() || (erab.erabId == defaultEbi && erab.qci <= 4))
        {
            failedAt[index] = s1ap::ErabFailedItem{erab.erabId, "radioNetwork", 27};
            continue;
        }
        if (!erab.ipv4Transport || erab.transportLayerAddress[0] == 0 ||
            erab.transportLayerAddress[0] >= 224 || TeidFromBytes(erab.gtpTeid) == 0)
        {
            failedAt[index] = s1ap::ErabFailedItem{erab.erabId, "transport", 0};
            continue;
        }
        if (bearer == nullptr && !dedicatedRole)
            bearer = &candidate.bearer;
        if (bearer != nullptr &&
            (bearer->signalingEstablished() || (restoring && !bearer->logicalConfirmed()) ||
             (bearer->kind() == BearerKind::DEDICATED && bearer->parameters().linkedDefaultEbi != defaultEbi)))
        {
            failedAt[index] = s1ap::ErabFailedItem{erab.erabId, "radioNetwork", 29};
            continue;
        }
        try
        {
            const uint32_t localTeid = m_registry.allocateLocalTeid();
            const uint8_t linkedDefault = static_cast<uint8_t>(erab.erabId == defaultEbi ? 0 : defaultEbi);
            if (bearer == nullptr)
                // A dedicated E-RAB of a fresh-target mobility bootstrap: the UE
                // declared it, so it is established on top of the default bearer
                // established first above and marked as a restoration of a
                // bearer its NAS already confirmed.
                m_registry.addDedicatedBearer(candidate,
                    {erab.erabId, erab.qci, entry->radioUeId, erab.transportLayerAddress,
                     TeidFromBytes(erab.gtpTeid), localTeid, linkedDefault, qos}, true);
            else
                bearer->establish({erab.erabId, erab.qci, entry->radioUeId, erab.transportLayerAddress,
                                   TeidFromBytes(erab.gtpTeid), localTeid, linkedDefault, qos},
                                  restoringTransport);
            establishedAt[index] = s1ap::ErabSetupItem{erab.erabId, ParseIpv4(m_config.s1uAddress),
                                                       TeidToBytes(localTeid)};
            ++establishedCount;
            defaultEstablished |= erab.erabId == defaultEbi;
            nonGbrEstablished |= erab.qci > 4;
        }
        catch (const std::exception &)
        {
            // Candidate is private; an unsuccessful item never becomes indexed.
            failedAt[index] = s1ap::ErabFailedItem{erab.erabId, "radioNetwork", 25};
        }
    }
    for (const auto &slot : establishedAt)
        if (slot.has_value())
            established.push_back(*slot);
    for (const auto &slot : failedAt)
        if (slot.has_value())
            failed.push_back(*slot);
    if (!defaultEstablished || !nonGbrEstablished)
    {
        fail("radioNetwork", 25);
        return;
    }
    // Complete the wire outcome before publishing transport. A failed encode
    // or index allocation leaves all original logical bearers untouched.
    const auto response = s1ap::EncodeInitialContextSetupResponse(
        request.mmeUeS1apId, request.enbUeS1apId, established, failed);
    candidate.ueAmbr = UeAmbr{request.ueAmbrDl, request.ueAmbrUl};
    candidate.s1 = UeS1State::CONTEXT_ESTABLISHED;
    candidate.sgwPeer = InetAddress(Ipv4ToString(candidate.bearer.parameters().sgwAddress), 2152);
    const uint32_t previousMmeId = entry->mmeUeS1apId;
    try
    {
        for (const auto &item : established)
        {
            auto *bearer = m_registry.findBearer(candidate, item.erabId);
            m_registry.bindLocalTeid(*entry, *bearer, bearer->parameters().localTeid);
        }
        m_registry.setMmeUeS1apId(*entry, request.mmeUeS1apId);
        if (!sendS1ap(streamFor(*entry), response))
            // The association died, or a test injection interrupted it, before
            // the outcome could leave the eNB. Nothing is published: the catch
            // below rolls back every allocated TEID so no half-committed bearer
            // can ever become forwardable.
            throw BearerError("Initial Context Setup Response could not be transmitted; context rolled back");
        candidate.mmeUeS1apId = request.mmeUeS1apId;
        *entry = std::move(candidate);
    }
    catch (...)
    {
        for (const auto &item : established)
            m_registry.unbindLocalTeid(*entry, TeidFromBytes(item.gtpTeid));
        if (previousMmeId == 0)
            m_registry.clearMmeUeS1apId(*entry);
        throw;
    }
    // Always notify default first, regardless of the MME's E-RAB list order.
    // A fresh-target mobility bootstrap needs the same notification as a
    // restoration on a cell that already held the contexts: in both cases the
    // bearers are ones this UE's NAS has already confirmed, and the fresh
    // transport of the target cell is what it is being told to confirm.
    if (restoringTransport)
        sendRadio(*entry, lte::ue::link::MessageType::S1_CONTEXT_RESTORED,
                  lte::ue::link::EncodeBearerRestoration(defaultEbi, entry->accessGeneration));
    for (const auto &item : established)
    {
        const auto *bearer = m_registry.findBearer(*entry, item.erabId);
        Log("INFO", "Initial Context Setup EBI=" + std::to_string(item.erabId) +
            " QCI=" + std::to_string(bearer->parameters().qci) +
            " eNB-TEID=" + Hex(bearer->parameters().localTeid, 8) +
            " SGW-TEID=" + Hex(bearer->parameters().sgwTeid, 8));
        if (restoringTransport && item.erabId != defaultEbi)
            sendRadio(*entry, lte::ue::link::MessageType::DEDICATED_BEARER_RESTORED,
                      lte::ue::link::EncodeBearerRestoration(item.erabId, entry->accessGeneration));
        const auto &requested = *std::find_if(request.erabs.begin(), request.erabs.end(),
            [&](const auto &r) { return r.erabId == item.erabId; });
        if (requested.nasPduPresent)
            sendRadio(*entry, lte::ue::link::MessageType::NAS_DOWNLINK, requested.nasPdu);
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

    auto candidate = *entry;
    std::vector<s1ap::ErabSetupItem> established;
    std::vector<s1ap::ErabFailedItem> failed;
    std::array<bool, 16> retained{};
    established.reserve(EnbUeEntry::MaxDedicatedBearers);
    failed.reserve(request.erabs.size());
    for (const auto &erab : request.erabs)
    {
        const ErabQos qos{erab.qci, erab.priorityLevel, erab.preemptionCapability,
                          erab.preemptionVulnerability, erab.gbr};
        auto *previous = m_registry.findBearer(candidate, erab.erabId);
        if (previous && previous->signalingEstablished())
        {
            failed.push_back({erab.erabId, "radioNetwork", 31});
            continue;
        }
        if (!qos.valid())
        {
            failed.push_back({erab.erabId, "radioNetwork", 27});
            continue;
        }
        if (erab.transportLayerAddress[0] == 0 || erab.transportLayerAddress[0] >= 224 ||
            TeidFromBytes(erab.gtpTeid) == 0 || erab.nasPdu.empty())
        {
            failed.push_back({erab.erabId, "transport", 0});
            continue;
        }
        try
        {
            // A dedicated bearer this eNB retained is re-established, and so is
            // one the UE declared with a mobility uplink onto a cell that never
            // saw its Attach: both are EPS bearers its NAS already confirmed,
            // so the fresh transport is restored and generation-bound rather
            // than announced as a brand-new bearer. An E-RAB the UE never
            // confirmed is none of those and stays an ordinary new bearer.
            const auto &declared = entry->declaredBearers;
            const bool restore = previous != nullptr ||
                                 (declared.has_value() &&
                                  std::find(declared->dedicatedEbis.begin(), declared->dedicatedEbis.end(),
                                            erab.erabId) != declared->dedicatedEbis.end());
            const uint32_t localTeid = m_registry.allocateLocalTeid();
            m_registry.addDedicatedBearer(candidate,
                {erab.erabId, erab.qci, entry->radioUeId, erab.transportLayerAddress,
                 TeidFromBytes(erab.gtpTeid), localTeid, entry->bearer.parameters().erabId, qos}, restore);
            established.push_back({erab.erabId, ParseIpv4(m_config.s1uAddress), TeidToBytes(localTeid)});
            if (restore)
                retained[erab.erabId] = true;
        }
        catch (const std::exception &e)
        {
            failed.push_back({erab.erabId, "radioNetwork", 25});
            Log("WARN", "Failed dedicated E-RAB " + std::to_string(erab.erabId) + ": " + e.what());
        }
    }
    const auto response = s1ap::EncodeErabSetupResponse(request.mmeUeS1apId, request.enbUeS1apId, established, failed);
    try
    {
        for (const auto &item : established)
        {
            auto *bearer = m_registry.findBearer(candidate, item.erabId);
            m_registry.bindLocalTeid(*entry, *bearer, bearer->parameters().localTeid);
        }
        if (!sendS1ap(streamFor(*entry), response))
            // Same rule as Initial Context Setup: an outcome that never left the
            // eNB is not an outcome, so the half-created dedicated bearers are
            // rolled back and never become ready.
            throw BearerError("E-RAB Setup Response could not be transmitted; context rolled back");
        *entry = std::move(candidate);
    }
    catch (...)
    {
        for (const auto &item : established)
            m_registry.unbindLocalTeid(*entry, TeidFromBytes(item.gtpTeid));
        throw;
    }
    for (const auto &item : established)
    {
        const auto &erab = *std::find_if(request.erabs.begin(), request.erabs.end(),
            [&](const auto &r) { return r.erabId == item.erabId; });
        // Committed transport only. A candidate that failed, or whose response
        // never left the eNB, was rolled back above and never reaches this line,
        // so the recorded TEIDs are the ones actually in force. This is the
        // standalone counterpart of the Initial Context Setup line and gives a
        // later fresh-TEID restoration an explicit baseline to compare against.
        const auto *bearer = m_registry.findBearer(*entry, item.erabId);
        Log("INFO", "Dedicated E-RAB Setup EBI=" + std::to_string(item.erabId) +
                        " QCI=" + std::to_string(bearer->parameters().qci) +
                        " eNB-TEID=" + Hex(bearer->parameters().localTeid, 8) +
                        " SGW-TEID=" + Hex(bearer->parameters().sgwTeid, 8));
        sendRadio(*entry, lte::ue::link::MessageType::NAS_DOWNLINK, erab.nasPdu);
        if (retained[erab.erabId])
            sendRadio(*entry, lte::ue::link::MessageType::DEDICATED_BEARER_RESTORED,
                lte::ue::link::EncodeBearerRestoration(erab.erabId, entry->accessGeneration));
    }
}

void EnbMultiplexer::onErabModifyRequest(const uint8_t *data, size_t size)
{
    const auto request = s1ap::DecodeErabModifyRequest(data, size);
    auto *entry = m_registry.findByEnbUeS1apId(request.enbUeS1apId);
    if (!entry || !entry->s1Active() || entry->mmeUeS1apId != request.mmeUeS1apId)
        throw s1ap::CodecError("E-RAB Modify has an unknown/stale S1AP identity pair");
    std::vector<uint8_t> modified;
    std::vector<s1ap::ErabFailedItem> failed;
    // Every item is validated into a candidate first and published only after
    // the Modify Response has actually left the eNB. An association loss in the
    // middle of the procedure therefore cannot leave a partially applied
    // NAS/QoS/transport transition behind.
    struct PendingModification
    {
        BearerContext *target;
        BearerContext candidate;
        const s1ap::ErabToBeModifiedItem *item;
    };
    std::vector<PendingModification> pending;
    for (const auto &item : request.erabs)
    {
        auto *bearer = m_registry.findBearer(*entry, item.erabId);
        if (!bearer || !bearer->signalingEstablished())
        {
            failed.push_back({item.erabId, "radioNetwork", 30}); // unknown-E-RAB-ID
            continue;
        }
        auto candidate = *bearer;
        try
        {
            if (item.transport)
            {
                if (!item.transport->ipv4)
                    throw BearerError("Only IPv4 S1-U transport replacement is supported");
                candidate.modifyTransport(item.transport->address, item.transport->teid);
            }
            else
            {
                candidate.modifyQos(item.qos);
                if (item.nasPdu.empty())
                    throw BearerError("Ordinary E-RAB Modify requires a NAS-PDU");
            }
        }
        catch (const BearerError &e)
        {
            failed.push_back({item.erabId, item.transport ? "transport" : "radioNetwork", item.transport ? 0 : 27});
            Log("WARN", "E-RAB Modify failed EBI=" + std::to_string(item.erabId) + ": " + e.what());
            continue;
        }
        pending.push_back({bearer, std::move(candidate), &item});
        modified.push_back(item.erabId);
    }
    if (!sendS1ap(streamFor(*entry),
                  s1ap::EncodeErabModifyResponse(request.mmeUeS1apId, request.enbUeS1apId, modified, failed)))
        throw BearerError("E-RAB Modify Response could not be transmitted; no bearer state was published");
    for (auto &entry2 : pending)
    {
        // The event loop cannot classify a packet between these operations.
        // NAS delivery is independent of the later UE Accept/Reject.
        if (!entry2.item->transport)
            sendRadio(*entry, lte::ue::link::MessageType::NAS_DOWNLINK, entry2.item->nasPdu);
        *entry2.target = std::move(entry2.candidate);
        Log("INFO", "E-RAB Modify applied EBI=" + std::to_string(entry2.item->erabId) + " QCI=" +
                        std::to_string(entry2.target->parameters().qci) +
                        " SGW-TEID=" + Hex(entry2.target->parameters().sgwTeid, 8) +
                        " eNB-TEID=" + Hex(entry2.target->parameters().localTeid, 8) +
                        (entry2.item->transport ? " transport replacement (QoS/NAS ignored)" : " QoS metadata; NAS relayed"));
    }
    if (request.ueAmbr && !modified.empty())
        entry->ueAmbr = request.ueAmbr;
}

void EnbMultiplexer::onErabReleaseCommand(const uint8_t *data, size_t size)
{
    auto command = s1ap::DecodeErabReleaseCommand(data, size);
    auto *entry = m_registry.findByEnbUeS1apId(command.enbUeS1apId);
    if (entry == nullptr)
        throw s1ap::CodecError("E-RAB Release Command references an unknown or released eNB-UE-S1AP-ID");
    if (entry->mmeUeS1apId != command.mmeUeS1apId)
        throw s1ap::CodecError("E-RAB Release Command does not match the UE context identity pair");

    // Validate the whole list before releasing anything, so a rejected item
    // cannot leave a half-applied release behind when the association drops.
    for (auto erabId : command.erabIds)
    {
        // Releasing the default bearer is a PDN teardown, not an E-RAB release;
        // treating it as one would leave the UE registered with no user plane.
        if (entry->bearer.parameters().erabId == erabId)
            throw BearerError("The default bearer cannot be released by an E-RAB Release Command");
        if (m_registry.findBearer(*entry, erabId) == nullptr)
            throw BearerError("E-RAB Release Command names an unknown dedicated bearer");
    }
    for (auto erabId : command.erabIds)
    {
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
    sendS1ap(streamFor(*entry), response);
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
    const bool notify = entry->bearer.logicalExists();
    m_registry.releaseS1(*entry);
    if (notify)
    {
        try
        {
            sendRadio(*entry, lte::ue::link::MessageType::S1_CONTEXT_RELEASED,
                      lte::ue::link::EncodeBearerRestoration(erabId, entry->accessGeneration));
        }
        catch (const std::exception &e)
        {
            // Old S1AP IDs are already invalid. Complete the MME release even
            // if the software radio notification cannot be delivered.
            Log("WARN", std::string("S1 release radio notification failed: ") + e.what());
        }
    }
    Log("INFO", "Released S1 context of LTE UE " + std::to_string(radioUeId) + " (eNB-UE-S1AP-ID=" +
                    std::to_string(enbId) + ", MME-UE-S1AP-ID=" + std::to_string(mmeId) +
                    "); its TEID mapping was invalidated");
    auto complete = s1ap::EncodeUeContextReleaseComplete(mmeId, enbId);
    sendS1ap(SctpStreamForUe(m_outboundStreams, enbId), complete);
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
                radio.type != lte::ue::link::MessageType::SERVICE_REQUEST &&
                radio.type != lte::ue::link::MessageType::NAS_UPLINK_MOBILITY &&
                radio.type != lte::ue::link::MessageType::NAS_UPLINK_MOBILITY_CONTEXT)
                throw lte::ue::link::DecodeError("Data arrived before an LTE UE NAS context");
            entry = &m_registry.registerPeer(radio.ueId, peer);
        }

        if (radio.type == lte::ue::link::MessageType::S1_CONTEXT_RELEASE_REQUEST)
        {
            if (!entry->s1Active() || !entry->bearer.signalingEstablished() || entry->mmeUeS1apId == 0 ||
                radio.payload[0] != entry->bearer.parameters().erabId)
                throw lte::ue::link::DecodeError("S1 release request does not match an active registered UE context");
            auto request = s1ap::EncodeUeContextReleaseRequest(entry->mmeUeS1apId, entry->enbUeS1apId);
            sendS1ap(streamFor(*entry), request);
            Log("INFO", "UE Context Release Request sent for " + Describe(*entry) +
                            ": cause=radioNetwork/user-inactivity");
        }
        else if (radio.type == lte::ue::link::MessageType::SERVICE_REQUEST)
        {
            // An ECM-IDLE UE is kept in IDLE_RETAINED precisely so it can send
            // this, and such an entry need not hold a confirmed bearer on this
            // cell: a UE that arrived by a Tracking Area Update carried its
            // session over NAS and this cell established no bearer for it at
            // all. The MME holds the bearer contexts and is the one that
            // decides what a Service Request restores, so the frame is
            // forwarded for any UE whose session the network still holds. A
            // session its own NAS has already deleted holds nothing to restore
            // and is refused here.
            if (!entry->bearer.logicalConfirmed() && !entry->sessionRetained)
                throw lte::ue::link::DecodeError("Service Request has no retained EPS session");
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
                sendS1ap(streamFor(*entry), uplink);
                Log("INFO", "Uplink NAS Transport sent for " + Describe(*entry));
            }
            else
            {
                // A new Attach is a new logical session, unlike Service Request.
                m_registry.beginNewAttach(*entry);
                startInitialUeMessage(*entry, std::move(radio.payload), std::nullopt);
            }
        }
        else if (radio.type == lte::ue::link::MessageType::NAS_UPLINK_MOBILITY ||
                 radio.type == lte::ue::link::MessageType::NAS_UPLINK_MOBILITY_CONTEXT)
        {
            // Uplink NAS that continues an existing EPS session over a new S1
            // connection because the UE reselected this cell in ECM-IDLE. This
            // is deliberately not the fresh-Attach branch above: a fresh Attach
            // is a new logical session and tears down whatever EPS bearer
            // context this eNB still holds, and reselecting into a cell is
            // neither. The session's bearer contexts survive so the network can
            // reconcile them; only the access epoch restarts here.
            if (entry->s1Active())
                throw lte::ue::link::DecodeError(
                    "A mobility uplink opens a new S1 connection and cannot replace an active one");
            // The identity prefix is always five octets. A context-carrying
            // uplink then declares the bearer inventory before its protected
            // NAS, which is what lets a cell that has never seen the session's
            // Attach tell the default bearer from the dedicated ones.
            const bool declares = radio.type == lte::ue::link::MessageType::NAS_UPLINK_MOBILITY_CONTEXT;
            lte::ue::link::BearerInventory inventory{};
            size_t offset = 5;
            if (declares)
                offset += lte::ue::link::DecodeBearerInventory(radio.payload.data() + 5,
                                                              radio.payload.size() - 5, inventory);
            if (radio.payload.size() <= offset)
                throw lte::ue::link::DecodeError("A mobility uplink carries no NAS payload");
            const uint32_t mTmsi = (static_cast<uint32_t>(radio.payload[1]) << 24U) |
                                   (static_cast<uint32_t>(radio.payload[2]) << 16U) |
                                   (static_cast<uint32_t>(radio.payload[3]) << 8U) | radio.payload[4];
            if (mTmsi == 0)
                throw lte::ue::link::DecodeError("A mobility uplink carries a zero M-TMSI");
            // The access generation counts access epochs on this cell, and the
            // UE restarts its own count when it reselects one. Restarting here
            // keeps the two in step without touching the EPS bearer contexts,
            // which belong to the session rather than to the cell. The new
            // epoch is numbered one rather than zero: zero means "no epoch at
            // all" and every generation-bound message carrying it is refused.
            entry->accessGeneration = 1;
            entry->mobilityBootstrap = true;
            entry->declaredBearers = declares ? std::make_optional(inventory) : std::nullopt;
            std::vector<uint8_t> nasPdu(radio.payload.begin() + offset, radio.payload.end());
            startInitialUeMessage(*entry, std::move(nasPdu), s1ap::STmsi{radio.payload[0], mTmsi});
        }
        else if (radio.type == lte::ue::link::MessageType::EPS_SESSION_DELETED)
        {
            const auto deleted = lte::ue::link::DecodeBearerRestoration(radio.payload);
            const bool releaseRaced = entry->s1 == UeS1State::IDLE_RETAINED &&
                                      entry->accessGeneration == deleted.second + 1U;
            if (deleted.first != entry->bearer.parameters().erabId ||
                (deleted.second != entry->accessGeneration && !releaseRaced))
                throw BearerError("Stale EPS session deletion indication");
            m_registry.deleteBearerContexts(*entry);
        }
        else if (radio.type == lte::ue::link::MessageType::BEARER_TRANSPORT_READY)
        {
            const auto ready = lte::ue::link::DecodeBearerTransportReady(radio.payload.data(), radio.payload.size());
            auto *bearer = m_registry.findBearer(*entry, ready.ebi);
            if (!entry->s1Active() || ready.generation == 0 ||
                ready.generation != entry->accessGeneration || bearer == nullptr || !bearer->signalingEstablished() || !bearer->restorationPending())
                throw BearerError("Stale or unrequested bearer transport confirmation");
            if (bearer->kind() == BearerKind::DEDICATED && !entry->bearer.active())
                throw BearerError("Dedicated transport confirmation precedes default readiness");
            // The UE restates the PDN address its own NAS assigned, because a
            // cell that never saw this session's Attach cannot learn it without
            // decrypting NAS. It only ever confirms an address: one this eNB
            // already holds is never replaced by a different claim, and a
            // dedicated bearer names the address of its own default bearer.
            std::array<uint8_t, 4> address = ready.ueIpv4.value_or(bearer->ueIpv4());
            if (address == std::array<uint8_t, 4>{})
                throw BearerError("Bearer transport confirmation names no UE address");
            if (bearer->kind() == BearerKind::DEFAULT && bearer->ueIpv4() != std::array<uint8_t, 4>{} &&
                address != bearer->ueIpv4())
                throw BearerError("Bearer transport confirmation contradicts the assigned UE address");
            if (bearer->kind() == BearerKind::DEDICATED && address != entry->bearer.ueIpv4())
                throw BearerError("Dedicated transport confirmation contradicts the assigned UE address");
            bearer->activateUe(entry->radioUeId, ready.ebi, address);
            if (bearer->kind() == BearerKind::DEFAULT)
            {
                entry->s1 = UeS1State::BEARER_ACTIVE;
                ++m_recovery.successfulUeRestorations;
                if (m_recovery.accessInvalidations != 0 && m_restorationLatencyMs == 0)
                    m_restorationLatencyMs = static_cast<uint64_t>(
                        std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::steady_clock::now() -
                                                                             m_accessInvalidatedAt)
                            .count());
            }
        }
        else if (radio.type == lte::ue::link::MessageType::BEARER_READY)
        {
            if (entry->bearer.restorationPending())
                throw BearerError("Restoration requires a generation-bound confirmation");
            onBearerReady(*entry, radio.payload);
        }
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
                throw lte::ue::link::DecodeError("Unexpected legacy bearer activation confirmation");
            BearerContext *bearer = m_registry.findBearer(*entry, radio.payload[0]);
            if (bearer == nullptr || bearer->kind() != BearerKind::DEDICATED || bearer->restorationPending())
                throw lte::ue::link::DecodeError("Activation names an unknown or restoring dedicated bearer");
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
        // Counts every datagram rejected as stale, malformed or unauthorized:
        // a stale generation, an unknown EBI, a duplicated confirmation, an
        // identity claimed from another endpoint and a genuine decode failure
        // all land here and none of them disturbs any other UE context.
        ++m_recovery.staleMessagesRejected;
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
    if (!sendS1ap(SctpStreamForUe(m_outboundStreams, enbUeId), initial))
    {
        // Nothing left the eNB, so no S1 procedure exists. The provisional
        // context is discarded instead of lingering in CONTEXT_PENDING and
        // blocking a later Service Request. The entry is returned to
        // IDLE_RETAINED first so releaseS1 does not advance the access
        // generation: no access epoch was ever created.
        entry.s1 = UeS1State::IDLE_RETAINED;
        m_registry.releaseS1(entry);
        throw BearerError("Initial UE Message could not be transmitted; the provisional context was discarded");
    }
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
