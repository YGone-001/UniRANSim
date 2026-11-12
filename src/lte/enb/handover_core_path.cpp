//
// This file is a part of UERANSIM project.
// Copyright (c) 2027 ALİ GÜNGÖR.
//
// https://github.com/aligungr/UERANSIM/
// See README, LICENSE, and CONTRIBUTING files for licensing details.
//

#include "handover_core_path.hpp"

#include <algorithm>
#include <iostream>
#include <stdexcept>
#include <utility>

#include "gtpu.hpp"
#include "handover_orchestration.hpp"
#include "multiplexer.hpp"
#include "ue_registry.hpp"

#include <lib/udp/server.hpp>

namespace lte::enb::s1ap
{
namespace
{

void Log(const char *level, const std::string &message)
{
    std::cout << "[lte-enb] [" << level << "] " << message << std::endl;
}

// The four octets of an IPv4 endpoint, read back out of the address the eNB
// itself bound. Nothing here is a caller assertion about where a cell is.
std::array<uint8_t, 4> Ipv4Of(const InetAddress &address)
{
    const std::string text = address.toString();
    const auto colon = text.rfind(':');
    if (colon == std::string::npos)
        return {};
    return ParseIpv4(text.substr(0, colon));
}

// TS 29.281 section 5.1 and table 6.1-1.
//
// An End Marker is version 1 with the protocol-type bit set and no optional
// fields: flags 0x30, message type 254, a length of zero because neither a
// sequence number nor a payload follows the mandatory header, and the TEID of
// the tunnel whose payload stream is ending. Eight octets in total and an empty
// information-element area.
//
// This is the isolated SGW's producer, not an eNB path. The eNB recognises and
// records an End Marker and never generates or transmits one; the only code
// that builds these octets is the simulator's core side, and it sends them to
// the old source endpoint and nowhere else.
std::vector<uint8_t> EncodeIsolatedEndMarker(uint32_t teid)
{
    if (teid == 0)
        throw std::invalid_argument("an End Marker must name a non-zero tunnel");
    return {0x30,
            gtpu::EndMarker,
            0x00,
            0x00,
            static_cast<uint8_t>(teid >> 24U),
            static_cast<uint8_t>(teid >> 16U),
            static_cast<uint8_t>(teid >> 8U),
            static_cast<uint8_t>(teid)};
}

const InstalledBearerPath *FindInstalled(const std::map<uint8_t, InstalledBearerPath> &bearers, uint8_t ebi)
{
    const auto it = bearers.find(ebi);
    return it == bearers.end() ? nullptr : &it->second;
}

bool SameEndpoint(const IsolatedDownlinkEndpoint &a, const IsolatedDownlinkEndpoint &b)
{
    return a.address == b.address && a.teid == b.teid && a.port == b.port;
}

} // namespace

bool operator==(const IsolatedSessionKey &a, const IsolatedSessionKey &b)
{
    return a.mmeUeS1apId == b.mmeUeS1apId && a.ueIpv4 == b.ueIpv4;
}

bool operator!=(const IsolatedSessionKey &a, const IsolatedSessionKey &b)
{
    return !(a == b);
}

bool operator<(const IsolatedSessionKey &a, const IsolatedSessionKey &b)
{
    // The address first and the identifier second, so the order is total even
    // when one session's identifier is zero.
    if (a.ueIpv4 != b.ueIpv4)
        return a.ueIpv4 < b.ueIpv4;
    return a.mmeUeS1apId < b.mmeUeS1apId;
}

std::string ToString(const IsolatedSessionKey &session)
{
    return "MME-UE-S1AP-ID=" + std::to_string(session.mmeUeS1apId) + " PDN=" +
           Ipv4ToString(session.ueIpv4);
}

bool operator==(const IsolatedDownlinkEndpoint &a, const IsolatedDownlinkEndpoint &b)
{
    return SameEndpoint(a, b);
}

bool operator!=(const IsolatedDownlinkEndpoint &a, const IsolatedDownlinkEndpoint &b)
{
    return !SameEndpoint(a, b);
}

std::string ToString(const IsolatedDownlinkEndpoint &endpoint)
{
    return Ipv4ToString(endpoint.address) + ":" + std::to_string(endpoint.port) + " TEID=" +
           std::to_string(endpoint.teid);
}

const char *ToString(CorePathRefusal refusal)
{
    switch (refusal)
    {
    case CorePathRefusal::LIVE_MODE_DISABLED: return "LIVE_MODE_DISABLED";
    case CorePathRefusal::INCOMPLETE_REQUEST: return "INCOMPLETE_REQUEST";
    case CorePathRefusal::UNKNOWN_SESSION: return "UNKNOWN_SESSION";
    case CorePathRefusal::CONFLICTING_TRANSACTION: return "CONFLICTING_TRANSACTION";
    case CorePathRefusal::CONFLICTING_REPLACEMENT: return "CONFLICTING_REPLACEMENT";
    case CorePathRefusal::BEARER_SET_MISMATCH: return "BEARER_SET_MISMATCH";
    case CorePathRefusal::DUPLICATE_EBI: return "DUPLICATE_EBI";
    case CorePathRefusal::WRONG_SGW_TEID: return "WRONG_SGW_TEID";
    case CorePathRefusal::INCOMPLETE_ENDPOINT: return "INCOMPLETE_ENDPOINT";
    case CorePathRefusal::WRONG_TARGET_ENDPOINT: return "WRONG_TARGET_ENDPOINT";
    case CorePathRefusal::BEARER_RELATIONSHIP_INVALID: return "BEARER_RELATIONSHIP_INVALID";
    case CorePathRefusal::DEFAULT_BEARER_INVALID: return "DEFAULT_BEARER_INVALID";
    case CorePathRefusal::STALE_GENERATION: return "STALE_GENERATION";
    case CorePathRefusal::STALE_ASSOCIATION: return "STALE_ASSOCIATION";
    case CorePathRefusal::WRONG_STATE: return "WRONG_STATE";
    case CorePathRefusal::NOT_ARRIVED: return "NOT_ARRIVED";
    case CorePathRefusal::NOT_COMMITTED: return "NOT_COMMITTED";
    case CorePathRefusal::TARGET_CONTEXT_LOST: return "TARGET_CONTEXT_LOST";
    case CorePathRefusal::BEARER_NOT_ACTIVE: return "BEARER_NOT_ACTIVE";
    case CorePathRefusal::CONFLICTING_UPDATE: return "CONFLICTING_UPDATE";
    case CorePathRefusal::SEND_FAILED: return "SEND_FAILED";
    }
    return "UNKNOWN_CORE_PATH_REFUSAL";
}

const char *ToString(CorePathConfirmationRefusal refusal)
{
    switch (refusal)
    {
    case CorePathConfirmationRefusal::CONFIRMED: return "CONFIRMED";
    case CorePathConfirmationRefusal::WRONG_SESSION: return "WRONG_SESSION";
    case CorePathConfirmationRefusal::WRONG_TRANSACTION: return "WRONG_TRANSACTION";
    case CorePathConfirmationRefusal::WRONG_ASSOCIATION_EPOCH: return "WRONG_ASSOCIATION_EPOCH";
    case CorePathConfirmationRefusal::WRONG_TARGET: return "WRONG_TARGET";
    case CorePathConfirmationRefusal::MISSING_EBI: return "MISSING_EBI";
    case CorePathConfirmationRefusal::DUPLICATE_EBI: return "DUPLICATE_EBI";
    case CorePathConfirmationRefusal::WRONG_SGW_TEID: return "WRONG_SGW_TEID";
    case CorePathConfirmationRefusal::WRONG_ENDPOINT: return "WRONG_ENDPOINT";
    case CorePathConfirmationRefusal::BEARER_RELATIONSHIP_INVALID: return "BEARER_RELATIONSHIP_INVALID";
    case CorePathConfirmationRefusal::STALE_GENERATION: return "STALE_GENERATION";
    case CorePathConfirmationRefusal::CONFLICTING_REPLACEMENT: return "CONFLICTING_REPLACEMENT";
    case CorePathConfirmationRefusal::INDETERMINATE: return "INDETERMINATE";
    }
    return "UNKNOWN_CONFIRMATION_REFUSAL";
}

IsolatedSgw::IsolatedSgw(ExecutionMode mode, const std::string &address, uint16_t port) : m_mode(mode)
{
    if (!enabled())
        return;
    if (address.empty() || address == "0.0.0.0")
        throw std::invalid_argument("the isolated SGW must bind a concrete local IPv4 address");
    m_socket = std::make_unique<udp::UdpServer>(address, port);
}

bool IsolatedSgw::enabled() const
{
    return m_mode == ExecutionMode::ISOLATED_SIMULATOR;
}

InetAddress IsolatedSgw::localAddress() const
{
    return m_socket != nullptr ? m_socket->LocalAddress() : InetAddress{};
}

bool IsolatedSgw::installSession(const IsolatedSessionKey &session, uint64_t mmeAssociationEpoch,
                                 const std::vector<AcceptedTargetEndpoint> &bearers, CorePathRefusalRecord *failure)
{
    auto refuse = [failure](CorePathRefusal why, std::string detail) {
        if (failure != nullptr)
            *failure = CorePathRefusalRecord{why, std::move(detail)};
        return false;
    };

    if (!enabled())
        return refuse(CorePathRefusal::LIVE_MODE_DISABLED,
                      "the isolated SGW refuses to act while attached to a live EPC");
    if (session.mmeUeS1apId == 0 || session.ueIpv4 == std::array<uint8_t, 4>{} || mmeAssociationEpoch == 0)
        return refuse(CorePathRefusal::INCOMPLETE_REQUEST, "a session mapping must name a UE, a PDN address and an epoch");
    if (bearers.empty())
        return refuse(CorePathRefusal::INCOMPLETE_REQUEST, "a session mapping must name at least one bearer");

    SessionState state;
    state.generation = 1;
    state.associationEpoch = mmeAssociationEpoch;

    size_t defaults = 0;
    for (const auto &bearer : bearers)
    {
        if (bearer.ebi == 0 || bearer.sgwTeid == 0)
            return refuse(CorePathRefusal::INCOMPLETE_REQUEST, "a bearer must name an EBI and an SGW TEID");
        if (!bearer.endpoint.complete())
            return refuse(CorePathRefusal::INCOMPLETE_ENDPOINT,
                          "a bearer's downlink endpoint must be a complete address and TEID");
        if (state.bearers.count(bearer.ebi) != 0)
            return refuse(CorePathRefusal::DUPLICATE_EBI, "the same EBI appears twice in one mapping");
        if (bearer.role == BearerRole::DEFAULT)
        {
            ++defaults;
            if (bearer.linkedDefaultEbi.has_value())
                return refuse(CorePathRefusal::BEARER_RELATIONSHIP_INVALID,
                              "a default bearer cannot name a linked default");
        }
        InstalledBearerPath path;
        path.session = session;
        path.ebi = bearer.ebi;
        path.role = bearer.role;
        path.linkedDefaultEbi = bearer.linkedDefaultEbi;
        path.sgwTeid = bearer.sgwTeid;
        path.endpoint = bearer.endpoint;
        // Nothing has been switched yet, so the old path is the current one.
        path.originalSource = bearer.endpoint;
        path.generation = state.generation;
        state.bearers.emplace(bearer.ebi, path);
    }
    if (defaults != 1)
        return refuse(CorePathRefusal::DEFAULT_BEARER_INVALID,
                      "a session mapping holds exactly one default bearer");
    for (const auto &item : state.bearers)
    {
        if (item.second.role != BearerRole::DEDICATED)
            continue;
        if (!item.second.linkedDefaultEbi.has_value() || state.bearers.count(*item.second.linkedDefaultEbi) == 0 ||
            *item.second.linkedDefaultEbi == item.first)
            return refuse(CorePathRefusal::BEARER_RELATIONSHIP_INVALID,
                          "a dedicated bearer must name a default bearer of its own session");
    }

    const auto existing = m_sessions.find(session);
    if (existing != m_sessions.end())
    {
        // Idempotent provisioning: the same mapping again is the same mapping.
        // A different one would be a second source path for a session that
        // already has one, which is exactly what this map must never hold.
        bool identical = existing->second.bearers.size() == state.bearers.size();
        for (const auto &item : state.bearers)
        {
            const InstalledBearerPath *current = FindInstalled(existing->second.bearers, item.first);
            if (current == nullptr || !SameEndpoint(current->endpoint, item.second.endpoint) ||
                current->sgwTeid != item.second.sgwTeid || current->role != item.second.role ||
                current->linkedDefaultEbi != item.second.linkedDefaultEbi)
                identical = false;
        }
        if (!identical)
            return refuse(CorePathRefusal::CONFLICTING_TRANSACTION,
                          "this session already holds another source path");
        return true;
    }

    m_sessions.emplace(session, std::move(state));
    Log("INFO", "Isolated SGW holds the source downlink path of " + ToString(session) + " for " +
                    std::to_string(bearers.size()) + " bearer(s)");
    return true;
}

const IsolatedSgw::SessionState *IsolatedSgw::findSession(const IsolatedSessionKey &session) const
{
    const auto it = m_sessions.find(session);
    return it == m_sessions.end() ? nullptr : &it->second;
}

bool IsolatedSgw::SameSet(const std::map<uint8_t, InstalledBearerPath> &installed,
                          const std::vector<AcceptedTargetEndpoint> &proposed)
{
    if (installed.size() != proposed.size())
        return false;
    for (const auto &bearer : proposed)
    {
        const InstalledBearerPath *current = FindInstalled(installed, bearer.ebi);
        if (current == nullptr || !SameEndpoint(current->endpoint, bearer.endpoint) ||
            current->sgwTeid != bearer.sgwTeid || current->role != bearer.role ||
            current->linkedDefaultEbi != bearer.linkedDefaultEbi)
            return false;
    }
    return true;
}

IsolatedPathUpdateCommit IsolatedSgw::apply(const IsolatedPathUpdateRequest &request)
{
    IsolatedPathUpdateCommit commit;
    commit.session = request.session;
    commit.transaction = request.transaction;

    auto refuse = [&commit](CorePathRefusal why, std::string detail) {
        commit.refusal = CorePathRefusalRecord{why, std::move(detail)};
        return commit;
    };

    if (!enabled())
        return refuse(CorePathRefusal::LIVE_MODE_DISABLED,
                      "the isolated SGW refuses to act while attached to a live EPC");
    if (request.session.mmeUeS1apId == 0 || request.session.ueIpv4 == std::array<uint8_t, 4>{} ||
        request.transaction.mmeUeS1apId == 0 || request.transaction.associationEpoch == 0 ||
        request.mmeAssociationEpoch == 0 || request.targetEnbId == 0 ||
        request.targetS1uAddress == std::array<uint8_t, 4>{} || request.bearers.empty())
        return refuse(CorePathRefusal::INCOMPLETE_REQUEST,
                      "a path update must name a session, a transaction, a target and its bearer set");

    const auto it = m_sessions.find(request.session);
    if (it == m_sessions.end())
        return refuse(CorePathRefusal::UNKNOWN_SESSION,
                      "no source downlink path exists for this session, so nothing can be replaced");
    SessionState &state = it->second;

    if (state.associationEpoch != request.mmeAssociationEpoch)
        return refuse(CorePathRefusal::STALE_ASSOCIATION,
                      "the request was written under another MME association epoch than this session holds");
    if (state.generation != request.expectedGeneration)
        return refuse(CorePathRefusal::STALE_GENERATION,
                      "the session's path generation moved since this request was written");
    if (state.owner.mmeUeS1apId != 0 && !(state.owner == request.transaction))
        return refuse(CorePathRefusal::CONFLICTING_TRANSACTION,
                      "another transaction already owns this session's downlink path");

    // A repeat of the replacement this transaction already installed is the
    // same update and publishes nothing a second time. A repeat that disagrees
    // with it would re-point a live path at another set, and is refused.
    if (state.owner == request.transaction)
    {
        if (SameSet(state.bearers, request.bearers))
        {
            commit.committed = true;
            commit.replayed = true;
            commit.pathGeneration = state.generation;
            for (const auto &item : state.bearers)
                commit.installed.push_back(item.second);
            return commit;
        }
        return refuse(CorePathRefusal::CONFLICTING_REPLACEMENT,
                      "this transaction already installed a different replacement for this session");
    }

    // Validate the whole proposed set before a single entry is written.
    std::map<uint8_t, const AcceptedTargetEndpoint *> proposed;
    size_t defaults = 0;
    for (const auto &bearer : request.bearers)
    {
        if (bearer.ebi == 0 || bearer.sgwTeid == 0)
            return refuse(CorePathRefusal::INCOMPLETE_REQUEST, "a bearer must name an EBI and an SGW TEID");
        if (!bearer.endpoint.complete())
            return refuse(CorePathRefusal::INCOMPLETE_ENDPOINT,
                          "a bearer's downlink endpoint must be a complete address and TEID");
        if (proposed.count(bearer.ebi) != 0)
            return refuse(CorePathRefusal::DUPLICATE_EBI, "the same EBI appears twice in one request");
        if (bearer.endpoint.address != request.targetS1uAddress)
            return refuse(CorePathRefusal::WRONG_TARGET_ENDPOINT,
                          "a destination is not on the target cell's own S1-U address");
        const InstalledBearerPath *current = FindInstalled(state.bearers, bearer.ebi);
        if (current == nullptr)
            return refuse(CorePathRefusal::BEARER_SET_MISMATCH,
                          "the request names a bearer this session does not hold");
        if (current->sgwTeid != bearer.sgwTeid)
            return refuse(CorePathRefusal::WRONG_SGW_TEID,
                          "a bearer's SGW-side tunnel identity does not match the installed mapping");
        if (current->role != bearer.role || current->linkedDefaultEbi != bearer.linkedDefaultEbi)
            return refuse(CorePathRefusal::BEARER_RELATIONSHIP_INVALID,
                          "a bearer's role or linked default disagrees with the session's inventory");
        if (bearer.role == BearerRole::DEFAULT)
        {
            ++defaults;
            if (bearer.linkedDefaultEbi.has_value())
                return refuse(CorePathRefusal::BEARER_RELATIONSHIP_INVALID,
                              "a default bearer cannot name a linked default");
        }
        proposed.emplace(bearer.ebi, &bearer);
    }
    if (proposed.size() != state.bearers.size())
        return refuse(CorePathRefusal::BEARER_SET_MISMATCH,
                      "a replacement must cover every bearer of the session and no others");
    if (defaults != 1)
        return refuse(CorePathRefusal::DEFAULT_BEARER_INVALID,
                      "a replacement holds exactly one default bearer");
    for (const auto &item : proposed)
    {
        if (item.second->role != BearerRole::DEDICATED)
            continue;
        if (!item.second->linkedDefaultEbi.has_value() ||
            proposed.count(*item.second->linkedDefaultEbi) == 0 ||
            *item.second->linkedDefaultEbi == item.first)
            return refuse(CorePathRefusal::BEARER_RELATIONSHIP_INVALID,
                          "a dedicated bearer must name a default bearer of the same replacement set");
    }

    // The complete replacement, prepared before anything is published.
    SessionState published;
    published.generation = state.generation + 1;
    published.associationEpoch = state.associationEpoch;
    published.owner = request.transaction;
    for (const auto &item : proposed)
    {
        InstalledBearerPath path = state.bearers.at(item.first);
        path.endpoint = item.second->endpoint;
        path.generation = published.generation;
        path.owner = request.transaction;
        // The previous destination is kept as the old path: it is what an End
        // Marker is sent to, and what a confirmation names as replaced.
        published.bearers.emplace(item.first, std::move(path));
    }

    // The publication boundary. One assignment of the whole session state; no
    // reader can observe a session whose default bearer is on the target while
    // its dedicated bearer is still on the source, because there is no such
    // intermediate state to observe.
    it->second = std::move(published);

    commit.committed = true;
    commit.pathGeneration = it->second.generation;
    for (const auto &item : it->second.bearers)
        commit.installed.push_back(item.second);
    Log("INFO", "Isolated SGW published downlink path generation " + std::to_string(commit.pathGeneration) +
                    " for " + ToString(request.session) + " to " + Ipv4ToString(request.targetS1uAddress) +
                    " (" + std::to_string(commit.installed.size()) + " bearer(s))");
    return commit;
}

std::optional<uint64_t> IsolatedSgw::generationOf(const IsolatedSessionKey &session) const
{
    const SessionState *state = findSession(session);
    if (state == nullptr)
        return std::nullopt;
    return state->generation;
}

std::optional<HandoverTransactionId> IsolatedSgw::ownerOf(const IsolatedSessionKey &session) const
{
    const SessionState *state = findSession(session);
    if (state == nullptr || state->owner.mmeUeS1apId == 0)
        return std::nullopt;
    return state->owner;
}

std::vector<InstalledBearerPath> IsolatedSgw::installed(const IsolatedSessionKey &session) const
{
    std::vector<InstalledBearerPath> out;
    const SessionState *state = findSession(session);
    if (state == nullptr)
        return out;
    for (const auto &item : state->bearers)
        out.push_back(item.second);
    return out;
}

std::optional<InstalledBearerPath> IsolatedSgw::installed(const IsolatedSessionKey &session, uint8_t ebi) const
{
    const SessionState *state = findSession(session);
    if (state == nullptr)
        return std::nullopt;
    const InstalledBearerPath *path = FindInstalled(state->bearers, ebi);
    if (path == nullptr)
        return std::nullopt;
    return *path;
}

bool IsolatedSgw::sendDownlink(const IsolatedSessionKey &session, uint8_t ebi, const uint8_t *payload, size_t size)
{
    CoreSendRecord record;
    record.session = session;
    record.ebi = ebi;

    if (!enabled())
    {
        m_sends.push_back(record);
        return false;
    }

    // The destination is read out of the installed map at send time. A caller
    // names a bearer and never an endpoint, which is what makes a post-update
    // send evidence of the migration rather than of the caller's choice.
    const SessionState *state = findSession(session);
    if (state == nullptr)
    {
        m_sends.push_back(record);
        return false;
    }
    const InstalledBearerPath *path = FindInstalled(state->bearers, ebi);
    if (path == nullptr)
    {
        m_sends.push_back(record);
        return false;
    }
    record.destination = path->endpoint;
    record.generation = state->generation;

    const auto datagram = gtpu::EncodeTPdu(record.destination.teid, payload, size);
    const InetAddress destination(Ipv4ToString(record.destination.address), record.destination.port);
    record.sent = m_socket->TrySend(destination, datagram.data(), datagram.size());
    m_sends.push_back(record);
    if (!record.sent)
        Log("WARN", "Isolated SGW could not send a downlink T-PDU to " + ToString(record.destination));
    return record.sent;
}

std::vector<IsolatedSgw::ReceivedUplink> IsolatedSgw::drainUplink()
{
    std::vector<ReceivedUplink> out;
    if (m_socket == nullptr || !enabled())
        return out;
    for (int i = 0; i < 32; ++i)
    {
        uint8_t buffer[2048];
        InetAddress from;
        const int length = m_socket->Receive(buffer, sizeof(buffer), 2, from);
        if (length <= 0)
            break;
        gtpu::Packet packet;
        try
        {
            packet = gtpu::Decode(buffer, static_cast<size_t>(length));
        }
        catch (const std::exception &)
        {
            continue;
        }
        if (packet.messageType != gtpu::TPdu)
            continue;
        out.push_back(ReceivedUplink{packet.teid, std::move(packet.payload)});
    }
    return out;
}

bool IsolatedSgw::sendEndMarker(const IsolatedSessionKey &session, uint8_t ebi)
{
    CoreSendRecord record;
    record.session = session;
    record.ebi = ebi;
    record.kind = CoreSendRecord::Kind::END_MARKER;

    const SessionState *state = findSession(session);
    if (state == nullptr)
    {
        m_sends.push_back(record);
        return false;
    }
    const InstalledBearerPath *path = FindInstalled(state->bearers, ebi);
    if (path == nullptr)
    {
        m_sends.push_back(record);
        return false;
    }
    // An End Marker describes a path that is ending. A bearer whose destination
    // has not moved has no old path, and sending one would describe an end that
    // did not happen.
    if (path->originalSource == path->endpoint)
    {
        m_sends.push_back(record);
        return false;
    }
    record.destination = path->originalSource;
    record.generation = state->generation;

    const auto datagram = EncodeIsolatedEndMarker(record.destination.teid);
    const InetAddress destination(Ipv4ToString(record.destination.address), record.destination.port);
    record.sent = m_socket->TrySend(destination, datagram.data(), datagram.size());
    m_sends.push_back(record);
    if (record.sent)
    {
        ++m_endMarkersSent;
        Log("INFO", "Isolated SGW sent an End Marker on the old path of " + ToString(session) + " EBI " +
                        std::to_string(static_cast<int>(ebi)) + " to " + ToString(record.destination));
    }
    return record.sent;
}

// --- Confirmation ---------------------------------------------------------

std::optional<IsolatedCoreUpdateConfirmation> ReadIsolatedPathState(const IsolatedSgw &sgw,
                                                                    const IsolatedSessionKey &session,
                                                                    uint64_t mmeAssociationEpoch)
{
    const auto generation = sgw.generationOf(session);
    const auto owner = sgw.ownerOf(session);
    if (!generation.has_value() || !owner.has_value())
        return std::nullopt;

    IsolatedCoreUpdateConfirmation confirmation;
    confirmation.session = session;
    confirmation.transaction = *owner;
    confirmation.mmeAssociationEpoch = mmeAssociationEpoch;
    confirmation.pathGeneration = *generation;
    confirmation.installed = sgw.installed(session);
    if (confirmation.installed.empty())
        return std::nullopt;
    return confirmation;
}

CorePathConfirmationResult VerifyIsolatedPathConfirmation(const IsolatedPathUpdateRequest &request,
                                                          const IsolatedCoreUpdateConfirmation &confirmation)
{
    auto refuse = [](CorePathConfirmationRefusal why, std::string detail) {
        return CorePathConfirmationResult{why, std::move(detail)};
    };

    // What the confirmation says about the session it belongs to. A core that
    // installed the replacement for another UE has installed nothing this
    // handover can use, whatever the bearer numbers look like.
    if (confirmation.session != request.session)
        return refuse(CorePathConfirmationRefusal::WRONG_SESSION,
                      "the installed mapping belongs to another EPS session");
    if (confirmation.transaction != request.transaction)
        return refuse(CorePathConfirmationRefusal::WRONG_TRANSACTION,
                      "the installed mapping is owned by another transaction");
    if (confirmation.mmeAssociationEpoch != request.mmeAssociationEpoch || request.mmeAssociationEpoch == 0)
        return refuse(CorePathConfirmationRefusal::WRONG_ASSOCIATION_EPOCH,
                      "the installed mapping was read under another MME association epoch");
    if (confirmation.pathGeneration == 0)
        return refuse(CorePathConfirmationRefusal::STALE_GENERATION,
                      "an installed mapping always carries a non-zero generation");
    if (confirmation.pathGeneration != request.expectedGeneration + 1)
        return refuse(CorePathConfirmationRefusal::STALE_GENERATION,
                      "the installed generation is not the one this request would have produced");

    // The accepted EBI set, exactly.
    std::map<uint8_t, const InstalledBearerPath *> installed;
    for (const auto &path : confirmation.installed)
    {
        if (installed.count(path.ebi) != 0)
            return refuse(CorePathConfirmationRefusal::DUPLICATE_EBI,
                          "the installed mapping names the same EBI twice");
        installed.emplace(path.ebi, &path);
    }
    if (installed.size() != request.bearers.size())
        return refuse(CorePathConfirmationRefusal::MISSING_EBI,
                      "the installed mapping does not cover exactly the accepted bearer set");

    for (const auto &bearer : request.bearers)
    {
        const auto it = installed.find(bearer.ebi);
        if (it == installed.end())
            return refuse(CorePathConfirmationRefusal::MISSING_EBI,
                          "the installed mapping omits an accepted EBI");
        const InstalledBearerPath &path = *it->second;
        if (path.session != request.session)
            return refuse(CorePathConfirmationRefusal::WRONG_SESSION,
                          "an installed bearer names another EPS session");
        if (!(path.owner == request.transaction))
            return refuse(CorePathConfirmationRefusal::WRONG_TRANSACTION,
                          "an installed bearer is owned by another transaction");
        if (path.sgwTeid != bearer.sgwTeid)
            return refuse(CorePathConfirmationRefusal::WRONG_SGW_TEID,
                          "an installed bearer names another SGW-side tunnel identity");
        if (path.endpoint != bearer.endpoint)
            return refuse(CorePathConfirmationRefusal::WRONG_ENDPOINT,
                          "an installed bearer's destination is not the accepted one");
        if (path.endpoint.address != request.targetS1uAddress)
            return refuse(CorePathConfirmationRefusal::WRONG_TARGET,
                          "an installed destination is not on the target cell's own S1-U address");
        if (path.role != bearer.role || path.linkedDefaultEbi != bearer.linkedDefaultEbi)
            return refuse(CorePathConfirmationRefusal::BEARER_RELATIONSHIP_INVALID,
                          "an installed bearer's role or linked default disagrees with the accepted set");
        // The original mapping is what the confirmation says was replaced. A
        // mapping that names no source cannot describe a migration at all.
        if (!path.originalSource.complete())
            return refuse(CorePathConfirmationRefusal::CONFLICTING_REPLACEMENT,
                          "an installed bearer names no original source mapping");
        if (path.generation != confirmation.pathGeneration)
            return refuse(CorePathConfirmationRefusal::STALE_GENERATION,
                          "an installed bearer was published under another generation");
    }

    return CorePathConfirmationResult{CorePathConfirmationRefusal::CONFIRMED, {}};
}

// --- The MME's control ----------------------------------------------------

bool ReadAcceptedTargetEndpoints(const CoordinationRecord &record, EnbMultiplexer &target,
                                 std::vector<AcceptedTargetEndpoint> *endpoints, CorePathRefusalRecord *failure)
{
    auto refuse = [failure](CorePathRefusal why, std::string detail) {
        if (failure != nullptr)
            *failure = CorePathRefusalRecord{why, std::move(detail)};
        return false;
    };
    if (endpoints == nullptr)
        return refuse(CorePathRefusal::INCOMPLETE_REQUEST, "no endpoint set was asked for");
    endpoints->clear();

    if (!record.complete())
        return refuse(CorePathRefusal::INCOMPLETE_REQUEST,
                      "the coordination record does not bind everything a core update needs");

    // The target's own reached context, found by the radio identity the
    // verified arrival produced. A provisional context is a UE that has not
    // arrived and holds no forwardable bearer.
    EnbUeEntry *entry = target.registry().find(record.source.radioUeId);
    if (entry == nullptr || UeRegistry::isProvisional(*entry))
        return refuse(CorePathRefusal::TARGET_CONTEXT_LOST,
                      "the target no longer holds a reached UE under the verified arrival's radio identity");
    if (entry->mmeUeS1apId != record.mmeUeS1apId)
        return refuse(CorePathRefusal::TARGET_CONTEXT_LOST,
                      "the target's reached context no longer carries this transaction's MME identity");

    const InetAddress targetS1u = target.s1uAddress();
    const auto targetAddress = Ipv4Of(targetS1u);
    if (targetAddress == std::array<uint8_t, 4>{} || targetS1u.getPort() == 0)
        return refuse(CorePathRefusal::INCOMPLETE_ENDPOINT, "the target has no S1-U endpoint of its own");

    for (const auto &binding : record.source.roles)
    {
        BearerContext *bearer = nullptr;
        if (binding.role == BearerRole::DEFAULT)
        {
            if (entry->bearer.parameters().erabId == binding.erabId)
                bearer = &entry->bearer;
        }
        else
        {
            bearer = target.registry().findBearer(*entry, binding.erabId);
        }
        if (bearer == nullptr || !bearer->signalingEstablished())
            return refuse(CorePathRefusal::BEARER_SET_MISMATCH,
                          "the target holds no established bearer for an accepted E-RAB");
        if (!bearer->active())
            return refuse(CorePathRefusal::BEARER_NOT_ACTIVE,
                          "a target bearer is no longer ready for forwarding");
        if (bearer->parameters().qci != binding.qci)
            return refuse(CorePathRefusal::BEARER_RELATIONSHIP_INVALID,
                          "a target bearer names another QCI than the accepted set");
        if (bearer->parameters().linkedDefaultEbi !=
            (binding.linkedDefaultErabId.has_value() ? *binding.linkedDefaultErabId : 0))
            return refuse(CorePathRefusal::BEARER_RELATIONSHIP_INVALID,
                          "a target bearer names another linked default than the accepted set");
        if (bearer->parameters().localTeid == 0 || bearer->parameters().sgwTeid == 0)
            return refuse(CorePathRefusal::INCOMPLETE_ENDPOINT,
                          "a target bearer holds no complete local transport");

        AcceptedTargetEndpoint endpoint;
        endpoint.ebi = binding.erabId;
        endpoint.role = binding.role;
        endpoint.linkedDefaultEbi = binding.linkedDefaultErabId;
        endpoint.sgwTeid = bearer->parameters().sgwTeid;
        // The target's own socket address and port, and the identifier its own
        // allocator bound. None of the three is a caller's choice, and the
        // port is the one the target actually listens on rather than a
        // constant this side assumes.
        endpoint.endpoint =
            IsolatedDownlinkEndpoint{targetAddress, bearer->parameters().localTeid, targetS1u.getPort()};
        endpoints->push_back(endpoint);
    }

    if (endpoints->size() != record.source.roles.size() || endpoints->empty())
        return refuse(CorePathRefusal::BEARER_SET_MISMATCH,
                      "the target endpoint set is not the admitted bearer set");

    size_t defaults = 0;
    for (const auto &endpoint : *endpoints)
        if (endpoint.role == BearerRole::DEFAULT)
            ++defaults;
    if (defaults != 1)
        return refuse(CorePathRefusal::DEFAULT_BEARER_INVALID,
                      "the target endpoint set must hold exactly one default bearer");
    for (const auto &endpoint : *endpoints)
    {
        if (endpoint.role != BearerRole::DEDICATED)
            continue;
        if (!endpoint.linkedDefaultEbi.has_value())
            return refuse(CorePathRefusal::BEARER_RELATIONSHIP_INVALID,
                          "a dedicated target bearer names no linked default");
        bool found = false;
        for (const auto &candidate : *endpoints)
            found = found || (candidate.ebi == *endpoint.linkedDefaultEbi && candidate.role == BearerRole::DEFAULT);
        if (!found)
            return refuse(CorePathRefusal::BEARER_RELATIONSHIP_INVALID,
                          "a dedicated target bearer's linked default is not part of the set");
    }
    return true;
}

bool BeginIsolatedCorePathUpdate(HandoverCoordinator &coordinator, EnbMultiplexer &target, IsolatedSgw &sgw,
                                 const HandoverTransactionId &transaction, CorePathRefusalRecord *failure)
{
    auto refuse = [failure](CorePathRefusal why, std::string detail) {
        if (failure != nullptr)
            *failure = CorePathRefusalRecord{why, std::move(detail)};
        return false;
    };

    if (!coordinator.enabled())
        return refuse(CorePathRefusal::LIVE_MODE_DISABLED,
                      "an isolated core path update is never dispatched while attached to a live EPC");

    CoordinationRecord *record = coordinator.findMutable(transaction);
    if (record == nullptr)
        return refuse(CorePathRefusal::WRONG_STATE, "no open coordination record names this transaction");
    // The Phase 18-D boundary is the only entry point. A transaction that has
    // not been notified has produced no evidence that the UE arrived, and a
    // transaction past this point has already been dispatched.
    if (record->state != OrchestrationState::AWAITING_CORE_PATH_UPDATE)
        return refuse(CorePathRefusal::WRONG_STATE,
                      "a core path update may only be dispatched from AWAITING_CORE_PATH_UPDATE");
    if (record->cancelled)
        return refuse(CorePathRefusal::WRONG_STATE, "the coordination record has been cancelled");
    if (record->arrivalToken == 0)
        return refuse(CorePathRefusal::NOT_ARRIVED,
                      "no verified target arrival was ever bound to this transaction");
    if (!record->complete())
        return refuse(CorePathRefusal::INCOMPLETE_REQUEST,
                      "the coordination record does not bind everything a core update needs");

    std::vector<AcceptedTargetEndpoint> accepted;
    CorePathRefusalRecord readFailure;
    if (!ReadAcceptedTargetEndpoints(*record, target, &accepted, &readFailure))
    {
        if (failure != nullptr)
            *failure = readFailure;
        return false;
    }

    // The generation the MME is writing against, read once here. If the SGW's
    // map moves between this dispatch and the apply, the request is stale and
    // the SGW refuses it rather than applying an update written for another
    // starting point.
    const auto generation = sgw.generationOf(IsolatedSessionKey{record->mmeUeS1apId, record->pdnAddress});
    if (!generation.has_value())
        return refuse(CorePathRefusal::UNKNOWN_SESSION,
                      "the isolated SGW holds no source downlink path for this session");

    IsolatedPathUpdateRequest request;
    request.transaction = transaction;
    request.session = IsolatedSessionKey{record->mmeUeS1apId, record->pdnAddress};
    request.mmeAssociationEpoch = record->sourceAssociationEpoch;
    request.targetEnbId = record->target.enbId;
    request.targetS1uAddress = accepted.front().endpoint.address;
    request.expectedGeneration = *generation;
    request.bearers = std::move(accepted);

    record->corePath.enabled = true;
    record->corePath.request = std::move(request);

    CoordinationRefusalRecord step;
    if (!coordinator.advance(transaction, OrchestrationState::CORE_UPDATE_REQUESTED, &step))
    {
        record->corePath.enabled = false;
        record->corePath.request = IsolatedPathUpdateRequest{};
        return refuse(CorePathRefusal::WRONG_STATE, step.detail);
    }
    record->corePath.dispatched = true;
    Log("INFO", "Isolated MME dispatched a bearer path update for " + ToString(record->corePath.request.session) +
                    " to target eNB " + std::to_string(record->target.enbId) + " with " +
                    std::to_string(record->corePath.request.bearers.size()) + " accepted bearer(s)");
    return true;
}

CorePathOutcome ApplyIsolatedBearerPathUpdate(IsolatedSgw &sgw, HandoverCoordinator &coordinator,
                                              const HandoverTransactionId &transaction)
{
    CorePathOutcome outcome;
    auto refuse = [&outcome](CorePathRefusal why, std::string detail) {
        outcome.refusal = CorePathRefusalRecord{why, std::move(detail)};
        return outcome;
    };

    if (!coordinator.enabled() || !sgw.enabled())
        return refuse(CorePathRefusal::LIVE_MODE_DISABLED,
                      "an isolated core path update is never applied while attached to a live EPC");

    CoordinationRecord *record = coordinator.findMutable(transaction);
    if (record == nullptr || !record->corePath.enabled || !record->corePath.dispatched)
        return refuse(CorePathRefusal::WRONG_STATE, "this transaction dispatched no core path update");
    if (record->state != OrchestrationState::CORE_UPDATE_REQUESTED)
        return refuse(CorePathRefusal::WRONG_STATE,
                      "a core path update is applied once, from CORE_UPDATE_REQUESTED");

    // The request carries the generation the MME read when it dispatched. The
    // SGW refuses it if its map has moved since, so an update can never be
    // applied against a starting point its author did not see.
    CoordinationRefusalRecord step;
    if (!coordinator.advance(transaction, OrchestrationState::CORE_UPDATE_COMMITTING, &step))
        return refuse(CorePathRefusal::WRONG_STATE, step.detail);

    // From here the SGW owns the publication. It validates the whole set and
    // publishes it in one step, or publishes nothing.
    const IsolatedPathUpdateCommit commit = sgw.apply(record->corePath.request);
    if (!commit.committed)
    {
        outcome.refusal = commit.refusal;
        outcome.detail = commit.refusal.has_value() ? commit.refusal->detail : std::string{};
        coordinator.advance(transaction, OrchestrationState::CORE_UPDATE_FAILED, nullptr);
        outcome.state = OrchestrationState::CORE_UPDATE_FAILED;
        Log("WARN", "Isolated core path update refused: " +
                        std::string(commit.refusal.has_value() ? ToString(commit.refusal->refusal) : "UNKNOWN"));
        return outcome;
    }

    // The MME does not trust the answer it asked for. It reads the map back and
    // verifies the installed generation, owner, EBI set and every destination
    // against what it dispatched.
    const auto confirmation =
        ReadIsolatedPathState(sgw, record->corePath.request.session, record->corePath.request.mmeAssociationEpoch);
    if (!confirmation.has_value())
    {
        record->corePath.indeterminate = true;
        coordinator.advance(transaction, OrchestrationState::CORE_UPDATE_INDETERMINATE, nullptr);
        outcome.indeterminate = true;
        outcome.state = OrchestrationState::CORE_UPDATE_INDETERMINATE;
        outcome.detail = "the isolated SGW reported a commit but holds no readable path for the session";
        return outcome;
    }

    const auto verification = VerifyIsolatedPathConfirmation(record->corePath.request, *confirmation);
    record->corePath.verification = verification;
    record->corePath.confirmation = *confirmation;
    if (!verification.confirmed())
    {
        record->corePath.indeterminate = true;
        coordinator.advance(transaction, OrchestrationState::CORE_UPDATE_INDETERMINATE, nullptr);
        outcome.indeterminate = true;
        outcome.state = OrchestrationState::CORE_UPDATE_INDETERMINATE;
        outcome.detail = std::string("the installed mapping does not match the request: ") +
                         ToString(verification.verdict) + " (" + verification.detail + ")";
        return outcome;
    }

    record->corePath.committed = true;
    record->corePath.pathGeneration = confirmation->pathGeneration;
    if (!coordinator.advance(transaction, OrchestrationState::CORE_PATH_UPDATED, &step))
        return refuse(CorePathRefusal::WRONG_STATE, step.detail);

    outcome.committed = true;
    outcome.confirmed = true;
    outcome.pathGeneration = record->corePath.pathGeneration;
    outcome.state = OrchestrationState::CORE_PATH_UPDATED;
    Log("INFO", "Isolated MME confirmed downlink path generation " +
                    std::to_string(record->corePath.pathGeneration) + " for " +
                    ToString(record->corePath.request.session) + " against the SGW's installed mapping");
    return outcome;
}

CorePathOutcome ReconcileIsolatedPathUpdate(IsolatedSgw &sgw, HandoverCoordinator &coordinator,
                                            const HandoverTransactionId &transaction)
{
    CorePathOutcome outcome;
    auto refuse = [&outcome](CorePathRefusal why, std::string detail) {
        outcome.refusal = CorePathRefusalRecord{why, std::move(detail)};
        return outcome;
    };

    if (!coordinator.enabled() || !sgw.enabled())
        return refuse(CorePathRefusal::LIVE_MODE_DISABLED,
                      "an isolated core path is never reconciled while attached to a live EPC");

    CoordinationRecord *record = coordinator.findMutable(transaction);
    if (record == nullptr || !record->corePath.enabled || !record->corePath.dispatched)
        return refuse(CorePathRefusal::WRONG_STATE, "this transaction dispatched no core path update");
    if (record->state != OrchestrationState::CORE_UPDATE_INDETERMINATE &&
        record->state != OrchestrationState::CORE_UPDATE_COMMITTING)
        return refuse(CorePathRefusal::WRONG_STATE,
                      "only an update whose answer was not observed can be reconciled");

    // Read the actual map. Nothing is applied again: a second apply would be a
    // second update, which is exactly what a lost answer must never cause.
    const auto confirmation =
        ReadIsolatedPathState(sgw, record->corePath.request.session, record->corePath.request.mmeAssociationEpoch);
    if (!confirmation.has_value())
    {
        outcome.indeterminate = true;
        outcome.state = record->state;
        outcome.detail = "the isolated SGW holds no readable path for this session";
        return outcome;
    }
    const auto verification = VerifyIsolatedPathConfirmation(record->corePath.request, *confirmation);
    record->corePath.verification = verification;
    if (!verification.confirmed())
    {
        record->corePath.indeterminate = true;
        outcome.indeterminate = true;
        outcome.state = record->state;
        outcome.detail = std::string("the installed mapping cannot be reconciled: ") + ToString(verification.verdict) +
                         " (" + verification.detail + ")";
        return outcome;
    }

    record->corePath.confirmation = *confirmation;
    record->corePath.committed = true;
    record->corePath.indeterminate = false;
    record->corePath.pathGeneration = confirmation->pathGeneration;
    CoordinationRefusalRecord step;
    if (!coordinator.advance(transaction, OrchestrationState::CORE_PATH_UPDATED, &step))
        return refuse(CorePathRefusal::WRONG_STATE, step.detail);

    outcome.committed = true;
    outcome.confirmed = true;
    outcome.pathGeneration = record->corePath.pathGeneration;
    outcome.state = OrchestrationState::CORE_PATH_UPDATED;
    Log("INFO", "Isolated MME reconciled path generation " + std::to_string(record->corePath.pathGeneration) +
                    " for " + ToString(record->corePath.request.session) +
                    " from the SGW's installed mapping; no second update was applied");
    return outcome;
}

} // namespace lte::enb::s1ap
