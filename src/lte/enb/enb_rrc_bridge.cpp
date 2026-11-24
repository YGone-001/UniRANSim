//
// This file is a part of UERANSIM project.
// Copyright (c) 2027 ALİ GÜNGÖR.
//

#include "enb_rrc_bridge.hpp"

#include "s1ap_security_capabilities.hpp"

#include <algorithm>
#include <string>

namespace lte::enb::s1ap
{

EnbRrcBridge::EnbRrcBridge(uu::Socket &socket, Config config, S1apSink sink)
    : socket_(socket), config_(std::move(config)), sink_(std::move(sink)),
      runtime_(socket, config_.srb1,
               [this](uint32_t association, const RrcConnectionSetupCompleteMessage &message) {
                   OnSetupComplete(association, message);
               })
{
    runtime_.SetUplinkNasCallback([this](uint32_t association, const std::vector<uint8_t> &nas) {
        OnUplinkNas(association, nas);
    });
}

EnbRrcBridge::EnbRrcBridge(uu::Socket &socket, Config config, IdentifiedSink sink, IdAllocator allocator,
                         SetupHandler onSetup)
    : socket_(socket), config_(std::move(config)), identifiedSink_(std::move(sink)), allocator_(std::move(allocator)),
      onSetup_(std::move(onSetup)),
      runtime_(socket, config_.srb1,
               [this](uint32_t association, const RrcConnectionSetupCompleteMessage &message) {
                   OnSetupComplete(association, message);
               })
{
    runtime_.SetUplinkNasCallback([this](uint32_t association, const std::vector<uint8_t> &nas) {
        OnUplinkNas(association, nas);
    });
}

void EnbRrcBridge::Pump(int timeoutMs)
{
    runtime_.Pump(timeoutMs);
}

void EnbRrcBridge::Tick()
{
    runtime_.Tick();
}

void EnbRrcBridge::OnSetupComplete(uint32_t association, const RrcConnectionSetupCompleteMessage &message)
{
    if (associations_.find(association) != associations_.end())
    {
        refused_++;
        return;
    }

    Association entry;
    entry.enbUeS1apId = allocator_ ? allocator_() : nextEnbUeS1apId_++;
    if (entry.enbUeS1apId == 0)
    {
        refused_++;
        return;
    }
    associations_.emplace(association, entry);
    byEnbId_[entry.enbUeS1apId] = association;

    // The owner binds its own registry slot before any S1AP answer about this
    // UE can arrive; the MME identity is still unknown and stays zero.
    if (onSetup_)
        onSetup_(association, entry.enbUeS1apId, runtime_.PeerPortOf(association), message.dedicatedInfoNas);

    // A UE that reconnects for a Service Request is named to the MME by the
    // S-TMSI it used in the RRC request, exactly as TS 36.413 9.2.3.13 allows.
    // The UE is no longer idle once its S1 context exists again.
    std::optional<STmsi> sTmsi;
    if (const auto &request = runtime_.RequestOf(association); request.has_value())
        sTmsi = STmsi{request->mmec, request->mTmsi};
    const uint16_t radioPort = runtime_.PeerPortOf(association);
    idleEndpoints_.erase(std::remove_if(idleEndpoints_.begin(), idleEndpoints_.end(),
                                        [radioPort](const IdleEndpoint &entry) { return entry.port == radioPort; }),
                         idleEndpoints_.end());

    // The MME has not named the UE yet: an Initial UE Message carries no
    // MME-UE-S1AP-ID, and none is invented here.
    const auto pdu = EncodeInitialUeMessage(config_.enb, entry.enbUeS1apId, message.dedicatedInfoNas, sTmsi);
    initialUeMessages_++;
    Emit(entry.enbUeS1apId, pdu);
}

void EnbRrcBridge::Emit(uint32_t enbUeS1apId, const std::vector<uint8_t> &pdu)
{
    if (identifiedSink_)
        identifiedSink_(enbUeS1apId, pdu);
    else if (sink_)
        sink_(pdu);
}

void EnbRrcBridge::OnUplinkNas(uint32_t association, const std::vector<uint8_t> &nas)
{
    const auto it = associations_.find(association);
    if (it == associations_.end() || it->second.mmeUeS1apId == 0)
    {
        // Nothing may be sent before the MME named the UE: an Uplink NAS
        // Transport needs the identity pair.
        refused_++;
        return;
    }

    UeContext context;
    context.enbUeS1apId = it->second.enbUeS1apId;
    context.mmeUeS1apId = it->second.mmeUeS1apId;
    const auto pdu = EncodeUplinkNasTransport(config_.enb, context, nas);
    uplinkNasTransports_++;
    Emit(it->second.enbUeS1apId, pdu);
}

void EnbRrcBridge::OnDownlinkNasTransport(const std::vector<uint8_t> &pdu)
{
    DownlinkNasTransport message;
    try
    {
        message = DecodeDownlinkNasTransport(pdu.data(), pdu.size());
    }
    catch (const CodecError &)
    {
        refused_++;
        return;
    }

    const auto mapped = byEnbId_.find(message.enbUeS1apId);
    const auto it = mapped == byEnbId_.end() ? associations_.end() : associations_.find(mapped->second);
    if (it == associations_.end())
    {
        refused_++;
        return;
    }
    if (it->second.mmeUeS1apId == 0)
    {
        // The first downlink NAS names the MME identity; a later one must match.
        it->second.mmeUeS1apId = message.mmeUeS1apId;
    }
    else if (it->second.mmeUeS1apId != message.mmeUeS1apId)
    {
        refused_++;
        return;
    }

    if (message.nasPdu.empty())
    {
        refused_++;
        return;
    }
    downlinkNasTransports_++;
    runtime_.SendDownlinkNas(it->first, message.nasPdu);
}

void EnbRrcBridge::OnInitialContextSetupRequest(const std::vector<uint8_t> &pdu)
{
    InitialContextSetupRequest request;
    try
    {
        request = DecodeInitialContextSetupRequest(pdu.data(), pdu.size());
    }
    catch (const CodecError &)
    {
        refused_++;
        return;
    }

    const auto mapped = byEnbId_.find(request.enbUeS1apId);
    const auto it = mapped == byEnbId_.end() ? associations_.end() : associations_.find(mapped->second);
    if (it == associations_.end() || it->second.icsPending || it->second.icsCompleted)
    {
        refused_++;
        return;
    }
    if (it->second.mmeUeS1apId != 0 && it->second.mmeUeS1apId != request.mmeUeS1apId)
    {
        refused_++;
        return;
    }
    if (request.erabs.empty())
    {
        refused_++;
        return;
    }

    it->second.mmeUeS1apId = request.mmeUeS1apId;
    it->second.request = request;
    it->second.icsPending = true;

    // TS 36.413 9.2.1.88: the capability BIT STRING is read most significant bit
    // first, with EEA0/EIA0 in the first bit. A raw cast would read EEA0 as
    // EEA15.
    const auto capabilities = MapUeSecurityCapabilities(request.encryptionAlgorithms, request.integrityAlgorithms);
    const security::Key256 kenb = request.securityKey;

    try
    {
        runtime_.StartAsSecurity(it->first, kenb, capabilities, config_.algorithms, request.mmeUeS1apId, 0);
    }
    catch (const std::exception &)
    {
        // No algorithm, no key, no common set: the transaction fails closed and
        // nothing is reported as set up.
        it->second.icsPending = false;
        refused_++;
    }
}

void EnbRrcBridge::StartAsSecurity(uint32_t association, const InitialContextSetupRequest &request)
{
    const auto it = associations_.find(association);
    if (it == associations_.end())
        throw lte::rrc::Srb1RuntimeException(lte::rrc::Srb1RuntimeError::NOT_ESTABLISHED);
    if (request.enbUeS1apId != it->second.enbUeS1apId)
        throw s1ap::CodecError("Initial Context Setup Request names another eNB-UE-S1AP-ID");
    if (it->second.mmeUeS1apId != 0 && it->second.mmeUeS1apId != request.mmeUeS1apId)
        throw s1ap::CodecError("Initial Context Setup Request names another MME-UE-S1AP-ID");

    it->second.mmeUeS1apId = request.mmeUeS1apId;
    const auto capabilities = MapUeSecurityCapabilities(request.encryptionAlgorithms, request.integrityAlgorithms);
    runtime_.StartAsSecurity(association, request.securityKey, capabilities, config_.algorithms,
                             request.mmeUeS1apId, 0);
}

void EnbRrcBridge::SendDownlinkNas(uint32_t association, const std::vector<uint8_t> &nas)
{
    runtime_.SendDownlinkNas(association, nas);
}

void EnbRrcBridge::CompleteInitialContextSetup(uint32_t association, const std::vector<ErabSetupItem> &erabs)
{
    const auto it = associations_.find(association);
    if (it == associations_.end() || !it->second.icsPending || it->second.icsCompleted)
    {
        refused_++;
        return;
    }
    if (!runtime_.AsSecurityActive(association))
    {
        // Reporting the outcome before the radio security procedure completed
        // would claim a bearer the UE cannot use.
        refused_++;
        return;
    }

    const auto pdu = EncodeInitialContextSetupResponse(it->second.mmeUeS1apId, it->second.enbUeS1apId, erabs);
    it->second.icsPending = false;
    it->second.icsCompleted = true;
    setupResponses_++;
    Emit(it->second.enbUeS1apId, pdu);
}

void EnbRrcBridge::OnUeContextReleaseCommand(const std::vector<uint8_t> &pdu)
{
    UeContextReleaseCommand command;
    try
    {
        command = DecodeUeContextReleaseCommand(pdu.data(), pdu.size());
    }
    catch (const CodecError &)
    {
        refused_++;
        return;
    }
    if (!command.enbUeS1apId.has_value())
    {
        // The eNB must be told which of its UEs is released; a command without
        // the eNB identity cannot be matched to any radio context.
        refused_++;
        return;
    }
    const auto mapped = byEnbId_.find(*command.enbUeS1apId);
    if (mapped == byEnbId_.end())
    {
        refused_++;
        return;
    }
    const auto it = associations_.find(mapped->second);
    if (it == associations_.end() || it->second.mmeUeS1apId != command.mmeUeS1apId)
    {
        refused_++;
        return;
    }
    const uint32_t association = mapped->second;
    const uint32_t enbUeS1apId = it->second.enbUeS1apId;
    const auto request = runtime_.RequestOf(association);
    const uint16_t peerPort = runtime_.PeerPortOf(association);

    // TS 36.331 5.3.8: the connection is released over the radio, and the S1AP
    // transaction is only complete once the eNB reports it.
    runtime_.SendRrcRelease(association);
    Emit(enbUeS1apId, EncodeUeContextReleaseComplete(command.mmeUeS1apId, enbUeS1apId));
    releaseCompletes_++;

    // The MME keeps its UE context; the eNB keeps just enough to page the UE
    // back. The radio bearer and the association itself are gone.
    const bool alreadyRetained = std::any_of(idleEndpoints_.begin(), idleEndpoints_.end(),
                                             [peerPort](const IdleEndpoint &entry) { return entry.port == peerPort; });
    if (!alreadyRetained)
        idleEndpoints_.push_back({association, peerPort});
    byEnbId_.erase(enbUeS1apId);
    associations_.erase(it);
    runtime_.ReleaseContext(association);
}

bool EnbRrcBridge::PageUe(const STmsi &sTmsi)
{
    if (idleEndpoints_.empty())
        return false;
    // One cell-wide page, delivered to every retained idle endpoint. Each UE
    // matches its own S-TMSI and ignores a page addressed to another identity.
    for (const auto &endpoint : idleEndpoints_)
        runtime_.SendPaging(endpoint.port, endpoint.association, sTmsi.mmeCode, sTmsi.mTmsi);
    pagesSent_++;
    return true;
}

void EnbRrcBridge::OnS1AssociationLost()
{
    for (const auto &entry : associations_)
    {
        // The radio association, its SRB1 bearer and its AS security state
        // belonged to the S1 context that just went away.
        runtime_.Release(entry.first);
    }
    associations_.clear();
    byEnbId_.clear();
}

bool EnbRrcBridge::HasContext(uint32_t association) const
{
    return associations_.find(association) != associations_.end();
}

RrcState EnbRrcBridge::StateOf(uint32_t association) const
{
    return runtime_.StateOf(association);
}

std::optional<uint32_t> EnbRrcBridge::EnbUeS1apIdOf(uint32_t association) const
{
    const auto it = associations_.find(association);
    return it == associations_.end() ? std::nullopt : std::optional<uint32_t>(it->second.enbUeS1apId);
}

std::optional<uint32_t> EnbRrcBridge::MmeUeS1apIdOf(uint32_t association) const
{
    const auto it = associations_.find(association);
    if (it == associations_.end() || it->second.mmeUeS1apId == 0)
        return std::nullopt;
    return it->second.mmeUeS1apId;
}

std::optional<uint32_t> EnbRrcBridge::AssociationOf(uint32_t enbUeS1apId) const
{
    const auto it = byEnbId_.find(enbUeS1apId);
    return it == byEnbId_.end() ? std::nullopt : std::optional<uint32_t>(it->second);
}

bool EnbRrcBridge::AsSecurityActive(uint32_t association) const
{
    return runtime_.AsSecurityActive(association);
}

} // namespace lte::enb::s1ap
