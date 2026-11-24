//
// This file is a part of UERANSIM project.
// Copyright (c) 2027 ALİ GÜNGÖR.
//

#include "rrc_srb1_runtime.hpp"

namespace lte::rrc
{

const char *ToString(Srb1RuntimeError error)
{
    switch (error)
    {
    case Srb1RuntimeError::NOT_ESTABLISHED: return "NOT_ESTABLISHED";
    case Srb1RuntimeError::NO_SETUP_CONFIGURED: return "NO_SETUP_CONFIGURED";
    case Srb1RuntimeError::UNEXPECTED_STATE: return "UNEXPECTED_STATE";
    case Srb1RuntimeError::ENCODE_FAILED: return "ENCODE_FAILED";
    case Srb1RuntimeError::SECURITY_NOT_PREPARED: return "SECURITY_NOT_PREPARED";
    case Srb1RuntimeError::SECURITY_ALREADY_ACTIVE: return "SECURITY_ALREADY_ACTIVE";
    case Srb1RuntimeError::SECURITY_REQUIRED: return "SECURITY_REQUIRED";
    }
    return "UNKNOWN_SRB1_RUNTIME_ERROR";
}

Srb1RuntimeException::Srb1RuntimeException(Srb1RuntimeError reason)
    : std::runtime_error(std::string("SRB1 runtime refusal: ") + ToString(reason)), reason_(reason)
{
}

namespace
{

const std::vector<uint8_t> &EmptyBytes()
{
    static const std::vector<uint8_t> empty{};
    return empty;
}

} // namespace

// --- UE ---------------------------------------------------------------------

UeSrb1Runtime::UeSrb1Runtime(uu::Socket &socket, uint16_t enbPort, Config config)
    : socket_(socket), enbPort_(enbPort), config_(config), srb0_(rlc::TmEntity::Create(config.association)),
      access_(UeInitialAccess::Idle(config.association, config.mmec, config.mTmsi)),
      pdcp_(pdcp::SrbPdcpEntity::Create(true))
{
}

void UeSrb1Runtime::StartAccess()
{
    const std::vector<uint8_t> request = srb0_.Submit(access_.BuildRequest());
    state_ = access_.State();

    uu::Frame frame;
    frame.association = config_.association;
    frame.direction = uu::Direction::UPLINK;
    frame.channel = uu::LogicalChannel::CCCH;
    frame.payload = request;
    if (!socket_.Send(enbPort_, frame, nullptr))
        throw Srb1RuntimeException(Srb1RuntimeError::ENCODE_FAILED);
}

void UeSrb1Runtime::Pump(int timeoutMs)
{
    uu::Frame frame;
    if (!socket_.Receive(frame, timeoutMs, nullptr))
        return;

    if (frame.association != config_.association)
    {
        refused_++;
        return;
    }

    if (frame.channel == uu::LogicalChannel::PCCH)
    {
        // A page is only meaningful while this UE is idle. A connected UE has
        // no page to answer, and a page for another identity is counted and
        // never acted on.
        if (frame.direction != uu::Direction::DOWNLINK || frame.payload.empty())
        {
            refused_++;
            return;
        }
        if (state_ != RrcState::RRC_IDLE)
        {
            refused_++;
            return;
        }
        PagingMessage paging;
        if (!DecodePaging(frame.payload.data(), frame.payload.size(), paging))
        {
            refused_++;
            return;
        }
        evidence_.pagingsReceived++;
        for (const auto &record : paging.records)
        {
            if (record.csDomain)
                continue;
            if (record.mmec != config_.mmec || record.mTmsi != config_.mTmsi)
                continue;
            evidence_.pagingsMatched++;
            if (onPaging_)
                onPaging_(record.mmec, record.mTmsi);
            return;
        }
        return;
    }

    if (frame.channel == uu::LogicalChannel::CCCH)
    {
        if (frame.direction != uu::Direction::DOWNLINK || frame.payload.empty())
        {
            refused_++;
            return;
        }
        if (state_ == RrcState::RRC_CONNECTION_REQUEST_PENDING)
            OnAccessAnswer(frame);
        else
            refused_++;
        return;
    }

    if (bearer_ == nullptr)
    {
        refused_++;
        return;
    }
    if (!bearer_->OnFrame(frame))
    {
        refused_++;
        return;
    }
}

void UeSrb1Runtime::OnAccessAnswer(const uu::Frame &frame)
{
    try
    {
        access_.OnDownlink(srb0_.Deliver(frame.payload));
    }
    catch (const AccessException &)
    {
        // The access layer already moved the state to its terminal value.
    }

    state_ = access_.State();
    if (state_ != RrcState::RRC_SRB1_CONFIGURING)
        return;

    if (!access_.StagedSrb1().has_value())
        throw Srb1RuntimeException(Srb1RuntimeError::NO_SETUP_CONFIGURED);
    setup_ = access_.StagedSrb1();
    EstablishSrb1(*setup_);
}

void UeSrb1Runtime::EstablishSrb1(const RrcConnectionSetupMessage &setup)
{
    resolved_ = MapSrb1Configuration(setup);
    bearer_ = std::make_unique<LteAmBearer>(
        socket_, enbPort_, EndpointRole::UE, config_.association, resolved_.am,
        [this](std::vector<uint8_t> pdu) { OnSrb1Pdu(std::move(pdu)); });
    state_ = RrcState::RRC_SRB1_CONFIGURING;
}

void UeSrb1Runtime::SetNasCallback(NasCallback callback)
{
    onNas_ = std::move(callback);
}

std::vector<uint8_t> UeSrb1Runtime::Protect(const std::vector<uint8_t> &rrc)
{
    if (secured_ && secureTx_.has_value())
        return secureTx_->Protect(rrc);
    return pdcp_.Protect(rrc);
}

std::vector<uint8_t> UeSrb1Runtime::Unprotect(const std::vector<uint8_t> &pdu)
{
    if (secured_ && secureRx_.has_value())
        return secureRx_->Unprotect(pdu);
    return pdcp_.Unprotect(pdu);
}

void UeSrb1Runtime::OnSrb1Pdu(std::vector<uint8_t> pdu)
{
    if (expectingCommand_ && asContext_.has_value())
    {
        // The NAS layer has completed NAS security, so the next SRB1 PDU may be
        // the RRC SecurityModeCommand. The procedure verifies it against its own
        // COUNT 0 and answers with the protected completion.
        expectingCommand_ = false;
        procedure_ = security::UeAsSecurityProcedure::Listening(*asContext_, config_.association);
        const std::vector<uint8_t> response = procedure_->OnCommand(pdu);
        if (procedure_->State() == security::AsSecurityState::COMPLETE_PENDING)
        {
            procedure_->ConfirmCompleteSent();
            secureTx_ = procedure_->TakeTx();
            secureRx_ = procedure_->TakeRx();
            secured_ = true;
        }
        if (!response.empty() && bearer_ != nullptr)
        {
            bearer_->SubmitSdu(response);
            evidence_.pdcpPdus++;
        }
        return;
    }

    std::vector<uint8_t> rrc;
    try
    {
        rrc = Unprotect(pdu);
    }
    catch (const pdcp::SrbPdcpException &)
    {
        refused_++;
        return;
    }
    OnRrc(rrc);
}

void UeSrb1Runtime::OnRrc(const std::vector<uint8_t> &rrc)
{
    InformationTransferMessage information;
    if (DecodeDlInformationTransfer(rrc.data(), rrc.size(), information))
    {
        evidence_.downlinkNas++;
        if (onNas_)
            onNas_(information.dedicatedInfoNas);
        return;
    }

    RrcConnectionReleaseMessage release;
    if (DecodeRrcConnectionRelease(rrc.data(), rrc.size(), release))
    {
        // TS 36.331 5.3.8: the UE moves to RRC_IDLE. The teardown is deferred
        // to Tick, once the bearer that is delivering this PDU is no longer on
        // the stack.
        evidence_.releases++;
        releasePending_ = true;
        return;
    }
    refused_++;
}

void UeSrb1Runtime::EnterIdle()
{
    if (bearer_ != nullptr)
    {
        bearer_->Release();
        bearer_.reset();
    }
    pdcp_.Release();
    pdcp_ = pdcp::SrbPdcpEntity::Create(true);
    secureTx_.reset();
    secureRx_.reset();
    asContext_.reset();
    procedure_.reset();
    secured_ = false;
    expectingCommand_ = false;
    setup_.reset();
    access_ = UeInitialAccess::Idle(config_.association, config_.mmec, config_.mTmsi);
    expectedAck_ = 0;
    state_ = RrcState::RRC_IDLE;
}

void UeSrb1Runtime::SetReleaseCallback(ReleaseCallback callback)
{
    onRelease_ = std::move(callback);
}

void UeSrb1Runtime::SetPagingCallback(PagingCallback callback)
{
    onPaging_ = std::move(callback);
}

void UeSrb1Runtime::SetIdentity(uint8_t mmec, uint32_t mTmsi)
{
    if (mTmsi == 0)
        throw Srb1RuntimeException(Srb1RuntimeError::UNEXPECTED_STATE);
    config_.mmec = mmec;
    config_.mTmsi = mTmsi;
    // While connected the current access keeps the identity it was established
    // with; EnterIdle() builds the next request from the new one.
    if (state_ == RrcState::RRC_IDLE)
        access_ = UeInitialAccess::Idle(config_.association, mmec, mTmsi);
}

void UeSrb1Runtime::SubmitSetupComplete(const std::vector<uint8_t> &nas)
{
    if (bearer_ == nullptr)
        throw Srb1RuntimeException(Srb1RuntimeError::NOT_ESTABLISHED);
    if (state_ != RrcState::RRC_SRB1_CONFIGURING || !setup_.has_value())
        throw Srb1RuntimeException(Srb1RuntimeError::UNEXPECTED_STATE);

    RrcConnectionSetupCompleteMessage message;
    message.transactionId = setup_->transactionId;
    message.selectedPlmnIdentity = config_.selectedPlmnIdentity;
    message.dedicatedInfoNas = nas;

    const std::vector<uint8_t> rrcPdu = EncodeRrcConnectionSetupComplete(message);
    if (rrcPdu.empty())
        throw Srb1RuntimeException(Srb1RuntimeError::ENCODE_FAILED);

    const std::vector<uint8_t> pdcpPdu = pdcp_.Protect(rrcPdu);
    evidence_.lastRrcPdu = rrcPdu;
    evidence_.lastPdcpPdu = pdcpPdu;
    evidence_.lastPdcpSn = static_cast<uint8_t>(pdcpPdu[0] & 0x1FU);
    evidence_.pdcpPdus++;
    evidence_.rrcMessages++;

    bearer_->SubmitSdu(pdcpPdu);
    expectedAck_ = bearer_->VtS();
    state_ = RrcState::RRC_CONNECTION_COMPLETE_PENDING;
}

void UeSrb1Runtime::SubmitNas(const std::vector<uint8_t> &nas)
{
    if (bearer_ == nullptr)
        throw Srb1RuntimeException(Srb1RuntimeError::NOT_ESTABLISHED);

    InformationTransferMessage message;
    message.dedicatedInfoNas = nas;
    const std::vector<uint8_t> rrc = EncodeUlInformationTransfer(message);
    if (rrc.empty())
        throw Srb1RuntimeException(Srb1RuntimeError::ENCODE_FAILED);

    const std::vector<uint8_t> pdu = Protect(rrc);
    bearer_->SubmitSdu(pdu);
    evidence_.uplinkNas++;
    evidence_.rrcMessages++;
}

void UeSrb1Runtime::PrepareAsSecurity(const security::Key256 &kasme, uint32_t ulNasCount, uint64_t nasGeneration)
{
    if (bearer_ == nullptr)
        throw Srb1RuntimeException(Srb1RuntimeError::NOT_ESTABLISHED);
    if (secured_)
        throw Srb1RuntimeException(Srb1RuntimeError::SECURITY_ALREADY_ACTIVE);

    asContext_ = security::AsSecurityContext::Create(config_.association, kasme, ulNasCount, nasGeneration,
                                                     security::AsAlgorithmSet{});
    expectingCommand_ = true;
}

bool UeSrb1Runtime::AsSecurityActive() const
{
    return secured_ && secureTx_.has_value() && secureRx_.has_value();
}

void UeSrb1Runtime::Tick()
{
    if (releasePending_)
    {
        releasePending_ = false;
        EnterIdle();
        if (onRelease_)
            onRelease_();
        return;
    }
    if (bearer_ != nullptr)
        bearer_->Tick();

    if (state_ == RrcState::RRC_CONNECTION_COMPLETE_PENDING && bearer_ != nullptr && bearer_->VtA() == expectedAck_)
        state_ = RrcState::RRC_CONNECTED;
}

void UeSrb1Runtime::Release()
{
    if (bearer_ != nullptr)
    {
        bearer_->Release();
        bearer_.reset();
    }
    pdcp_.Release();
    secureTx_.reset();
    secureRx_.reset();
    asContext_.reset();
    procedure_.reset();
    secured_ = false;
    state_ = RrcState::RRC_RELEASED;
}

// --- eNB --------------------------------------------------------------------

EnbSrb1Runtime::EnbSrb1Runtime(uu::Socket &socket, Config config, NasCallback onNas)
    : socket_(socket), config_(config), onNas_(std::move(onNas)), srb0_(rlc::TmEntity::Create(0))
{
    access_.SetSetup(config_.setup);
    (void)MapSrb1Configuration(config_.setup);
}

void EnbSrb1Runtime::SetUplinkNasCallback(UplinkNasCallback callback)
{
    onUplinkNas_ = std::move(callback);
}

void EnbSrb1Runtime::Pump(int timeoutMs)
{
    uu::Frame frame;
    uint16_t sourcePort = 0;
    if (!socket_.Receive(frame, timeoutMs, nullptr, &sourcePort))
        return;

    if (frame.channel == uu::LogicalChannel::CCCH)
        OnRequestFrame(frame.association, frame, sourcePort);
    else
        OnSrb1Frame(frame.association, frame);
}

void EnbSrb1Runtime::OnRequestFrame(uint32_t association, const uu::Frame &frame, uint16_t sourcePort)
{
    if (frame.direction != uu::Direction::UPLINK || frame.payload.empty())
    {
        refused_++;
        return;
    }

    std::vector<uint8_t> answer;
    try
    {
        answer = access_.OnRequest(association, srb0_.Deliver(frame.payload));
    }
    catch (const AccessException &)
    {
        refused_++;
        return;
    }
    if (answer.empty())
    {
        refused_++;
        return;
    }

    auto existing = contexts_.find(association);
    if (existing != contexts_.end())
    {
        if (existing->second.peerPort != sourcePort)
        {
            refused_++;
            return;
        }
        uu::Frame reply;
        reply.association = association;
        reply.direction = uu::Direction::DOWNLINK;
        reply.channel = uu::LogicalChannel::CCCH;
        reply.payload = answer;
        socket_.Send(sourcePort, reply, nullptr);
        return;
    }

    Context context;
    context.state = RrcState::RRC_SETUP_PENDING;
    context.peerPort = sourcePort;
    context.transactionId = config_.setup.transactionId;
    // The RRC request carries the S-TMSI the UE was assigned. It is what the
    // Initial UE Message reports and what a later page is addressed to.
    RrcConnectionRequestMessage request;
    if (DecodeRrcConnectionRequest(frame.payload.data(), frame.payload.size(), request))
        context.request = request;
    context.resolved = MapSrb1Configuration(config_.setup);
    context.pdcp = pdcp::SrbPdcpEntity::Create(false);

    auto inserted = contexts_.emplace(association, std::move(context));
    Context &stored = inserted.first->second;
    stored.bearer = std::make_unique<LteAmBearer>(
        socket_, sourcePort, EndpointRole::ENB, association, stored.resolved.am,
        [this, association](std::vector<uint8_t> pdu) { OnPdcpPdu(contexts_.at(association), association, pdu); });

    uu::Frame reply;
    reply.association = association;
    reply.direction = uu::Direction::DOWNLINK;
    reply.channel = uu::LogicalChannel::CCCH;
    reply.payload = answer;
    socket_.Send(sourcePort, reply, nullptr);
}

void EnbSrb1Runtime::OnSrb1Frame(uint32_t association, const uu::Frame &frame)
{
    const auto it = contexts_.find(association);
    if (it == contexts_.end())
    {
        refused_++;
        return;
    }
    if (it->second.bearer == nullptr || !it->second.bearer->OnFrame(frame))
        refused_++;
}

const std::optional<RrcConnectionRequestMessage> &EnbSrb1Runtime::RequestOf(uint32_t association) const
{
    static const std::optional<RrcConnectionRequestMessage> empty{};
    const auto it = contexts_.find(association);
    return it == contexts_.end() ? empty : it->second.request;
}

void EnbSrb1Runtime::SendRrcRelease(uint32_t association)
{
    const auto it = contexts_.find(association);
    if (it == contexts_.end() || it->second.bearer == nullptr)
    {
        refused_++;
        return;
    }
    Context &context = it->second;
    if (context.state != RrcState::RRC_CONNECTED)
    {
        refusedRrc_++;
        return;
    }
    RrcConnectionReleaseMessage message;
    message.transactionId = context.transactionId & 0x03U;
    const std::vector<uint8_t> rrc = EncodeRrcConnectionRelease(message);
    if (rrc.empty())
    {
        refusedRrc_++;
        return;
    }
    context.bearer->SubmitSdu(Protect(context, rrc));
    context.state = RrcState::RRC_IDLE;
}

void EnbSrb1Runtime::ReleaseContext(uint32_t association)
{
    // The initial-access context belongs to the connection too: keeping it
    // would make the eNB refuse the UE's next RRCConnectionRequest because it
    // carries the newly assigned S-TMSI.
    access_.Release(association);
    const auto it = contexts_.find(association);
    if (it == contexts_.end())
        return;
    if (it->second.bearer != nullptr)
    {
        it->second.bearer->Release();
        it->second.bearer.reset();
    }
    contexts_.erase(it);
}

void EnbSrb1Runtime::SendPaging(uint16_t peerPort, uint32_t association, uint8_t mmec, uint32_t mTmsi)
{
    PagingMessage message;
    PagingRecord record;
    record.mmec = mmec;
    record.mTmsi = mTmsi;
    record.csDomain = false;
    message.records.push_back(record);
    const std::vector<uint8_t> pdu = EncodePaging(message);
    if (pdu.empty())
    {
        refused_++;
        return;
    }
    uu::Frame frame;
    frame.association = association;
    frame.direction = uu::Direction::DOWNLINK;
    frame.channel = uu::LogicalChannel::PCCH;
    frame.payload = pdu;
    socket_.Send(peerPort, frame, nullptr);
}

std::vector<uint8_t> EnbSrb1Runtime::Protect(Context &context, const std::vector<uint8_t> &rrc)
{
    if (context.secured && context.secureTx.has_value())
        return context.secureTx->Protect(rrc);
    return context.pdcp.Protect(rrc);
}

std::vector<uint8_t> EnbSrb1Runtime::Unprotect(Context &context, const std::vector<uint8_t> &pdu)
{
    if (context.secured && context.secureRx.has_value())
        return context.secureRx->Unprotect(pdu);
    return context.pdcp.Unprotect(pdu);
}

void EnbSrb1Runtime::OnPdcpPdu(Context &context, uint32_t association, const std::vector<uint8_t> &pdu)
{
    context.pdcpPdus.push_back(pdu);

    // The first uplink after the command is the SecurityModeComplete, which the
    // procedure verifies with the entities it created. It is never handed to the
    // steady-state receive path.
    if (context.procedure.has_value() &&
        context.procedure->State() == security::AsSecurityState::COMMAND_PENDING)
    {
        try
        {
            context.procedure->OnComplete(pdu);
        }
        catch (const security::ProcedureException &)
        {
            refusedRrc_++;
            return;
        }
        context.secureTx = context.procedure->TakeTx();
        context.secureRx = context.procedure->TakeRx();
        context.secured = context.secureTx.has_value() && context.secureRx.has_value();
        return;
    }

    if (context.state != RrcState::RRC_CONNECTED && context.state != RrcState::RRC_SETUP_PENDING)
    {
        refusedRrc_++;
        return;
    }

    std::vector<uint8_t> rrc;
    try
    {
        rrc = Unprotect(context, pdu);
    }
    catch (const pdcp::SrbPdcpException &)
    {
        // Before the connection is up the only expected SRB1 PDU is the
        // SetupComplete, so a malformed PDU is a refused SetupComplete.
        if (context.state == RrcState::RRC_SETUP_PENDING)
            refusedSetupComplete_++;
        else
            refusedRrc_++;
        return;
    }
    catch (const security::PdcpSecurityException &)
    {
        // A bad MAC-I, a replayed COUNT or a malformed secure header: nothing is
        // delivered and no state is replaced.
        refusedRrc_++;
        return;
    }
    OnRrc(context, association, rrc);
}

void EnbSrb1Runtime::OnRrc(Context &context, uint32_t association, const std::vector<uint8_t> &rrc)
{
    // Before the SetupComplete is accepted, the only RRC message on SRB1 is it.
    if (context.state == RrcState::RRC_SETUP_PENDING)
    {
        RrcConnectionSetupCompleteMessage message;
        if (!DecodeRrcConnectionSetupComplete(rrc.data(), rrc.size(), message))
        {
            refusedSetupComplete_++;
            return;
        }
        if (message.transactionId != context.transactionId ||
            message.selectedPlmnIdentity != config_.expectedPlmnIdentity)
        {
            refusedSetupComplete_++;
            return;
        }

        context.received = message;
        context.deliveredNas = message.dedicatedInfoNas;
        context.deliveries++;
        context.state = RrcState::RRC_CONNECTED;
        if (onNas_)
            onNas_(association, message);
        return;
    }

    InformationTransferMessage information;
    if (DecodeUlInformationTransfer(rrc.data(), rrc.size(), information))
    {
        context.uplinkNas.push_back(information.dedicatedInfoNas);
        if (onUplinkNas_)
            onUplinkNas_(association, information.dedicatedInfoNas);
        return;
    }
    refusedRrc_++;
}

void EnbSrb1Runtime::SendDownlinkNas(uint32_t association, const std::vector<uint8_t> &nas)
{
    const auto it = contexts_.find(association);
    if (it == contexts_.end() || it->second.bearer == nullptr)
    {
        refused_++;
        return;
    }
    Context &context = it->second;
    if (context.state != RrcState::RRC_CONNECTED)
    {
        refusedRrc_++;
        return;
    }

    InformationTransferMessage message;
    message.dedicatedInfoNas = nas;
    const std::vector<uint8_t> rrc = EncodeDlInformationTransfer(message);
    if (rrc.empty())
    {
        refusedRrc_++;
        return;
    }
    context.bearer->SubmitSdu(Protect(context, rrc));
    context.downlinkNas++;
}

void EnbSrb1Runtime::StartAsSecurity(uint32_t association, const security::Key256 &kenb,
                                     const security::UeAlgorithmCapabilities &capabilities,
                                     const security::AsAlgorithmConfiguration &configuration,
                                     uint64_t s1Generation, uint8_t transactionId)
{
    const auto it = contexts_.find(association);
    if (it == contexts_.end() || it->second.bearer == nullptr)
        throw Srb1RuntimeException(Srb1RuntimeError::NOT_ESTABLISHED);
    Context &context = it->second;
    if (context.secured)
        throw Srb1RuntimeException(Srb1RuntimeError::SECURITY_ALREADY_ACTIVE);

    context.asContext = security::EnbAsSecurityContext::Create(association, kenb, s1Generation);
    context.procedure = security::EnbAsSecurityProcedure::Start(*context.asContext, association, capabilities,
                                                               configuration, configuration.ciphering.generation,
                                                               transactionId);
    // The command is already an integrity-protected PDCP PDU: it bypasses the
    // pre-security profile and is the first secure downlink COUNT.
    context.bearer->SubmitSdu(context.procedure->Command());
}

void EnbSrb1Runtime::Tick()
{
    for (auto &entry : contexts_)
    {
        if (entry.second.bearer != nullptr)
            entry.second.bearer->Tick();
    }
}

bool EnbSrb1Runtime::HasContext(uint32_t association) const
{
    return contexts_.find(association) != contexts_.end();
}

RrcState EnbSrb1Runtime::StateOf(uint32_t association) const
{
    const auto it = contexts_.find(association);
    return it == contexts_.end() ? RrcState::RRC_IDLE : it->second.state;
}

uint16_t EnbSrb1Runtime::PeerPortOf(uint32_t association) const
{
    const auto it = contexts_.find(association);
    return it == contexts_.end() ? 0 : it->second.peerPort;
}

size_t EnbSrb1Runtime::Deliveries(uint32_t association) const
{
    const auto it = contexts_.find(association);
    return it == contexts_.end() ? 0 : it->second.deliveries;
}

const std::vector<uint8_t> &EnbSrb1Runtime::DeliveredNas(uint32_t association) const
{
    const auto it = contexts_.find(association);
    return it == contexts_.end() ? EmptyBytes() : it->second.deliveredNas;
}

const std::optional<RrcConnectionSetupCompleteMessage> &EnbSrb1Runtime::ReceivedOf(uint32_t association) const
{
    static const std::optional<RrcConnectionSetupCompleteMessage> empty{};
    const auto it = contexts_.find(association);
    return it == contexts_.end() ? empty : it->second.received;
}

const Srb1ResolvedConfig &EnbSrb1Runtime::ConfigurationOf(uint32_t association) const
{
    static const Srb1ResolvedConfig empty{};
    const auto it = contexts_.find(association);
    return it == contexts_.end() ? empty : it->second.resolved;
}

const pdcp::SrbPdcpEntity *EnbSrb1Runtime::PdcpOf(uint32_t association) const
{
    const auto it = contexts_.find(association);
    return it == contexts_.end() ? nullptr : &it->second.pdcp;
}

const std::vector<std::vector<uint8_t>> &EnbSrb1Runtime::PdcpPdusOf(uint32_t association) const
{
    static const std::vector<std::vector<uint8_t>> empty{};
    const auto it = contexts_.find(association);
    return it == contexts_.end() ? empty : it->second.pdcpPdus;
}

bool EnbSrb1Runtime::AsSecurityActive(uint32_t association) const
{
    const auto it = contexts_.find(association);
    return it != contexts_.end() && it->second.secured && it->second.secureTx.has_value() &&
           it->second.secureRx.has_value();
}

const security::EnbAsSecurityContext *EnbSrb1Runtime::SecurityContextOf(uint32_t association) const
{
    const auto it = contexts_.find(association);
    return it == contexts_.end() || !it->second.asContext.has_value() ? nullptr : &*it->second.asContext;
}

security::AsSecurityState EnbSrb1Runtime::AsSecurityStateOf(uint32_t association) const
{
    const auto it = contexts_.find(association);
    if (it == contexts_.end() || !it->second.procedure.has_value())
        return security::AsSecurityState::UNINITIALIZED;
    return it->second.procedure->State();
}

size_t EnbSrb1Runtime::UplinkNasCount(uint32_t association) const
{
    const auto it = contexts_.find(association);
    return it == contexts_.end() ? 0 : it->second.uplinkNas.size();
}

size_t EnbSrb1Runtime::DownlinkNasCount(uint32_t association) const
{
    const auto it = contexts_.find(association);
    return it == contexts_.end() ? 0 : it->second.downlinkNas;
}

const std::vector<std::vector<uint8_t>> &EnbSrb1Runtime::UplinkNasOf(uint32_t association) const
{
    static const std::vector<std::vector<uint8_t>> empty{};
    const auto it = contexts_.find(association);
    return it == contexts_.end() ? empty : it->second.uplinkNas;
}

void EnbSrb1Runtime::Release(uint32_t association) noexcept
{
    contexts_.erase(association);
    access_.Release(association);
}

} // namespace lte::rrc
