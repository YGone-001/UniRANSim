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
    : socket_(socket), enbPort_(enbPort), config_(config),
      srb0_(rlc::TmEntity::Create(config.association)),
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
        refused_++;
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
    bearer_ = std::make_unique<LteAmBearer>(socket_, enbPort_, EndpointRole::UE, config_.association, resolved_.am,
                                            nullptr);
    state_ = RrcState::RRC_SRB1_CONFIGURING;
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

void UeSrb1Runtime::Tick()
{
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
    state_ = RrcState::RRC_RELEASED;
}

// --- eNB --------------------------------------------------------------------

EnbSrb1Runtime::EnbSrb1Runtime(uu::Socket &socket, Config config, NasCallback onNas)
    : socket_(socket), config_(config), onNas_(std::move(onNas)), srb0_(rlc::TmEntity::Create(0))
{
    access_.SetSetup(config_.setup);
    // The eNB instantiates exactly the configuration it offers. An unsupported
    // enumeration is refused here, before any UE can be reached.
    (void)MapSrb1Configuration(config_.setup);
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
        // One context per association. A repeat from the same endpoint gets the
        // same answer; a different endpoint claiming the association is refused.
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

void EnbSrb1Runtime::OnPdcpPdu(Context &context, uint32_t association, const std::vector<uint8_t> &pdu)
{
    context.pdcpPdus.push_back(pdu);

    std::vector<uint8_t> rrcPdu;
    try
    {
        rrcPdu = context.pdcp.Unprotect(pdu);
    }
    catch (const pdcp::SrbPdcpException &)
    {
        refusedSetupComplete_++;
        return;
    }

    // One SetupComplete per context: once the context is connected, a second
    // message is an unexpected RRC message, not a second NAS delivery.
    if (context.state != RrcState::RRC_SETUP_PENDING)
    {
        refusedSetupComplete_++;
        return;
    }

    RrcConnectionSetupCompleteMessage message;
    if (!DecodeRrcConnectionSetupComplete(rrcPdu.data(), rrcPdu.size(), message))
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

void EnbSrb1Runtime::Release(uint32_t association) noexcept
{
    contexts_.erase(association);
    access_.Release(association);
}

} // namespace lte::rrc
