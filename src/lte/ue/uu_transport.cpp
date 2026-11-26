//
// This file is a part of UERANSIM project.
// Copyright (c) 2027 ALİ GÜNGÖR.
//

#include "uu_transport.hpp"

#include <stdexcept>

namespace lte::ue
{

UuNasTransport::UuNasTransport(UuEndpoint endpoint, rrc::UeSrb1Runtime::Config config)
    : endpoint_(std::move(endpoint)), config_(config)
{
}

UuNasTransport::~UuNasTransport()
{
    Release();
}

void UuNasTransport::Start()
{
    if (released_)
        throw std::logic_error("the Uu transport is released");
    if (runtime_ != nullptr)
        throw std::logic_error("the Uu transport is already started");

    std::string why;
    auto socket = uu::Socket::Bind(endpoint_.localAddress, endpoint_.localPort, &why);
    if (!socket)
        throw std::runtime_error("the UE Uu endpoint could not be bound: " + why);
    socket_ = std::make_unique<uu::Socket>(std::move(*socket));

    runtime_ = std::make_unique<rrc::UeSrb1Runtime>(*socket_, endpoint_.enbPort, config_);
    runtime_->SetNasCallback([this](const std::vector<uint8_t> &nas) {
        if (!released_ && handler_)
            handler_(nas);
    });
    runtime_->SetReleaseCallback([this]() {
        if (!released_ && releaseHandler_)
            releaseHandler_();
    });
    runtime_->SetPagingCallback([this](uint8_t mmec, uint32_t mTmsi) {
        if (!released_ && pagingHandler_)
            pagingHandler_(mmec, mTmsi);
    });
    runtime_->SetUserPlaneCallback([this](const uu::Frame &frame) {
        if (!released_ && userPlaneHandler_)
            userPlaneHandler_(frame);
    });
    runtime_->SetDrbReconfigurationCallback([this](const rrc::DrbReconfiguration &configuration) {
        if (!released_ && drbReconfigurationHandler_)
            drbReconfigurationHandler_(configuration);
    });
    runtime_->StartAccess();
}

void UuNasTransport::SetNasHandler(NasHandler handler)
{
    handler_ = std::move(handler);
}

void UuNasTransport::SetReleaseHandler(ReleaseHandler handler)
{
    releaseHandler_ = std::move(handler);
}

void UuNasTransport::SetPagingHandler(PagingHandler handler)
{
    pagingHandler_ = std::move(handler);
}

void UuNasTransport::SetUserPlaneHandler(UserPlaneHandler handler)
{
    userPlaneHandler_ = std::move(handler);
}

void UuNasTransport::SetDrbReconfigurationHandler(DrbReconfigurationHandler handler)
{
    drbReconfigurationHandler_ = std::move(handler);
}

void UuNasTransport::SetIdentity(uint8_t mmec, uint32_t mTmsi)
{
    if (released_ || runtime_ == nullptr)
        throw std::logic_error("the Uu transport is not started");
    runtime_->SetIdentity(mmec, mTmsi);
}

void UuNasTransport::ResumeAccess()
{
    if (released_ || runtime_ == nullptr)
        throw std::logic_error("the Uu transport is not started");
    // The runtime has already moved itself to RRC_IDLE on the release. A new
    // access sends a fresh RRCConnectionRequest; the first NAS that SendNas
    // accepts will travel in the new RRCConnectionSetupComplete.
    setupCompleteSent_ = false;
    runtime_->StartAccess();
}

bool UuNasTransport::SendNas(const std::vector<uint8_t> &nas)
{
    if (released_ || runtime_ == nullptr || nas.empty())
        return false;

    try
    {
        if (!setupCompleteSent_ && runtime_->State() == rrc::RrcState::RRC_SRB1_CONFIGURING)
        {
            runtime_->SubmitSetupComplete(nas);
            setupCompleteSent_ = true;
            return true;
        }
        if (runtime_->Srb1Established())
        {
            runtime_->SubmitNas(nas);
            return true;
        }
    }
    catch (const std::exception &)
    {
        // The failure is reported, never retried on another transport.
        return false;
    }
    return false;
}

void UuNasTransport::Pump(int timeoutMs)
{
    if (released_ || runtime_ == nullptr)
        return;
    // The first call may wait for the caller's timeout; the following bounded
    // calls drain a burst without sleeping. A single frame per turn let a TCP
    // burst overflow the Uu UDP receive queue.
    runtime_->Pump(timeoutMs);
    for (int i = 0; i < 63; ++i)
        runtime_->Pump(0);
}

void UuNasTransport::Tick()
{
    if (released_ || runtime_ == nullptr)
        return;
    runtime_->Tick();
}

void UuNasTransport::PrepareAsSecurity(const security::Key256 &kasme, uint32_t ulNasCount, uint64_t nasGeneration)
{
    if (released_ || runtime_ == nullptr)
        throw std::logic_error("the Uu transport is not started");
    runtime_->PrepareAsSecurity(kasme, ulNasCount, nasGeneration);
}

rrc::RrcState UuNasTransport::State() const
{
    return runtime_ == nullptr ? rrc::RrcState::RRC_IDLE : runtime_->State();
}

bool UuNasTransport::Connected() const
{
    return runtime_ != nullptr && runtime_->State() == rrc::RrcState::RRC_CONNECTED;
}

bool UuNasTransport::AsSecurityActive() const
{
    return runtime_ != nullptr && runtime_->AsSecurityActive();
}

uint16_t UuNasTransport::LocalPort() const
{
    return socket_ == nullptr ? 0 : socket_->Port();
}

bool UuNasTransport::SendUserPlane(const std::vector<uint8_t> &payload)
{
    if (released_ || runtime_ == nullptr || socket_ == nullptr || payload.empty())
        return false;
    if (runtime_->State() != rrc::RrcState::RRC_CONNECTED || payload.size() > uu::MaxPayload)
        return false;
    uu::Frame frame;
    frame.association = config_.association;
    frame.direction = uu::Direction::UPLINK;
    frame.channel = uu::LogicalChannel::DTCH;
    frame.payload = payload;
    return socket_->Send(endpoint_.enbPort, frame, nullptr);
}

bool UuNasTransport::SendKeepalive()
{
    if (released_ || runtime_ == nullptr || socket_ == nullptr)
        return false;
    if (runtime_->State() != rrc::RrcState::RRC_CONNECTED)
        return false;
    uu::Frame frame;
    frame.association = config_.association;
    frame.direction = uu::Direction::UPLINK;
    frame.channel = uu::LogicalChannel::KEEPALIVE;
    return socket_->Send(endpoint_.enbPort, frame, nullptr);
}

void UuNasTransport::SubmitReconfigurationComplete(uint8_t transactionId)
{
    if (released_ || runtime_ == nullptr)
        throw std::logic_error("the Uu transport is not started");
    runtime_->SubmitReconfigurationComplete(transactionId);
}

const security::AsSecurityContext *UuNasTransport::SecurityContext() const
{
    return runtime_ == nullptr ? nullptr : runtime_->SecurityContext();
}

void UuNasTransport::Release()
{
    if (released_)
        return;
    released_ = true;
    handler_ = nullptr;
    releaseHandler_ = nullptr;
    pagingHandler_ = nullptr;
    userPlaneHandler_ = nullptr;
    drbReconfigurationHandler_ = nullptr;
    if (runtime_ != nullptr)
    {
        runtime_->Release();
        runtime_.reset();
    }
    socket_.reset();
}

} // namespace lte::ue
