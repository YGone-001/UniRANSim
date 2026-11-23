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
    runtime_->StartAccess();
}

void UuNasTransport::SetNasHandler(NasHandler handler)
{
    handler_ = std::move(handler);
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
    runtime_->Pump(timeoutMs);
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

void UuNasTransport::Release()
{
    if (released_)
        return;
    released_ = true;
    handler_ = nullptr;
    if (runtime_ != nullptr)
    {
        runtime_->Release();
        runtime_.reset();
    }
    socket_.reset();
}

} // namespace lte::ue
