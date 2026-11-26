//
// This file is a part of UERANSIM project.
// Copyright (c) 2027 ALİ GÜNGÖR.
//

#include "lte_am_bearer.hpp"

namespace lte::rlc::am
{

const char *ToString(EndpointRole role)
{
    return role == EndpointRole::UE ? "UE" : "ENB";
}

uu::Direction TransmitDirection(EndpointRole role)
{
    return role == EndpointRole::UE ? uu::Direction::UPLINK : uu::Direction::DOWNLINK;
}

uu::Direction ReceiveDirection(EndpointRole role)
{
    return role == EndpointRole::UE ? uu::Direction::DOWNLINK : uu::Direction::UPLINK;
}

LteAmBearer::LteAmBearer(std::unique_ptr<uu::Socket> socket, uint16_t peerPort, EndpointRole role,
                         uint32_t association, AmConfig config, LteAmEntity::Deliverer deliverer,
                         uu::LogicalChannel channel)
    : owned_(std::move(socket)), transport_(owned_.get()), peerPort_(peerPort), role_(role),
      association_(association), channel_(channel)
{
    entity_ = LteAmEntity(
        config, [this](std::vector<uint8_t> pdu) { Send(pdu); },
        [this, deliver = std::move(deliverer)](std::vector<uint8_t> sdu) {
            delivered_++;
            if (deliver)
                deliver(std::move(sdu));
        });
}

LteAmBearer::LteAmBearer(uu::Socket &transport, uint16_t peerPort, EndpointRole role, uint32_t association,
                         AmConfig config, LteAmEntity::Deliverer deliverer, uu::LogicalChannel channel)
    : transport_(&transport), peerPort_(peerPort), role_(role), association_(association), channel_(channel)
{
    entity_ = LteAmEntity(
        config, [this](std::vector<uint8_t> pdu) { Send(pdu); },
        [this, deliver = std::move(deliverer)](std::vector<uint8_t> sdu) {
            delivered_++;
            if (deliver)
                deliver(std::move(sdu));
        });
}

LteAmBearer::LteAmBearer(EndpointRole role, uint32_t association, AmConfig config,
                         LteAmEntity::Deliverer deliverer, uu::LogicalChannel channel, PduSender sender)
    : externalSender_(std::move(sender)), role_(role), association_(association), channel_(channel)
{
    entity_ = LteAmEntity(
        config, [this](std::vector<uint8_t> pdu) { Send(pdu); },
        [this, deliver = std::move(deliverer)](std::vector<uint8_t> sdu) {
            delivered_++;
            if (deliver)
                deliver(std::move(sdu));
        });
}

void LteAmBearer::Send(const std::vector<uint8_t> &pdu)
{
    if (externalSender_)
    {
        externalSender_(pdu);
        sent_++;
        return;
    }
    if (transport_ == nullptr)
        return;
    uu::Frame frame;
    frame.association = association_;
    frame.direction = TransmitDirection(role_);
    frame.channel = channel_;
    frame.payload = pdu;
    if (transport_->Send(peerPort_, frame, nullptr))
        sent_++;
}

void LteAmBearer::SubmitSdu(const std::vector<uint8_t> &sdu)
{
    entity_.SubmitSdu(sdu);
}

void LteAmBearer::SubmitSdus(const std::vector<std::vector<uint8_t>> &sdus)
{
    entity_.SubmitSdus(sdus);
}

bool LteAmBearer::Pump(int timeoutMs)
{
    if (transport_ == nullptr)
        return false;
    uu::Frame frame;
    if (!transport_->Receive(frame, timeoutMs, nullptr))
        return false;
    OnFrame(frame);
    return true;
}

bool LteAmBearer::OnFrame(const uu::Frame &frame)
{
    if (frame.association != association_)
    {
        refused_.foreignAssociation++;
        return false;
    }
    if (frame.direction != ReceiveDirection(role_))
    {
        refused_.wrongDirection++;
        return false;
    }
    if (frame.channel != channel_)
    {
        refused_.wrongChannel++;
        return false;
    }
    if (frame.payload.empty())
    {
        refused_.emptyPayload++;
        return false;
    }

    // D/C = 1 is an AMD PDU, D/C = 0 a control PDU (STATUS). The LTE header
    // itself carries the discriminator, so the transport stays protocol-neutral.
    // A frame that does not decode as its own type never reaches the entity.
    if ((frame.payload[0] & 0x80U) != 0)
    {
        AmdPdu decoded;
        std::string why;
        if (!DecodeAmd(frame.payload.data(), frame.payload.size(), decoded, &why))
        {
            refused_.malformedRlc++;
            return false;
        }
        entity_.OnPdu(frame.payload);
        return true;
    }

    StatusPdu status;
    std::string why;
    if (!DecodeStatus(frame.payload.data(), frame.payload.size(), status, &why))
    {
        refused_.malformedRlc++;
        return false;
    }
    entity_.OnStatusPdu(frame.payload);
    return true;
}

void LteAmBearer::Tick()
{
    entity_.OnTick();
    lastKnownNext_ = entity_.NextTickIn();
}

uint32_t LteAmBearer::NextTickIn() const
{
    return entity_.NextTickIn();
}

void LteAmBearer::SetActivityCallback(std::function<void()> callback)
{
    onActivity_ = std::move(callback);
    entity_.SetActivityCallback([this] {
        if (onActivity_)
            onActivity_();
    });
}

void LteAmBearer::AdvanceTo(int64_t nowMs)
{
    if (lastKnownNext_ == LteAmEntity::NeverTick)
    {
        // The bearer was idle. Work created by this activity starts its timers
        // at now; the idle interval must not be charged to them.
        lastTickMs_ = nowMs;
        lastKnownNext_ = entity_.NextTickIn();
        return;
    }
    int64_t elapsed = nowMs - lastTickMs_;
    if (elapsed <= 0)
    {
        if (nowMs < lastTickMs_ + static_cast<int64_t>(lastKnownNext_))
            return;
        elapsed = 1;
    }
    if (elapsed > 20)
        elapsed = 20;
    entity_.Tick(static_cast<uint32_t>(elapsed));
    lastTickMs_ += elapsed;
    if (lastTickMs_ > nowMs)
        lastTickMs_ = nowMs;
    lastKnownNext_ = entity_.NextTickIn();
}

AmState LteAmBearer::State() const
{
    return entity_.State();
}

uint16_t LteAmBearer::VtA() const
{
    return entity_.VtA();
}

uint16_t LteAmBearer::VtS() const
{
    return entity_.VtS();
}

uint16_t LteAmBearer::VrR() const
{
    return entity_.VrR();
}

uint16_t LteAmBearer::OutstandingPdus() const
{
    // The entity's SN space is the LTE AM 1024 modulus; a simple modular
    // difference is the in-flight count and never exceeds the 512 window.
    return static_cast<uint16_t>((VtS() + 1024U - VtA()) % 1024U);
}

size_t LteAmBearer::Delivered() const
{
    return delivered_;
}

void LteAmBearer::Release() noexcept
{
    entity_.Release();
}

} // namespace lte::rlc::am
