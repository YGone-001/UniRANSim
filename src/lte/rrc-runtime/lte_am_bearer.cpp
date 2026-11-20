//
// This file is a part of UERANSIM project.
// Copyright (c) 2027 ALİ GÜNGÖR.
//

#include "lte_am_bearer.hpp"

namespace lte::rlc::am
{

LteAmBearer::LteAmBearer(uu::Socket socket, uint16_t peerPort, uint32_t association, AmConfig config,
                         LteAmEntity::Deliverer deliverer)
    : socket_(std::move(socket)), peerPort_(peerPort), association_(association)
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
    uu::Frame frame;
    frame.association = association_;
    frame.direction = uu::Direction::UPLINK;
    frame.channel = uu::LogicalChannel::DCCH;
    frame.payload = pdu;
    if (socket_.Send(peerPort_, frame, nullptr))
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
    uu::Frame frame;
    if (!socket_.Receive(frame, timeoutMs, nullptr))
        return false;
    if (frame.payload.empty() || frame.association != association_)
        return true;

    // D/C = 1 is an AMD PDU, D/C = 0 a control PDU (STATUS). The LTE header
    // itself carries the discriminator, so the transport stays protocol-neutral.
    if ((frame.payload[0] & 0x80U) != 0)
        entity_.OnPdu(frame.payload);
    else
        entity_.OnStatusPdu(frame.payload);
    return true;
}

void LteAmBearer::Tick()
{
    entity_.OnTick();
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

size_t LteAmBearer::Delivered() const
{
    return delivered_;
}

void LteAmBearer::Release() noexcept
{
    entity_.Release();
}

} // namespace lte::rlc::am
