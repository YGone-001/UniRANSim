//
// This file is a part of UERANSIM project.
// Copyright (c) 2027 ALİ GÜNGÖR.
//

// Phase 18-F-B6-B1-R2-C3: the LTE AM entity on the simulated Uu bearer.
//
// The transport carries opaque RLC PDUs on DCCH; AMD and STATUS are told apart
// by the D/C bit, which is what the LTE header itself uses. Phase 18-F-B6-B2
// gives the bearer an explicit endpoint role: a UE transmits uplink and accepts
// downlink, an eNB the reverse, and neither infers its role from a frame.
#pragma once

#include "lte_am.hpp"
#include "uu_transport.hpp"

#include <cstdint>
#include <memory>
#include <string>
#include <vector>

namespace lte::rlc::am
{

enum class EndpointRole : uint8_t
{
    UE,
    ENB,
};

[[nodiscard]] const char *ToString(EndpointRole role);
[[nodiscard]] uu::Direction TransmitDirection(EndpointRole role);
[[nodiscard]] uu::Direction ReceiveDirection(EndpointRole role);

class LteAmBearer
{
  public:
    // What the bearer refused before an entity could see it.
    struct Rejections
    {
        uint64_t foreignAssociation{0};
        uint64_t wrongDirection{0};
        uint64_t wrongChannel{0};
        uint64_t emptyPayload{0};
        uint64_t malformedRlc{0};

        [[nodiscard]] uint64_t Total() const
        {
            return foreignAssociation + wrongDirection + wrongChannel + emptyPayload + malformedRlc;
        }
    };

    LteAmBearer() = default;

    // The socket is moved in: the bearer owns this transport endpoint.
    LteAmBearer(std::unique_ptr<uu::Socket> socket, uint16_t peerPort, EndpointRole role, uint32_t association,
                AmConfig config, LteAmEntity::Deliverer deliverer);

    // The socket is borrowed: one endpoint can carry several associations (an
    // eNB radio with several UE contexts) and still route by association.
    LteAmBearer(uu::Socket &transport, uint16_t peerPort, EndpointRole role, uint32_t association, AmConfig config,
                LteAmEntity::Deliverer deliverer);

    LteAmBearer(const LteAmBearer &) = delete;
    LteAmBearer &operator=(const LteAmBearer &) = delete;

    void SubmitSdu(const std::vector<uint8_t> &sdu);
    void SubmitSdus(const std::vector<std::vector<uint8_t>> &sdus);

    // Receives at most one frame and dispatches it. Returns false on timeout,
    // which is normal and never an error.
    bool Pump(int timeoutMs);

    // Validates one already received frame and passes it to the entity. Returns
    // true when the frame was accepted; a rejected frame changes no RLC state.
    bool OnFrame(const uu::Frame &frame);

    void Tick();

    [[nodiscard]] EndpointRole Role() const
    {
        return role_;
    }
    [[nodiscard]] uint32_t Association() const
    {
        return association_;
    }
    [[nodiscard]] AmState State() const;
    [[nodiscard]] uint16_t VtA() const;
    [[nodiscard]] uint16_t VtS() const;
    [[nodiscard]] uint16_t VrR() const;
    [[nodiscard]] size_t Delivered() const;
    [[nodiscard]] size_t Sent() const
    {
        return sent_;
    }
    // Entity counters, so a test can state the retransmission count it observed
    // instead of inferring it from the frame stream.
    [[nodiscard]] size_t Transmissions() const
    {
        return entity_.Transmissions();
    }
    [[nodiscard]] size_t Retransmissions() const
    {
        return entity_.Retransmissions();
    }
    [[nodiscard]] size_t DroppedOutOfWindow() const
    {
        return entity_.DroppedOutOfWindow();
    }
    [[nodiscard]] const Rejections &Refused() const
    {
        return refused_;
    }
    [[nodiscard]] const uu::Socket &Transport() const
    {
        return *transport_;
    }
    [[nodiscard]] uu::Socket &Transport()
    {
        return *transport_;
    }

    void Release() noexcept;

  private:
    void Send(const std::vector<uint8_t> &pdu);

    std::unique_ptr<uu::Socket> owned_{};
    uu::Socket *transport_{nullptr};
    uint16_t peerPort_{0};
    EndpointRole role_{EndpointRole::UE};
    uint32_t association_{0};
    LteAmEntity entity_{};
    size_t sent_{0};
    size_t delivered_{0};
    Rejections refused_{};
};

} // namespace lte::rlc::am
