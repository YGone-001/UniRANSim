//
// This file is a part of UERANSIM project.
// Copyright (c) 2027 ALİ GÜNGÖR.
//

// Phase 18-F-B6-B1-R2: the LTE RLC AM entity (TS 36.322 Release 18).
//
// Its own entity, not the NR one: the NR engine carries NR PDU objects and the
// NR segment-info enum, so it cannot be adapted without inventing NR headers.
// This entity reuses only the protocol-neutral ideas (SN comparison, SO
// overlap, segment insertion, tick-driven timers) and consumes the LTE codec.
#pragma once

#include "rlc_am.hpp"

#include <cstdint>
#include <functional>
#include <map>
#include <optional>
#include <vector>

namespace lte::rlc::am
{

enum class AmState : uint8_t
{
    ACTIVE,
    FAILED,
    RELEASED,
};

const char *ToString(AmState state);

struct AmConfig
{
    // Largest PDU this entity may emit, header included.
    size_t maxPduBytes{128};
    // Transmissions of one PDU before the entity fails (maxRetxThreshold).
    uint8_t maxRetx{8};
    uint32_t pollTicks{10};
    uint32_t reorderingTicks{10};
    uint32_t prohibitTicks{5};
};

// One stored transmission: the exact Data field plus the framing that produced
// it, so a retransmission, or a re-segmentation of it, reproduces the same SDU
// boundary.
struct StoredSdu
{
    uint16_t sn{0};
    FramingInfo fi{FramingInfo::COMPLETE};
    std::vector<uint8_t> data{};
    uint8_t transmissions{0};
    bool acked{false};
};

class LteAmEntity
{
  public:
    using Sender = std::function<void(std::vector<uint8_t>)>;
    using Deliverer = std::function<void(std::vector<uint8_t>)>;

    LteAmEntity() = default;
    LteAmEntity(AmConfig config, Sender sender, Deliverer deliverer);

    void SubmitSdu(const std::vector<uint8_t> &sdu);
    void OnPdu(const std::vector<uint8_t> &pdu);
    void OnStatusPdu(const std::vector<uint8_t> &pdu);
    void OnTick();

    [[nodiscard]] AmState State() const noexcept
    {
        return state_;
    }
    [[nodiscard]] uint16_t VtA() const noexcept
    {
        return vtA_;
    }
    [[nodiscard]] uint16_t VtS() const noexcept
    {
        return vtS_;
    }
    [[nodiscard]] uint16_t VrR() const noexcept
    {
        return vrR_;
    }
    [[nodiscard]] uint16_t VrH() const noexcept
    {
        return vrH_;
    }
    [[nodiscard]] size_t Transmissions() const noexcept
    {
        return transmissionsCount_;
    }
    [[nodiscard]] size_t Retransmissions() const noexcept
    {
        return retransmissions_;
    }
    [[nodiscard]] size_t DeliveredSdus() const noexcept
    {
        return delivered_;
    }
    [[nodiscard]] size_t DroppedOutOfWindow() const noexcept
    {
        return droppedOutOfWindow_;
    }

    void Release() noexcept;

  private:
    struct RxSegment
    {
        uint16_t so{0};
        bool lsf{false};
        std::vector<uint8_t> data{};
    };
    struct RxEntry
    {
        FramingInfo fi{FramingInfo::COMPLETE};
        std::vector<RxSegment> segments{};
        bool complete{false};
        size_t totalSize{0};
    };

    void SendPdu(uint16_t sn, bool poll, FramingInfo fi, const std::vector<uint8_t> &data,
                 std::optional<std::pair<uint16_t, uint16_t>> soRange);
    void TransmitStored(StoredSdu &stored, bool poll);
    void TryDeliverInOrder();
    void SendStatus();
    void Fail();

    static int Distance(uint16_t from, uint16_t to);

    AmConfig config_{};
    Sender sender_{};
    Deliverer deliverer_{};

    AmState state_{AmState::RELEASED};
    uint16_t vtA_{0};
    uint16_t vtS_{0};
    uint16_t vrR_{0};
    uint16_t vrH_{0};
    uint16_t vrX_{0};

    uint32_t pollTimer_{0};
    uint32_t reorderTimer_{0};
    uint32_t prohibitTimer_{0};
    bool reordering_{false};
    bool statusPending_{false};
    bool pollPending_{false};

    std::map<uint16_t, StoredSdu> transmissions_{};
    std::map<uint16_t, RxEntry> receive_{};
    // An SDU that spans several AMD PDUs is assembled here; FI says whether a
    // PDU starts, continues, or ends it.
    std::vector<uint8_t> assembly_{};

    size_t transmissionsCount_{0};
    size_t retransmissions_{0};
    size_t delivered_{0};
    size_t droppedOutOfWindow_{0};
};

} // namespace lte::rlc::am
