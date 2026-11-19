//
// This file is a part of UERANSIM project.
// Copyright (c) 2027 ALİ GÜNGÖR.
//

// Phase 18-F-B6-A: LTE RLC Transparent Mode for SRB0 (TS 36.322).
//
// Transparent Mode adds no header, no sequence number, no STATUS and no
// retransmission. The RLC TM PDU is the SDU. Anything that would turn this into
// a reliable queue belongs to a different layer and is refused here.
#pragma once

#include <cstdint>
#include <stdexcept>
#include <vector>

namespace lte::rlc
{

enum class TmError : uint8_t
{
    OVERSIZED_SDU,
    EMPTY_SDU,
    ENTITY_RELEASED,
};

const char *ToString(TmError error);

class TmException : public std::runtime_error
{
  public:
    explicit TmException(TmError reason);

    [[nodiscard]] TmError Reason() const noexcept
    {
        return reason_;
    }

  private:
    TmError reason_;
};

class TmEntity
{
  public:
    // The largest SDU this entity accepts. An SDU above it is refused, never
    // truncated and never segmented: TM has no segmentation.
    static constexpr size_t MaxSduBytes = 1024;

    static TmEntity Create(uint32_t association);

    [[nodiscard]] uint32_t Association() const noexcept
    {
        return association_;
    }
    [[nodiscard]] bool Released() const noexcept
    {
        return released_;
    }

    // Returns the RLC TM PDU for an SDU: the same bytes, no header.
    [[nodiscard]] std::vector<uint8_t> Submit(const std::vector<uint8_t> &sdu);

    // The receive side: accepts a PDU that arrived over the transport and
    // returns the SDU for RRC. No deduplication, no reordering, no retransmit.
    [[nodiscard]] std::vector<uint8_t> Deliver(const std::vector<uint8_t> &pdu);

    void Release() noexcept;

  private:
    uint32_t association_{0};
    bool released_{false};
};

} // namespace lte::rlc
