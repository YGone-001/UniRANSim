//
// This file is a part of UERANSIM project.
// Copyright (c) 2027 ALİ GÜNGÖR.
//

// Phase 18-F-B6-B2: the SRB PDCP runtime of TS 36.323 6.2.2 as it exists before
// the AS Security Mode procedure.
//
// RRCConnectionSetupComplete is sent before SecurityModeCommand, so the initial
// SRB1 PDU has no MAC-I and no ciphering: a one-octet header with three reserved
// bits and a five-bit SN, then the data. The B5/B5-R1 PdcpSecurityEntity stays
// what it is - the post-activation security component - and is not invoked here.
#pragma once

#include <cstdint>
#include <stdexcept>
#include <string>
#include <vector>

namespace lte::pdcp
{

enum class SrbPdcpError : uint8_t
{
    MALFORMED_PDU,
    RESERVED_BITS_SET,
    DUPLICATE,
    OUT_OF_SEQUENCE,
    COUNT_EXHAUSTED,
    RELEASED,
};

const char *ToString(SrbPdcpError error);

class SrbPdcpException : public std::runtime_error
{
  public:
    explicit SrbPdcpException(SrbPdcpError reason);

    [[nodiscard]] SrbPdcpError Reason() const noexcept
    {
        return reason_;
    }

  private:
    SrbPdcpError reason_;
};

// One direction of SRB1. TX and RX sequence state are independent, which is why
// a UE entity and an eNB entity never share a counter.
class SrbPdcpEntity
{
  public:
    static constexpr uint8_t SnBits = 5;
    static constexpr uint32_t SnModulus = 1U << SnBits;
    static constexpr size_t HeaderBytes = 1;

    static SrbPdcpEntity Create(bool uplink);

    // Header + data. Pre-security: no MAC-I, no ciphering.
    [[nodiscard]] std::vector<uint8_t> Protect(const std::vector<uint8_t> &sdu);

    // Validates the header and returns the data. A duplicate, an out-of-order
    // SN, a reserved bit or a short PDU is a typed refusal.
    [[nodiscard]] std::vector<uint8_t> Unprotect(const std::vector<uint8_t> &pdu);

    void Release() noexcept;

    [[nodiscard]] bool Uplink() const noexcept
    {
        return uplink_;
    }
    [[nodiscard]] bool Released() const noexcept
    {
        return released_;
    }
    [[nodiscard]] uint8_t NextSn() const noexcept
    {
        return static_cast<uint8_t>(txCount_ % SnModulus);
    }
    [[nodiscard]] uint32_t NextCount() const noexcept
    {
        return static_cast<uint32_t>(txCount_);
    }
    [[nodiscard]] uint32_t TxHfn() const noexcept
    {
        return static_cast<uint32_t>(txCount_ / SnModulus);
    }
    [[nodiscard]] uint8_t ExpectedSn() const noexcept
    {
        return static_cast<uint8_t>(rxCount_ % SnModulus);
    }
    [[nodiscard]] uint32_t ReceivedCount() const noexcept
    {
        return static_cast<uint32_t>(rxCount_);
    }
    [[nodiscard]] uint32_t RxHfn() const noexcept
    {
        return static_cast<uint32_t>(rxCount_ / SnModulus);
    }
    [[nodiscard]] size_t Delivered() const noexcept
    {
        return delivered_;
    }
    [[nodiscard]] size_t Refused() const noexcept
    {
        return refused_;
    }

  private:
    bool uplink_{true};
    bool released_{false};
    uint64_t txCount_{0};
    uint64_t rxCount_{0};
    size_t delivered_{0};
    size_t refused_{0};
};

} // namespace lte::pdcp
