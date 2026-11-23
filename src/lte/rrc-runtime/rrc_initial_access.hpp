//
// This file is a part of UERANSIM project.
// Copyright (c) 2027 ALİ GÜNGÖR.
//

// Phase 18-F-B6-A: RRC initial access over SRB0 (TS 36.331 5.3.3, first half).
//
// RRCConnectionRequest (UL-CCCH) and RRCConnectionSetup / RRCConnectionReject
// (DL-CCCH), encoded with the accepted LTE RRC UPER codec and carried through
// RLC TM. RRCConnectionSetupComplete needs SRB1 and belongs to B6-B, so a UE
// that receives a valid setup stops in SRB1_CONFIGURING: it never claims
// RRC_CONNECTED.
#pragma once

#include <cstdint>
#include <map>
#include <optional>
#include <stdexcept>
#include <string>
#include <vector>

namespace lte::rrc
{

enum class RrcState : uint8_t
{
    RRC_IDLE,
    RRC_CONNECTION_REQUEST_PENDING,
    RRC_SETUP_PENDING,
    RRC_SRB1_CONFIGURING,
    // SetupComplete has been submitted on SRB1 and the RLC acknowledgement for
    // it has not arrived yet. RRC_CONNECTED is claimed only after that ack.
    RRC_CONNECTION_COMPLETE_PENDING,
    RRC_CONNECTED,
    RRC_CONNECTION_REJECTED,
    RRC_CONNECTION_FAILED,
    RRC_RELEASED,
};

const char *ToString(RrcState state);

enum class AccessError : uint8_t
{
    MALFORMED_REQUEST,
    INVALID_IDENTITY,
    UNEXPECTED_MESSAGE,
    NO_PENDING_CONTEXT,
    REQUEST_WHILE_PENDING,
    CONFIGURATION_INVALID,
    TIMEOUT,
    RELEASED,
};

const char *ToString(AccessError error);

class AccessException : public std::runtime_error
{
  public:
    explicit AccessException(AccessError reason);

    [[nodiscard]] AccessError Reason() const noexcept
    {
        return reason_;
    }

  private:
    AccessError reason_;
};

struct RrcConnectionRequestMessage
{
    uint8_t mmec{0};
    uint32_t mTmsi{0};
    uint8_t establishmentCause{0};
};

struct RrcConnectionSetupMessage
{
    uint8_t transactionId{0};
    uint8_t srbIdentity{1};
    // The explicit RLC AM configuration of SRB1, as TS 36.331 encodes it.
    uint8_t tPollRetransmit{0};
    uint8_t pollPdu{0};
    uint8_t pollByte{0};
    uint8_t maxRetxThreshold{0};
    uint8_t tReordering{0};
    uint8_t tStatusProhibit{0};
};

struct RrcConnectionRejectMessage
{
    uint8_t waitTime{0};
};

[[nodiscard]] std::vector<uint8_t> EncodeRrcConnectionRequest(const RrcConnectionRequestMessage &message);
[[nodiscard]] bool DecodeRrcConnectionRequest(const uint8_t *data, size_t size, RrcConnectionRequestMessage &out);
[[nodiscard]] std::vector<uint8_t> EncodeRrcConnectionSetup(const RrcConnectionSetupMessage &message);
[[nodiscard]] bool DecodeRrcConnectionSetup(const uint8_t *data, size_t size, RrcConnectionSetupMessage &out);
[[nodiscard]] std::vector<uint8_t> EncodeRrcConnectionReject(const RrcConnectionRejectMessage &message);
[[nodiscard]] bool DecodeRrcConnectionReject(const uint8_t *data, size_t size, RrcConnectionRejectMessage &out);

// The UE side of the initial access. It builds the request, and advances only
// on a message it actually decoded and validated.
class UeInitialAccess
{
  public:
    static UeInitialAccess Idle(uint32_t association, uint8_t mmec, uint32_t mTmsi);

    [[nodiscard]] uint32_t Association() const noexcept
    {
        return association_;
    }
    [[nodiscard]] RrcState State() const noexcept
    {
        return state_;
    }

    // Builds the UL-CCCH RRCConnectionRequest and moves to CONNECTION_REQUEST_PENDING.
    [[nodiscard]] std::vector<uint8_t> BuildRequest();

    // Consumes a DL-CCCH message. A setup moves the UE to SRB1_CONFIGURING with
    // the configuration staged for B6-B; it never moves it to CONNECTED.
    void OnDownlink(const std::vector<uint8_t> &pdu);

    // No answer arrived. The access fails; nothing is retried here.
    void OnTimeout() noexcept;

    [[nodiscard]] const std::optional<RrcConnectionSetupMessage> &StagedSrb1() const noexcept
    {
        return staged_;
    }

  private:
    uint32_t association_{0};
    uint8_t mmec_{0};
    uint32_t mTmsi_{0};
    RrcState state_{RrcState::RRC_IDLE};
    std::optional<RrcConnectionSetupMessage> staged_{};
};

// The eNB side. One pending context per transport association, never two.
class EnbInitialAccess
{
  public:
    void SetReject(bool reject, uint8_t waitTime = 0)
    {
        reject_ = reject;
        waitTime_ = waitTime;
    }

    // The SRB1 configuration this eNB offers. The runtime that carries SRB1
    // must map exactly this message, so there is one source of truth for what
    // the UE receives and what the eNB instantiates.
    void SetSetup(const RrcConnectionSetupMessage &setup)
    {
        setup_ = setup;
    }
    [[nodiscard]] const RrcConnectionSetupMessage &Setup() const
    {
        return setup_;
    }

    // Handles an UL-CCCH RRCConnectionRequest and returns the DL-CCCH answer.
    // A repeated request for a pending association returns the same answer and
    // does not create a second context.
    [[nodiscard]] std::vector<uint8_t> OnRequest(uint32_t association, const std::vector<uint8_t> &pdu);

    [[nodiscard]] RrcState StateOf(uint32_t association) const;
    [[nodiscard]] bool HasContext(uint32_t association) const;
    [[nodiscard]] size_t ContextCount() const noexcept
    {
        return contexts_.size();
    }
    void Release(uint32_t association) noexcept;

  private:
    struct Pending
    {
        uint8_t mmec{0};
        uint32_t mTmsi{0};
        RrcState state{RrcState::RRC_IDLE};
        std::vector<uint8_t> answer{};
    };

    bool reject_{false};
    uint8_t waitTime_{0};
    RrcConnectionSetupMessage setup_{0, 1, 2, 1, 1, 5, 1, 1};
    std::map<uint32_t, Pending> contexts_{};
};

} // namespace lte::rrc
