//
// This file is a part of UERANSIM project.
// Copyright (c) 2027 ALİ GÜNGÖR.
//
// https://github.com/aligungr/UERANSIM/
// See README, LICENSE, and CONTRIBUTING files for licensing details.
//

// Phase 18-F-B5: the initial AS security mode procedure (TS 33.401 7.2.4,
// TS 36.331 5.3.4) as two explicit state machines driven by real RRC messages
// over real PDCP PDUs.
//
// What this is not: there is no SRB1 transport in this simulator, so the bytes
// these objects produce are handed to a test or to a future radio path, not to
// a socket. The messages, the PDCP protection and the state transitions are
// real; the carrier is the caller's problem.
#pragma once

#include "as_algorithm_selection.hpp"
#include "as_security.hpp"
#include "pdcp_security.hpp"

#include <cstdint>
#include <optional>
#include <stdexcept>
#include <string>
#include <vector>

namespace lte::security
{

enum class AsSecurityState : uint8_t
{
    UNINITIALIZED,
    KEY_PREPARED,
    ALGORITHM_SELECTED,
    COMMAND_PENDING,
    UE_VERIFIED,
    COMPLETE_PENDING,
    ACTIVE,
    FAILED,
};

const char *ToString(AsSecurityState state);

enum class ProcedureError : uint8_t
{
    NOT_PREPARED,
    UNEXPECTED_MESSAGE,
    TRANSACTION_MISMATCH,
    INTEGRITY_FAILURE,
    ALGORITHM_REJECTED,
    ALREADY_ACTIVE,
    CONTEXT_MISMATCH,
    MALFORMED_MESSAGE,
    ACTIVATION_REFUSED,
};

const char *ToString(ProcedureError error);

class ProcedureException : public std::runtime_error
{
  public:
    explicit ProcedureException(ProcedureError reason);

    [[nodiscard]] ProcedureError Reason() const noexcept
    {
        return reason_;
    }

  private:
    ProcedureError reason_;
};

// The eNB side. Start selects the algorithms, derives the keys and produces the
// integrity-protected SecurityModeCommand; OnComplete verifies the UE's
// SecurityModeComplete and only then activates uplink deciphering.
class EnbAsSecurityProcedure
{
  public:
    EnbAsSecurityProcedure() = default;

    static EnbAsSecurityProcedure Start(AsSecurityContext &context, uint32_t ueId,
                                        const UeAlgorithmCapabilities &capabilities,
                                        const AsAlgorithmConfiguration &configuration,
                                        uint64_t expectedConfigurationGeneration, uint8_t transactionId);

    [[nodiscard]] const std::vector<uint8_t> &Command() const;
    [[nodiscard]] const AlgorithmSelection &Selection() const;
    [[nodiscard]] AsSecurityState State() const noexcept
    {
        return state_;
    }
    [[nodiscard]] bool CipheringActive() const;

    // Verifies and applies the UE's SecurityModeComplete. Throws a
    // ProcedureException on any failure and leaves the state at FAILED with no
    // ciphering activated.
    void OnComplete(const std::vector<uint8_t> &uplinkPdu);

    // A SecurityModeFailure ends the transaction without activating anything.
    void OnFailure(const std::vector<uint8_t> &uplinkPdu);

  private:
    AsSecurityContext *context_{nullptr};
    AlgorithmSelection selection_{};
    uint8_t transactionId_{0};
    AsSecurityState state_{AsSecurityState::UNINITIALIZED};
    std::vector<uint8_t> command_;
    std::optional<PdcpSecurityEntity> tx_{};
    std::optional<PdcpSecurityEntity> rx_{};
};

// The UE side. Listening holds no state; OnCommand verifies the command,
// derives the keys and returns the SecurityModeComplete to send. The caller
// then calls ConfirmCompleteSent, which is the only path to ACTIVE.
class UeAsSecurityProcedure
{
  public:
    UeAsSecurityProcedure() = default;

    static UeAsSecurityProcedure Listening(AsSecurityContext &context, uint32_t ueId);

    // Parses, verifies and applies a SecurityModeCommand. Returns the
    // SecurityModeComplete PDU on success, or a SecurityModeFailure PDU when
    // the command cannot be accepted. Throws only on a programming error, not
    // on a rejected command.
    [[nodiscard]] std::vector<uint8_t> OnCommand(const std::vector<uint8_t> &downlinkPdu);

    // The UE activates RRC/UP ciphering once the SecurityModeComplete has been
    // sent; this is that step, and it is the only path to ACTIVE.
    void ConfirmCompleteSent();

    [[nodiscard]] AsSecurityState State() const noexcept
    {
        return state_;
    }
    [[nodiscard]] const AlgorithmSelection &Selection() const
    {
        return selection_;
    }
    [[nodiscard]] bool CipheringActive() const;

  private:
    AsSecurityContext *context_{nullptr};
    uint32_t ueId_{0};
    AlgorithmSelection selection_{};
    uint8_t transactionId_{0};
    AsSecurityState state_{AsSecurityState::UNINITIALIZED};
    std::optional<PdcpSecurityEntity> tx_{};
    std::optional<PdcpSecurityEntity> rx_{};
};

} // namespace lte::security
