//
// This file is a part of UERANSIM project.
// Copyright (c) 2027 ALİ GÜNGÖR.
//
// https://github.com/aligungr/UERANSIM/
// See README, LICENSE, and CONTRIBUTING files for licensing details.
//

#include "as_security_procedure.hpp"

#include "as_security_codec.hpp"

namespace lte::security
{
namespace
{

[[noreturn]] void Fail(ProcedureError reason)
{
    throw ProcedureException(reason);
}

AsAlgorithmSet AlgorithmSetFor(const AlgorithmSelection &selection)
{
    AsAlgorithmSet set;
    set.negotiated = true;
    set.rrcIntegrity = selection.integrity;
    set.rrcCiphering = selection.ciphering;
    set.upCiphering = selection.ciphering;
    // This LTE UE profile has no UP integrity algorithm, so none is negotiated
    // and no K_UPint is derived for a DRB.
    set.upIntegrity = std::nullopt;
    return set;
}

bool SupportedIdentity(uint8_t identity)
{
    return identity <= 3;
}

} // namespace

const char *ToString(AsSecurityState state)
{
    switch (state)
    {
    case AsSecurityState::UNINITIALIZED: return "AS_SECURITY_UNINITIALIZED";
    case AsSecurityState::KEY_PREPARED: return "AS_SECURITY_KEY_PREPARED";
    case AsSecurityState::ALGORITHM_SELECTED: return "AS_SECURITY_ALGORITHM_SELECTED";
    case AsSecurityState::COMMAND_PENDING: return "AS_SECURITY_COMMAND_PENDING";
    case AsSecurityState::UE_VERIFIED: return "AS_SECURITY_UE_VERIFIED";
    case AsSecurityState::COMPLETE_PENDING: return "AS_SECURITY_COMPLETE_PENDING";
    case AsSecurityState::ACTIVE: return "AS_SECURITY_ACTIVE";
    case AsSecurityState::FAILED: return "AS_SECURITY_FAILED";
    }
    return "AS_SECURITY_UNKNOWN";
}

const char *ToString(ProcedureError error)
{
    switch (error)
    {
    case ProcedureError::NOT_PREPARED: return "NOT_PREPARED";
    case ProcedureError::UNEXPECTED_MESSAGE: return "UNEXPECTED_MESSAGE";
    case ProcedureError::TRANSACTION_MISMATCH: return "TRANSACTION_MISMATCH";
    case ProcedureError::INTEGRITY_FAILURE: return "INTEGRITY_FAILURE";
    case ProcedureError::ALGORITHM_REJECTED: return "ALGORITHM_REJECTED";
    case ProcedureError::ALREADY_ACTIVE: return "ALREADY_ACTIVE";
    case ProcedureError::CONTEXT_MISMATCH: return "CONTEXT_MISMATCH";
    case ProcedureError::MALFORMED_MESSAGE: return "MALFORMED_MESSAGE";
    case ProcedureError::ACTIVATION_REFUSED: return "ACTIVATION_REFUSED";
    }
    return "UNKNOWN_PROCEDURE_ERROR";
}

ProcedureException::ProcedureException(ProcedureError reason)
    : std::runtime_error(std::string("AS security procedure refusal: ") + ToString(reason)), reason_(reason)
{
}

// --- eNB --------------------------------------------------------------------

EnbAsSecurityProcedure EnbAsSecurityProcedure::Start(AsKeySource &context, uint32_t ueId,
                                                     const UeAlgorithmCapabilities &capabilities,
                                                     const AsAlgorithmConfiguration &configuration,
                                                     uint64_t expectedConfigurationGeneration,
                                                     uint8_t transactionId)
{
    if (!context.IsActive())
        Fail(ProcedureError::NOT_PREPARED);
    if (context.OwnerUeId() != ueId)
        Fail(ProcedureError::CONTEXT_MISMATCH);
    if (transactionId > MaxRrcTransactionId)
        Fail(ProcedureError::MALFORMED_MESSAGE);

    EnbAsSecurityProcedure procedure;
    procedure.context_ = &context;
    procedure.transactionId_ = transactionId;

    try
    {
        procedure.selection_ = SelectAsAlgorithms(capabilities, configuration, expectedConfigurationGeneration);
    }
    catch (const SelectionException &error)
    {
        (void)error;
        Fail(ProcedureError::ALGORITHM_REJECTED);
    }

    context.ApplyAsAlgorithms(AlgorithmSetFor(procedure.selection_));
    const AsKeys keys = context.DeriveAccessKeys();

    // SRB1 on the control-plane profile: RB identity 1, BEARER field 0.
    procedure.tx_.emplace(PdcpSecurityEntity::Create(PdcpProfile::SRB, RadioBearerIdentity::Srb1(), false,
                                                     procedure.selection_.integrity, procedure.selection_.ciphering,
                                                     keys.kRrcInt, keys.kRrcEnc));
    procedure.rx_.emplace(PdcpSecurityEntity::Create(PdcpProfile::SRB, RadioBearerIdentity::Srb1(), true,
                                                     procedure.selection_.integrity, procedure.selection_.ciphering,
                                                     keys.kRrcInt, keys.kRrcEnc));
    // The initial SecurityModeCommand is integrity protected and never ciphered:
    // only integrity is active on the SRB1 downlink at this point.
    procedure.tx_->ActivateIntegrity();
    procedure.rx_->ActivateIntegrity();

    SecurityModeCommandMessage command;
    command.transactionId = transactionId;
    command.cipheringAlgorithm = procedure.selection_.ciphering;
    command.integrityAlgorithm = procedure.selection_.integrity;
    const auto encoded = EncodeSecurityModeCommand(command);
    if (encoded.empty())
        Fail(ProcedureError::MALFORMED_MESSAGE);

    procedure.command_ = procedure.tx_->Protect(encoded);
    procedure.state_ = AsSecurityState::COMMAND_PENDING;
    return procedure;
}

const std::vector<uint8_t> &EnbAsSecurityProcedure::Command() const
{
    if (state_ != AsSecurityState::COMMAND_PENDING && state_ != AsSecurityState::ACTIVE)
        Fail(ProcedureError::NOT_PREPARED);
    return command_;
}

const AlgorithmSelection &EnbAsSecurityProcedure::Selection() const
{
    return selection_;
}

bool EnbAsSecurityProcedure::CipheringActive() const
{
    return tx_.has_value() && rx_.has_value() && tx_->CipheringActive() && rx_->CipheringActive();
}

void EnbAsSecurityProcedure::OnComplete(const std::vector<uint8_t> &uplinkPdu)
{
    if (state_ != AsSecurityState::COMMAND_PENDING)
        Fail(ProcedureError::UNEXPECTED_MESSAGE);

    std::vector<uint8_t> plain;
    try
    {
        plain = rx_->Unprotect(uplinkPdu);
    }
    catch (const PdcpSecurityException &error)
    {
        state_ = AsSecurityState::FAILED;
        throw ProcedureException(error.Reason() == PdcpSecurityError::INTEGRITY_FAILURE ? ProcedureError::INTEGRITY_FAILURE
                                                                                        : ProcedureError::MALFORMED_MESSAGE);
    }

    SecurityModeCompleteMessage complete;
    if (!DecodeSecurityModeComplete(plain.data(), plain.size(), complete))
    {
        state_ = AsSecurityState::FAILED;
        Fail(ProcedureError::MALFORMED_MESSAGE);
    }
    if (complete.transactionId != transactionId_)
    {
        state_ = AsSecurityState::FAILED;
        Fail(ProcedureError::TRANSACTION_MISMATCH);
    }

    // Only now, after the UE's integrity-protected completion, does the eNB
    // switch on ciphering in both directions.
    try
    {
        tx_->ActivateCiphering();
        rx_->ActivateCiphering();
    }
    catch (const PdcpSecurityException &error)
    {
        (void)error;
        state_ = AsSecurityState::FAILED;
        Fail(ProcedureError::ACTIVATION_REFUSED);
    }
    state_ = AsSecurityState::ACTIVE;
}

std::optional<PdcpSecurityEntity> EnbAsSecurityProcedure::TakeTx()
{
    if (state_ != AsSecurityState::ACTIVE || !tx_.has_value())
        Fail(ProcedureError::NOT_PREPARED);
    std::optional<PdcpSecurityEntity> out = std::move(tx_);
    tx_.reset();
    return out;
}

std::optional<PdcpSecurityEntity> EnbAsSecurityProcedure::TakeRx()
{
    if (state_ != AsSecurityState::ACTIVE || !rx_.has_value())
        Fail(ProcedureError::NOT_PREPARED);
    std::optional<PdcpSecurityEntity> out = std::move(rx_);
    rx_.reset();
    return out;
}

void EnbAsSecurityProcedure::OnFailure(const std::vector<uint8_t> &uplinkPdu)
{
    (void)uplinkPdu;
    if (state_ != AsSecurityState::COMMAND_PENDING)
        Fail(ProcedureError::UNEXPECTED_MESSAGE);
    state_ = AsSecurityState::FAILED;
}

// --- UE ---------------------------------------------------------------------

UeAsSecurityProcedure UeAsSecurityProcedure::Listening(AsSecurityContext &context, uint32_t ueId)
{
    if (!context.IsActive())
        Fail(ProcedureError::NOT_PREPARED);

    UeAsSecurityProcedure procedure;
    procedure.context_ = &context;
    procedure.ueId_ = ueId;
    procedure.state_ = AsSecurityState::KEY_PREPARED;
    return procedure;
}

bool UeAsSecurityProcedure::CipheringActive() const
{
    return tx_.has_value() && rx_.has_value() && tx_->CipheringActive() && rx_->CipheringActive();
}

std::vector<uint8_t> UeAsSecurityProcedure::OnCommand(const std::vector<uint8_t> &downlinkPdu)
{
    if (state_ == AsSecurityState::ACTIVE)
        Fail(ProcedureError::ALREADY_ACTIVE);
    if (state_ != AsSecurityState::KEY_PREPARED)
        Fail(ProcedureError::UNEXPECTED_MESSAGE);

    // The command is readable before it is verified: it is not ciphered, and it
    // carries the algorithm that selects the key it is verified with.
    std::vector<uint8_t> payload;
    try
    {
        payload = ExtractPdcpPayload(downlinkPdu, PdcpProfile::SRB);
    }
    catch (const PdcpSecurityException &error)
    {
        (void)error;
        state_ = AsSecurityState::FAILED;
        Fail(ProcedureError::MALFORMED_MESSAGE);
    }

    SecurityModeCommandMessage command;
    if (!DecodeSecurityModeCommand(payload.data(), payload.size(), command) || !SupportedIdentity(command.cipheringAlgorithm) ||
        !SupportedIdentity(command.integrityAlgorithm))
    {
        state_ = AsSecurityState::FAILED;
        Fail(ProcedureError::MALFORMED_MESSAGE);
    }

    transactionId_ = command.transactionId;
    selection_.ciphering = command.cipheringAlgorithm;
    selection_.integrity = command.integrityAlgorithm;
    selection_.cipheringNull = command.cipheringAlgorithm == 0;
    selection_.integrityNull = command.integrityAlgorithm == 0;

    context_->ApplyAsAlgorithms(AlgorithmSetFor(selection_));
    const AsKeys keys = context_->DeriveAccessKeys();

    rx_.emplace(PdcpSecurityEntity::Create(PdcpProfile::SRB, RadioBearerIdentity::Srb1(), false, selection_.integrity,
                                           selection_.ciphering, keys.kRrcInt, keys.kRrcEnc));
    rx_->ActivateIntegrity();

    try
    {
        // Integrity only: ciphering is still inactive, so Unprotect checks the
        // MAC-I over the message exactly as it arrived.
        (void)rx_->Unprotect(downlinkPdu);
    }
    catch (const PdcpSecurityException &error)
    {
        state_ = AsSecurityState::FAILED;
        SecurityModeFailureMessage failure;
        failure.transactionId = transactionId_;
        return EncodeSecurityModeFailure(failure);
    }
    state_ = AsSecurityState::UE_VERIFIED;

    tx_.emplace(PdcpSecurityEntity::Create(PdcpProfile::SRB, RadioBearerIdentity::Srb1(), true, selection_.integrity,
                                           selection_.ciphering, keys.kRrcInt, keys.kRrcEnc));
    tx_->ActivateIntegrity();

    SecurityModeCompleteMessage complete;
    complete.transactionId = transactionId_;
    const auto encoded = EncodeSecurityModeComplete(complete);
    if (encoded.empty())
    {
        state_ = AsSecurityState::FAILED;
        Fail(ProcedureError::MALFORMED_MESSAGE);
    }

    // The SecurityModeComplete is integrity protected and not ciphered.
    auto protectedComplete = tx_->Protect(encoded);
    state_ = AsSecurityState::COMPLETE_PENDING;
    return protectedComplete;
}

std::optional<PdcpSecurityEntity> UeAsSecurityProcedure::TakeTx()
{
    if (state_ != AsSecurityState::ACTIVE || !tx_.has_value())
        Fail(ProcedureError::NOT_PREPARED);
    std::optional<PdcpSecurityEntity> out = std::move(tx_);
    tx_.reset();
    return out;
}

std::optional<PdcpSecurityEntity> UeAsSecurityProcedure::TakeRx()
{
    if (state_ != AsSecurityState::ACTIVE || !rx_.has_value())
        Fail(ProcedureError::NOT_PREPARED);
    std::optional<PdcpSecurityEntity> out = std::move(rx_);
    rx_.reset();
    return out;
}

void UeAsSecurityProcedure::ConfirmCompleteSent()
{
    if (state_ != AsSecurityState::COMPLETE_PENDING)
        Fail(ProcedureError::UNEXPECTED_MESSAGE);
    try
    {
        tx_->ActivateCiphering();
        rx_->ActivateCiphering();
    }
    catch (const PdcpSecurityException &error)
    {
        (void)error;
        state_ = AsSecurityState::FAILED;
        Fail(ProcedureError::ACTIVATION_REFUSED);
    }
    state_ = AsSecurityState::ACTIVE;
}

} // namespace lte::security
