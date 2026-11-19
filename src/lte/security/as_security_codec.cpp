//
// This file is a part of UERANSIM project.
// Copyright (c) 2027 ALİ GÜNGÖR.
//
// https://github.com/aligungr/UERANSIM/
// See README, LICENSE, and CONTRIBUTING files for licensing details.
//

#include "as_security_codec.hpp"

#include <cstdlib>
#include <type_traits>
#include <cstring>

#include "CipheringAlgorithm-r12.h"
#include "DL-DCCH-Message.h"
#include "SecurityAlgorithmConfig.h"
#include "SecurityConfigSMC.h"
#include "SecurityModeCommand-r8-IEs.h"
#include "SecurityModeCommand.h"
#include "SecurityModeComplete-r8-IEs.h"
#include "SecurityModeComplete.h"
#include "SecurityModeFailure-r8-IEs.h"
#include "SecurityModeFailure.h"
#include "UL-DCCH-Message.h"

namespace lte::security
{
namespace
{

template <typename T> T *Alloc()
{
    return static_cast<T *>(std::calloc(1, sizeof(T)));
}

int AppendBytes(const void *buffer, size_t size, void *applicationData)
{
    auto *out = static_cast<std::vector<uint8_t> *>(applicationData);
    const auto *bytes = static_cast<const uint8_t *>(buffer);
    out->insert(out->end(), bytes, bytes + size);
    return 0;
}

bool EncodePdu(asn_TYPE_descriptor_t &descriptor, void *pdu, std::vector<uint8_t> *out)
{
    const asn_enc_rval_t encoded = uper_encode(&descriptor, nullptr, pdu, AppendBytes, out);
    return encoded.encoded >= 0;
}

bool ValidTransactionId(uint8_t transactionId)
{
    return transactionId <= MaxRrcTransactionId;
}

bool ValidAlgorithm(uint8_t identity)
{
    return identity <= 3;
}

// A DL-DCCH or UL-DCCH wrapper with exactly one c1 alternative, or nothing.
template <typename Message> void *DecodeDcch(asn_TYPE_descriptor_t *descriptor, const uint8_t *data, size_t size)
{
    asn_codec_ctx_t context{};
    void *decoded = nullptr;
    const asn_dec_rval_t rval = uper_decode_complete(&context, descriptor, &decoded, data, size);
    if (rval.code != RC_OK || decoded == nullptr)
    {
        ASN_STRUCT_FREE(*descriptor, decoded);
        return nullptr;
    }
    (void)sizeof(Message);
    return decoded;
}

} // namespace

std::vector<uint8_t> EncodeSecurityModeCommand(const SecurityModeCommandMessage &message)
{
    if (!ValidTransactionId(message.transactionId) || !ValidAlgorithm(message.cipheringAlgorithm) ||
        !ValidAlgorithm(message.integrityAlgorithm))
        return {};

    auto *dl = Alloc<DL_DCCH_Message_t>();
    if (dl == nullptr)
        return {};
    dl->message.present = DL_DCCH_MessageType_PR_c1;
    using DlC1 = std::remove_pointer_t<decltype(dl->message.choice.c1)>;
    dl->message.choice.c1 = static_cast<DlC1 *>(std::calloc(1, sizeof(DlC1)));
    if (dl->message.choice.c1 == nullptr)
    {
        std::free(dl);
        return {};
    }
    dl->message.choice.c1->present = DL_DCCH_MessageType__c1_PR_securityModeCommand;

    auto *command = Alloc<SecurityModeCommand_t>();
    using ScC1 = std::remove_pointer_t<decltype(command->criticalExtensions.choice.c1)>;
    auto *c1 = static_cast<ScC1 *>(std::calloc(1, sizeof(ScC1)));
    auto *ies = Alloc<SecurityModeCommand_r8_IEs_t>();
    if (command == nullptr || c1 == nullptr || ies == nullptr)
    {
        std::free(command);
        std::free(c1);
        std::free(ies);
        ASN_STRUCT_FREE(asn_DEF_DL_DCCH_Message, dl);
        return {};
    }

    command->rrc_TransactionIdentifier = message.transactionId;
    command->criticalExtensions.present = SecurityModeCommand__criticalExtensions_PR_c1;
    command->criticalExtensions.choice.c1 = c1;
    c1->present = SecurityModeCommand__criticalExtensions__c1_PR_securityModeCommand_r8;
    c1->choice.securityModeCommand_r8 = ies;
    ies->securityConfigSMC.securityAlgorithmConfig.cipheringAlgorithm =
        static_cast<CipheringAlgorithm_r12_t>(message.cipheringAlgorithm);
    ies->securityConfigSMC.securityAlgorithmConfig.integrityProtAlgorithm = message.integrityAlgorithm;

    dl->message.choice.c1->choice.securityModeCommand = command;

    std::vector<uint8_t> out;
    const bool ok = EncodePdu(asn_DEF_DL_DCCH_Message, dl, &out);
    ASN_STRUCT_FREE(asn_DEF_DL_DCCH_Message, dl);
    return ok ? out : std::vector<uint8_t>{};
}

std::vector<uint8_t> EncodeSecurityModeComplete(const SecurityModeCompleteMessage &message)
{
    if (!ValidTransactionId(message.transactionId))
        return {};

    auto *ul = Alloc<UL_DCCH_Message_t>();
    if (ul == nullptr)
        return {};
    ul->message.present = UL_DCCH_MessageType_PR_c1;
    using UlC1 = std::remove_pointer_t<decltype(ul->message.choice.c1)>;
    ul->message.choice.c1 = static_cast<UlC1 *>(std::calloc(1, sizeof(UlC1)));
    if (ul->message.choice.c1 == nullptr)
    {
        std::free(ul);
        return {};
    }
    ul->message.choice.c1->present = UL_DCCH_MessageType__c1_PR_securityModeComplete;

    auto *complete = Alloc<SecurityModeComplete_t>();
    auto *ies = Alloc<SecurityModeComplete_r8_IEs_t>();
    if (complete == nullptr || ies == nullptr)
    {
        std::free(complete);
        std::free(ies);
        ASN_STRUCT_FREE(asn_DEF_UL_DCCH_Message, ul);
        return {};
    }
    complete->rrc_TransactionIdentifier = message.transactionId;
    complete->criticalExtensions.present = SecurityModeComplete__criticalExtensions_PR_securityModeComplete_r8;
    complete->criticalExtensions.choice.securityModeComplete_r8 = ies;
    ul->message.choice.c1->choice.securityModeComplete = complete;

    std::vector<uint8_t> out;
    const bool ok = EncodePdu(asn_DEF_UL_DCCH_Message, ul, &out);
    ASN_STRUCT_FREE(asn_DEF_UL_DCCH_Message, ul);
    return ok ? out : std::vector<uint8_t>{};
}

std::vector<uint8_t> EncodeSecurityModeFailure(const SecurityModeFailureMessage &message)
{
    if (!ValidTransactionId(message.transactionId))
        return {};

    auto *ul = Alloc<UL_DCCH_Message_t>();
    if (ul == nullptr)
        return {};
    ul->message.present = UL_DCCH_MessageType_PR_c1;
    using UlC1 = std::remove_pointer_t<decltype(ul->message.choice.c1)>;
    ul->message.choice.c1 = static_cast<UlC1 *>(std::calloc(1, sizeof(UlC1)));
    if (ul->message.choice.c1 == nullptr)
    {
        std::free(ul);
        return {};
    }
    ul->message.choice.c1->present = UL_DCCH_MessageType__c1_PR_securityModeFailure;

    auto *failure = Alloc<SecurityModeFailure_t>();
    auto *ies = Alloc<SecurityModeFailure_r8_IEs_t>();
    if (failure == nullptr || ies == nullptr)
    {
        std::free(failure);
        std::free(ies);
        ASN_STRUCT_FREE(asn_DEF_UL_DCCH_Message, ul);
        return {};
    }
    failure->rrc_TransactionIdentifier = message.transactionId;
    failure->criticalExtensions.present = SecurityModeFailure__criticalExtensions_PR_securityModeFailure_r8;
    failure->criticalExtensions.choice.securityModeFailure_r8 = ies;
    ul->message.choice.c1->choice.securityModeFailure = failure;

    std::vector<uint8_t> out;
    const bool ok = EncodePdu(asn_DEF_UL_DCCH_Message, ul, &out);
    ASN_STRUCT_FREE(asn_DEF_UL_DCCH_Message, ul);
    return ok ? out : std::vector<uint8_t>{};
}

bool DecodeSecurityModeCommand(const uint8_t *data, size_t size, SecurityModeCommandMessage &out)
{
    auto *dl = static_cast<DL_DCCH_Message_t *>(DecodeDcch<DL_DCCH_Message_t>(&asn_DEF_DL_DCCH_Message, data, size));
    if (dl == nullptr)
        return false;

    bool ok = false;
    if (dl->message.present == DL_DCCH_MessageType_PR_c1 && dl->message.choice.c1 != nullptr &&
        dl->message.choice.c1->present == DL_DCCH_MessageType__c1_PR_securityModeCommand &&
        dl->message.choice.c1->choice.securityModeCommand != nullptr)
    {
        const auto *command = dl->message.choice.c1->choice.securityModeCommand;
        if (command->criticalExtensions.present == SecurityModeCommand__criticalExtensions_PR_c1 &&
            command->criticalExtensions.choice.c1 != nullptr &&
            command->criticalExtensions.choice.c1->present ==
                SecurityModeCommand__criticalExtensions__c1_PR_securityModeCommand_r8 &&
            command->criticalExtensions.choice.c1->choice.securityModeCommand_r8 != nullptr)
        {
            const auto &config =
                command->criticalExtensions.choice.c1->choice.securityModeCommand_r8->securityConfigSMC
                    .securityAlgorithmConfig;
            const auto ciphering = static_cast<uint8_t>(config.cipheringAlgorithm);
            const auto integrity = static_cast<uint8_t>(config.integrityProtAlgorithm);
            if (ciphering <= 3 && integrity <= 3)
            {
                out.transactionId = static_cast<uint8_t>(command->rrc_TransactionIdentifier);
                out.cipheringAlgorithm = ciphering;
                out.integrityAlgorithm = integrity;
                ok = true;
            }
        }
    }

    ASN_STRUCT_FREE(asn_DEF_DL_DCCH_Message, dl);
    return ok;
}

bool DecodeSecurityModeComplete(const uint8_t *data, size_t size, SecurityModeCompleteMessage &out)
{
    auto *ul = static_cast<UL_DCCH_Message_t *>(DecodeDcch<UL_DCCH_Message_t>(&asn_DEF_UL_DCCH_Message, data, size));
    if (ul == nullptr)
        return false;

    bool ok = false;
    if (ul->message.present == UL_DCCH_MessageType_PR_c1 && ul->message.choice.c1 != nullptr &&
        ul->message.choice.c1->present == UL_DCCH_MessageType__c1_PR_securityModeComplete &&
        ul->message.choice.c1->choice.securityModeComplete != nullptr)
    {
        out.transactionId = static_cast<uint8_t>(ul->message.choice.c1->choice.securityModeComplete->rrc_TransactionIdentifier);
        ok = out.transactionId <= MaxRrcTransactionId;
    }

    ASN_STRUCT_FREE(asn_DEF_UL_DCCH_Message, ul);
    return ok;
}

bool DecodeSecurityModeFailure(const uint8_t *data, size_t size, SecurityModeFailureMessage &out)
{
    auto *ul = static_cast<UL_DCCH_Message_t *>(DecodeDcch<UL_DCCH_Message_t>(&asn_DEF_UL_DCCH_Message, data, size));
    if (ul == nullptr)
        return false;

    bool ok = false;
    if (ul->message.present == UL_DCCH_MessageType_PR_c1 && ul->message.choice.c1 != nullptr &&
        ul->message.choice.c1->present == UL_DCCH_MessageType__c1_PR_securityModeFailure &&
        ul->message.choice.c1->choice.securityModeFailure != nullptr)
    {
        out.transactionId = static_cast<uint8_t>(ul->message.choice.c1->choice.securityModeFailure->rrc_TransactionIdentifier);
        ok = out.transactionId <= MaxRrcTransactionId;
    }

    ASN_STRUCT_FREE(asn_DEF_UL_DCCH_Message, ul);
    return ok;
}

} // namespace lte::security
