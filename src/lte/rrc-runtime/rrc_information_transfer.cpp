//
// This file is a part of UERANSIM project.
// Copyright (c) 2027 ALİ GÜNGÖR.
//

#include "rrc_information_transfer.hpp"

#include <cstdlib>
#include <cstring>
#include <type_traits>

#include "DL-DCCH-Message.h"
#include "DLInformationTransfer-r8-IEs.h"
#include "DLInformationTransfer.h"
#include "UL-DCCH-Message.h"
#include "ULInformationTransfer-r8-IEs.h"
#include "ULInformationTransfer.h"

namespace lte::rrc
{
namespace
{

template <typename T> T *Alloc()
{
    return static_cast<T *>(std::calloc(1, sizeof(T)));
}

template <typename T> T *AllocAnonymous(T *prototype)
{
    (void)prototype;
    using U = std::remove_pointer_t<T>;
    return static_cast<U *>(std::calloc(1, sizeof(U)));
}

int AppendBytes(const void *buffer, size_t size, void *applicationData)
{
    auto *out = static_cast<std::vector<uint8_t> *>(applicationData);
    const auto *bytes = static_cast<const uint8_t *>(buffer);
    out->insert(out->end(), bytes, bytes + size);
    return 0;
}

bool ValidNas(const std::vector<uint8_t> &nas)
{
    return !nas.empty() && nas.size() <= MaxDedicatedInfoNasBytes;
}

void SetNas(DedicatedInfoNAS_t &target, const std::vector<uint8_t> &nas)
{
    target.buf = static_cast<uint8_t *>(std::calloc(nas.size(), 1));
    if (target.buf != nullptr)
    {
        std::memcpy(target.buf, nas.data(), nas.size());
        target.size = static_cast<int>(nas.size());
    }
}

} // namespace

std::vector<uint8_t> EncodeUlInformationTransfer(const InformationTransferMessage &message)
{
    if (!ValidNas(message.dedicatedInfoNas))
        return {};

    auto *ul = Alloc<UL_DCCH_Message_t>();
    if (ul == nullptr)
        return {};
    ul->message.present = UL_DCCH_MessageType_PR_c1;
    ul->message.choice.c1 = AllocAnonymous(ul->message.choice.c1);
    if (ul->message.choice.c1 == nullptr)
    {
        std::free(ul);
        return {};
    }
    ul->message.choice.c1->present = UL_DCCH_MessageType__c1_PR_ulInformationTransfer;

    auto *transfer = Alloc<ULInformationTransfer_t>();
    auto *c1 = transfer != nullptr ? AllocAnonymous(transfer->criticalExtensions.choice.c1) : nullptr;
    auto *ies = Alloc<ULInformationTransfer_r8_IEs_t>();
    if (transfer == nullptr || c1 == nullptr || ies == nullptr)
    {
        std::free(transfer);
        std::free(c1);
        std::free(ies);
        ASN_STRUCT_FREE(asn_DEF_UL_DCCH_Message, ul);
        return {};
    }

    transfer->criticalExtensions.present = ULInformationTransfer__criticalExtensions_PR_c1;
    transfer->criticalExtensions.choice.c1 = c1;
    c1->present = ULInformationTransfer__criticalExtensions__c1_PR_ulInformationTransfer_r8;
    c1->choice.ulInformationTransfer_r8 = ies;
    ies->dedicatedInfoType.present = ULInformationTransfer_r8_IEs__dedicatedInfoType_PR_dedicatedInfoNAS;
    SetNas(ies->dedicatedInfoType.choice.dedicatedInfoNAS, message.dedicatedInfoNas);
    if (ies->dedicatedInfoType.choice.dedicatedInfoNAS.buf == nullptr)
    {
        ASN_STRUCT_FREE(asn_DEF_UL_DCCH_Message, ul);
        return {};
    }

    ul->message.choice.c1->choice.ulInformationTransfer = transfer;

    std::vector<uint8_t> out;
    const asn_enc_rval_t encoded = uper_encode(&asn_DEF_UL_DCCH_Message, nullptr, ul, AppendBytes, &out);
    ASN_STRUCT_FREE(asn_DEF_UL_DCCH_Message, ul);
    return encoded.encoded >= 0 ? out : std::vector<uint8_t>{};
}

std::vector<uint8_t> EncodeDlInformationTransfer(const InformationTransferMessage &message)
{
    if (!ValidNas(message.dedicatedInfoNas))
        return {};

    auto *dl = Alloc<DL_DCCH_Message_t>();
    if (dl == nullptr)
        return {};
    dl->message.present = DL_DCCH_MessageType_PR_c1;
    dl->message.choice.c1 = AllocAnonymous(dl->message.choice.c1);
    if (dl->message.choice.c1 == nullptr)
    {
        std::free(dl);
        return {};
    }
    dl->message.choice.c1->present = DL_DCCH_MessageType__c1_PR_dlInformationTransfer;

    auto *transfer = Alloc<DLInformationTransfer_t>();
    auto *c1 = transfer != nullptr ? AllocAnonymous(transfer->criticalExtensions.choice.c1) : nullptr;
    auto *ies = Alloc<DLInformationTransfer_r8_IEs_t>();
    if (transfer == nullptr || c1 == nullptr || ies == nullptr)
    {
        std::free(transfer);
        std::free(c1);
        std::free(ies);
        ASN_STRUCT_FREE(asn_DEF_DL_DCCH_Message, dl);
        return {};
    }

    transfer->criticalExtensions.present = DLInformationTransfer__criticalExtensions_PR_c1;
    transfer->criticalExtensions.choice.c1 = c1;
    c1->present = DLInformationTransfer__criticalExtensions__c1_PR_dlInformationTransfer_r8;
    c1->choice.dlInformationTransfer_r8 = ies;
    ies->dedicatedInfoType.present = DLInformationTransfer_r8_IEs__dedicatedInfoType_PR_dedicatedInfoNAS;
    SetNas(ies->dedicatedInfoType.choice.dedicatedInfoNAS, message.dedicatedInfoNas);
    if (ies->dedicatedInfoType.choice.dedicatedInfoNAS.buf == nullptr)
    {
        ASN_STRUCT_FREE(asn_DEF_DL_DCCH_Message, dl);
        return {};
    }

    dl->message.choice.c1->choice.dlInformationTransfer = transfer;

    std::vector<uint8_t> out;
    const asn_enc_rval_t encoded = uper_encode(&asn_DEF_DL_DCCH_Message, nullptr, dl, AppendBytes, &out);
    ASN_STRUCT_FREE(asn_DEF_DL_DCCH_Message, dl);
    return encoded.encoded >= 0 ? out : std::vector<uint8_t>{};
}

bool DecodeUlInformationTransfer(const uint8_t *data, size_t size, InformationTransferMessage &out)
{
    asn_codec_ctx_t context{};
    void *decoded = nullptr;
    const asn_dec_rval_t rval = uper_decode_complete(&context, &asn_DEF_UL_DCCH_Message, &decoded, data, size);
    if (rval.code != RC_OK || decoded == nullptr)
    {
        ASN_STRUCT_FREE(asn_DEF_UL_DCCH_Message, decoded);
        return false;
    }

    auto *ul = static_cast<UL_DCCH_Message_t *>(decoded);
    bool ok = false;
    if (ul->message.present == UL_DCCH_MessageType_PR_c1 && ul->message.choice.c1 != nullptr &&
        ul->message.choice.c1->present == UL_DCCH_MessageType__c1_PR_ulInformationTransfer &&
        ul->message.choice.c1->choice.ulInformationTransfer != nullptr)
    {
        const auto *transfer = ul->message.choice.c1->choice.ulInformationTransfer;
        if (transfer->criticalExtensions.present == ULInformationTransfer__criticalExtensions_PR_c1 &&
            transfer->criticalExtensions.choice.c1 != nullptr &&
            transfer->criticalExtensions.choice.c1->present ==
                ULInformationTransfer__criticalExtensions__c1_PR_ulInformationTransfer_r8 &&
            transfer->criticalExtensions.choice.c1->choice.ulInformationTransfer_r8 != nullptr)
        {
            const auto &info =
                transfer->criticalExtensions.choice.c1->choice.ulInformationTransfer_r8->dedicatedInfoType;
            if (info.present == ULInformationTransfer_r8_IEs__dedicatedInfoType_PR_dedicatedInfoNAS &&
                info.choice.dedicatedInfoNAS.buf != nullptr && info.choice.dedicatedInfoNAS.size > 0 &&
                static_cast<size_t>(info.choice.dedicatedInfoNAS.size) <= MaxDedicatedInfoNasBytes)
            {
                out.dedicatedInfoNas.assign(info.choice.dedicatedInfoNAS.buf,
                                            info.choice.dedicatedInfoNAS.buf + info.choice.dedicatedInfoNAS.size);
                ok = true;
            }
        }
    }
    ASN_STRUCT_FREE(asn_DEF_UL_DCCH_Message, ul);
    return ok;
}

bool DecodeDlInformationTransfer(const uint8_t *data, size_t size, InformationTransferMessage &out)
{
    asn_codec_ctx_t context{};
    void *decoded = nullptr;
    const asn_dec_rval_t rval = uper_decode_complete(&context, &asn_DEF_DL_DCCH_Message, &decoded, data, size);
    if (rval.code != RC_OK || decoded == nullptr)
    {
        ASN_STRUCT_FREE(asn_DEF_DL_DCCH_Message, decoded);
        return false;
    }

    auto *dl = static_cast<DL_DCCH_Message_t *>(decoded);
    bool ok = false;
    if (dl->message.present == DL_DCCH_MessageType_PR_c1 && dl->message.choice.c1 != nullptr &&
        dl->message.choice.c1->present == DL_DCCH_MessageType__c1_PR_dlInformationTransfer &&
        dl->message.choice.c1->choice.dlInformationTransfer != nullptr)
    {
        const auto *transfer = dl->message.choice.c1->choice.dlInformationTransfer;
        if (transfer->criticalExtensions.present == DLInformationTransfer__criticalExtensions_PR_c1 &&
            transfer->criticalExtensions.choice.c1 != nullptr &&
            transfer->criticalExtensions.choice.c1->present ==
                DLInformationTransfer__criticalExtensions__c1_PR_dlInformationTransfer_r8 &&
            transfer->criticalExtensions.choice.c1->choice.dlInformationTransfer_r8 != nullptr)
        {
            const auto &info =
                transfer->criticalExtensions.choice.c1->choice.dlInformationTransfer_r8->dedicatedInfoType;
            if (info.present == DLInformationTransfer_r8_IEs__dedicatedInfoType_PR_dedicatedInfoNAS &&
                info.choice.dedicatedInfoNAS.buf != nullptr && info.choice.dedicatedInfoNAS.size > 0 &&
                static_cast<size_t>(info.choice.dedicatedInfoNAS.size) <= MaxDedicatedInfoNasBytes)
            {
                out.dedicatedInfoNas.assign(info.choice.dedicatedInfoNAS.buf,
                                            info.choice.dedicatedInfoNAS.buf + info.choice.dedicatedInfoNAS.size);
                ok = true;
            }
        }
    }
    ASN_STRUCT_FREE(asn_DEF_DL_DCCH_Message, dl);
    return ok;
}

} // namespace lte::rrc
