//
// This file is a part of UERANSIM project.
// Copyright (c) 2027 ALİ GÜNGÖR.
//

#include "rrc_connection_setup_complete.hpp"

#include <cstdlib>
#include <cstring>
#include <type_traits>

#include "DedicatedInfoNAS.h"
#include "RRCConnectionSetupComplete-r8-IEs.h"
#include "RRCConnectionSetupComplete.h"
#include "UL-DCCH-Message.h"

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

} // namespace

std::vector<uint8_t> EncodeRrcConnectionSetupComplete(const RrcConnectionSetupCompleteMessage &message)
{
    if (message.transactionId > 3 || message.selectedPlmnIdentity < 1 || message.selectedPlmnIdentity > 6)
        return {};
    if (message.dedicatedInfoNas.empty() || message.dedicatedInfoNas.size() > MaxDedicatedInfoNasBytes)
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
    ul->message.choice.c1->present = UL_DCCH_MessageType__c1_PR_rrcConnectionSetupComplete;

    auto *complete = Alloc<RRCConnectionSetupComplete_t>();
    auto *c1 = complete != nullptr ? AllocAnonymous(complete->criticalExtensions.choice.c1) : nullptr;
    auto *ies = Alloc<RRCConnectionSetupComplete_r8_IEs_t>();
    if (complete == nullptr || c1 == nullptr || ies == nullptr)
    {
        std::free(complete);
        std::free(c1);
        std::free(ies);
        ASN_STRUCT_FREE(asn_DEF_UL_DCCH_Message, ul);
        return {};
    }

    complete->rrc_TransactionIdentifier = message.transactionId;
    complete->criticalExtensions.present = RRCConnectionSetupComplete__criticalExtensions_PR_c1;
    complete->criticalExtensions.choice.c1 = c1;
    c1->present = RRCConnectionSetupComplete__criticalExtensions__c1_PR_rrcConnectionSetupComplete_r8;
    c1->choice.rrcConnectionSetupComplete_r8 = ies;

    ies->selectedPLMN_Identity = message.selectedPlmnIdentity;
    ies->dedicatedInfoNAS.buf = static_cast<uint8_t *>(std::calloc(message.dedicatedInfoNas.size(), 1));
    if (ies->dedicatedInfoNAS.buf == nullptr)
    {
        ASN_STRUCT_FREE(asn_DEF_UL_DCCH_Message, ul);
        return {};
    }
    std::memcpy(ies->dedicatedInfoNAS.buf, message.dedicatedInfoNas.data(), message.dedicatedInfoNas.size());
    ies->dedicatedInfoNAS.size = static_cast<int>(message.dedicatedInfoNas.size());

    ul->message.choice.c1->choice.rrcConnectionSetupComplete = complete;

    std::vector<uint8_t> out;
    const asn_enc_rval_t encoded = uper_encode(&asn_DEF_UL_DCCH_Message, nullptr, ul, AppendBytes, &out);
    ASN_STRUCT_FREE(asn_DEF_UL_DCCH_Message, ul);
    return encoded.encoded >= 0 ? out : std::vector<uint8_t>{};
}

bool DecodeRrcConnectionSetupComplete(const uint8_t *data, size_t size, RrcConnectionSetupCompleteMessage &out)
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
        ul->message.choice.c1->present == UL_DCCH_MessageType__c1_PR_rrcConnectionSetupComplete &&
        ul->message.choice.c1->choice.rrcConnectionSetupComplete != nullptr)
    {
        const auto *complete = ul->message.choice.c1->choice.rrcConnectionSetupComplete;
        if (complete->criticalExtensions.present == RRCConnectionSetupComplete__criticalExtensions_PR_c1 &&
            complete->criticalExtensions.choice.c1 != nullptr &&
            complete->criticalExtensions.choice.c1->present ==
                RRCConnectionSetupComplete__criticalExtensions__c1_PR_rrcConnectionSetupComplete_r8 &&
            complete->criticalExtensions.choice.c1->choice.rrcConnectionSetupComplete_r8 != nullptr)
        {
            const auto *ies = complete->criticalExtensions.choice.c1->choice.rrcConnectionSetupComplete_r8;
            const long plmn = ies->selectedPLMN_Identity;
            const int nasSize = ies->dedicatedInfoNAS.size;
            if (complete->rrc_TransactionIdentifier >= 0 && complete->rrc_TransactionIdentifier <= 3 && plmn >= 1 &&
                plmn <= 6 && nasSize > 0 && static_cast<size_t>(nasSize) <= MaxDedicatedInfoNasBytes &&
                ies->dedicatedInfoNAS.buf != nullptr)
            {
                out.transactionId = static_cast<uint8_t>(complete->rrc_TransactionIdentifier);
                out.selectedPlmnIdentity = static_cast<uint8_t>(plmn);
                out.dedicatedInfoNas.assign(ies->dedicatedInfoNAS.buf,
                                            ies->dedicatedInfoNAS.buf + static_cast<size_t>(nasSize));
                ok = true;
            }
        }
    }
    ASN_STRUCT_FREE(asn_DEF_UL_DCCH_Message, ul);
    return ok;
}

} // namespace lte::rrc
