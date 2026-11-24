//
// This file is a part of UERANSIM project.
// Copyright (c) 2027 ALİ GÜNGÖR.
//

#include "rrc_connection_release.hpp"

#include <cstdlib>
#include <type_traits>

#include "DL-DCCH-Message.h"
#include "RRCConnectionRelease.h"
#include "RRCConnectionRelease-r8-IEs.h"

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

std::vector<uint8_t> EncodeRrcConnectionRelease(const RrcConnectionReleaseMessage &message)
{
    if (message.transactionId > 3)
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
    dl->message.choice.c1->present = DL_DCCH_MessageType__c1_PR_rrcConnectionRelease;

    auto *release = Alloc<RRCConnectionRelease_t>();
    auto *c1 = release != nullptr ? AllocAnonymous(release->criticalExtensions.choice.c1) : nullptr;
    auto *ies = Alloc<RRCConnectionRelease_r8_IEs_t>();
    if (release == nullptr || c1 == nullptr || ies == nullptr)
    {
        std::free(release);
        std::free(c1);
        std::free(ies);
        ASN_STRUCT_FREE(asn_DEF_DL_DCCH_Message, dl);
        return {};
    }

    release->rrc_TransactionIdentifier = message.transactionId;
    release->criticalExtensions.present = RRCConnectionRelease__criticalExtensions_PR_c1;
    release->criticalExtensions.choice.c1 = c1;
    c1->present = RRCConnectionRelease__criticalExtensions__c1_PR_rrcConnectionRelease_r8;
    c1->choice.rrcConnectionRelease_r8 = ies;
    // TS 36.331 ReleaseCause: loadBalancing(0), other(1), ...
    ies->releaseCause = 1;

    dl->message.choice.c1->choice.rrcConnectionRelease = release;

    std::vector<uint8_t> out;
    const asn_enc_rval_t encoded = uper_encode(&asn_DEF_DL_DCCH_Message, nullptr, dl, AppendBytes, &out);
    ASN_STRUCT_FREE(asn_DEF_DL_DCCH_Message, dl);
    return encoded.encoded >= 0 ? out : std::vector<uint8_t>{};
}

bool DecodeRrcConnectionRelease(const uint8_t *data, size_t size, RrcConnectionReleaseMessage &out)
{
    if (data == nullptr || size == 0)
        return false;
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
        dl->message.choice.c1->present == DL_DCCH_MessageType__c1_PR_rrcConnectionRelease &&
        dl->message.choice.c1->choice.rrcConnectionRelease != nullptr)
    {
        const auto *release = dl->message.choice.c1->choice.rrcConnectionRelease;
        if (release->rrc_TransactionIdentifier >= 0 && release->rrc_TransactionIdentifier <= 3 &&
            release->criticalExtensions.present == RRCConnectionRelease__criticalExtensions_PR_c1 &&
            release->criticalExtensions.choice.c1 != nullptr &&
            release->criticalExtensions.choice.c1->present ==
                RRCConnectionRelease__criticalExtensions__c1_PR_rrcConnectionRelease_r8 &&
            release->criticalExtensions.choice.c1->choice.rrcConnectionRelease_r8 != nullptr)
        {
            out.transactionId = static_cast<uint8_t>(release->rrc_TransactionIdentifier);
            ok = true;
        }
    }
    ASN_STRUCT_FREE(asn_DEF_DL_DCCH_Message, dl);
    return ok;
}

} // namespace lte::rrc
