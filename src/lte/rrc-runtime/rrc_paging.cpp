//
// This file is a part of UERANSIM project.
// Copyright (c) 2027 ALİ GÜNGÖR.
//

#include "rrc_paging.hpp"

#include <cstdlib>
#include <type_traits>

#include "PCCH-Message.h"
#include "Paging.h"
#include "PagingRecord.h"
#include "PagingRecordList.h"
#include "PagingUE-Identity.h"
#include "S-TMSI.h"

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

uint64_t GetBits(const BIT_STRING_t &source, size_t bits)
{
    uint64_t value = 0;
    const size_t octets = (bits + 7) / 8;
    for (size_t i = 0; i < octets && i < static_cast<size_t>(source.size); i++)
        value = (value << 8U) | source.buf[i];
    const size_t slack = octets * 8 - bits;
    return slack == 0 ? value : (value >> slack);
}

bool SetBits(BIT_STRING_t &target, uint64_t value, size_t bits)
{
    const size_t octets = (bits + 7) / 8;
    target.buf = static_cast<uint8_t *>(std::calloc(octets, 1));
    if (target.buf == nullptr)
        return false;
    target.size = static_cast<int>(octets);
    target.bits_unused = static_cast<int>(octets * 8 - bits);
    for (size_t i = 0; i < octets; i++)
        target.buf[i] = static_cast<uint8_t>((value >> ((octets - 1 - i) * 8)) & 0xFFU);
    return true;
}

} // namespace

std::vector<uint8_t> EncodePaging(const PagingMessage &message)
{
    if (message.records.empty() || message.records.size() > MaxPagingRecords)
        return {};

    auto *pcch = Alloc<PCCH_Message_t>();
    if (pcch == nullptr)
        return {};
    pcch->message.present = PCCH_MessageType_PR_c1;
    pcch->message.choice.c1 = AllocAnonymous(pcch->message.choice.c1);
    if (pcch->message.choice.c1 == nullptr)
    {
        std::free(pcch);
        return {};
    }
    pcch->message.choice.c1->present = PCCH_MessageType__c1_PR_paging;

    auto *paging = Alloc<Paging_t>();
    auto *list = Alloc<PagingRecordList_t>();
    if (paging == nullptr || list == nullptr)
    {
        std::free(paging);
        std::free(list);
        std::free(pcch->message.choice.c1);
        std::free(pcch);
        return {};
    }

    for (const auto &source : message.records)
    {
        auto *record = Alloc<PagingRecord_t>();
        auto *identity = Alloc<S_TMSI_t>();
        if (record == nullptr || identity == nullptr)
        {
            std::free(record);
            std::free(identity);
            ASN_STRUCT_FREE(asn_DEF_PCCH_Message, pcch);
            return {};
        }
        if (!SetBits(identity->mmec, source.mmec, 8) || !SetBits(identity->m_TMSI, source.mTmsi, 32))
        {
            std::free(record);
            ASN_STRUCT_FREE(asn_DEF_S_TMSI, identity);
            ASN_STRUCT_FREE(asn_DEF_PCCH_Message, pcch);
            return {};
        }
        record->ue_Identity.present = PagingUE_Identity_PR_s_TMSI;
        record->ue_Identity.choice.s_TMSI = identity;
        record->cn_Domain = source.csDomain ? PagingRecord__cn_Domain_cs : PagingRecord__cn_Domain_ps;
        if (ASN_SEQUENCE_ADD(&list->list, record) != 0)
        {
            ASN_STRUCT_FREE(asn_DEF_PagingRecord, record);
            ASN_STRUCT_FREE(asn_DEF_PCCH_Message, pcch);
            return {};
        }
    }

    paging->pagingRecordList = list;
    pcch->message.choice.c1->choice.paging = paging;

    std::vector<uint8_t> out;
    const asn_enc_rval_t encoded = uper_encode(&asn_DEF_PCCH_Message, nullptr, pcch, AppendBytes, &out);
    ASN_STRUCT_FREE(asn_DEF_PCCH_Message, pcch);
    return encoded.encoded >= 0 ? out : std::vector<uint8_t>{};
}

bool DecodePaging(const uint8_t *data, size_t size, PagingMessage &out)
{
    if (data == nullptr || size == 0)
        return false;
    asn_codec_ctx_t context{};
    void *decoded = nullptr;
    const asn_dec_rval_t rval = uper_decode_complete(&context, &asn_DEF_PCCH_Message, &decoded, data, size);
    if (rval.code != RC_OK || decoded == nullptr)
    {
        ASN_STRUCT_FREE(asn_DEF_PCCH_Message, decoded);
        return false;
    }

    auto *pcch = static_cast<PCCH_Message_t *>(decoded);
    bool ok = false;
    out.records.clear();
    if (pcch->message.present == PCCH_MessageType_PR_c1 && pcch->message.choice.c1 != nullptr &&
        pcch->message.choice.c1->present == PCCH_MessageType__c1_PR_paging &&
        pcch->message.choice.c1->choice.paging != nullptr)
    {
        const auto *paging = pcch->message.choice.c1->choice.paging;
        const auto *list = paging->pagingRecordList;
        if (list != nullptr && list->list.count > 0 && static_cast<size_t>(list->list.count) <= MaxPagingRecords)
        {
            ok = true;
            for (int i = 0; i < list->list.count; i++)
            {
                const auto *record = list->list.array[i];
                if (record == nullptr || record->ue_Identity.present != PagingUE_Identity_PR_s_TMSI ||
                    record->ue_Identity.choice.s_TMSI == nullptr)
                {
                    ok = false;
                    break;
                }
                const auto *identity = record->ue_Identity.choice.s_TMSI;
                if (identity->m_TMSI.size != 4 || identity->m_TMSI.buf == nullptr || identity->m_TMSI.bits_unused != 0)
                {
                    ok = false;
                    break;
                }
                PagingRecord entry;
                entry.mmec = static_cast<uint8_t>(GetBits(identity->mmec, 8));
                entry.mTmsi = (static_cast<uint32_t>(identity->m_TMSI.buf[0]) << 24U) |
                              (static_cast<uint32_t>(identity->m_TMSI.buf[1]) << 16U) |
                              (static_cast<uint32_t>(identity->m_TMSI.buf[2]) << 8U) |
                              static_cast<uint32_t>(identity->m_TMSI.buf[3]);
                if (record->cn_Domain != PagingRecord__cn_Domain_ps &&
                    record->cn_Domain != PagingRecord__cn_Domain_cs)
                {
                    ok = false;
                    break;
                }
                entry.csDomain = record->cn_Domain == PagingRecord__cn_Domain_cs;
                out.records.push_back(entry);
            }
        }
    }
    ASN_STRUCT_FREE(asn_DEF_PCCH_Message, pcch);
    if (!ok)
        out.records.clear();
    return ok;
}

} // namespace lte::rrc
