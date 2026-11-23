//
// This file is a part of UERANSIM project.
// Copyright (c) 2027 ALİ GÜNGÖR.
//

#include "rrc_initial_access.hpp"

#include <cstdlib>
#include <type_traits>

#include "DL-CCCH-Message.h"
#include "DL-AM-RLC.h"
#include "RLC-Config.h"
#include "SRB-ToAddMod.h"
#include "SRB-ToAddModList.h"
#include "UL-AM-RLC.h"
#include "RRCConnectionReject-r8-IEs.h"
#include "RRCConnectionReject.h"
#include "RRCConnectionRequest-r8-IEs.h"
#include "RRCConnectionRequest.h"
#include "RRCConnectionSetup-r8-IEs.h"
#include "RRCConnectionSetup.h"
#include "S-TMSI.h"
#include "UL-CCCH-Message.h"

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

bool EncodePdu(asn_TYPE_descriptor_t &descriptor, void *pdu, std::vector<uint8_t> *out)
{
    const asn_enc_rval_t encoded = uper_encode(&descriptor, nullptr, pdu, AppendBytes, out);
    return encoded.encoded >= 0;
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

uint64_t GetBits(const BIT_STRING_t &source, size_t bits)
{
    uint64_t value = 0;
    const size_t octets = (bits + 7) / 8;
    for (size_t i = 0; i < octets && i < static_cast<size_t>(source.size); i++)
        value = (value << 8U) | source.buf[i];
    const size_t slack = octets * 8 - bits;
    return slack == 0 ? value : (value >> slack);
}

bool SetSpare(BIT_STRING_t &spare)
{
    spare.buf = static_cast<uint8_t *>(std::calloc(1, 1));
    if (spare.buf == nullptr)
        return false;
    spare.size = 1;
    spare.bits_unused = 7;
    spare.buf[0] = 0;
    return true;
}

[[noreturn]] void Fail(AccessError reason)
{
    throw AccessException(reason);
}

} // namespace

const char *ToString(RrcState state)
{
    switch (state)
    {
    case RrcState::RRC_IDLE: return "RRC_IDLE";
    case RrcState::RRC_CONNECTION_REQUEST_PENDING: return "RRC_CONNECTION_REQUEST_PENDING";
    case RrcState::RRC_SETUP_PENDING: return "RRC_SETUP_PENDING";
    case RrcState::RRC_SRB1_CONFIGURING: return "RRC_SRB1_CONFIGURING";
    case RrcState::RRC_CONNECTION_COMPLETE_PENDING: return "RRC_CONNECTION_COMPLETE_PENDING";
    case RrcState::RRC_CONNECTED: return "RRC_CONNECTED";
    case RrcState::RRC_CONNECTION_REJECTED: return "RRC_CONNECTION_REJECTED";
    case RrcState::RRC_CONNECTION_FAILED: return "RRC_CONNECTION_FAILED";
    case RrcState::RRC_RELEASED: return "RRC_RELEASED";
    }
    return "RRC_UNKNOWN";
}

const char *ToString(AccessError error)
{
    switch (error)
    {
    case AccessError::MALFORMED_REQUEST: return "MALFORMED_REQUEST";
    case AccessError::INVALID_IDENTITY: return "INVALID_IDENTITY";
    case AccessError::UNEXPECTED_MESSAGE: return "UNEXPECTED_MESSAGE";
    case AccessError::NO_PENDING_CONTEXT: return "NO_PENDING_CONTEXT";
    case AccessError::REQUEST_WHILE_PENDING: return "REQUEST_WHILE_PENDING";
    case AccessError::CONFIGURATION_INVALID: return "CONFIGURATION_INVALID";
    case AccessError::TIMEOUT: return "TIMEOUT";
    case AccessError::RELEASED: return "RELEASED";
    }
    return "UNKNOWN_ACCESS_ERROR";
}

AccessException::AccessException(AccessError reason)
    : std::runtime_error(std::string("RRC initial access refusal: ") + ToString(reason)), reason_(reason)
{
}

std::vector<uint8_t> EncodeRrcConnectionRequest(const RrcConnectionRequestMessage &message)
{
    auto *ul = Alloc<UL_CCCH_Message_t>();
    if (ul == nullptr)
        return {};
    ul->message.present = UL_CCCH_MessageType_PR_c1;
    ul->message.choice.c1 = AllocAnonymous(ul->message.choice.c1);
    if (ul->message.choice.c1 == nullptr)
    {
        std::free(ul);
        return {};
    }
    ul->message.choice.c1->present = UL_CCCH_MessageType__c1_PR_rrcConnectionRequest;

    auto *request = Alloc<RRCConnectionRequest_t>();
    auto *ies = Alloc<RRCConnectionRequest_r8_IEs_t>();
    auto *tmsi = Alloc<S_TMSI_t>();
    if (request == nullptr || ies == nullptr || tmsi == nullptr || !SetSpare(ies->spare))
    {
        std::free(request);
        std::free(ies);
        std::free(tmsi);
        ASN_STRUCT_FREE(asn_DEF_UL_CCCH_Message, ul);
        return {};
    }

    // This message's criticalExtensions is flattened by asn1c: no c1 wrapper.
    request->criticalExtensions.present = RRCConnectionRequest__criticalExtensions_PR_rrcConnectionRequest_r8;
    request->criticalExtensions.choice.rrcConnectionRequest_r8 = ies;

    ies->ue_Identity.present = InitialUE_Identity_PR_s_TMSI;
    ies->ue_Identity.choice.s_TMSI = tmsi;
    if (!SetBits(tmsi->mmec, message.mmec, 8) || !SetBits(tmsi->m_TMSI, message.mTmsi, 32))
    {
        ASN_STRUCT_FREE(asn_DEF_UL_CCCH_Message, ul);
        return {};
    }
    ies->establishmentCause = message.establishmentCause;

    ul->message.choice.c1->choice.rrcConnectionRequest = request;

    std::vector<uint8_t> out;
    const bool ok = EncodePdu(asn_DEF_UL_CCCH_Message, ul, &out);
    ASN_STRUCT_FREE(asn_DEF_UL_CCCH_Message, ul);
    return ok ? out : std::vector<uint8_t>{};
}

bool DecodeRrcConnectionRequest(const uint8_t *data, size_t size, RrcConnectionRequestMessage &out)
{
    asn_codec_ctx_t context{};
    void *decoded = nullptr;
    const asn_dec_rval_t rval = uper_decode_complete(&context, &asn_DEF_UL_CCCH_Message, &decoded, data, size);
    if (rval.code != RC_OK || decoded == nullptr)
    {
        ASN_STRUCT_FREE(asn_DEF_UL_CCCH_Message, decoded);
        return false;
    }
    auto *ul = static_cast<UL_CCCH_Message_t *>(decoded);
    bool ok = false;
    if (ul->message.present == UL_CCCH_MessageType_PR_c1 && ul->message.choice.c1 != nullptr &&
        ul->message.choice.c1->present == UL_CCCH_MessageType__c1_PR_rrcConnectionRequest &&
        ul->message.choice.c1->choice.rrcConnectionRequest != nullptr)
    {
        const auto *request = ul->message.choice.c1->choice.rrcConnectionRequest;
        if (request->criticalExtensions.present == RRCConnectionRequest__criticalExtensions_PR_rrcConnectionRequest_r8 &&
            request->criticalExtensions.choice.rrcConnectionRequest_r8 != nullptr)
        {
            const auto *ies = request->criticalExtensions.choice.rrcConnectionRequest_r8;
            if (ies->ue_Identity.present == InitialUE_Identity_PR_s_TMSI && ies->ue_Identity.choice.s_TMSI != nullptr)
            {
                out.mmec = static_cast<uint8_t>(GetBits(ies->ue_Identity.choice.s_TMSI->mmec, 8));
                out.mTmsi = static_cast<uint32_t>(GetBits(ies->ue_Identity.choice.s_TMSI->m_TMSI, 32));
                out.establishmentCause = static_cast<uint8_t>(ies->establishmentCause);
                ok = out.mTmsi != 0;
            }
        }
    }
    ASN_STRUCT_FREE(asn_DEF_UL_CCCH_Message, ul);
    return ok;
}

std::vector<uint8_t> EncodeRrcConnectionSetup(const RrcConnectionSetupMessage &message)
{
    auto *dl = Alloc<DL_CCCH_Message_t>();
    if (dl == nullptr)
        return {};
    dl->message.present = DL_CCCH_MessageType_PR_c1;
    dl->message.choice.c1 = AllocAnonymous(dl->message.choice.c1);
    if (dl->message.choice.c1 == nullptr)
    {
        std::free(dl);
        return {};
    }
    dl->message.choice.c1->present = DL_CCCH_MessageType__c1_PR_rrcConnectionSetup;

    auto *setup = Alloc<RRCConnectionSetup_t>();
    auto *c1 = setup != nullptr ? AllocAnonymous(setup->criticalExtensions.choice.c1) : nullptr;
    auto *ies = Alloc<RRCConnectionSetup_r8_IEs_t>();
    auto *list = Alloc<SRB_ToAddModList_t>();
    auto *srb = Alloc<SRB_ToAddMod_t>();
    auto *rlcChoice = srb != nullptr ? AllocAnonymous(srb->rlc_Config) : nullptr;
    auto *rlc = Alloc<RLC_Config_t>();
    auto *lchChoice = srb != nullptr ? AllocAnonymous(srb->logicalChannelConfig) : nullptr;

    if (setup == nullptr || c1 == nullptr || ies == nullptr || list == nullptr || srb == nullptr || rlcChoice == nullptr ||
        rlc == nullptr || lchChoice == nullptr)
    {
        std::free(setup);
        std::free(c1);
        std::free(ies);
        std::free(list);
        std::free(srb);
        std::free(rlcChoice);
        std::free(rlc);
        std::free(lchChoice);
        ASN_STRUCT_FREE(asn_DEF_DL_CCCH_Message, dl);
        return {};
    }

    setup->rrc_TransactionIdentifier = message.transactionId;
    setup->criticalExtensions.present = RRCConnectionSetup__criticalExtensions_PR_c1;
    setup->criticalExtensions.choice.c1 = c1;
    c1->present = RRCConnectionSetup__criticalExtensions__c1_PR_rrcConnectionSetup_r8;
    c1->choice.rrcConnectionSetup_r8 = ies;

    srb->srb_Identity = message.srbIdentity;
    rlc->present = RLC_Config_PR_am;
    using AmConfig = std::remove_pointer_t<decltype(rlc->choice.am)>;
    rlc->choice.am = static_cast<AmConfig *>(std::calloc(1, sizeof(AmConfig)));
    if (rlc->choice.am == nullptr)
    {
        ASN_STRUCT_FREE(asn_DEF_DL_CCCH_Message, dl);
        return {};
    }
    rlc->choice.am->ul_AM_RLC.t_PollRetransmit = static_cast<T_PollRetransmit_t>(message.tPollRetransmit);
    rlc->choice.am->ul_AM_RLC.pollPDU = static_cast<PollPDU_t>(message.pollPdu);
    rlc->choice.am->ul_AM_RLC.pollByte = static_cast<PollByte_t>(message.pollByte);
    rlc->choice.am->ul_AM_RLC.maxRetxThreshold = message.maxRetxThreshold;
    rlc->choice.am->dl_AM_RLC.t_Reordering = static_cast<T_Reordering_t>(message.tReordering);
    rlc->choice.am->dl_AM_RLC.t_StatusProhibit = static_cast<T_StatusProhibit_t>(message.tStatusProhibit);

    rlcChoice->present = SRB_ToAddMod__rlc_Config_PR_explicitValue;
    rlcChoice->choice.explicitValue = rlc;
    srb->rlc_Config = rlcChoice;

    lchChoice->present = SRB_ToAddMod__logicalChannelConfig_PR_defaultValue;
    srb->logicalChannelConfig = lchChoice;

    ASN_SEQUENCE_ADD(&list->list, srb);
    ies->radioResourceConfigDedicated.srb_ToAddModList = list;
    dl->message.choice.c1->choice.rrcConnectionSetup = setup;

    std::vector<uint8_t> out;
    const bool ok = EncodePdu(asn_DEF_DL_CCCH_Message, dl, &out);
    ASN_STRUCT_FREE(asn_DEF_DL_CCCH_Message, dl);
    return ok ? out : std::vector<uint8_t>{};
}

bool DecodeRrcConnectionSetup(const uint8_t *data, size_t size, RrcConnectionSetupMessage &out)
{
    asn_codec_ctx_t context{};
    void *decoded = nullptr;
    const asn_dec_rval_t rval = uper_decode_complete(&context, &asn_DEF_DL_CCCH_Message, &decoded, data, size);
    if (rval.code != RC_OK || decoded == nullptr)
    {
        ASN_STRUCT_FREE(asn_DEF_DL_CCCH_Message, decoded);
        return false;
    }
    auto *dl = static_cast<DL_CCCH_Message_t *>(decoded);
    bool ok = false;
    if (dl->message.present == DL_CCCH_MessageType_PR_c1 && dl->message.choice.c1 != nullptr &&
        dl->message.choice.c1->present == DL_CCCH_MessageType__c1_PR_rrcConnectionSetup &&
        dl->message.choice.c1->choice.rrcConnectionSetup != nullptr)
    {
        const auto *setup = dl->message.choice.c1->choice.rrcConnectionSetup;
        if (setup->criticalExtensions.present == RRCConnectionSetup__criticalExtensions_PR_c1 &&
            setup->criticalExtensions.choice.c1 != nullptr &&
            setup->criticalExtensions.choice.c1->present ==
                RRCConnectionSetup__criticalExtensions__c1_PR_rrcConnectionSetup_r8 &&
            setup->criticalExtensions.choice.c1->choice.rrcConnectionSetup_r8 != nullptr)
        {
            const auto &dedicated =
                setup->criticalExtensions.choice.c1->choice.rrcConnectionSetup_r8->radioResourceConfigDedicated;
            out.transactionId = static_cast<uint8_t>(setup->rrc_TransactionIdentifier);
            // SRB1 must be present, must carry an explicit AM RLC configuration.
            if (dedicated.srb_ToAddModList != nullptr && dedicated.srb_ToAddModList->list.count == 1 &&
                dedicated.srb_ToAddModList->list.array[0] != nullptr)
            {
                const auto *srb = dedicated.srb_ToAddModList->list.array[0];
                if (srb->srb_Identity == 1 && srb->rlc_Config != nullptr &&
                    srb->rlc_Config->present == SRB_ToAddMod__rlc_Config_PR_explicitValue &&
                    srb->rlc_Config->choice.explicitValue != nullptr &&
                    srb->rlc_Config->choice.explicitValue->present == RLC_Config_PR_am)
                {
                    out.srbIdentity = 1;
                    const auto *am = srb->rlc_Config->choice.explicitValue->choice.am;
                    if (am == nullptr)
                    {
                        ASN_STRUCT_FREE(asn_DEF_DL_CCCH_Message, dl);
                        return false;
                    }
                    out.tPollRetransmit = static_cast<uint8_t>(am->ul_AM_RLC.t_PollRetransmit);
                    out.pollPdu = static_cast<uint8_t>(am->ul_AM_RLC.pollPDU);
                    out.pollByte = static_cast<uint8_t>(am->ul_AM_RLC.pollByte);
                    out.maxRetxThreshold = static_cast<uint8_t>(am->ul_AM_RLC.maxRetxThreshold);
                    out.tReordering = static_cast<uint8_t>(am->dl_AM_RLC.t_Reordering);
                    out.tStatusProhibit = static_cast<uint8_t>(am->dl_AM_RLC.t_StatusProhibit);
                    ok = true;
                }
            }
        }
    }
    ASN_STRUCT_FREE(asn_DEF_DL_CCCH_Message, dl);
    return ok;
}

std::vector<uint8_t> EncodeRrcConnectionReject(const RrcConnectionRejectMessage &message)
{
    auto *dl = Alloc<DL_CCCH_Message_t>();
    if (dl == nullptr)
        return {};
    dl->message.present = DL_CCCH_MessageType_PR_c1;
    dl->message.choice.c1 = AllocAnonymous(dl->message.choice.c1);
    if (dl->message.choice.c1 == nullptr)
    {
        std::free(dl);
        return {};
    }
    dl->message.choice.c1->present = DL_CCCH_MessageType__c1_PR_rrcConnectionReject;

    auto *reject = Alloc<RRCConnectionReject_t>();
    auto *c1 = reject != nullptr ? AllocAnonymous(reject->criticalExtensions.choice.c1) : nullptr;
    auto *ies = Alloc<RRCConnectionReject_r8_IEs_t>();
    if (reject == nullptr || c1 == nullptr || ies == nullptr)
    {
        std::free(reject);
        std::free(c1);
        std::free(ies);
        ASN_STRUCT_FREE(asn_DEF_DL_CCCH_Message, dl);
        return {};
    }
    reject->criticalExtensions.present = RRCConnectionReject__criticalExtensions_PR_c1;
    reject->criticalExtensions.choice.c1 = c1;
    c1->present = RRCConnectionReject__criticalExtensions__c1_PR_rrcConnectionReject_r8;
    c1->choice.rrcConnectionReject_r8 = ies;
    ies->waitTime = message.waitTime;
    dl->message.choice.c1->choice.rrcConnectionReject = reject;

    std::vector<uint8_t> out;
    const bool ok = EncodePdu(asn_DEF_DL_CCCH_Message, dl, &out);
    ASN_STRUCT_FREE(asn_DEF_DL_CCCH_Message, dl);
    return ok ? out : std::vector<uint8_t>{};
}

bool DecodeRrcConnectionReject(const uint8_t *data, size_t size, RrcConnectionRejectMessage &out)
{
    asn_codec_ctx_t context{};
    void *decoded = nullptr;
    const asn_dec_rval_t rval = uper_decode_complete(&context, &asn_DEF_DL_CCCH_Message, &decoded, data, size);
    if (rval.code != RC_OK || decoded == nullptr)
    {
        ASN_STRUCT_FREE(asn_DEF_DL_CCCH_Message, decoded);
        return false;
    }
    auto *dl = static_cast<DL_CCCH_Message_t *>(decoded);
    bool ok = false;
    if (dl->message.present == DL_CCCH_MessageType_PR_c1 && dl->message.choice.c1 != nullptr &&
        dl->message.choice.c1->present == DL_CCCH_MessageType__c1_PR_rrcConnectionReject &&
        dl->message.choice.c1->choice.rrcConnectionReject != nullptr)
    {
        const auto *reject = dl->message.choice.c1->choice.rrcConnectionReject;
        if (reject->criticalExtensions.present == RRCConnectionReject__criticalExtensions_PR_c1 &&
            reject->criticalExtensions.choice.c1 != nullptr &&
            reject->criticalExtensions.choice.c1->present ==
                RRCConnectionReject__criticalExtensions__c1_PR_rrcConnectionReject_r8 &&
            reject->criticalExtensions.choice.c1->choice.rrcConnectionReject_r8 != nullptr)
        {
            out.waitTime = static_cast<uint8_t>(reject->criticalExtensions.choice.c1->choice.rrcConnectionReject_r8->waitTime);
            ok = true;
        }
    }
    ASN_STRUCT_FREE(asn_DEF_DL_CCCH_Message, dl);
    return ok;
}

// --- UE ---------------------------------------------------------------------

UeInitialAccess UeInitialAccess::Idle(uint32_t association, uint8_t mmec, uint32_t mTmsi)
{
    UeInitialAccess ue;
    ue.association_ = association;
    ue.mmec_ = mmec;
    ue.mTmsi_ = mTmsi;
    ue.state_ = RrcState::RRC_IDLE;
    return ue;
}

std::vector<uint8_t> UeInitialAccess::BuildRequest()
{
    if (state_ != RrcState::RRC_IDLE)
        Fail(AccessError::REQUEST_WHILE_PENDING);
    if (mTmsi_ == 0)
        Fail(AccessError::INVALID_IDENTITY);

    RrcConnectionRequestMessage request;
    request.mmec = mmec_;
    request.mTmsi = mTmsi_;
    request.establishmentCause = 0;  // mo-Signalling
    auto pdu = EncodeRrcConnectionRequest(request);
    if (pdu.empty())
        Fail(AccessError::MALFORMED_REQUEST);
    state_ = RrcState::RRC_CONNECTION_REQUEST_PENDING;
    return pdu;
}

void UeInitialAccess::OnDownlink(const std::vector<uint8_t> &pdu)
{
    if (state_ != RrcState::RRC_CONNECTION_REQUEST_PENDING)
        Fail(AccessError::UNEXPECTED_MESSAGE);

    RrcConnectionSetupMessage setup;
    if (DecodeRrcConnectionSetup(pdu.data(), pdu.size(), setup))
    {
        staged_ = setup;
        // SRB1 needs RLC AM, which this phase does not implement: the UE holds
        // the configuration and stops, it never claims RRC_CONNECTED.
        state_ = RrcState::RRC_SRB1_CONFIGURING;
        return;
    }

    RrcConnectionRejectMessage reject;
    if (DecodeRrcConnectionReject(pdu.data(), pdu.size(), reject))
    {
        state_ = RrcState::RRC_CONNECTION_REJECTED;
        return;
    }

    state_ = RrcState::RRC_CONNECTION_FAILED;
    Fail(AccessError::UNEXPECTED_MESSAGE);
}

void UeInitialAccess::OnTimeout() noexcept
{
    if (state_ == RrcState::RRC_CONNECTION_REQUEST_PENDING)
        state_ = RrcState::RRC_CONNECTION_FAILED;
}

// --- eNB --------------------------------------------------------------------

std::vector<uint8_t> EnbInitialAccess::OnRequest(uint32_t association, const std::vector<uint8_t> &pdu)
{
    RrcConnectionRequestMessage request;
    if (!DecodeRrcConnectionRequest(pdu.data(), pdu.size(), request))
        Fail(AccessError::MALFORMED_REQUEST);
    if (request.mTmsi == 0)
        Fail(AccessError::INVALID_IDENTITY);

    auto existing = contexts_.find(association);
    if (existing != contexts_.end())
    {
        // A repeated request for the same association returns the same answer.
        // It does not create a second context and does not invent an RLC SN.
        if (existing->second.mTmsi != request.mTmsi)
            Fail(AccessError::INVALID_IDENTITY);
        return existing->second.answer;
    }

    Pending pending;
    pending.mmec = request.mmec;
    pending.mTmsi = request.mTmsi;

    if (reject_)
    {
        RrcConnectionRejectMessage reject;
        reject.waitTime = waitTime_;
        pending.answer = EncodeRrcConnectionReject(reject);
        pending.state = RrcState::RRC_CONNECTION_REJECTED;
    }
    else
    {
        pending.answer = EncodeRrcConnectionSetup(setup_);
        pending.state = RrcState::RRC_SETUP_PENDING;
    }

    if (pending.answer.empty())
        Fail(AccessError::CONFIGURATION_INVALID);

    contexts_.emplace(association, pending);
    return pending.answer;
}

RrcState EnbInitialAccess::StateOf(uint32_t association) const
{
    const auto it = contexts_.find(association);
    return it == contexts_.end() ? RrcState::RRC_IDLE : it->second.state;
}

bool EnbInitialAccess::HasContext(uint32_t association) const
{
    return contexts_.find(association) != contexts_.end();
}

void EnbInitialAccess::Release(uint32_t association) noexcept
{
    contexts_.erase(association);
}

} // namespace lte::rrc
