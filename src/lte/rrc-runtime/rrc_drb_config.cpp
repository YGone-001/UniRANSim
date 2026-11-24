//
// This file is a part of UERANSIM project.
// Copyright (c) 2027 ALİ GÜNGÖR.
//

#include "rrc_drb_config.hpp"

#include <cstdlib>
#include <cstring>
#include <type_traits>

#include "DL-DCCH-Message.h"
#include "DRB-ToAddMod.h"
#include "DRB-ToAddModList.h"
#include "LogicalChannelConfig.h"
#include "PDCP-Config.h"
#include "RLC-Config.h"
#include "RRCConnectionReconfiguration-r8-IEs.h"
#include "RRCConnectionReconfiguration.h"
#include "RRCConnectionReconfigurationComplete-r8-IEs.h"
#include "RRCConnectionReconfigurationComplete.h"
#include "RadioResourceConfigDedicated.h"
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

bool InRange(long value, long min, long max)
{
    return value >= min && value <= max;
}

bool Validate(const DrbReconfiguration &message)
{
    if (!InRange(message.transactionId, 0, 3))
        return false;
    if (message.drbs.empty() || message.drbs.size() > MaxDrbToAdd)
        return false;
    for (size_t i = 0; i < message.drbs.size(); ++i)
    {
        const auto &drb = message.drbs[i];
        if (drb.ebi < 5 || drb.ebi > 15)
            return false;
        if (drb.drbIdentity < MinDrbIdentity || drb.drbIdentity > MaxDrbIdentity)
            return false;
        if (drb.logicalChannelIdentity < MinDrbLogicalChannel ||
            drb.logicalChannelIdentity > MaxDrbLogicalChannel)
            return false;
        if (drb.priority < 1 || drb.priority > 16)
            return false;
        for (size_t j = 0; j < i; ++j)
        {
            if (message.drbs[j].ebi == drb.ebi || message.drbs[j].drbIdentity == drb.drbIdentity ||
                message.drbs[j].logicalChannelIdentity == drb.logicalChannelIdentity)
                return false;
        }
    }
    return true;
}

PDCP_Config_t *BuildPdcpConfig()
{
    auto *pdcp = Alloc<PDCP_Config_t>();
    if (pdcp == nullptr)
        return nullptr;
    pdcp->rlc_AM = AllocAnonymous(pdcp->rlc_AM);
    if (pdcp->rlc_AM == nullptr)
    {
        std::free(pdcp);
        return nullptr;
    }
    // The PDCP status report is an AM DRB feature this runtime does not
    // generate or consume, so it is not requested.
    pdcp->rlc_AM->statusReportRequired = 0;
    pdcp->headerCompression.present = PDCP_Config__headerCompression_PR_notUsed;
    return pdcp;
}

RLC_Config_t *BuildRlcConfig()
{
    auto *rlc = Alloc<RLC_Config_t>();
    if (rlc == nullptr)
        return nullptr;
    rlc->present = RLC_Config_PR_am;
    rlc->choice.am = AllocAnonymous(rlc->choice.am);
    if (rlc->choice.am == nullptr)
    {
        std::free(rlc);
        return nullptr;
    }
    // The same enumerators the SRB1 runtime uses: t-PollRetransmit ms15,
    // pollPDU pInfinity, pollByte kBinfinity, maxRetxThreshold t8, t-Reordering
    // ms5 and t-StatusProhibit ms5.
    rlc->choice.am->ul_AM_RLC.t_PollRetransmit = 2;
    rlc->choice.am->ul_AM_RLC.pollPDU = 7;
    rlc->choice.am->ul_AM_RLC.pollByte = 14;
    rlc->choice.am->ul_AM_RLC.maxRetxThreshold = 5;
    rlc->choice.am->dl_AM_RLC.t_Reordering = 1;
    rlc->choice.am->dl_AM_RLC.t_StatusProhibit = 1;
    return rlc;
}

LogicalChannelConfig_t *BuildLogicalChannelConfig(uint8_t priority)
{
    auto *config = Alloc<LogicalChannelConfig_t>();
    if (config == nullptr)
        return nullptr;
    config->ul_SpecificParameters = AllocAnonymous(config->ul_SpecificParameters);
    if (config->ul_SpecificParameters == nullptr)
    {
        std::free(config);
        return nullptr;
    }
    auto *ul = config->ul_SpecificParameters;
    ul->priority = priority;
    ul->prioritisedBitRate = 7;   // kBpsInfinity
    ul->bucketSizeDuration = 4;   // ms500
    ul->logicalChannelGroup = static_cast<long *>(std::calloc(1, sizeof(long)));
    if (ul->logicalChannelGroup == nullptr)
    {
        ASN_STRUCT_FREE(asn_DEF_LogicalChannelConfig, config);
        return nullptr;
    }
    *ul->logicalChannelGroup = 0;
    return config;
}

DRB_ToAddMod_t *BuildDrbToAdd(const DrbToAdd &drb)
{
    auto *entry = Alloc<DRB_ToAddMod_t>();
    if (entry == nullptr)
        return nullptr;
    entry->eps_BearerIdentity = static_cast<long *>(std::calloc(1, sizeof(long)));
    if (entry->eps_BearerIdentity == nullptr)
    {
        std::free(entry);
        return nullptr;
    }
    *entry->eps_BearerIdentity = drb.ebi;
    entry->drb_Identity = drb.drbIdentity;
    entry->pdcp_Config = BuildPdcpConfig();
    entry->rlc_Config = BuildRlcConfig();
    entry->logicalChannelIdentity = static_cast<long *>(std::calloc(1, sizeof(long)));
    if (entry->logicalChannelIdentity == nullptr)
    {
        ASN_STRUCT_FREE(asn_DEF_DRB_ToAddMod, entry);
        return nullptr;
    }
    *entry->logicalChannelIdentity = drb.logicalChannelIdentity;
    entry->logicalChannelConfig = BuildLogicalChannelConfig(drb.priority);
    if (entry->pdcp_Config == nullptr || entry->rlc_Config == nullptr || entry->logicalChannelConfig == nullptr)
    {
        ASN_STRUCT_FREE(asn_DEF_DRB_ToAddMod, entry);
        return nullptr;
    }
    return entry;
}

bool IsAbsent(const void *pointer)
{
    return pointer == nullptr;
}

// The reconfiguration this phase emits may carry nothing but the DRB list.
// A field it cannot represent is refused rather than silently ignored, so a
// message cannot appear to have configured less than it asked for.
bool CanonicalRadioResourceConfig(const RadioResourceConfigDedicated_t &config)
{
    return IsAbsent(config.srb_ToAddModList) && config.drb_ToAddModList != nullptr &&
           IsAbsent(config.drb_ToReleaseList) && IsAbsent(config.mac_MainConfig) &&
           IsAbsent(config.sps_Config) && IsAbsent(config.physicalConfigDedicated) &&
           IsAbsent(config.rlf_TimersAndConstants_r9) && IsAbsent(config.measSubframePatternPCell_r10) &&
           IsAbsent(config.neighCellsCRS_Info_r11) && IsAbsent(config.naics_Info_r12) &&
           IsAbsent(config.neighCellsCRS_Info_r13) && IsAbsent(config.rlf_TimersAndConstants_r13) &&
           IsAbsent(config.sps_Config_v1430) && IsAbsent(config.srb_ToAddModListExt_r15) &&
           IsAbsent(config.srb_ToReleaseListExt_r15) && IsAbsent(config.sps_Config_v1530) &&
           IsAbsent(config.crs_IntfMitigConfig_r15) && IsAbsent(config.neighCellsCRS_Info_r15) &&
           IsAbsent(config.drb_ToAddModList_r15) && IsAbsent(config.drb_ToReleaseList_r15) &&
           IsAbsent(config.dummy) && IsAbsent(config.sps_Config_v1540);
}

bool CanonicalPdcp(const PDCP_Config_t &pdcp)
{
    return pdcp.rlc_AM != nullptr && pdcp.rlc_UM == nullptr &&
           pdcp.headerCompression.present == PDCP_Config__headerCompression_PR_notUsed &&
           IsAbsent(pdcp.rn_IntegrityProtection_r10) && IsAbsent(pdcp.pdcp_SN_Size_v1130) &&
           IsAbsent(pdcp.ul_DataSplitDRB_ViaSCG_r12) && IsAbsent(pdcp.t_Reordering_r12) &&
           IsAbsent(pdcp.ul_DataSplitThreshold_r13) && IsAbsent(pdcp.pdcp_SN_Size_v1310) &&
           IsAbsent(pdcp.statusFeedback_r13) && IsAbsent(pdcp.ul_LWA_Config_r14) &&
           IsAbsent(pdcp.uplinkOnlyHeaderCompression_r14) && IsAbsent(pdcp.uplinkDataCompression_r15) &&
           IsAbsent(pdcp.pdcp_DuplicationConfig_r15);
}

bool CanonicalRlc(const RLC_Config_t &rlc)
{
    return rlc.present == RLC_Config_PR_am && rlc.choice.am != nullptr;
}

bool CanonicalExtension(const DRB_ToAddMod_t &entry)
{
    return IsAbsent(entry.drb_TypeChange_r12) && IsAbsent(entry.rlc_Config_v1250) &&
           IsAbsent(entry.rlc_Config_v1310) && IsAbsent(entry.drb_TypeLWA_r13) &&
           IsAbsent(entry.drb_TypeLWIP_r13) && IsAbsent(entry.rlc_Config_v1430) &&
           IsAbsent(entry.lwip_UL_Aggregation_r14) && IsAbsent(entry.lwip_DL_Aggregation_r14) &&
           IsAbsent(entry.lwa_WLAN_AC_r14) && IsAbsent(entry.rlc_Config_v1510) &&
           IsAbsent(entry.rlc_Config_v1530) && IsAbsent(entry.rlc_BearerConfigSecondary_r15) &&
           IsAbsent(entry.logicalChannelIdentity_r15);
}

bool CanonicalLogicalChannel(const LogicalChannelConfig_t &config)
{
    if (config.ul_SpecificParameters == nullptr)
        return false;
    const auto &ul = *config.ul_SpecificParameters;
    if (!InRange(ul.priority, 1, 16) || !InRange(ul.prioritisedBitRate, 0, 15) ||
        !InRange(ul.bucketSizeDuration, 0, 7))
        return false;
    if (ul.logicalChannelGroup != nullptr && !InRange(*ul.logicalChannelGroup, 0, 3))
        return false;
    return IsAbsent(config.logicalChannelSR_Mask_r9) && IsAbsent(config.logicalChannelSR_Prohibit_r12) &&
           IsAbsent(config.laa_UL_Allowed_r14) && IsAbsent(config.bitRateQueryProhibitTimer_r14) &&
           IsAbsent(config.allowedTTI_Lengths_r15) && IsAbsent(config.logicalChannelSR_Restriction_r15) &&
           IsAbsent(config.channellAccessPriority_r15) && IsAbsent(config.lch_CellRestriction_r15);
}

} // namespace

std::vector<uint8_t> EncodeDrbReconfiguration(const DrbReconfiguration &message)
{
    if (!Validate(message))
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
    dl->message.choice.c1->present = DL_DCCH_MessageType__c1_PR_rrcConnectionReconfiguration;

    auto *reconfiguration = Alloc<RRCConnectionReconfiguration_t>();
    if (reconfiguration == nullptr)
    {
        ASN_STRUCT_FREE(asn_DEF_DL_DCCH_Message, dl);
        return {};
    }
    reconfiguration->rrc_TransactionIdentifier = message.transactionId;
    reconfiguration->criticalExtensions.present = RRCConnectionReconfiguration__criticalExtensions_PR_c1;
    reconfiguration->criticalExtensions.choice.c1 =
        AllocAnonymous(reconfiguration->criticalExtensions.choice.c1);
    if (reconfiguration->criticalExtensions.choice.c1 == nullptr)
    {
        std::free(reconfiguration);
        ASN_STRUCT_FREE(asn_DEF_DL_DCCH_Message, dl);
        return {};
    }
    auto *c1 = reconfiguration->criticalExtensions.choice.c1;
    c1->present = RRCConnectionReconfiguration__criticalExtensions__c1_PR_rrcConnectionReconfiguration_r8;
    c1->choice.rrcConnectionReconfiguration_r8 = Alloc<RRCConnectionReconfiguration_r8_IEs_t>();
    if (c1->choice.rrcConnectionReconfiguration_r8 == nullptr)
    {
        ASN_STRUCT_FREE(asn_DEF_RRCConnectionReconfiguration, reconfiguration);
        ASN_STRUCT_FREE(asn_DEF_DL_DCCH_Message, dl);
        return {};
    }
    auto *ies = c1->choice.rrcConnectionReconfiguration_r8;
    ies->radioResourceConfigDedicated = Alloc<RadioResourceConfigDedicated_t>();
    if (ies->radioResourceConfigDedicated == nullptr)
    {
        ASN_STRUCT_FREE(asn_DEF_RRCConnectionReconfiguration, reconfiguration);
        ASN_STRUCT_FREE(asn_DEF_DL_DCCH_Message, dl);
        return {};
    }
    auto *radio = ies->radioResourceConfigDedicated;
    radio->drb_ToAddModList = Alloc<DRB_ToAddModList_t>();
    if (radio->drb_ToAddModList == nullptr)
    {
        ASN_STRUCT_FREE(asn_DEF_RRCConnectionReconfiguration, reconfiguration);
        ASN_STRUCT_FREE(asn_DEF_DL_DCCH_Message, dl);
        return {};
    }
    for (const auto &drb : message.drbs)
    {
        auto *entry = BuildDrbToAdd(drb);
        if (entry == nullptr)
        {
            ASN_STRUCT_FREE(asn_DEF_RRCConnectionReconfiguration, reconfiguration);
            ASN_STRUCT_FREE(asn_DEF_DL_DCCH_Message, dl);
            return {};
        }
        ASN_SEQUENCE_ADD(&radio->drb_ToAddModList->list, entry);
    }

    dl->message.choice.c1->choice.rrcConnectionReconfiguration = reconfiguration;

    std::vector<uint8_t> out;
    const asn_enc_rval_t encoded = uper_encode(&asn_DEF_DL_DCCH_Message, nullptr, dl, AppendBytes, &out);
    ASN_STRUCT_FREE(asn_DEF_DL_DCCH_Message, dl);
    return encoded.encoded >= 0 ? out : std::vector<uint8_t>{};
}

bool DecodeDrbReconfiguration(const uint8_t *data, size_t size, DrbReconfiguration &out)
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
    DrbReconfiguration parsed;
    if (dl->message.present == DL_DCCH_MessageType_PR_c1 && dl->message.choice.c1 != nullptr &&
        dl->message.choice.c1->present == DL_DCCH_MessageType__c1_PR_rrcConnectionReconfiguration &&
        dl->message.choice.c1->choice.rrcConnectionReconfiguration != nullptr)
    {
        const auto *reconfiguration = dl->message.choice.c1->choice.rrcConnectionReconfiguration;
        if (reconfiguration->criticalExtensions.present == RRCConnectionReconfiguration__criticalExtensions_PR_c1 &&
            reconfiguration->criticalExtensions.choice.c1 != nullptr &&
            reconfiguration->criticalExtensions.choice.c1->present ==
                RRCConnectionReconfiguration__criticalExtensions__c1_PR_rrcConnectionReconfiguration_r8 &&
            reconfiguration->criticalExtensions.choice.c1->choice.rrcConnectionReconfiguration_r8 != nullptr)
        {
            const auto *ies =
                reconfiguration->criticalExtensions.choice.c1->choice.rrcConnectionReconfiguration_r8;
            // This message configures DRBs; it must not move a UE, carry NAS or
            // change security.
            if (ies->mobilityControlInfo == nullptr && ies->dedicatedInfoNASList == nullptr &&
                ies->securityConfigHO == nullptr && ies->nonCriticalExtension == nullptr &&
                ies->radioResourceConfigDedicated != nullptr &&
                CanonicalRadioResourceConfig(*ies->radioResourceConfigDedicated))
            {
                parsed.transactionId = static_cast<uint8_t>(reconfiguration->rrc_TransactionIdentifier);
                const auto &list = *ies->radioResourceConfigDedicated->drb_ToAddModList;
                ok = list.list.count > 0 && static_cast<size_t>(list.list.count) <= MaxDrbToAdd;
                for (int index = 0; ok && index < list.list.count; ++index)
                {
                    const auto *entry = list.list.array[index];
                    if (entry == nullptr || entry->eps_BearerIdentity == nullptr ||
                        entry->logicalChannelIdentity == nullptr || entry->pdcp_Config == nullptr ||
                        entry->rlc_Config == nullptr || entry->logicalChannelConfig == nullptr ||
                        !CanonicalExtension(*entry) || !CanonicalPdcp(*entry->pdcp_Config) ||
                        !CanonicalRlc(*entry->rlc_Config) ||
                        !CanonicalLogicalChannel(*entry->logicalChannelConfig))
                    {
                        ok = false;
                        break;
                    }
                    DrbToAdd drb;
                    drb.ebi = static_cast<uint8_t>(*entry->eps_BearerIdentity);
                    drb.drbIdentity = static_cast<uint8_t>(entry->drb_Identity);
                    drb.logicalChannelIdentity = static_cast<uint8_t>(*entry->logicalChannelIdentity);
                    drb.priority = static_cast<uint8_t>(entry->logicalChannelConfig->ul_SpecificParameters->priority);
                    try
                    {
                        drb.am = MapAmRlcConfiguration(
                            static_cast<uint8_t>(entry->rlc_Config->choice.am->ul_AM_RLC.t_PollRetransmit),
                            static_cast<uint8_t>(entry->rlc_Config->choice.am->ul_AM_RLC.pollPDU),
                            static_cast<uint8_t>(entry->rlc_Config->choice.am->ul_AM_RLC.pollByte),
                            static_cast<uint8_t>(entry->rlc_Config->choice.am->ul_AM_RLC.maxRetxThreshold),
                            static_cast<uint8_t>(entry->rlc_Config->choice.am->dl_AM_RLC.t_Reordering),
                            static_cast<uint8_t>(entry->rlc_Config->choice.am->dl_AM_RLC.t_StatusProhibit));
                    }
                    catch (const Srb1ConfigException &)
                    {
                        ok = false;
                        break;
                    }
                    parsed.drbs.push_back(drb);
                }
                if (ok && !Validate(parsed))
                    ok = false;
            }
        }
    }
    ASN_STRUCT_FREE(asn_DEF_DL_DCCH_Message, dl);
    if (ok)
        out = std::move(parsed);
    return ok;
}

std::vector<uint8_t> EncodeDrbReconfigurationComplete(uint8_t transactionId)
{
    if (transactionId > 3)
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
    ul->message.choice.c1->present = UL_DCCH_MessageType__c1_PR_rrcConnectionReconfigurationComplete;

    auto *complete = Alloc<RRCConnectionReconfigurationComplete_t>();
    if (complete == nullptr)
    {
        ASN_STRUCT_FREE(asn_DEF_UL_DCCH_Message, ul);
        return {};
    }
    complete->rrc_TransactionIdentifier = transactionId;
    complete->criticalExtensions.present =
        RRCConnectionReconfigurationComplete__criticalExtensions_PR_rrcConnectionReconfigurationComplete_r8;
    complete->criticalExtensions.choice.rrcConnectionReconfigurationComplete_r8 =
        Alloc<RRCConnectionReconfigurationComplete_r8_IEs_t>();
    if (complete->criticalExtensions.choice.rrcConnectionReconfigurationComplete_r8 == nullptr)
    {
        ASN_STRUCT_FREE(asn_DEF_RRCConnectionReconfigurationComplete, complete);
        ASN_STRUCT_FREE(asn_DEF_UL_DCCH_Message, ul);
        return {};
    }
    ul->message.choice.c1->choice.rrcConnectionReconfigurationComplete = complete;

    std::vector<uint8_t> out;
    const asn_enc_rval_t encoded = uper_encode(&asn_DEF_UL_DCCH_Message, nullptr, ul, AppendBytes, &out);
    ASN_STRUCT_FREE(asn_DEF_UL_DCCH_Message, ul);
    return encoded.encoded >= 0 ? out : std::vector<uint8_t>{};
}

bool DecodeDrbReconfigurationComplete(const uint8_t *data, size_t size, uint8_t &transactionId)
{
    if (data == nullptr || size == 0)
        return false;
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
        ul->message.choice.c1->present == UL_DCCH_MessageType__c1_PR_rrcConnectionReconfigurationComplete &&
        ul->message.choice.c1->choice.rrcConnectionReconfigurationComplete != nullptr)
    {
        const auto *complete = ul->message.choice.c1->choice.rrcConnectionReconfigurationComplete;
        if (complete->criticalExtensions.present ==
                RRCConnectionReconfigurationComplete__criticalExtensions_PR_rrcConnectionReconfigurationComplete_r8 &&
            complete->criticalExtensions.choice.rrcConnectionReconfigurationComplete_r8 != nullptr)
        {
            transactionId = static_cast<uint8_t>(complete->rrc_TransactionIdentifier);
            ok = transactionId <= 3;
        }
    }
    ASN_STRUCT_FREE(asn_DEF_UL_DCCH_Message, ul);
    return ok;
}

} // namespace lte::rrc
