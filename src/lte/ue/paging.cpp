//
// This file is a part of UERANSIM project.
// Copyright (c) 2027 ALİ GÜNGÖR.
//
// https://github.com/aligungr/UERANSIM/
// See README, LICENSE, and CONTRIBUTING files for licensing details.
//

#include "paging.hpp"

#include "security.hpp"

#include <lte/enb/codec.hpp>

namespace lte::ue
{

namespace
{

// TS 24.301 9.9.3.8: the GUTI type octet carries the identity type in bits 3-1.
constexpr uint8_t GutiTypeMask = 0x07;
constexpr uint8_t GutiType = 0x06;

uint16_t Read16(const uint8_t *data)
{
    return static_cast<uint16_t>((static_cast<uint16_t>(data[0]) << 8U) | data[1]);
}

} // namespace

std::optional<STmsi> STmsiFromGuti(const std::array<uint8_t, 11> &guti)
{
    if ((guti[0] & GutiTypeMask) != GutiType)
        return std::nullopt;
    STmsi sTmsi{};
    sTmsi.mmeCode = guti[6];
    sTmsi.mTmsi = (static_cast<uint32_t>(guti[7]) << 24U) | (static_cast<uint32_t>(guti[8]) << 16U) |
                  (static_cast<uint32_t>(guti[9]) << 8U) | guti[10];
    if (sTmsi.mTmsi == 0)
        return std::nullopt;
    return sTmsi;
}

bool TaiListContains(const std::vector<uint8_t> &taiList, const enb::Plmn &plmn, uint16_t tac)
{
    if (taiList.empty())
        return false;
    const uint8_t header = taiList[0];
    const int type = static_cast<int>((header >> 5U) & 0x07U);
    // TS 24.301 9.9.3.33: the element-count field carries (number of elements
    // - 1). Open5GS encodes its single served TAI as 0x40 64F020 0001.
    const size_t count = static_cast<size_t>(header & 0x1FU) + 1U;
    const size_t remaining = taiList.size() - 1U;

    // Two valid layouts exist. Every element may carry PLMN + TAC (5 octets,
    // the form Open5GS emits for its type 2 list), or only the first element
    // may carry the PLMN with 2-octet TACs after it (types 1 and 3). The
    // encoded length must exactly match the layout, otherwise the list is
    // rejected as inconsistent and can never authorize a paging response.
    const bool full = remaining == count * 5U;
    const bool compact = remaining == 5U + (count - 1U) * 2U;
    if (!full && !compact)
        return false;

    const auto expectedPlmn = enb::s1ap::EncodePlmn(plmn);
    size_t offset = 1;
    std::array<uint8_t, 3> currentPlmn{};
    uint16_t currentTac = 0;
    for (size_t i = 0; i < count; ++i)
    {
        if (full || i == 0)
        {
            currentPlmn = {{taiList[offset], taiList[offset + 1], taiList[offset + 2]}};
            currentTac = Read16(taiList.data() + offset + 3);
            offset += 5;
        }
        else
        {
            const uint16_t encoded = Read16(taiList.data() + offset);
            offset += 2;
            // Consecutive-value lists (types 1 and 2) increment the TAC; a
            // same-PLMN list (type 3) carries each TAC explicitly.
            currentTac = (type == 1 || type == 2) ? static_cast<uint16_t>(currentTac + 1U) : encoded;
        }
        if (currentPlmn == expectedPlmn && currentTac == tac)
            return true;
    }
    return false;
}

const char *ToString(PagingMatch match)
{
    switch (match)
    {
    case PagingMatch::ACCEPTED: return "ACCEPTED";
    case PagingMatch::NOT_REGISTERED: return "NOT_REGISTERED";
    case PagingMatch::NO_SECURITY: return "NO_SECURITY";
    case PagingMatch::NO_IDENTITY: return "NO_IDENTITY";
    case PagingMatch::IDENTITY_MISMATCH: return "IDENTITY_MISMATCH";
    case PagingMatch::CONNECTED: return "CONNECTED";
    case PagingMatch::BEARER_UNAVAILABLE: return "BEARER_UNAVAILABLE";
    case PagingMatch::PROCEDURE_PENDING: return "PROCEDURE_PENDING";
    case PagingMatch::AREA_MISMATCH: return "AREA_MISMATCH";
    }
    return "UNKNOWN";
}

PagingMatch EvaluatePaging(const MobilityContext &context, const enb::Plmn &plmn,
                           const link::PagingNotification &notification)
{
    if (context.emm != EmmState::REGISTERED)
        return PagingMatch::NOT_REGISTERED;
    if (!context.securityContextValid)
        return PagingMatch::NO_SECURITY;
    if (!context.guti.has_value())
        return PagingMatch::NO_IDENTITY;

    const auto assigned = STmsiFromGuti(*context.guti);
    if (!assigned.has_value())
        return PagingMatch::NO_IDENTITY;
    if (assigned->mmeCode != notification.mmeCode || assigned->mTmsi != notification.mTmsi)
        return PagingMatch::IDENTITY_MISMATCH;

    // A page only starts a restoration procedure; it never makes an already
    // connected bearer active again.
    if (context.ecm == EcmState::CONNECTED)
        return PagingMatch::CONNECTED;
    if (context.bearer != EpsBearerState::SIGNALING_ESTABLISHED)
        return PagingMatch::BEARER_UNAVAILABLE;
    if (context.pending != PendingProcedure::NONE)
        return PagingMatch::PROCEDURE_PENDING;
    if (!TaiListContains(context.taiList, plmn, notification.tac))
        return PagingMatch::AREA_MISMATCH;
    return PagingMatch::ACCEPTED;
}

std::optional<std::vector<uint8_t>> RespondToPaging(MobilityContext &context, const enb::Plmn &plmn,
                                                   const link::PagingNotification &notification,
                                                   SecurityContext &security)
{
    if (EvaluatePaging(context, plmn, notification) != PagingMatch::ACCEPTED)
        return std::nullopt;

    context.startServiceRequest();
    auto nas = nas::EncodeServiceRequest(security);
    security.ulNasCount = (security.ulNasCount + 1U) & 0xFFFFFFU;
    return nas;
}

} // namespace lte::ue
