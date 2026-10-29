//
// This file is a part of UERANSIM project.
// Copyright (c) 2027 ALİ GÜNGÖR.
//
// https://github.com/aligungr/UERANSIM/
// See README, LICENSE, and CONTRIBUTING files for licensing details.
//

#include "paging.hpp"

#include "security.hpp"
#include "tai.hpp"

#include <lte/enb/codec.hpp>

namespace lte::ue
{

namespace
{

// TS 24.301 9.9.3.8: the GUTI type octet carries the identity type in bits 3-1.
constexpr uint8_t GutiTypeMask = 0x07;
constexpr uint8_t GutiType = 0x06;

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
    // Membership is decided on the explicitly parsed tracking areas, never on
    // the raw octets. An unparseable assignment yields no authorized TAC at
    // all, so it can never authorize a paging response.
    std::vector<Tai> parsed;
    if (!ParseTaiList(taiList, parsed))
        return false;
    return TaiListContains(parsed, Tai{plmn, tac});
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
    if (!TaiListContains(context.taiList, Tai{plmn, notification.tac}))
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
