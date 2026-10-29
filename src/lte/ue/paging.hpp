//
// This file is a part of UERANSIM project.
// Copyright (c) 2027 ALİ GÜNGÖR.
//
// https://github.com/aligungr/UERANSIM/
// See README, LICENSE, and CONTRIBUTING files for licensing details.
//

// Network-triggered paging reception for the simulated LTE UE.
//
// The eNB fans out one PAGING_INDICATION frame to each retained idle radio
// endpoint because it does not hold the UEs' NAS identities. Each UE
// independently re-derives its S-TMSI from its own valid GUTI and only the
// matching UE starts a compact EPS Service Request.

#pragma once

#include "lifecycle.hpp"
#include "radio_link.hpp"
#include "tai.hpp"
#include "types.hpp"

#include <array>
#include <cstdint>
#include <optional>
#include <vector>

#include <lte/enb/types.hpp>

namespace lte::ue
{

// S-TMSI carried by an 11-octet EPS GUTI information element (TS 24.301
// 9.9.3.8): type octet, PLMN, MME group identity, MMEC, then M-TMSI.
struct STmsi
{
    uint8_t mmeCode{};
    uint32_t mTmsi{};

    [[nodiscard]] bool operator==(const STmsi &other) const
    {
        return mmeCode == other.mmeCode && mTmsi == other.mTmsi;
    }
};

// Returns the S-TMSI of a valid assigned GUTI, or nullopt when the octets are
// not an EPS GUTI or the M-TMSI is zero.
std::optional<STmsi> STmsiFromGuti(const std::array<uint8_t, 11> &guti);

// True when `taiList` (raw TS 24.301 9.9.3.33 TAI list contents, without the
// length octet) contains the given PLMN/TAC. The value is fully parsed and
// validated first, so membership rests on explicit tracking areas rather than
// on a heuristic over the octets; an unparseable or partially valid list
// yields false and can therefore never authorize a paging response.
bool TaiListContains(const std::vector<uint8_t> &taiList, const enb::Plmn &plmn, uint16_t tac);

// Outcome of evaluating one paging notification against the live UE context.
enum class PagingMatch
{
    ACCEPTED,
    NOT_REGISTERED,
    NO_SECURITY,
    NO_IDENTITY,
    IDENTITY_MISMATCH,
    CONNECTED,
    BEARER_UNAVAILABLE,
    PROCEDURE_PENDING,
    AREA_MISMATCH
};

const char *ToString(PagingMatch match);

// Evaluates a page against EMM/ECM state, the EPS security context, the
// assigned GUTI and the assigned TAI list. It never mutates the context.
PagingMatch EvaluatePaging(const MobilityContext &context, const enb::Plmn &plmn,
                           const link::PagingNotification &notification);

// Network-triggered Service Request. On an accepted page it enters the
// SERVICE_REQUEST pending state, builds the compact EPS Service Request and
// advances the uplink NAS COUNT exactly once. Returns nullopt without touching
// state or COUNT when the page must not be answered (wrong identity, already
// connected, duplicate page while a procedure is pending, and so on).
std::optional<std::vector<uint8_t>> RespondToPaging(MobilityContext &context, const enb::Plmn &plmn,
                                                   const link::PagingNotification &notification,
                                                   SecurityContext &security);

} // namespace lte::ue
