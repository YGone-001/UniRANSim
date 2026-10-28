//
// This file is a part of UERANSIM project.
// Copyright (c) 2027 ALİ GÜNGÖR.
//
// https://github.com/aligungr/UERANSIM/
// See README, LICENSE, and CONTRIBUTING files for licensing details.
//
#pragma once

#include <cstdint>

namespace lte::ue
{

// Which trigger started the one access restoration that is in flight.
enum class RestorationOwner
{
    NONE,
    PAGING,
    RECOVERY
};

const char *ToString(RestorationOwner owner);

// Owns the single pending access restoration of one UE. A matched network page
// and the UE-initiated recovery timer compete for the same slot: whichever
// takes it owns the Service Request, its retransmission state and the
// restoration it produces. The loser is cancelled instead of being counted as
// well, so at most one Service Request procedure exists per UE and every
// outcome is attributed to exactly one trigger.
//
// The slot is deliberately not a state machine of its own: it never sends
// anything and never touches EMM/ECM state. It only answers "may this trigger
// start a procedure?" and "who owns the one that is already running?".
class RestorationTrigger
{
  public:
    // Unexpected S1 access loss clears any previous owner and schedules the
    // UE-initiated recovery timer when that mode is enabled.
    void onAccessLoss(bool recoveryEnabled);

    // A matched network page takes the slot and cancels the recovery timer, so
    // no stale timer can fire after a paging restoration. Returns false when a
    // trigger already owns the restoration, so a duplicate or stale page
    // cannot start a second Service Request nor erase a UE-initiated one.
    bool tryTakeFromPaging();

    // The UE-initiated recovery timer fires. Returns false when the timer is
    // not armed or another trigger already owns the restoration. The timer
    // stays armed afterwards so a failed attempt can be retried.
    bool tryTakeFromRecovery();

    // The restoration completed. Reports the owner and releases the slot,
    // disarming the recovery timer for good.
    RestorationOwner takeRestored();

    // The restoration failed after bounded retransmissions. Reports the owner
    // and releases the slot. An armed recovery timer is left armed so the
    // bounded retry policy can fire again; a paging trigger has no retry of
    // its own.
    RestorationOwner takeFailed();

    // Drop both the owner and the recovery timer: a Service Request that could
    // not even start, a recovery that exhausted its attempts, a detach or a
    // shutdown.
    void abandon();

    [[nodiscard]] RestorationOwner owner() const { return m_owner; }
    [[nodiscard]] bool recoveryArmed() const { return m_recoveryArmed; }
    [[nodiscard]] bool pending() const { return m_owner != RestorationOwner::NONE; }

  private:
    RestorationOwner m_owner{RestorationOwner::NONE};
    bool m_recoveryArmed{false};
};

} // namespace lte::ue
