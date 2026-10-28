//
// This file is a part of UERANSIM project.
// Copyright (c) 2027 ALİ GÜNGÖR.
//
// https://github.com/aligungr/UERANSIM/
// See README, LICENSE, and CONTRIBUTING files for licensing details.
//

// Trigger ownership between a network page and the UE-initiated recovery
// timer: one restoration per UE, one owner per outcome, no stale loser firing.

#include <ext/doctest/doctest.h>

#include <lte/ue/trigger.hpp>

#include <string>

namespace
{

using namespace lte::ue;

} // namespace

TEST_CASE("lte/arbitration: an access loss arms only the UE-initiated recovery timer")
{
    RestorationTrigger trigger;
    CHECK_FALSE(trigger.pending());
    CHECK_FALSE(trigger.recoveryArmed());

    trigger.onAccessLoss(true);
    CHECK(trigger.recoveryArmed());
    CHECK_FALSE(trigger.pending());

    // Paging-only mode schedules no recovery timer at all.
    trigger.onAccessLoss(false);
    CHECK_FALSE(trigger.recoveryArmed());
    CHECK_FALSE(trigger.tryTakeFromRecovery());
}

TEST_CASE("lte/arbitration: a matched page takes the restoration and disarms the recovery timer")
{
    RestorationTrigger trigger;
    trigger.onAccessLoss(true);
    REQUIRE(trigger.recoveryArmed());

    CHECK(trigger.tryTakeFromPaging());
    CHECK(trigger.owner() == RestorationOwner::PAGING);
    // The page won the race, so the timer must never fire for this restoration.
    CHECK_FALSE(trigger.recoveryArmed());
    CHECK_FALSE(trigger.tryTakeFromRecovery());
}

TEST_CASE("lte/arbitration: a second page cannot start a second restoration")
{
    RestorationTrigger trigger;
    trigger.onAccessLoss(true);
    REQUIRE(trigger.tryTakeFromPaging());

    CHECK_FALSE(trigger.tryTakeFromPaging());
    CHECK(trigger.owner() == RestorationOwner::PAGING);
}

TEST_CASE("lte/arbitration: a stale page cannot erase a UE-initiated restoration")
{
    RestorationTrigger trigger;
    trigger.onAccessLoss(true);
    REQUIRE(trigger.tryTakeFromRecovery());
    CHECK(trigger.owner() == RestorationOwner::RECOVERY);

    CHECK_FALSE(trigger.tryTakeFromPaging());
    CHECK(trigger.owner() == RestorationOwner::RECOVERY);
}

TEST_CASE("lte/arbitration: a stale recovery timer cannot fire after a paging restoration")
{
    RestorationTrigger trigger;
    trigger.onAccessLoss(true);
    REQUIRE(trigger.tryTakeFromPaging());
    REQUIRE(trigger.takeRestored() == RestorationOwner::PAGING);

    CHECK_FALSE(trigger.recoveryArmed());
    CHECK_FALSE(trigger.tryTakeFromRecovery());
    CHECK_FALSE(trigger.pending());
}

TEST_CASE("lte/arbitration: a completed restoration is reported to exactly one trigger")
{
    RestorationTrigger paging;
    paging.onAccessLoss(true);
    REQUIRE(paging.tryTakeFromPaging());
    CHECK(paging.takeRestored() == RestorationOwner::PAGING);
    // The slot is released and cannot report the same restoration twice.
    CHECK(paging.takeRestored() == RestorationOwner::NONE);

    RestorationTrigger recovery;
    recovery.onAccessLoss(true);
    REQUIRE(recovery.tryTakeFromRecovery());
    CHECK(recovery.takeRestored() == RestorationOwner::RECOVERY);
    CHECK(recovery.takeRestored() == RestorationOwner::NONE);
}

TEST_CASE("lte/arbitration: a failed restoration is attributed to its own trigger")
{
    RestorationTrigger paging;
    paging.onAccessLoss(true);
    REQUIRE(paging.tryTakeFromPaging());
    CHECK(paging.takeFailed() == RestorationOwner::PAGING);
    // A paging trigger has no retry of its own and leaves no timer behind.
    CHECK_FALSE(paging.recoveryArmed());
    CHECK_FALSE(paging.pending());

    RestorationTrigger recovery;
    recovery.onAccessLoss(true);
    REQUIRE(recovery.tryTakeFromRecovery());
    CHECK(recovery.takeFailed() == RestorationOwner::RECOVERY);
    // The bounded retry policy may fire again for the same access loss.
    CHECK(recovery.recoveryArmed());
    CHECK_FALSE(recovery.pending());
    CHECK(recovery.tryTakeFromRecovery());
}

TEST_CASE("lte/arbitration: abandoning clears both the owner and the recovery timer")
{
    RestorationTrigger trigger;
    trigger.onAccessLoss(true);
    REQUIRE(trigger.tryTakeFromRecovery());
    trigger.abandon();
    CHECK_FALSE(trigger.pending());
    CHECK_FALSE(trigger.recoveryArmed());
    CHECK_FALSE(trigger.tryTakeFromRecovery());
}

TEST_CASE("lte/arbitration: a new access loss reopens the slot for the new restoration")
{
    RestorationTrigger trigger;
    trigger.onAccessLoss(true);
    REQUIRE(trigger.tryTakeFromRecovery());
    REQUIRE(trigger.takeRestored() == RestorationOwner::RECOVERY);

    // A second unexpected loss is a new restoration with a fresh owner.
    trigger.onAccessLoss(true);
    CHECK_FALSE(trigger.pending());
    CHECK(trigger.recoveryArmed());
    CHECK(trigger.tryTakeFromPaging());
    CHECK(trigger.owner() == RestorationOwner::PAGING);
}

TEST_CASE("lte/arbitration: the owner names the trigger it belongs to")
{
    CHECK(std::string(ToString(RestorationOwner::NONE)) == "NONE");
    CHECK(std::string(ToString(RestorationOwner::PAGING)) == "PAGING");
    CHECK(std::string(ToString(RestorationOwner::RECOVERY)) == "RECOVERY");
}
