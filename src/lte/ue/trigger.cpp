//
// This file is a part of UERANSIM project.
// Copyright (c) 2027 ALİ GÜNGÖR.
//
// https://github.com/aligungr/UERANSIM/
// See README, LICENSE, and CONTRIBUTING files for licensing details.
//
#include "trigger.hpp"

namespace lte::ue
{

const char *ToString(RestorationOwner owner)
{
    switch (owner)
    {
    case RestorationOwner::NONE:
        return "NONE";
    case RestorationOwner::PAGING:
        return "PAGING";
    case RestorationOwner::RECOVERY:
        return "RECOVERY";
    }
    return "UNKNOWN";
}

void RestorationTrigger::onAccessLoss(bool recoveryEnabled)
{
    m_owner = RestorationOwner::NONE;
    m_recoveryArmed = recoveryEnabled;
}

bool RestorationTrigger::tryTakeFromPaging()
{
    if (m_owner != RestorationOwner::NONE)
        return false;
    m_owner = RestorationOwner::PAGING;
    // The page won the race, so the UE-initiated timer must never fire for this
    // restoration.
    m_recoveryArmed = false;
    return true;
}

bool RestorationTrigger::tryTakeFromRecovery()
{
    if (!m_recoveryArmed || m_owner != RestorationOwner::NONE)
        return false;
    m_owner = RestorationOwner::RECOVERY;
    return true;
}

RestorationOwner RestorationTrigger::takeRestored()
{
    const auto owner = m_owner;
    m_owner = RestorationOwner::NONE;
    m_recoveryArmed = false;
    return owner;
}

RestorationOwner RestorationTrigger::takeFailed()
{
    const auto owner = m_owner;
    m_owner = RestorationOwner::NONE;
    if (owner == RestorationOwner::PAGING)
        m_recoveryArmed = false;
    return owner;
}

void RestorationTrigger::abandon()
{
    m_owner = RestorationOwner::NONE;
    m_recoveryArmed = false;
}

} // namespace lte::ue
