//
// This file is a part of UERANSIM project.
// Copyright (c) 2027 ALİ GÜNGÖR.
//
// https://github.com/aligungr/UERANSIM/
// See README, LICENSE, and CONTRIBUTING files for licensing details.
//

#pragma once

#include "types.hpp"

#include <atomic>

namespace lte::enb
{

// Bounded exponential backoff between S1 reconnection attempts. The delay is
// clamped to recovery.delayMaxMs and never falls below a TimeToWait floor the
// MME requested in an S1 Setup Failure. Zero or negative attempts are treated
// as the first attempt.
int RecoveryBackoffMs(const RecoveryConfig &recovery, int attempt, int requestedFloorMs);

// Sleeps for at most `milliseconds`, returning early as soon as shutdown is
// requested. Returns false when the wait ended because of shutdown, so a
// reconnect backoff is interrupted promptly instead of delaying the stop.
bool InterruptibleDelay(int milliseconds, const std::atomic_bool &shutdownRequested);

} // namespace lte::enb
