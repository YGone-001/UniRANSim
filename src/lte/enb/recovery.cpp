//
// This file is a part of UERANSIM project.
// Copyright (c) 2027 ALİ GÜNGÖR.
//
// https://github.com/aligungr/UERANSIM/
// See README, LICENSE, and CONTRIBUTING files for licensing details.
//

#include "recovery.hpp"

#include <algorithm>
#include <chrono>
#include <thread>

namespace lte::enb
{

int RecoveryBackoffMs(const RecoveryConfig &recovery, int attempt, int requestedFloorMs)
{
    const long long ceiling = std::max(recovery.delayMs, recovery.delayMaxMs);
    long long delay = std::max(1, recovery.delayMs);
    for (int i = 1; i < std::max(1, attempt) && delay < ceiling; ++i)
        delay = std::min(ceiling, delay * 2);
    delay = std::max<long long>(delay, std::max(0, requestedFloorMs));
    return static_cast<int>(std::min(ceiling, delay));
}

bool InterruptibleDelay(int milliseconds, const std::atomic_bool &shutdownRequested)
{
    if (shutdownRequested)
        return false;
    const auto deadline = std::chrono::steady_clock::now() + std::chrono::milliseconds(std::max(0, milliseconds));
    // A short polling interval keeps a shutdown request prompt without a busy
    // loop; the caller owns the shutdown flag.
    constexpr auto granularity = std::chrono::milliseconds(25);
    while (!shutdownRequested && std::chrono::steady_clock::now() < deadline)
        std::this_thread::sleep_for(granularity);
    return !shutdownRequested;
}

} // namespace lte::enb
