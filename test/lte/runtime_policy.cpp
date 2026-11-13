//
// This file is a part of UERANSIM project.
// Copyright (c) 2027 ALİ GÜNGÖR.
//
// https://github.com/aligungr/UERANSIM/
// See README, LICENSE, and CONTRIBUTING files for licensing details.
//

#include <ext/doctest/doctest.h>

#include <lte/ue/runtime_policy.hpp>

TEST_CASE("lte/ue: continuous uplink does not wait for a downlink")
{
    using lte::ue::RadioReceiveTimeoutMs;

    // A TUN packet was read: check the radio socket without blocking, then let
    // the next turn read the TUN again. This is what removes the 16 packets /
    // 50 ms ceiling from an uplink-only workload.
    CHECK(RadioReceiveTimeoutMs(true, true) == 0);
    CHECK(RadioReceiveTimeoutMs(false, true) == 0);

    // No uplink packet: keep the existing idle waits so the process sleeps.
    CHECK(RadioReceiveTimeoutMs(true, false) == 50);
    CHECK(RadioReceiveTimeoutMs(false, false) == 250);
}
