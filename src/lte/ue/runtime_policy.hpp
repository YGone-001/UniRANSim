//
// This file is a part of UERANSIM project.
// Copyright (c) 2027 ALİ GÜNGÖR.
//
// https://github.com/aligungr/UERANSIM/
// See README, LICENSE, and CONTRIBUTING files for licensing details.
//

#pragma once

namespace lte::ue
{

// The radio receive wait after a main-loop turn. Continuous uplink traffic must
// not wait on a downlink that may not exist: with a 50 ms wait the UE would
// serve at most 16 TUN packets per 50 ms (about 320 packet/s), regardless of the
// link capacity. When the TUN produced at least one packet, the radio socket is
// checked without blocking; the next turn reads the TUN again. An idle UE keeps
// the longer waits so the process does not spin.
constexpr int RadioReceiveTimeoutMs(bool registered, bool tunHadUplink)
{
    if (tunHadUplink)
        return 0;
    return registered ? 50 : 250;
}

} // namespace lte::ue
