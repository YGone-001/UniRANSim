//
// This file is a part of UERANSIM project.
// Copyright (c) 2027 ALİ GÜNGÖR.
//

// Phase 18-F-B6-B2: the SRB1 RLC AM configuration of TS 36.331 6.3.2 mapped to
// the runtime entity's timer and polling parameters.
//
// The received fields are enumerators, not numbers: t-PollRetransmit = 7 means
// "ms40", not "7 ticks". The mapper resolves the enumerator to its duration and
// the duration to runtime ticks, and refuses anything it cannot resolve. No
// value is silently replaced with a default.
#pragma once

#include "lte_am.hpp"
#include "rrc_initial_access.hpp"

#include <cstdint>
#include <stdexcept>
#include <string>

namespace lte::rrc
{

// One runtime tick is one millisecond of simulated time. The ratio is a named
// constant so the conversion is explicit and testable, rather than an implicit
// assumption that an enumerator is a tick count.
constexpr uint32_t Srb1DefaultTickMilliseconds = 1;

struct Srb1RuntimeTiming
{
    uint32_t tickMilliseconds{Srb1DefaultTickMilliseconds};
};

enum class Srb1ConfigError : uint8_t
{
    INVALID_SRB_IDENTITY,
    ZERO_TICK,
    UNSUPPORTED_T_POLL_RETRANSMIT,
    UNSUPPORTED_POLL_PDU,
    UNSUPPORTED_POLL_BYTE,
    UNSUPPORTED_MAX_RETX_THRESHOLD,
    UNSUPPORTED_T_REORDERING,
    UNSUPPORTED_T_STATUS_PROHIBIT,
};

const char *ToString(Srb1ConfigError error);

class Srb1ConfigException : public std::runtime_error
{
  public:
    explicit Srb1ConfigException(Srb1ConfigError reason);

    [[nodiscard]] Srb1ConfigError Reason() const noexcept
    {
        return reason_;
    }

  private:
    Srb1ConfigError reason_;
};

struct Srb1ResolvedConfig
{
    rlc::am::AmConfig am{};
    // The durations the enumerators stood for, so a test can state what was
    // mapped without re-deriving the table.
    uint32_t pollRetransmitMs{0};
    uint32_t reorderingMs{0};
    uint32_t statusProhibitMs{0};
    // 0 means the enumerator said "infinity": the trigger is disabled.
    uint32_t pollPduCount{0};
    uint32_t pollByteCount{0};
    // The TS 36.331 threshold counts retransmissions; AmConfig counts
    // transmissions, so the entity value is this plus one.
    uint8_t maxRetransmissions{0};
};

// Resolves every field and cross-checks the SRB identity. Throws
// Srb1ConfigException with the exact field that cannot be mapped.
[[nodiscard]] Srb1ResolvedConfig MapSrb1Configuration(const RrcConnectionSetupMessage &setup,
                                                      Srb1RuntimeTiming timing = {});

// Phase 18-F-B6-D6: the AM parameters shared by every LTE AM bearer, resolved
// from the TS 36.331 enumerators. A DRB carries the same fields on a different
// logical channel, so the mapping is the same and is not duplicated.
[[nodiscard]] rlc::am::AmConfig MapAmRlcConfiguration(uint8_t tPollRetransmit, uint8_t pollPdu, uint8_t pollByte,
                                                      uint8_t maxRetxThreshold, uint8_t tReordering,
                                                      uint8_t tStatusProhibit, Srb1RuntimeTiming timing = {});

} // namespace lte::rrc
