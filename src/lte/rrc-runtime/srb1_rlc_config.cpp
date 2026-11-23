//
// This file is a part of UERANSIM project.
// Copyright (c) 2027 ALİ GÜNGÖR.
//

#include "srb1_rlc_config.hpp"

#include <array>

namespace lte::rrc
{
namespace
{

// TS 36.331 6.3.2 T-PollRetransmit, indices 0..58. The spare values 59..63 are
// not a duration and are refused.
constexpr std::array<uint32_t, 59> PollRetransmitMs{5,   10,  15,  20,  25,  30,  35,  40,  45,  50,  55,  60,
                                                    65,  70,  75,  80,  85,  90,  95,  100, 105, 110, 115, 120,
                                                    125, 130, 135, 140, 145, 150, 155, 160, 165, 170, 175, 180,
                                                    185, 190, 195, 200, 205, 210, 215, 220, 225, 230, 235, 240,
                                                    245, 250, 300, 350, 400, 450, 500, 800, 1000, 2000, 4000};

// T-Reordering, indices 0..31. ms0 means the timer is not started.
constexpr std::array<uint32_t, 32> ReorderingMs{0,   5,   10,  15,  20,  25,  30,  35,  40,  45,  50,
                                                55,  60,  65,  70,  75,  80,  85,  90,  95,  100, 110,
                                                120, 130, 140, 150, 160, 170, 180, 190, 200, 1600};

// T-StatusProhibit, indices 0..61; 62..63 are spare.
constexpr std::array<uint32_t, 62> StatusProhibitMs{0,   5,    10,   15,   20,   25,   30,   35,   40,   45,
                                                    50,  55,   60,   65,   70,   75,   80,   85,   90,   95,
                                                    100, 105,  110,  115,  120,  125,  130,  135,  140,  145,
                                                    150, 155,  160,  165,  170,  175,  180,  185,  190,  195,
                                                    200, 205,  210,  215,  220,  225,  230,  235,  240,  245,
                                                    250, 300,  350,  400,  450,  500,  800,  1000, 1200, 1600,
                                                    2000, 2400};

// PollPDU: p4..p256, and pInfinity disables the trigger.
constexpr std::array<uint32_t, 8> PollPduCount{4, 8, 16, 32, 64, 128, 256, 0};
// PollByte in bytes (kB25 .. kB3000); kBinfinity disables the trigger.
constexpr std::array<uint32_t, 15> PollByteCount{25,   50,    75,    100,   125,   250,  375,  500,
                                                 750,  1000,  1250,  1500,  2000,  3000, 0};
// UL-AM-RLC maxRetxThreshold t1..t32, in retransmissions.
constexpr std::array<uint8_t, 8> MaxRetransmissions{1, 2, 3, 4, 6, 8, 16, 32};

[[noreturn]] void Fail(Srb1ConfigError reason)
{
    throw Srb1ConfigException(reason);
}

uint32_t ToTicks(uint32_t milliseconds, uint32_t tickMilliseconds)
{
    if (milliseconds == 0)
        return 0;  // "the timer is not started"
    return (milliseconds + tickMilliseconds - 1) / tickMilliseconds;
}

} // namespace

const char *ToString(Srb1ConfigError error)
{
    switch (error)
    {
    case Srb1ConfigError::INVALID_SRB_IDENTITY: return "INVALID_SRB_IDENTITY";
    case Srb1ConfigError::ZERO_TICK: return "ZERO_TICK";
    case Srb1ConfigError::UNSUPPORTED_T_POLL_RETRANSMIT: return "UNSUPPORTED_T_POLL_RETRANSMIT";
    case Srb1ConfigError::UNSUPPORTED_POLL_PDU: return "UNSUPPORTED_POLL_PDU";
    case Srb1ConfigError::UNSUPPORTED_POLL_BYTE: return "UNSUPPORTED_POLL_BYTE";
    case Srb1ConfigError::UNSUPPORTED_MAX_RETX_THRESHOLD: return "UNSUPPORTED_MAX_RETX_THRESHOLD";
    case Srb1ConfigError::UNSUPPORTED_T_REORDERING: return "UNSUPPORTED_T_REORDERING";
    case Srb1ConfigError::UNSUPPORTED_T_STATUS_PROHIBIT: return "UNSUPPORTED_T_STATUS_PROHIBIT";
    }
    return "UNKNOWN_SRB1_CONFIG_ERROR";
}

Srb1ConfigException::Srb1ConfigException(Srb1ConfigError reason)
    : std::runtime_error(std::string("SRB1 RLC configuration refusal: ") + ToString(reason)), reason_(reason)
{
}

Srb1ResolvedConfig MapSrb1Configuration(const RrcConnectionSetupMessage &setup, Srb1RuntimeTiming timing)
{
    if (timing.tickMilliseconds == 0)
        Fail(Srb1ConfigError::ZERO_TICK);
    if (setup.srbIdentity != 1)
        Fail(Srb1ConfigError::INVALID_SRB_IDENTITY);

    Srb1ResolvedConfig resolved;

    if (setup.tPollRetransmit >= PollRetransmitMs.size())
        Fail(Srb1ConfigError::UNSUPPORTED_T_POLL_RETRANSMIT);
    resolved.pollRetransmitMs = PollRetransmitMs[setup.tPollRetransmit];

    if (setup.pollPdu >= PollPduCount.size())
        Fail(Srb1ConfigError::UNSUPPORTED_POLL_PDU);
    resolved.pollPduCount = PollPduCount[setup.pollPdu];

    if (setup.pollByte >= PollByteCount.size())
        Fail(Srb1ConfigError::UNSUPPORTED_POLL_BYTE);
    resolved.pollByteCount = PollByteCount[setup.pollByte];

    if (setup.maxRetxThreshold >= MaxRetransmissions.size())
        Fail(Srb1ConfigError::UNSUPPORTED_MAX_RETX_THRESHOLD);
    resolved.maxRetransmissions = MaxRetransmissions[setup.maxRetxThreshold];

    if (setup.tReordering >= ReorderingMs.size())
        Fail(Srb1ConfigError::UNSUPPORTED_T_REORDERING);
    resolved.reorderingMs = ReorderingMs[setup.tReordering];

    if (setup.tStatusProhibit >= StatusProhibitMs.size())
        Fail(Srb1ConfigError::UNSUPPORTED_T_STATUS_PROHIBIT);
    resolved.statusProhibitMs = StatusProhibitMs[setup.tStatusProhibit];

    resolved.am.pollTicks = ToTicks(resolved.pollRetransmitMs, timing.tickMilliseconds);
    resolved.am.reorderingTicks = ToTicks(resolved.reorderingMs, timing.tickMilliseconds);
    resolved.am.prohibitTicks = ToTicks(resolved.statusProhibitMs, timing.tickMilliseconds);
    resolved.am.pollPdu = resolved.pollPduCount;
    resolved.am.pollByte = resolved.pollByteCount;
    // One more transmission than the retransmission threshold: the counter in
    // the entity starts at the first transmission, the TS field counts only the
    // retransmissions.
    resolved.am.maxRetx = static_cast<uint8_t>(resolved.maxRetransmissions + 1);
    return resolved;
}

} // namespace lte::rrc
