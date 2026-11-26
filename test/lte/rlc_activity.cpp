#include <doctest/doctest.h>

#include <lte/rrc-runtime/lte_am_bearer.hpp>
#include <lte/rrc-runtime/rlc_tick_scheduler.hpp>

#include <cstdint>
#include <vector>

using namespace lte::rlc;
using namespace lte::rlc::am;

namespace
{

AmConfig SmallConfig()
{
    AmConfig config;
    config.maxPduBytes = 256;
    config.maxRetx = 8;
    config.pollTicks = 10;
    config.reorderingTicks = 10;
    config.prohibitTicks = 5;
    return config;
}

LteAmBearer MakeBearer(uint32_t association, std::vector<std::vector<uint8_t>> &sent)
{
    return LteAmBearer(EndpointRole::UE, association, SmallConfig(),
                       [](std::vector<uint8_t>) {}, lte::uu::LogicalChannel::DTCH,
                       [&sent](const std::vector<uint8_t> &pdu) { sent.push_back(pdu); });
}

} // namespace

TEST_CASE("lte/rlc/activity: an idle entity has no deadline and a submit starts the poll timer")
{
    std::vector<std::vector<uint8_t>> sent;
    LteAmEntity entity(SmallConfig(),
                       [&sent](std::vector<uint8_t> pdu) { sent.push_back(std::move(pdu)); },
                       [](std::vector<uint8_t>) {});
    CHECK(entity.NextTickIn() == LteAmEntity::NeverTick);

    entity.SubmitSdu(std::vector<uint8_t>(32, 0x5A));
    CHECK(entity.NextTickIn() == SmallConfig().pollTicks);
    CHECK(sent.size() == 1);

    entity.Tick(SmallConfig().pollTicks - 1);
    CHECK(entity.PollsSent() == 0);
    entity.Tick(1);
    CHECK(entity.PollsSent() == 1);
    CHECK(sent.size() == 2);

    entity.Release();
}

TEST_CASE("lte/rlc/activity: the activity callback reports every submit")
{
    LteAmEntity entity(SmallConfig(), [](std::vector<uint8_t>) {}, [](std::vector<uint8_t>) {});
    int events = 0;
    entity.SetActivityCallback([&events] { ++events; });
    entity.SubmitSdu(std::vector<uint8_t>(16, 1));
    CHECK(events == 1);
    entity.SubmitSdu(std::vector<uint8_t>(16, 2));
    CHECK(events == 2);
    entity.Release();
}

TEST_CASE("lte/rlc/activity: a first submit is not charged the idle interval")
{
    std::vector<std::vector<uint8_t>> sent;
    auto bearer = MakeBearer(7, sent);
    CHECK(bearer.NextTickIn() == LteAmEntity::NeverTick);

    // The bearer has been idle for a long time; the owner polls it once.
    bearer.AdvanceTo(1000);
    CHECK(bearer.NextTickIn() == LteAmEntity::NeverTick);

    int activity = 0;
    bearer.SetActivityCallback([&activity] { ++activity; });
    bearer.SubmitSdu(std::vector<uint8_t>(24, 0x11));
    CHECK(activity == 1);
    // The owner's activity callback reschedules at the submit time; the new
    // timer's base is then, not the process origin.
    bearer.AdvanceTo(1000);
    CHECK(bearer.NextTickIn() == SmallConfig().pollTicks);

    // Five milliseconds later the poll has not fired; the idle 1000 ms was not
    // applied to work created after it.
    bearer.AdvanceTo(1005);
    CHECK(bearer.PollsSent() == 0);
    CHECK(bearer.NextTickIn() == 5);

    bearer.AdvanceTo(1010);
    CHECK(bearer.PollsSent() == 1);
    bearer.Release();
}

TEST_CASE("lte/rlc/activity: the deadline scheduler orders entries and holds only active ones")
{
    RlcTickScheduler scheduler;
    for (uint32_t i = 0; i < 8; i++)
        scheduler.Push({100 + static_cast<int64_t>(i), i, 0, 1, 1});
    // 504 idle contexts are not scheduled at all.
    CHECK(scheduler.Size() == 8);

    RlcTickScheduler::Entry entry;
    CHECK_FALSE(scheduler.PopDue(99, entry));
    for (uint32_t i = 0; i < 8; i++)
    {
        REQUIRE(scheduler.PopDue(100 + static_cast<int64_t>(i), entry));
        CHECK(entry.id == i);
    }
    CHECK(scheduler.Empty());
}

TEST_CASE("lte/rlc/activity: equal deadlines keep insertion order and all 512 active entities run")
{
    RlcTickScheduler scheduler;
    for (uint32_t i = 0; i < 512; i++)
        scheduler.Push({500, i, 0, 1, 1});
    CHECK(scheduler.Size() == 512);
    uint32_t next = 0;
    RlcTickScheduler::Entry entry;
    while (scheduler.PopDue(500, entry))
        CHECK(entry.id == next++);
    CHECK(next == 512);
}

TEST_CASE("lte/rlc/activity: a stale version is rejected before the entity is ticked")
{
    RlcTickScheduler scheduler;
    scheduler.Push({100, 3, 4, 9, 1});
    scheduler.Push({100, 3, 4, 9, 2});
    RlcTickScheduler::Entry entry;
    REQUIRE(scheduler.PopDue(100, entry));
    const uint64_t currentVersion = 2;
    CHECK(entry.version != currentVersion); // the older schedule is stale
    REQUIRE(scheduler.PopDue(100, entry));
    CHECK(entry.version == currentVersion);
    CHECK(entry.generation == 9);
    CHECK(entry.id == 3);
    CHECK(entry.subId == 4);
}
