//
// This file is a part of UERANSIM project.
// Copyright (c) 2027 ALİ GÜNGÖR.
//
// https://github.com/aligungr/UERANSIM/
// See README, LICENSE, and CONTRIBUTING files for licensing details.
//

// Phase 19-C: 512 independent radio endpoints through the production eNB
// receive path, under the production default poll budget.
//
// A fixture socket is not an lte-ue process, and a radio registration is not
// an EPS Attach. Everything here is SIMULATED_RADIO_ENDPOINT_ACTIVE only: the
// frames are real encoded simulated-radio frames, the receive path and the
// registry are the production ones, and no MME, NAS procedure or bearer exists.

#include <ext/doctest/doctest.h>

#include <algorithm>
#include <chrono>
#include <cstdint>
#include <iostream>
#include <memory>
#include <random>
#include <set>
#include <string>
#include <unordered_map>
#include <vector>

#include <lib/udp/server.hpp>
#include <lte/enb/capacity_report.hpp>
#include <lte/enb/multiplexer.hpp>
#include <lte/enb/runtime_metrics.hpp>
#include <lte/enb/ue_registry.hpp>
#include <lte/ue/radio_link.hpp>
#include <utils/network.hpp>

namespace
{

using namespace lte::enb;
using Clock = std::chrono::steady_clock;

constexpr size_t kPeers = 512;
constexpr uint32_t kBaseUeId = 5000;

// Stands in for the absent MME-facing SCTP association. It records what the
// production multiplexer encoded; it delivers nothing and is not an MME.
struct CapturingSender : IS1apSender
{
    size_t messages{};
    size_t bytes{};
    void sendS1ap(uint16_t, const std::vector<uint8_t> &pdu) override
    {
        ++messages;
        bytes += pdu.size();
    }
};

EnbConfig IsolatedConfig()
{
    EnbConfig config;
    config.plmn = Plmn{"460", "02"};
    config.enbId = 0x00ABCDE;
    config.tac = 7;
    config.localAddress = "127.0.0.1";
    config.mmeAddress = "127.0.0.1";
    config.ueLinkAddress = "127.0.0.1";
    config.ueLinkPort = 0;
    config.s1uAddress = "127.0.0.1";
    config.s1uPort = 0;
    config.allowLoopbackS1u = true;
    config.maxUes = 512;
    return config;
}

std::vector<std::unique_ptr<udp::UdpServer>> MakeSenders(size_t count)
{
    std::vector<std::unique_ptr<udp::UdpServer>> senders;
    senders.reserve(count);
    for (size_t i = 0; i < count; ++i)
        senders.push_back(std::make_unique<udp::UdpServer>("127.0.0.1", 0));
    return senders;
}

void SendFrame(udp::UdpServer &sender, const InetAddress &radio, uint32_t ueId,
               const std::vector<uint8_t> &payload = {0x01, 0x02})
{
    lte::ue::link::Message frame;
    frame.type = lte::ue::link::MessageType::NAS_UPLINK;
    frame.ueId = ueId;
    frame.payload = payload;
    const auto bytes = lte::ue::link::Encode(frame);
    sender.Send(radio, bytes.data(), bytes.size());
}

// Frames are paced by the production loop: at most one 16-frame batch is in the
// kernel queue at a time, so a full 512-peer arrival never becomes an
// accidental microburst.
void SendUniformPaced(EnbMultiplexer &multiplexer, const InetAddress &radio,
                      const std::vector<std::unique_ptr<udp::UdpServer>> &senders)
{
    for (size_t i = 0; i < senders.size(); ++i)
    {
        SendFrame(*senders[i], radio, static_cast<uint32_t>(kBaseUeId + i));
        if ((i % 4) == 3)
            multiplexer.poll(); // the production default: 16 radio + 16 S1-U
    }
    for (size_t i = 0; i < 64 && multiplexer.registry().size() < senders.size(); ++i)
        multiplexer.poll();
}

} // namespace

TEST_CASE("lte/radio-scale: 512 independent endpoints reach the production registry under the default budget")
{
    CapturingSender sender;
    EnbMultiplexer multiplexer{IsolatedConfig(), sender};
    const InetAddress radio = multiplexer.ueLinkAddress();
    REQUIRE(radio.getPort() != 0);
    CHECK(multiplexer.radioReceiveBufferBytes() > 0);

    auto senders = MakeSenders(kPeers);
    multiplexer.perfCounters().enabled.store(true);
    SendUniformPaced(multiplexer, radio, senders);

    CHECK(multiplexer.registry().size() == kPeers);
    CHECK(multiplexer.perfCounters().pollIterations.load() > 0);
    CHECK(sender.messages == kPeers);

    // Every endpoint is independently addressable by radio identity and by the
    // peer that owns it. A collision or a merged context would show here.
    size_t verified = 0;
    for (size_t i = 0; i < kPeers; ++i)
    {
        const auto *entry = multiplexer.registry().find(static_cast<uint32_t>(kBaseUeId + i));
        if (entry != nullptr && entry->peer == senders[i]->LocalAddress())
            ++verified;
    }
    CHECK(verified == kPeers);

    // A paced arrival under the default budget must not drop: the kernel queue
    // never holds more than the batch that is about to be drained.
    const auto accounting = ReadUdpSocketAccounting(radio.getPort());
    REQUIRE(accounting.found);
    CHECK(accounting.drops == 0);
    std::cout << "UNIRANSIM-RADIO-UNIFORM peers=" << kPeers
              << " delivered=" << multiplexer.registry().size() << " drops=" << accounting.drops
              << " polls=" << multiplexer.perfCounters().pollIterations.load()
              << " rcvbuf_bytes=" << multiplexer.radioReceiveBufferBytes() << std::endl;

    // Simultaneous teardown releases every context and every index.
    for (auto *entry : multiplexer.registry().all())
        multiplexer.registry().remove(*entry);
    CHECK(multiplexer.registry().size() == 0);
    for (size_t i = 0; i < kPeers; ++i)
    {
        CHECK(multiplexer.registry().find(static_cast<uint32_t>(kBaseUeId + i)) == nullptr);
        CHECK(multiplexer.registry().findByPeer(senders[i]->LocalAddress()) == nullptr);
    }
}

TEST_CASE("lte/radio-scale: a 512-frame microburst is accounted for, drops included")
{
    CapturingSender sender;
    EnbMultiplexer multiplexer{IsolatedConfig(), sender};
    const InetAddress radio = multiplexer.ueLinkAddress();
    auto senders = MakeSenders(kPeers);

    // Unpaced: every datagram is offered before the receiver runs. This is the
    // deliberate microburst profile, not a paced arrival.
    for (size_t i = 0; i < kPeers; ++i)
        SendFrame(*senders[i], radio, static_cast<uint32_t>(kBaseUeId + i));

    const auto burst = ReadUdpSocketAccounting(radio.getPort());
    REQUIRE(burst.found);
    const size_t sent = kPeers;
    const size_t dropped = static_cast<size_t>(burst.drops);

    for (size_t i = 0; i < 400 && multiplexer.registry().size() + dropped < sent; ++i)
        multiplexer.poll();

    const size_t delivered = multiplexer.registry().size();
    const auto after = ReadUdpSocketAccounting(radio.getPort());
    CHECK(after.found);
    // Whether this kernel drops depends on its datagram accounting and the
    // configured receive buffer. The result is reported, not required: what the
    // test requires is that every offered datagram is either delivered or
    // counted as dropped by the socket itself.
    CHECK(delivered > 0);
    CHECK(delivered + dropped == sent);
    CHECK(after.drops == burst.drops); // the drop count is final once sending stops
    CHECK(burst.receiveQueueBytes > 0);

    // Say nothing about unaccounted packets unless the identity actually holds.
    const size_t unaccounted = sent - delivered - dropped;
    CHECK(unaccounted == 0);
    std::cout << "UNIRANSIM-RADIO-MICROBURST sent=" << sent << " delivered=" << delivered
              << " dropped=" << dropped << " unaccounted=" << unaccounted
              << " queue_bytes_at_burst=" << burst.receiveQueueBytes
              << " rcvbuf_bytes=" << multiplexer.radioReceiveBufferBytes() << std::endl;
}

TEST_CASE("lte/radio-scale: staggered arrival and repeated 512-endpoint cycles leave no residue")
{
    for (int cycle = 0; cycle < 3; ++cycle)
    {
        CapturingSender sender;
        EnbMultiplexer multiplexer{IsolatedConfig(), sender};
        const InetAddress radio = multiplexer.ueLinkAddress();
        auto senders = MakeSenders(kPeers);

        // Bounded staggered arrival: eight datagrams, then a production poll.
        for (size_t i = 0; i < kPeers; ++i)
        {
            SendFrame(*senders[i], radio, static_cast<uint32_t>(kBaseUeId + i));
            if ((i % 4) == 3)
                multiplexer.poll();
        }
        for (size_t i = 0; i < 128 && multiplexer.registry().size() < kPeers; ++i)
            multiplexer.poll();
        REQUIRE(multiplexer.registry().size() == kPeers);

        // Mixed teardown and registration: release every second context, then
        // fill the freed slots with new identities before the final release.
        size_t released = 0;
        for (size_t i = 0; i < kPeers; i += 2)
        {
            auto *entry = multiplexer.registry().find(static_cast<uint32_t>(kBaseUeId + i));
            REQUIRE(entry != nullptr);
            multiplexer.registry().remove(*entry);
            ++released;
        }
        CHECK(multiplexer.registry().size() == kPeers - released);

        for (size_t i = 0; i < released; ++i)
            (void)multiplexer.registry().registerPeer(
                static_cast<uint32_t>(9000 + i), InetAddress{"127.0.0.1", static_cast<uint16_t>(30000 + i)});
        CHECK(multiplexer.registry().size() == kPeers);

        for (auto *entry : multiplexer.registry().all())
            multiplexer.registry().remove(*entry);
        CHECK(multiplexer.registry().size() == 0);
    }
}

TEST_CASE("lte/radio-scale: one hot endpoint cannot starve or corrupt 511 cold endpoints")
{
    // The bound is stated before the measurement: after every cold datagram has
    // been offered, every cold identity must be served within 600 production
    // poll iterations (9600 frame slots for 511 cold and 128 hot frames).
    constexpr size_t kCold = kPeers - 1;
    constexpr size_t kHotFrames = 128;
    constexpr int kPollBound = 600;

    CapturingSender sender;
    EnbMultiplexer multiplexer{IsolatedConfig(), sender};
    const InetAddress radio = multiplexer.ueLinkAddress();
    auto cold = MakeSenders(kCold);
    udp::UdpServer hot{"127.0.0.1", 0};
    multiplexer.perfCounters().enabled.store(true);

    // Interleave the hot and cold arrivals so the offered load is real but the
    // kernel queue is not asked to hold a burst larger than it can.
    size_t hotSent = 0;
    for (size_t i = 0; i < kCold; ++i)
    {
        SendFrame(*cold[i], radio, static_cast<uint32_t>(kBaseUeId + i));
        if (hotSent < kHotFrames)
        {
            SendFrame(hot, radio, 9000);
            ++hotSent;
        }
        if ((i % 4) == 3)
            multiplexer.poll();
    }
    for (size_t i = 0; i < 8; ++i)
    {
        SendFrame(hot, radio, 9000);
        ++hotSent;
        multiplexer.poll();
    }

    const int iterationsBefore = static_cast<int>(multiplexer.perfCounters().pollIterations.load());
    int iterations = 0;
    for (; iterations < kPollBound && multiplexer.registry().size() < kCold + 1; ++iterations)
        multiplexer.poll();

    CHECK(iterations < kPollBound);
    CHECK(multiplexer.registry().find(9000) != nullptr);

    size_t served = 0;
    size_t correctPeer = 0;
    for (size_t i = 0; i < kCold; ++i)
    {
        const auto *entry = multiplexer.registry().find(static_cast<uint32_t>(kBaseUeId + i));
        if (entry == nullptr)
            continue;
        ++served;
        // No cross-UE identity mutation: the entry still owns the peer that
        // presented its own identity, and no other UE's context was renamed.
        if (entry->peer == cold[i]->LocalAddress() && entry->radioUeId == static_cast<uint32_t>(kBaseUeId + i))
            ++correctPeer;
    }
    CHECK(served == kCold);
    CHECK(correctPeer == kCold);
    CHECK(multiplexer.perfCounters().pollIterations.load() - static_cast<uint64_t>(iterationsBefore) ==
          static_cast<uint64_t>(iterations));
}

TEST_CASE("lte/radio-scale: enqueue-to-processing latency is measured, not inferred from absence of starvation")
{
    // The stated bound before the run: p99 enqueue-to-handled latency must stay
    // under 500 ms for 512 paced endpoints under the default budget. This is a
    // liveness bound for an unloaded host, not a throughput claim.
    constexpr double kP99BoundMs = 500.0;

    CapturingSender sender;
    EnbMultiplexer multiplexer{IsolatedConfig(), sender};
    const InetAddress radio = multiplexer.ueLinkAddress();
    auto senders = MakeSenders(kPeers);

    std::unordered_map<uint32_t, Clock::time_point> enqueuedAt;
    std::vector<double> endToEnd;
    std::vector<double> processing;
    multiplexer.setRadioFrameObserver(
        [&](const InetAddress &, const uint8_t *data, size_t size, Clock::time_point receivedAt,
            Clock::time_point handledAt) {
            try
            {
                const auto message = lte::ue::link::Decode(data, size);
                const auto it = enqueuedAt.find(message.ueId);
                if (it == enqueuedAt.end())
                    return;
                endToEnd.push_back(std::chrono::duration<double, std::milli>(handledAt - it->second).count());
                processing.push_back(std::chrono::duration<double, std::milli>(handledAt - receivedAt).count());
                enqueuedAt.erase(it);
            }
            catch (const std::exception &)
            {
            }
        });
    multiplexer.perfCounters().enabled.store(true);

    for (size_t i = 0; i < kPeers; ++i)
    {
        const uint32_t ueId = static_cast<uint32_t>(kBaseUeId + i);
        enqueuedAt[ueId] = Clock::now();
        SendFrame(*senders[i], radio, ueId);
        if ((i % 4) == 3)
            multiplexer.poll();
    }
    for (size_t i = 0; i < 64 && multiplexer.registry().size() < kPeers; ++i)
        multiplexer.poll();

    CHECK(multiplexer.registry().size() == kPeers);
    CHECK(endToEnd.size() == kPeers);
    CHECK(processing.size() == kPeers);

    const auto endToEndSummary = SummarizeLatencies(endToEnd);
    const auto processingSummary = SummarizeLatencies(processing);
    std::cout << "UNIRANSIM-RADIO-LATENCY enqueue_to_handled " << DescribeLatency(endToEndSummary)
              << " | multiplexer_handle " << DescribeLatency(processingSummary)
              << " | polls=" << multiplexer.perfCounters().pollIterations.load() << std::endl;
    INFO("enqueue-to-handled " << DescribeLatency(endToEndSummary));
    INFO("multiplexer-handle " << DescribeLatency(processingSummary));
    CHECK(endToEndSummary.count == kPeers);
    CHECK(endToEndSummary.p50 <= endToEndSummary.p95);
    CHECK(endToEndSummary.p95 <= endToEndSummary.p99);
    CHECK(endToEndSummary.p99 < kP99BoundMs);
    CHECK(processingSummary.p99 < kP99BoundMs);

    // Effective work per iteration is observable and bounded by the default
    // budget; this is a rate observation, not a throughput claim.
    const uint64_t iterations = multiplexer.perfCounters().pollIterations.load();
    CHECK(iterations > 0);
    CHECK(static_cast<double>(kPeers) / static_cast<double>(iterations) <= 16.0);
}