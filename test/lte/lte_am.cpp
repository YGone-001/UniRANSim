//
// This file is a part of UERANSIM project.
// Copyright (c) 2027 ALİ GÜNGÖR.
//

// Phase 18-F-B6-B1-R2: the LTE RLC AM entity over the LTE wire codec.
#include <ext/doctest/doctest.h>

#include <lte/rrc-runtime/lte_am.hpp>

#include <functional>
#include <memory>
#include <string>
#include <vector>

using namespace lte::rlc::am;

namespace
{

struct Pair
{
    LteAmEntity tx;
    LteAmEntity rx;
    std::vector<std::vector<uint8_t>> delivered;
    std::vector<std::vector<uint8_t>> wire;
    int drops{0};
};

// A two-entity harness: the TX entity emits PDUs into the RX entity, and the RX
// entity's STATUS PDUs go back to the TX entity. Nothing bypasses the codec.
std::unique_ptr<Pair> MakePair(AmConfig config = {})
{
    auto pair = std::make_unique<Pair>();
    pair->tx = LteAmEntity(
        config,
        [raw = pair.get()](std::vector<uint8_t> pdu) {
            raw->wire.push_back(pdu);
            if (raw->drops > 0)
            {
                raw->drops--;
                return;
            }
            raw->rx.OnPdu(pdu);
        },
        [](std::vector<uint8_t>) {});
    pair->rx = LteAmEntity(
        config, [raw = pair.get()](std::vector<uint8_t> pdu) { raw->tx.OnStatusPdu(pdu); },
        [raw = pair.get()](std::vector<uint8_t> sdu) { raw->delivered.push_back(sdu); });
    return pair;
}

} // namespace

TEST_CASE("lte/rlc-am-entity/a short sdu becomes one amd pdu and is delivered")
{
    auto pair = MakePair();
    const std::vector<uint8_t> sdu = {0x11, 0x22, 0x33};

    pair->tx.SubmitSdu(sdu);
    CHECK(pair->tx.VtS() == 1);
    REQUIRE(pair->wire.size() == 1);
    CHECK(pair->delivered.size() == 1);
    CHECK(pair->delivered[0] == sdu);
    CHECK(pair->rx.VrR() == 1);
}

TEST_CASE("lte/rlc-am-entity/a long sdu is segmented and reassembled in order")
{
    AmConfig config;
    config.maxPduBytes = 6;  // 2-octet header + 4 payload bytes
    auto pair = MakePair(config);

    const std::vector<uint8_t> sdu = {1, 2, 3, 4, 5, 6, 7, 8, 9};
    pair->tx.SubmitSdu(sdu);

    CHECK(pair->wire.size() == 3);
    CHECK(pair->tx.VtS() == 3);
    REQUIRE(pair->delivered.size() == 1);
    CHECK(pair->delivered[0] == sdu);

    // The first segmented PDU advertises FI = first segment.
    AmdPdu first;
    std::string why;
    REQUIRE(DecodeAmd(pair->wire[0].data(), pair->wire[0].size(), first, &why));
    CHECK(first.fi == FramingInfo::FIRST_SEGMENT);
}

TEST_CASE("lte/rlc-am-entity/out of order reception is buffered and delivered in sequence")
{
    auto pair = MakePair();
    pair->wire.clear();

    // Hold the first PDU back, deliver the second first.
    pair->tx.SubmitSdu({0xA1});
    pair->tx.SubmitSdu({0xA2});
    REQUIRE(pair->wire.size() == 2);

    const auto first = pair->wire[0];
    const auto second = pair->wire[1];

    auto fresh = MakePair();
    fresh->rx.OnPdu(second);
    CHECK(fresh->delivered.empty());
    CHECK(fresh->rx.VrR() == 0);

    fresh->rx.OnPdu(first);
    REQUIRE(fresh->delivered.size() == 2);
    CHECK(fresh->delivered[0] == std::vector<uint8_t>({0xA1}));
    CHECK(fresh->delivered[1] == std::vector<uint8_t>({0xA2}));
    CHECK(fresh->rx.VrR() == 2);
}

TEST_CASE("lte/rlc-am-entity/a duplicate is not delivered twice")
{
    auto pair = MakePair();
    pair->tx.SubmitSdu({0xB1});
    REQUIRE(pair->wire.size() == 1);
    const auto pdu = pair->wire[0];

    pair->rx.OnPdu(pdu);
    CHECK(pair->delivered.size() == 1);
    pair->rx.OnPdu(pdu);
    CHECK(pair->delivered.size() == 1);
    CHECK(pair->rx.VrR() == 1);
}

TEST_CASE("lte/rlc-am-entity/loss triggers a status with a nack and the pdu is retransmitted")
{
    auto pair = MakePair();
    pair->drops = 1;  // the first PDU is lost

    pair->tx.SubmitSdu({0xC1});
    pair->tx.SubmitSdu({0xC2});
    CHECK(pair->delivered.empty());

    // The receiver reports the gap, the transmitter retransmits the missing SN.
    pair->rx.OnTick();
    pair->rx.OnTick();
    CHECK(pair->tx.Retransmissions() >= 1);

    // Drain any remaining status exchange.
    for (int i = 0; i < 5 && pair->delivered.size() < 2; i++)
    {
        pair->tx.OnTick();
        pair->rx.OnTick();
    }
    REQUIRE(pair->delivered.size() == 2);
    CHECK(pair->delivered[0] == std::vector<uint8_t>({0xC1}));
    CHECK(pair->delivered[1] == std::vector<uint8_t>({0xC2}));

    // Let the final STATUS reach the transmitter, then both PDUs are
    // acknowledged and the retransmission buffer is empty.
    for (int i = 0; i < 12; i++)
    {
        pair->rx.OnTick();
        pair->tx.OnTick();
    }
    CHECK(pair->tx.VtA() == 2);
}

TEST_CASE("lte/rlc-am-entity/cumulative acknowledgement advances vt-a")
{
    auto pair = MakePair();
    pair->tx.SubmitSdu({1});
    pair->tx.SubmitSdu({2});
    REQUIRE(pair->tx.VtS() == 2);

    StatusPdu ack;
    ack.ackSn = 2;
    pair->tx.OnStatusPdu(EncodeStatus(ack));
    CHECK(pair->tx.VtA() == 2);
}

TEST_CASE("lte/rlc-am-entity/repeated nacks exhaust maxRetx and fail the entity")
{
    AmConfig config;
    config.maxRetx = 2;
    auto pair = MakePair(config);
    pair->tx.SubmitSdu({7});

    StatusPdu nack;
    nack.ackSn = 0;
    StatusNack entry;
    entry.sn = 0;
    nack.nacks.push_back(entry);
    const auto status = EncodeStatus(nack);

    pair->tx.OnStatusPdu(status);
    CHECK(pair->tx.State() == AmState::ACTIVE);
    pair->tx.OnStatusPdu(status);
    CHECK(pair->tx.State() == AmState::FAILED);
}

TEST_CASE("lte/rlc-am-entity/poll timer retransmits and the window refuses overflow")
{
    AmConfig config;
    config.pollTicks = 2;
    config.maxPduBytes = 6;
    auto pair = MakePair(config);

    pair->tx.SubmitSdu({1});
    const auto before = pair->tx.Retransmissions();
    pair->tx.OnTick();
    pair->tx.OnTick();
    CHECK(pair->tx.Retransmissions() == before + 1);

    // 512 outstanding sequence numbers is the LTE AM window.
    AmConfig wide;
    wide.maxPduBytes = 5;
    auto window = MakePair(wide);
    for (int i = 0; i < 512; i++)
        window->tx.SubmitSdu({static_cast<uint8_t>(i)});
    CHECK(window->tx.VtS() == 512);
    CHECK_THROWS(window->tx.SubmitSdu({0xFF}));
}

TEST_CASE("lte/rlc-am-entity/entity release stops all processing")
{
    auto pair = MakePair();
    pair->tx.SubmitSdu({1});
    const size_t before = pair->delivered.size();
    pair->rx.Release();
    CHECK(pair->rx.State() == AmState::RELEASED);
    pair->rx.OnPdu(pair->wire.back());
    CHECK(pair->delivered.size() == before);
    pair->tx.Release();
    CHECK(pair->tx.State() == AmState::RELEASED);
    CHECK_THROWS(pair->tx.SubmitSdu({2}));
}
namespace
{

struct RxHarness
{
    LteAmEntity entity;
    std::vector<std::vector<uint8_t>> statuses;
    std::vector<std::vector<uint8_t>> delivered;

    RxHarness()
    {
        entity = LteAmEntity(
            AmConfig{},
            [this](std::vector<uint8_t> pdu) { statuses.push_back(std::move(pdu)); },
            [this](std::vector<uint8_t> sdu) { delivered.push_back(std::move(sdu)); });
    }
};

std::vector<uint8_t> Segment(uint16_t sn, uint16_t so, bool lsf, const std::vector<uint8_t> &data)
{
    AmdPdu pdu;
    pdu.sn = sn;
    pdu.segment = true;
    pdu.so = so;
    pdu.lsf = lsf;
    // FI describes the SDU boundary inside this segment, not the segmentation
    // itself: a first segment starts an SDU, a last one ends it.
    if (so == 0 && lsf)
        pdu.fi = FramingInfo::COMPLETE;
    else if (so == 0)
        pdu.fi = FramingInfo::FIRST_SEGMENT;
    else if (lsf)
        pdu.fi = FramingInfo::LAST_SEGMENT;
    else
        pdu.fi = FramingInfo::MIDDLE_SEGMENT;
    pdu.data = data;
    return EncodeAmd(pdu);
}

StatusPdu LastStatus(const RxHarness &harness)
{
    StatusPdu status;
    std::string why;
    REQUIRE_FALSE(harness.statuses.empty());
    const auto &pdu = harness.statuses.back();
    REQUIRE(DecodeStatus(pdu.data(), pdu.size(), status, &why));
    return status;
}

} // namespace

TEST_CASE("lte/rlc-am-entity/a partial pdu produces a segment-specific nack with soend 0x7fff")
{
    RxHarness harness;
    harness.entity.OnPdu(Segment(0, 0, false, {1, 2, 3, 4}));
    harness.entity.OnTick();

    const auto status = LastStatus(harness);
    CHECK(status.ackSn == 0);
    REQUIRE(status.nacks.size() == 1);
    CHECK(status.nacks[0].sn == 0);
    REQUIRE(status.nacks[0].soRange.has_value());
    CHECK(status.nacks[0].soRange->first == 4);
    CHECK(status.nacks[0].soRange->second == SoMax);
}

TEST_CASE("lte/rlc-am-entity/a missing middle range is reported and never acknowledged")
{
    RxHarness harness;
    harness.entity.OnPdu(Segment(0, 0, false, {1, 2, 3, 4}));
    harness.entity.OnPdu(Segment(0, 8, true, {9, 10, 11, 12}));
    harness.entity.OnTick();

    const auto status = LastStatus(harness);
    CHECK(status.ackSn == 0);
    REQUIRE(status.nacks.size() == 1);
    REQUIRE(status.nacks[0].soRange.has_value());
    CHECK(status.nacks[0].soRange->first == 4);
    CHECK(status.nacks[0].soRange->second == 7);
    CHECK(harness.delivered.empty());

    // The missing middle arrives: the PDU completes and the SDU is delivered in
    // order, with the gaps filled.
    harness.entity.OnPdu(Segment(0, 4, false, {5, 6, 7, 8}));
    REQUIRE(harness.delivered.size() == 1);
    CHECK(harness.delivered[0] == std::vector<uint8_t>({1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12}));
    CHECK(harness.entity.VrR() == 1);

    // A completed PDU is acknowledged, not nacked.
    harness.entity.OnTick();
    harness.entity.OnTick();
    const auto after = LastStatus(harness);
    CHECK(after.ackSn == 1);
    CHECK(after.nacks.empty());
}

TEST_CASE("lte/rlc-am-entity/a whole missing pdu stays a whole-pdu nack")
{
    RxHarness harness;
    harness.entity.OnPdu(EncodeAmd([] {
        AmdPdu pdu;
        pdu.sn = 1;
        pdu.data = {0x42};
        return pdu;
    }()));
    harness.entity.OnTick();

    const auto status = LastStatus(harness);
    CHECK(status.ackSn == 0);
    REQUIRE(status.nacks.size() == 1);
    CHECK(status.nacks[0].sn == 0);
    CHECK_FALSE(status.nacks[0].soRange.has_value());
}
TEST_CASE("lte/rlc-am-entity/concatenated sdus carry an li chain and are split on delivery")
{
    auto pair = MakePair();
    pair->tx.SubmitSdus({std::vector<uint8_t>{0x01}, std::vector<uint8_t>{0x02, 0x03}, std::vector<uint8_t>{0x04}});

    REQUIRE(pair->wire.size() == 1);
    AmdPdu pdu;
    std::string why;
    REQUIRE(DecodeAmd(pair->wire[0].data(), pair->wire[0].size(), pdu, &why));
    // Three elements: two LIs (1 and 2), the last element carries none.
    REQUIRE(pdu.li.size() == 2);
    CHECK(pdu.li[0] == 1);
    CHECK(pdu.li[1] == 2);
    CHECK(pdu.fi == FramingInfo::COMPLETE);

    REQUIRE(pair->delivered.size() == 3);
    CHECK(pair->delivered[0] == std::vector<uint8_t>({0x01}));
    CHECK(pair->delivered[1] == std::vector<uint8_t>({0x02, 0x03}));
    CHECK(pair->delivered[2] == std::vector<uint8_t>({0x04}));

    // A single SDU still travels without any LI.
    auto single = MakePair();
    single->tx.SubmitSdus({std::vector<uint8_t>{0xAA}});
    AmdPdu plain;
    REQUIRE(DecodeAmd(single->wire[0].data(), single->wire[0].size(), plain, &why));
    CHECK(plain.li.empty());
}
