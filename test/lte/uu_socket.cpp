//
// This file is a part of UERANSIM project.
// Copyright (c) 2027 ALİ GÜNGÖR.
//

// Phase 18-F-B6-B2: the simulated Uu socket's own link model.
//
// The earlier transport held a reordered outgoing frame in the same
// `pending_` slot the receive path consulted, so the sending endpoint could
// receive its own delayed frame and the frame lost its destination. These tests
// pin the corrected lifecycle directly on the socket, without a relay in
// between.
#include <ext/doctest/doctest.h>

#include <lte/rrc-runtime/uu_transport.hpp>

#include <string>
#include <vector>

using namespace lte;

namespace
{

uu::Frame MakeFrame(uint32_t association, uu::Direction direction, uint8_t tag)
{
    uu::Frame frame;
    frame.association = association;
    frame.direction = direction;
    frame.channel = uu::LogicalChannel::DCCH;
    frame.payload = {tag};
    return frame;
}

} // namespace

TEST_CASE("lte/uu-socket/an outgoing delayed frame is never returned to its sender")
{
    auto sender = uu::Socket::BindLoopback(0, nullptr);
    auto receiver = uu::Socket::BindLoopback(0, nullptr);
    REQUIRE(sender.has_value());
    REQUIRE(receiver.has_value());

    uu::LinkModel reorder;
    reorder.reorderEveryNth = 1;
    sender->SetLinkModel(reorder);

    REQUIRE(sender->Send(receiver->Port(), MakeFrame(1, uu::Direction::UPLINK, 0x11), nullptr));
    CHECK(sender->HasPending());
    CHECK(sender->Held() == 1);

    // The held frame is not local traffic: neither endpoint has it.
    uu::Frame received;
    CHECK_FALSE(sender->Receive(received, 30, nullptr));
    CHECK_FALSE(receiver->Receive(received, 30, nullptr));
}

TEST_CASE("lte/uu-socket/a later frame releases the held one to its original destination")
{
    auto sender = uu::Socket::BindLoopback(0, nullptr);
    auto receiver = uu::Socket::BindLoopback(0, nullptr);
    REQUIRE(sender.has_value());
    REQUIRE(receiver.has_value());

    uu::LinkModel reorder;
    reorder.reorderEveryNth = 1;
    sender->SetLinkModel(reorder);

    REQUIRE(sender->Send(receiver->Port(), MakeFrame(1, uu::Direction::UPLINK, 0x21), nullptr));
    REQUIRE(sender->Send(receiver->Port(), MakeFrame(1, uu::Direction::UPLINK, 0x22), nullptr));
    CHECK_FALSE(sender->HasPending());
    CHECK(sender->Released() == 1);

    // The pair arrives out of order, at the destination the first one named.
    uu::Frame received;
    REQUIRE(receiver->Receive(received, 100, nullptr));
    CHECK(received.payload == std::vector<uint8_t>({0x22}));
    REQUIRE(receiver->Receive(received, 100, nullptr));
    CHECK(received.payload == std::vector<uint8_t>({0x21}));
}

TEST_CASE("lte/uu-socket/two destinations never exchange a pending frame")
{
    auto sender = uu::Socket::BindLoopback(0, nullptr);
    auto first = uu::Socket::BindLoopback(0, nullptr);
    auto second = uu::Socket::BindLoopback(0, nullptr);
    REQUIRE(sender.has_value());
    REQUIRE(first.has_value());
    REQUIRE(second.has_value());

    uu::LinkModel reorder;
    reorder.reorderEveryNth = 1;
    sender->SetLinkModel(reorder);

    REQUIRE(sender->Send(first->Port(), MakeFrame(1, uu::Direction::UPLINK, 0x31), nullptr));
    // Selecting the second destination must release the first frame to its own
    // port instead of swapping the two.
    REQUIRE(sender->Send(second->Port(), MakeFrame(1, uu::Direction::UPLINK, 0x32), nullptr));

    uu::Frame received;
    REQUIRE(first->Receive(received, 100, nullptr));
    CHECK(received.payload == std::vector<uint8_t>({0x31}));
    CHECK_FALSE(second->Receive(received, 30, nullptr));

    REQUIRE(sender->FlushPending(nullptr));
    REQUIRE(second->Receive(received, 100, nullptr));
    CHECK(received.payload == std::vector<uint8_t>({0x32}));
    CHECK_FALSE(first->Receive(received, 30, nullptr));
}

TEST_CASE("lte/uu-socket/duplicate and drop rules keep their counts")
{
    auto sender = uu::Socket::BindLoopback(0, nullptr);
    auto receiver = uu::Socket::BindLoopback(0, nullptr);
    REQUIRE(sender.has_value());
    REQUIRE(receiver.has_value());

    uu::LinkModel duplicate;
    duplicate.duplicateEveryNth = 1;
    sender->SetLinkModel(duplicate);
    REQUIRE(sender->Send(receiver->Port(), MakeFrame(1, uu::Direction::UPLINK, 0x41), nullptr));

    uu::Frame received;
    REQUIRE(receiver->Receive(received, 100, nullptr));
    CHECK(received.payload == std::vector<uint8_t>({0x41}));
    REQUIRE(receiver->Receive(received, 100, nullptr));
    CHECK(received.payload == std::vector<uint8_t>({0x41}));
    CHECK_FALSE(receiver->Receive(received, 30, nullptr));

    auto lossy = uu::Socket::BindLoopback(0, nullptr);
    auto silent = uu::Socket::BindLoopback(0, nullptr);
    REQUIRE(lossy.has_value());
    REQUIRE(silent.has_value());
    uu::LinkModel loss;
    loss.dropEveryNth = 2;
    lossy->SetLinkModel(loss);

    REQUIRE(lossy->Send(silent->Port(), MakeFrame(1, uu::Direction::UPLINK, 0x42), nullptr));
    REQUIRE(lossy->Send(silent->Port(), MakeFrame(1, uu::Direction::UPLINK, 0x43), nullptr));
    CHECK(lossy->Dropped() == 1);
    CHECK(lossy->Sent() == 2);
    REQUIRE(silent->Receive(received, 100, nullptr));
    CHECK(received.payload == std::vector<uint8_t>({0x42}));
    CHECK_FALSE(silent->Receive(received, 30, nullptr));
}

TEST_CASE("lte/uu-socket/closing an endpoint discards its held frame without leaking it")
{
    auto sender = uu::Socket::BindLoopback(0, nullptr);
    auto receiver = uu::Socket::BindLoopback(0, nullptr);
    REQUIRE(sender.has_value());
    REQUIRE(receiver.has_value());

    uu::LinkModel reorder;
    reorder.reorderEveryNth = 1;
    sender->SetLinkModel(reorder);
    REQUIRE(sender->Send(receiver->Port(), MakeFrame(1, uu::Direction::UPLINK, 0x51), nullptr));
    CHECK(sender->HasPending());

    sender->Close();
    CHECK_FALSE(sender->HasPending());
    CHECK(sender->PendingDropped() == 1);

    uu::Frame received;
    CHECK_FALSE(receiver->Receive(received, 50, nullptr));

    // A new endpoint is unaffected by the discarded one.
    auto replacement = uu::Socket::BindLoopback(0, nullptr);
    REQUIRE(replacement.has_value());
    replacement->SetLinkModel(reorder);
    REQUIRE(replacement->Send(receiver->Port(), MakeFrame(1, uu::Direction::UPLINK, 0x52), nullptr));
    REQUIRE(replacement->FlushPending(nullptr));
    REQUIRE(receiver->Receive(received, 100, nullptr));
    CHECK(received.payload == std::vector<uint8_t>({0x52}));
}
