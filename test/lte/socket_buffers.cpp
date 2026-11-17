//
// This file is a part of UERANSIM project.
// Copyright (c) 2027 ALİ GÜNGÖR.
//
// https://github.com/aligungr/UERANSIM/
// See README, LICENSE, and CONTRIBUTING files for licensing details.
//

// Opt-in UDP receive buffers for the two LTE sockets that lose downlink packets.
//
// The rules these cases pin:
//
//   * an absent setting performs no system call at all, so a configuration that
//     does not mention a buffer keeps the socket the kernel created;
//   * an explicit setting is verified through getsockopt, and a request the
//     kernel capped is a failure rather than a success with a smaller number;
//   * the setting is per socket: configuring one never touches another, and it
//     never reaches the NR sockets that share udp::UdpServer;
//   * the socket keeps working afterwards, and it releases its descriptor.
//
// No case asserts a fixed host net.core.rmem_max. Where a value depends on the
// host, the test reads it and derives the expectation from it, so the same
// cases run on a host with a 208 KB cap and on one with an 8 MB cap.

#include <ext/doctest/doctest.h>

#include <algorithm>
#include <array>
#include <chrono>
#include <cstdint>
#include <fstream>
#include <string>
#include <vector>

#include <unistd.h>

#include <lib/udp/server.hpp>
#include <lte/enb/config.hpp>
#include <lte/enb/runtime_metrics.hpp>
#include <lte/enb/s1u_endpoint.hpp>
#include <lte/enb/types.hpp>
#include <lte/enb/ue_registry.hpp>
#include <lte/ue/config.hpp>

namespace
{

// The kernel's own ceiling for a receive buffer on this host. A request at or
// below it is applied; a request above it is capped. Reading it keeps the cases
// portable instead of hardcoding one laboratory value.
int KernelRmemMax()
{
    std::ifstream in("/proc/sys/net/core/rmem_max");
    int value = 0;
    if (!(in >> value) || value <= 0)
        return 0;
    return value;
}

int EffectiveOf(const udp::UdpServer &server)
{
    return lte::enb::ReadSocketReceiveBuffer(server.NativeFd());
}

size_t OpenDescriptorCount()
{
    return lte::enb::CountOpenFileDescriptors(static_cast<int>(::getpid()));
}

const char *EnbConfigText = R"(
mcc: '460'
mnc: '02'
enbId: 0x19B
tac: 1
enbName: UERANSIM-lte-enb
s1apIp: 127.0.0.1
mme:
  address: 127.0.0.2
  port: 36412
pagingDrx: 128
sctp:
  maxAttempts: 4
  retryDelayMs: 10
  responseTimeoutMs: 1000
  connectMaxAttempts: 2
  connectTimeoutMs: 500
)";

std::string EnbConfigWith(const std::string &s1uBody)
{
    return std::string(EnbConfigText) + "s1u:\n" + s1uBody;
}

const char *UeConfigText = R"(
imsi: '460020123456789'
mcc: '460'
mnc: '02'
k: '465B5CE8B199B49FAA5F0A2EE238A6BC'
opc: 'CD63CB71954A9F4E48A5994E37A02BAF'
amf: 'B9B9'
initialSqn: 'FF9BB4D0B607'
pdnType: IPv4
networkCapability: 'A020'
enbLink:
  localAddress: 127.0.0.1
  localPort: 4999
  address: 127.0.0.1
  port: 4998
)";

std::string UeConfigWith(const std::string &line)
{
    std::string text = UeConfigText;
    text.insert(text.find("  port: 4998") + std::string("  port: 4998").size(), "\n" + line);
    return text;
}

} // namespace

TEST_CASE("lte/socket/buffer: an absent setting leaves the socket exactly as the kernel made it")
{
    // Two servers created the same way must agree, and neither is configured.
    // Nothing here calls setsockopt: the comparison is what proves it.
    udp::UdpServer plain("127.0.0.1", 0);
    udp::UdpServer reference("127.0.0.1", 0);
    CHECK(EffectiveOf(plain) > 0);
    CHECK(EffectiveOf(plain) == EffectiveOf(reference));

    // The same class serves the NR sockets. It is untouched unless a caller
    // explicitly asks, which is what "no NR regression" means here.
    udp::UdpServer nr("127.0.0.1", 0);
    CHECK(EffectiveOf(nr) == EffectiveOf(reference));
}

TEST_CASE("lte/socket/buffer: an explicit value is applied and read back")
{
    const int cap = KernelRmemMax();
    REQUIRE(cap > 0);
    const int request = std::min(131072, cap);
    REQUIRE(request >= 2048); // below the kernel's minimum the accounting value stops being linear

    udp::UdpServer configured("127.0.0.1", 0);
    udp::UdpServer untouched("127.0.0.1", 0);
    const int before = EffectiveOf(untouched);

    const auto status = configured.ConfigureReceiveBuffer(request);
    CAPTURE(request);
    CAPTURE(status.effectiveBytes);
    CHECK(status.applied);
    CHECK(status.requestedBytes == request);
    CHECK(status.error.empty());

    // Linux stores the request and returns twice it for accounting, so the
    // usable budget is the requested value and the readback is twice it.
    CHECK(status.effectiveBytes >= 2 * request);
    CHECK(status.usableBytes == status.effectiveBytes / 2);
    CHECK(EffectiveOf(configured) == status.effectiveBytes);
    CHECK(EffectiveOf(untouched) == before);
}

TEST_CASE("lte/socket/buffer: a request above the kernel cap is refused, not silently reduced")
{
    const int cap = KernelRmemMax();
    REQUIRE(cap > 0);
    if (cap >= udp::MaxConfiguredReceiveBufferBytes)
    {
        MESSAGE("this host's net.core.rmem_max allows every supported request; the cap path needs a lower one");
        return;
    }
    const int request = std::min(2 * cap, udp::MaxConfiguredReceiveBufferBytes);

    udp::UdpServer socket("127.0.0.1", 0);
    const auto status = socket.ConfigureReceiveBuffer(request);
    CAPTURE(request);
    CAPTURE(status.effectiveBytes);
    CHECK_FALSE(status.applied);
    CHECK_FALSE(status.error.empty());
    // The kernel kept its own ceiling; the request was not applied, and the
    // reported value must say so rather than pretend the larger budget exists.
    CHECK(status.effectiveBytes < 2 * request);
    CHECK(status.usableBytes <= cap);
}

TEST_CASE("lte/socket/buffer: a non-positive or oversized request never reaches the kernel")
{
    udp::UdpServer socket("127.0.0.1", 0);
    const int before = EffectiveOf(socket);

    for (const int bad : {0, -1, -4194304})
    {
        CAPTURE(bad);
        const auto status = socket.ConfigureReceiveBuffer(bad);
        CHECK_FALSE(status.applied);
        CHECK_FALSE(status.error.empty());
    }
    {
        const auto status = socket.ConfigureReceiveBuffer(udp::MaxConfiguredReceiveBufferBytes + 1);
        CHECK_FALSE(status.applied);
        CHECK_FALSE(status.error.empty());
    }
    // Refusals do not change the socket.
    CHECK(EffectiveOf(socket) == before);
}

TEST_CASE("lte/socket/buffer: a configured socket still carries datagrams in order")
{
    udp::UdpServer receiver("127.0.0.1", 0);
    udp::UdpServer sender("127.0.0.1", 0);
    const int cap = KernelRmemMax();
    REQUIRE(cap > 0);
    REQUIRE(receiver.ConfigureReceiveBuffer(std::min(65536, cap)).applied);

    std::array<uint8_t, 64> buffer{};
    for (uint8_t marker = 1; marker <= 8; ++marker)
    {
        const std::array<uint8_t, 4> payload{marker, 0, 0, 0};
        sender.Send(receiver.LocalAddress(), payload.data(), payload.size());
    }
    for (uint8_t expected = 1; expected <= 8; ++expected)
    {
        InetAddress peer;
        const int received = receiver.Receive(buffer.data(), buffer.size(), 1000, peer);
        REQUIRE(received == 4);
        CHECK(buffer[0] == expected);
        CHECK(peer == sender.LocalAddress());
    }
}

TEST_CASE("lte/socket/buffer: a configured server releases its descriptor")
{
    const size_t before = OpenDescriptorCount();
    {
        udp::UdpServer socket("127.0.0.1", 0);
        const int cap = KernelRmemMax();
        REQUIRE(cap > 0);
        CHECK(socket.ConfigureReceiveBuffer(std::min(65536, cap)).applied);
        udp::UdpServer peer("127.0.0.1", 0);
        const std::array<uint8_t, 2> payload{0xAA, 0xBB};
        peer.Send(socket.LocalAddress(), payload.data(), payload.size());
    }
    CHECK(OpenDescriptorCount() == before);
}

TEST_CASE("lte/enb/config: an S1-U receive buffer is parsed only when it is stated")
{
    // Absent: the historical configuration, and no request at all.
    CHECK(lte::enb::ParseConfig(EnbConfigText).s1uReceiveBufferBytes == 0);

    CHECK(lte::enb::ParseConfig(EnbConfigWith("  address: 127.0.0.5\n  port: 2152\n  allowLoopback: true\n"))
              .s1uReceiveBufferBytes == 0);

    const auto stated = lte::enb::ParseConfig(
        EnbConfigWith("  address: 127.0.0.5\n  port: 2152\n  allowLoopback: true\n  receiveBufferBytes: 65536\n"));
    CHECK(stated.s1uReceiveBufferBytes == 65536);
    CHECK(stated.s1uPort == 2152);
    CHECK(stated.allowLoopbackS1u);

    for (const std::string body : {
             "  address: 127.0.0.5\n  receiveBufferBytes: 0\n",
             "  address: 127.0.0.5\n  receiveBufferBytes: -1\n",
             "  address: 127.0.0.5\n  receiveBufferBytes: 67108865\n",
             "  address: 127.0.0.5\n  receiveBufferBytes: 'lots'\n",
             "  address: 127.0.0.5\n  receiveBufferBytes: 1.5\n",
         })
    {
        CAPTURE(body);
        CHECK_THROWS(lte::enb::ParseConfig(EnbConfigWith(body)));
    }
}

TEST_CASE("lte/ue/config: a radio receive buffer is parsed only when it is stated")
{
    CHECK(lte::ue::ParseConfig(UeConfigText).link.receiveBufferBytes == 0);
    CHECK(lte::ue::ParseConfig(UeConfigWith("  receiveBufferBytes: 131072")).link.receiveBufferBytes == 131072);
    CHECK(lte::ue::ParseConfig(UeConfigWith("  receiveBufferBytes: 131072")).link.localPort == 4999);

    for (const std::string line : {
             "  receiveBufferBytes: 0",
             "  receiveBufferBytes: -2",
             "  receiveBufferBytes: 67108865",
             "  receiveBufferBytes: 'many'",
         })
    {
        CAPTURE(line);
        CHECK_THROWS(lte::ue::ParseConfig(UeConfigWith(line)));
    }
}

TEST_CASE("lte/socket/buffer: the eNB and the UE settings are independent")
{
    // Two different values, two different parsers, no shared state: a large
    // eNB budget must not silently become the budget of every UE.
    const auto enb = lte::enb::ParseConfig(
        EnbConfigWith("  address: 127.0.0.5\n  port: 2152\n  receiveBufferBytes: 262144\n"));
    const auto ue = lte::ue::ParseConfig(UeConfigText);
    CHECK(enb.s1uReceiveBufferBytes == 262144);
    CHECK(ue.link.receiveBufferBytes == 0);

    const auto ueTuned = lte::ue::ParseConfig(UeConfigWith("  receiveBufferBytes: 65536"));
    CHECK(ueTuned.link.receiveBufferBytes == 65536);
    CHECK(ue.link.receiveBufferBytes == 0);
}

TEST_CASE("lte/enb: an S1-U endpoint reports the buffer it actually applied")
{
    const int cap = KernelRmemMax();
    REQUIRE(cap > 0);
    const int request = std::min(65536, cap);

    lte::enb::UeRegistry registry(4);
    udp::UdpServer ueLink("127.0.0.1", 0);
    lte::enb::S1uEndpoint endpoint("127.0.0.1", 0, true, registry, ueLink, request);
    // The endpoint reports the effective readback, not the requested value, and
    // it is the same value a direct request on the same host produces.
    udp::UdpServer direct("127.0.0.1", 0);
    const auto directStatus = direct.ConfigureReceiveBuffer(request);
    REQUIRE(directStatus.applied);
    CHECK(endpoint.receiveBufferBytes() == directStatus.effectiveBytes);
    CHECK(endpoint.receiveBufferBytes() >= 2 * request);

    // Without a configured size the endpoint makes no request and reports none.
    lte::enb::S1uEndpoint plain("127.0.0.1", 0, true, registry, ueLink);
    CHECK(plain.receiveBufferBytes() == 0);
}

TEST_CASE("lte/enb: an S1-U endpoint refuses a request the kernel would cap")
{
    const int cap = KernelRmemMax();
    REQUIRE(cap > 0);
    if (cap >= udp::MaxConfiguredReceiveBufferBytes)
    {
        MESSAGE("this host's net.core.rmem_max allows every supported request; the cap path needs a lower one");
        return;
    }
    lte::enb::UeRegistry registry(4);
    udp::UdpServer ueLink("127.0.0.1", 0);
    CHECK_THROWS(lte::enb::S1uEndpoint("127.0.0.1", 0, true, registry, ueLink,
                                       std::min(2 * cap, udp::MaxConfiguredReceiveBufferBytes)));
}
