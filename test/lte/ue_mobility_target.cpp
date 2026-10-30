//
// This file is a part of UERANSIM project.
// Copyright (c) 2027 ALİ GÜNGÖR.
//
// https://github.com/aligungr/UERANSIM/
// See README, LICENSE, and CONTRIBUTING files for licensing details.
//

// Integration of the production UE sender with the production target eNB
// receiver.
//
// Every other test in this area proves one half of the reselection contract:
// test/lte/ue_mobility_context.cpp drives the real lte::ue::Run() sender against
// a scripted radio endpoint, and test/lte/mobility_target.cpp drives a real
// EnbMultiplexer against frames a test assembled by hand. Neither of them shows
// that the message the running UE leaves on the wire is the message the real
// target eNB accepts. This file closes that gap: the UE runs its real Run()
// path, the reselected cell is a real EnbMultiplexer bound to its own
// simulated-radio endpoint, and the network that answers it is authored here
// out of the public S1AP and NAS codecs.
//
// The serving cell is a minimal fake MME performing a real EPS AKA exchange
// over the 3GPP TS 35.208 test subscriber already present in test/lte/ue.cpp.
// The same security context that protected the Attach then answers the Tracking
// Area Update at the target, so the whole protected-NAS round trip is genuine
// and no HSS, EPC daemon or subscriber is involved.
//
// The UE asks for control-plane-only mode: the single requested route carries
// host bits, so the kernel rejects it and no TUN is created. That keeps the test
// deterministic and non-root, and it is also why the bearer transport
// confirmations of the target eNB cannot be exercised through the real UE here:
// they need the local user plane. Those legs are covered at the target in
// test/lte/mobility_target.cpp and are reported as TUN-gated rather than
// simulated.
//
// The third case in this file closes that gap for real. It runs the same
// production UE and the same production target eNB, but it asks for an actual
// kernel TUN device and moves real IPv4 datagrams through it in both
// directions, so the transport confirmations of the target are produced by the
// running UE rather than asserted at the target in isolation. It needs root, a
// usable /dev/net/tun and a private network namespace, so it is decorated with
// doctest::skip() and is only forced to run by the privileged CI job. See the
// case itself for the exact contract it verifies.

#include <ext/doctest/doctest.h>

#include "log_capture.hpp"

#include <lib/udp/server.hpp>

#include <lte/enb/codec.hpp>
#include <lte/enb/config.hpp>
#include <lte/enb/gtpu.hpp>
#include <lte/enb/multiplexer.hpp>
#include <lte/enb/ue_registry.hpp>
#include <lte/enb/user_plane.hpp>
#include <lte/ip_packet.hpp>
#include <lte/ue/app.hpp>
#include <lte/ue/config.hpp>
#include <lte/ue/nas.hpp>
#include <lte/ue/radio_link.hpp>
#include <lte/ue/security.hpp>

#include <algorithm>
#include <array>
#include <atomic>
#include <cerrno>
#include <chrono>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <fstream>
#include <memory>
#include <optional>
#include <set>
#include <sstream>
#include <stdexcept>
#include <string>
#include <thread>
#include <utility>
#include <vector>

#include <arpa/inet.h>
#include <dirent.h>
#include <ifaddrs.h>
#include <net/if.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <unistd.h>

namespace
{

using namespace lte::enb;
using namespace lte::ue;
namespace link = lte::ue::link;
using Clock = std::chrono::steady_clock;

// ---------------------------------------------------------------------------
// Configuration
// ---------------------------------------------------------------------------

// The 3GPP TS 35.208 test subscriber, identical to test/lte/ue.cpp. It is
// fixture data only; no subscription is created and no HSS is consulted.
//
// The serving cell is at sourcePort inside tracking area 460/02/1. The
// reselected cell is the real target eNB on its own radio endpoint in tracking
// area 460/02/2, so leaving the registered tracking area list is what forces
// the reselection to open a new S1 connection there.
// The children of the `tun:` mapping are supplied by the caller, so one case
// can ask for the control-plane-only route that keeps the ordinary suite
// non-root while the privileged case demands a real kernel TUN device.
const char *const kControlPlaneOnlyTun = "  required: false\n  routes: ['192.168.5.7/24']";

const char *const kPrivilegedTun =
    "  required: true\n"
    "  namePrefix: \"u13ad\"\n"
    "  mtu: 1400\n"
    "  routes:\n"
    "    - \"198.18.0.2/32\"";

std::string UeYaml(uint16_t uePort, uint16_t sourcePort, uint16_t targetPort, int procedureTimeoutMs, int maxRetries,
                   const std::string &tunBlock = kControlPlaneOnlyTun)
{
    std::ostringstream out;
    out << R"(imsi: '460020123456789'
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
  localPort: )"
       << uePort << R"(
  address: 127.0.0.1
  port: )"
       << sourcePort << R"(
  tac: 1
  targetCell:
    mcc: '460'
    mnc: '02'
    tac: 2
    address: 127.0.0.1
    port: )"
       << targetPort << R"(
  timeoutMs: 10000
tun:
)"
       << tunBlock << R"(
lifecycle:
  scenario: idle-reselection
  triggerAfterMs: 1000
  procedureTimeoutMs: )"
       << procedureTimeoutMs << R"(
  maxRetries: )"
       << maxRetries << R"(
  pagingWaitMs: 30000
  recoveryDelayMs: 0
  recoveryRetryMs: 5000
  recoveryMaxAttempts: 0
)";
    return out.str();
}

// The S-TMSI of the GUTI the Attach Accept below assigns.
constexpr uint8_t kMmeCode = 1;
constexpr uint32_t kMTmsi = 0xC000018Eu;
constexpr uint8_t kDefaultEbi = 5;

// The S-TMSI value the target eNB has to put in the Initial UE Message: the
// two preamble bits and the MMEC of X.691 aligned PER, then the M-TMSI.
const std::vector<uint8_t> kExpectedSTmsi{0x00, 0x40, 0xC0, 0x00, 0x01, 0x8E};

// ---------------------------------------------------------------------------
// S1AP capture
// ---------------------------------------------------------------------------

struct CapturedS1ap
{
    uint16_t stream{};
    std::vector<uint8_t> pdu;
};

// The stand-in MME association. The real multiplexer writes every S1AP PDU it
// produces through this interface, so what lands here is what a real MME would
// receive.
class CaptureSender final : public IS1apSender
{
  public:
    void sendS1ap(uint16_t stream, const std::vector<uint8_t> &pdu) override
    {
        sent.push_back(CapturedS1ap{stream, pdu});
    }

    [[nodiscard]] size_t count(uint8_t procedureCode) const
    {
        size_t total = 0;
        for (const auto &item : sent)
        {
            const auto pdu = s1ap::ProbeS1apPdu(item.pdu.data(), item.pdu.size());
            if (pdu.kind == s1ap::S1apPdu::Kind::INITIATING && pdu.procedureCode == procedureCode)
                ++total;
        }
        return total;
    }

    // The first initiating message of a procedure code, or an empty vector when
    // the network never sent one. Returned rather than thrown so a test can
    // assert on the absence without a doctest macro firing inside the harness.
    [[nodiscard]] std::vector<uint8_t> first(uint8_t procedureCode) const
    {
        for (const auto &item : sent)
        {
            const auto pdu = s1ap::ProbeS1apPdu(item.pdu.data(), item.pdu.size());
            if (pdu.kind == s1ap::S1apPdu::Kind::INITIATING && pdu.procedureCode == procedureCode)
                return item.pdu;
        }
        return {};
    }

    std::vector<CapturedS1ap> sent;
};

// The target eNB the UE reselects into. It gets its own identifier, its own
// simulated-radio endpoint and its own S1-U endpoint, and it is never prepared
// by hand: nothing about the UE's session exists in its registry until the UE's
// own mobility uplink arrives.
EnbConfig TestEnbConfig(uint32_t enbId, const std::string &s1uAddress, uint16_t tac)
{
    EnbConfig config{};
    config.plmn = {"460", "02"};
    config.enbId = enbId;
    config.tac = tac;
    config.localAddress = "127.0.0.1";
    config.mmeAddress = "127.0.0.2";
    config.mmePort = 36412;
    config.ueLinkAddress = "127.0.0.1";
    config.ueLinkPort = 0;
    config.s1uAddress = s1uAddress;
    config.s1uPort = 0;
    config.allowLoopbackS1u = true;
    config.maxUes = 8;
    return config;
}

bool Contains(const std::vector<uint8_t> &haystack, const std::vector<uint8_t> &needle)
{
    return std::search(haystack.begin(), haystack.end(), needle.begin(), needle.end()) != haystack.end();
}

bool Contains(const std::string &haystack, const std::string &needle)
{
    return haystack.find(needle) != std::string::npos;
}

// A network-authored E-RAB item for an Initial Context Setup Request or an
// E-RAB Setup Request.
s1ap::ErabToBeSetupItem Erab(uint8_t ebi, uint8_t qci, uint32_t sgwTeid)
{
    s1ap::ErabToBeSetupItem item{};
    item.erabId = ebi;
    item.qci = qci;
    item.transportLayerAddress = {127, 0, 0, 2};
    item.gtpTeid = TeidToBytes(sgwTeid);
    return item;
}

s1ap::ErabToBeSetupItem ErabWithNas(uint8_t ebi, uint8_t qci, uint32_t sgwTeid)
{
    auto item = Erab(ebi, qci, sgwTeid);
    item.nasPduPresent = true;
    item.nasPdu = {0x2E, 0x01};
    return item;
}

// ---------------------------------------------------------------------------
// Kernel networking observation for the privileged case
// ---------------------------------------------------------------------------

// The privileged case moves real IPv4 traffic through a real kernel TUN, so it
// has to be able to see what the kernel did: which interface the production UE
// allocated, what address and MTU it was given, and which route points at it.
// Everything here is read-only observation of the running kernel; the only
// command ever executed is the one the sweep guard uses to undo a leftover
// interface from a run that died before the production UE could release it.

const char *const kTunPrefix = "u13ad";
const char *const kTunRoute = "198.18.0.2/32";

// The PDN address the Attach Accept assigns and the peer the UE's explicit
// route names. The peer is not a local address: it is reached only through the
// TUN, which is what makes the routing leg of the scenario real.
constexpr std::array<uint8_t, 4> kPdnIpv4{10, 0, 0, 1};
constexpr std::array<uint8_t, 4> kPeerIpv4{198, 18, 0, 2};
constexpr uint16_t kApplicationPort = 47349;
constexpr uint16_t kPeerPort = 47350;
constexpr int kTunMtu = 1400;

// /proc/net/route prints each IPv4 field as %08X of the little-endian memory
// word, so 198.18.0.2 appears as 020012C6.
std::string RouteHex(const std::array<uint8_t, 4> &address)
{
    char text[9];
    std::snprintf(text, sizeof(text), "%02X%02X%02X%02X", address[3], address[2], address[1], address[0]);
    return text;
}

std::vector<std::string> ListInterfaces(const std::string &prefix)
{
    std::vector<std::string> names;
    struct if_nameindex *list = if_nameindex();
    if (list == nullptr)
        return names;
    for (struct if_nameindex *item = list; item->if_name != nullptr; ++item)
    {
        const std::string name = item->if_name;
        if (prefix.empty() || name.rfind(prefix, 0) == 0)
            names.push_back(name);
    }
    if_freenameindex(list);
    return names;
}

bool InterfaceExists(const std::string &name)
{
    if (name.empty())
        return false;
    const auto names = ListInterfaces("");
    return std::find(names.begin(), names.end(), name) != names.end();
}

struct InterfaceAddress
{
    std::array<uint8_t, 4> address{};
    int prefixLength{};
};

std::optional<InterfaceAddress> InterfaceIpv4(const std::string &name)
{
    struct ifaddrs *list = nullptr;
    if (getifaddrs(&list) != 0)
        return std::nullopt;
    std::optional<InterfaceAddress> found;
    for (struct ifaddrs *item = list; item != nullptr; item = item->ifa_next)
    {
        if (item->ifa_addr == nullptr || item->ifa_addr->sa_family != AF_INET || item->ifa_name == nullptr)
            continue;
        if (name != item->ifa_name)
            continue;
        InterfaceAddress out;
        const auto *sin = reinterpret_cast<const sockaddr_in *>(item->ifa_addr);
        const uint32_t raw = ntohl(sin->sin_addr.s_addr);
        out.address = {static_cast<uint8_t>(raw >> 24U), static_cast<uint8_t>(raw >> 16U),
                       static_cast<uint8_t>(raw >> 8U), static_cast<uint8_t>(raw)};
        if (item->ifa_netmask != nullptr && item->ifa_netmask->sa_family == AF_INET)
        {
            const auto *mask = reinterpret_cast<const sockaddr_in *>(item->ifa_netmask);
            uint32_t bits = ntohl(mask->sin_addr.s_addr);
            int count = 0;
            while (bits != 0)
            {
                count += static_cast<int>(bits & 1U);
                bits >>= 1U;
            }
            out.prefixLength = count;
        }
        found = out;
    }
    freeifaddrs(list);
    return found;
}

std::optional<int> InterfaceMtu(const std::string &name)
{
    if (name.empty() || name.size() >= IFNAMSIZ)
        return std::nullopt;
    ifreq ifr{};
    std::memcpy(ifr.ifr_name, name.c_str(), name.size());
    const int fd = socket(AF_INET, SOCK_DGRAM, 0);
    if (fd < 0)
        return std::nullopt;
    const int ok = ioctl(fd, SIOCGIFMTU, &ifr);
    close(fd);
    if (ok < 0)
        return std::nullopt;
    return ifr.ifr_mtu;
}

bool RouteExists(const std::array<uint8_t, 4> &destination, const std::string &interfaceName)
{
    std::ifstream input("/proc/net/route");
    if (!input)
        return false;
    std::string line;
    std::getline(input, line); // column header
    const std::string wanted = RouteHex(destination);
    while (std::getline(input, line))
    {
        std::istringstream fields(line);
        std::string iface, dest, gateway, flags, refCnt, use, metric, mask;
        if (!(fields >> iface >> dest >> gateway >> flags >> refCnt >> use >> metric >> mask))
            continue;
        if (!interfaceName.empty() && iface != interfaceName)
            continue;
        if (dest == wanted)
            return true;
    }
    return false;
}

std::vector<std::string> DefaultRouteLines()
{
    std::vector<std::string> lines;
    std::ifstream input("/proc/net/route");
    std::string line;
    std::getline(input, line);
    while (std::getline(input, line))
    {
        std::istringstream fields(line);
        std::string iface, dest;
        if (!(fields >> iface >> dest))
            continue;
        if (dest == "00000000")
            lines.push_back(line);
    }
    return lines;
}

// The network namespace directory is whatever the host exposes; a run that
// created none must leave it exactly as it found it.
std::vector<std::string> ListNetworkNamespaces()
{
    std::vector<std::string> names;
    DIR *directory = opendir("/var/run/netns");
    if (directory == nullptr)
        return names;
    while (const dirent *entry = readdir(directory))
    {
        const std::string name = entry->d_name;
        if (name != "." && name != "..")
            names.push_back(name);
    }
    closedir(directory);
    std::sort(names.begin(), names.end());
    return names;
}

uint16_t OnesComplementSum(const uint8_t *data, size_t size)
{
    uint32_t sum = 0;
    for (size_t i = 0; i + 1 < size; i += 2)
        sum += (static_cast<uint32_t>(data[i]) << 8U) | data[i + 1];
    if (size % 2 != 0)
        sum += static_cast<uint32_t>(data[size - 1]) << 8U;
    while ((sum >> 16U) != 0)
        sum = (sum & 0xFFFFU) + (sum >> 16U);
    return static_cast<uint16_t>(sum);
}

// A complete IPv4/UDP datagram with both checksums filled in. The kernel
// validates both on the way into a TUN, so a packet without them is dropped
// silently and could never reach the application socket it is addressed to.
std::vector<uint8_t> BuildUdpIpv4(const std::array<uint8_t, 4> &source, const std::array<uint8_t, 4> &destination,
                                  uint16_t sourcePort, uint16_t destinationPort, const std::vector<uint8_t> &payload)
{
    const size_t udpLength = 8 + payload.size();
    const size_t totalLength = 20 + udpLength;
    std::vector<uint8_t> packet(totalLength, 0);
    packet[0] = 0x45;
    packet[2] = static_cast<uint8_t>(totalLength >> 8U);
    packet[3] = static_cast<uint8_t>(totalLength);
    packet[6] = 0x40; // do not fragment, fragment offset zero
    packet[8] = 64;
    packet[9] = 17;
    std::copy(source.begin(), source.end(), packet.begin() + 12);
    std::copy(destination.begin(), destination.end(), packet.begin() + 16);
    const uint16_t ipSum = static_cast<uint16_t>(~OnesComplementSum(packet.data(), 20));
    packet[10] = static_cast<uint8_t>(ipSum >> 8U);
    packet[11] = static_cast<uint8_t>(ipSum);

    packet[20] = static_cast<uint8_t>(sourcePort >> 8U);
    packet[21] = static_cast<uint8_t>(sourcePort);
    packet[22] = static_cast<uint8_t>(destinationPort >> 8U);
    packet[23] = static_cast<uint8_t>(destinationPort);
    packet[24] = static_cast<uint8_t>(udpLength >> 8U);
    packet[25] = static_cast<uint8_t>(udpLength);
    std::copy(payload.begin(), payload.end(), packet.begin() + 28);

    // The UDP checksum covers the IPv4 pseudo-header as well as the datagram.
    std::vector<uint8_t> pseudo;
    pseudo.insert(pseudo.end(), source.begin(), source.end());
    pseudo.insert(pseudo.end(), destination.begin(), destination.end());
    pseudo.push_back(0);
    pseudo.push_back(17);
    pseudo.push_back(static_cast<uint8_t>(udpLength >> 8U));
    pseudo.push_back(static_cast<uint8_t>(udpLength));
    pseudo.insert(pseudo.end(), packet.begin() + 20, packet.end());
    uint16_t udpSum = static_cast<uint16_t>(~OnesComplementSum(pseudo.data(), pseudo.size()));
    if (udpSum == 0)
        udpSum = 0xFFFF;
    packet[26] = static_cast<uint8_t>(udpSum >> 8U);
    packet[27] = static_cast<uint8_t>(udpSum);
    return packet;
}

// Only the interface names the privileged case is allowed to remove ever reach
// the shell, and only through this guard.
bool IsSweepableInterface(const std::string &name)
{
    if (name.rfind(kTunPrefix, 0) != 0 || name.size() <= std::strlen(kTunPrefix))
        return false;
    for (size_t i = std::strlen(kTunPrefix); i < name.size(); ++i)
        if (name[i] < '0' || name[i] > '9')
            return false;
    return true;
}

// Undoes a TUN interface or route left behind by a run that aborted before the
// production UE could release it, so a failed assertion never leaves the host
// networking modified. A clean run removes nothing and records nothing.
// A sweep command is best effort: a non-zero status simply means the resource
// was already gone, and it must never become the run's verdict.
void SweepCommand(const std::string &command)
{
    if (std::system(command.c_str()) != 0)
        return;
}

class TunSweepGuard
{
  public:
    TunSweepGuard() = default;
    TunSweepGuard(const TunSweepGuard &) = delete;
    TunSweepGuard &operator=(const TunSweepGuard &) = delete;

    ~TunSweepGuard()
    {
        for (const auto &name : ListInterfaces(kTunPrefix))
        {
            if (!IsSweepableInterface(name))
                continue;
            swept.push_back(name);
            SweepCommand("ip link del dev " + name + " >/dev/null 2>&1");
        }
        if (RouteExists(kPeerIpv4, std::string{}))
        {
            swept.push_back(kTunRoute);
            SweepCommand(std::string("ip route del ") + kTunRoute + " >/dev/null 2>&1");
        }
    }

    std::vector<std::string> swept;
};

// Decodes one captured radio frame without letting a malformed one escape as an
// exception into the harness.
std::optional<link::Message> DecodeRadio(const std::vector<uint8_t> &frame)
{
    try
    {
        return link::Decode(frame.data(), frame.size());
    }
    catch (const std::exception &)
    {
        return std::nullopt;
    }
}

// ---------------------------------------------------------------------------
// The laboratory: a real UE, a fake serving MME and a real target eNB
// ---------------------------------------------------------------------------

// Everything the scripted serving cell and the scripted target MME do runs on
// the test thread, so the NAS security context is single-threaded and needs no
// synchronisation. Only lte::ue::Run() runs elsewhere.
//
// The harness deliberately never fires a doctest assertion of its own: the
// running UE logs through std::cout, which LogCapture owns until finish(), and
// an assertion reported into a captured stream is invisible. Every observation
// is instead recorded and asserted after the capture has been released.
// The ordinary cases drive the target's simulated-radio endpoint directly. The
// privileged case relays that endpoint through a capturing one of its own, so
// the exact frames the production UE writes become observable: every datagram
// is forwarded verbatim in both directions and nothing is synthesised.
struct LabOptions
{
    int procedureTimeoutMs{30000};
    int maxRetries{2};
    std::string tunBlock{kControlPlaneOnlyTun};
    bool radioTap{false};
};

class Lab
{
  public:
    Lab(uint16_t uePort, uint16_t sourcePort, const LabOptions &options)
        : m_capture(std::make_unique<lte::test::LogCapture>()), m_source("127.0.0.1", sourcePort)
    {
        m_target = std::make_unique<EnbMultiplexer>(TestEnbConfig(0x2C1, "127.0.0.3", 2), m_targetWire);
        m_targetRadio = m_target->ueLinkAddress();
        uint16_t targetRadioPort = m_targetRadio.getPort();
        if (options.radioTap)
        {
            m_tap.emplace("127.0.0.1", 0);
            targetRadioPort = m_tap->LocalAddress().getPort();
        }
        m_config = lte::ue::ParseConfig(UeYaml(uePort, sourcePort, targetRadioPort, options.procedureTimeoutMs,
                                               options.maxRetries, options.tunBlock));
    }

    // The entry point the ordinary cases have always used; their wiring is
    // untouched by the privileged one.
    Lab(uint16_t uePort, uint16_t sourcePort, int procedureTimeoutMs = 30000, int maxRetries = 2)
        : Lab(uePort, sourcePort, LabOptions{procedureTimeoutMs, maxRetries, kControlPlaneOnlyTun, false})
    {
    }

    void scriptDedicated(std::vector<uint8_t> activate) { m_activate = std::move(activate); }

    void startUe()
    {
        m_ue = std::thread([this] { m_exit = lte::ue::Run(m_config, m_shutdown); });
    }

    // Joins the UE, copies its log out and releases std::cout so every later
    // assertion is visible. Idempotent.
    void finish()
    {
        if (m_ue.joinable())
            m_ue.join();
        m_target->poll();
        if (m_capture)
        {
            log = m_capture->text();
            m_capture.reset();
        }
    }

    void shutdownUe()
    {
        m_shutdown = true;
        finish();
    }

    ~Lab()
    {
        m_shutdown = true;
        if (m_ue.joinable())
            m_ue.join();
        closeApplicationSocket();
    }

    // Drives both simulated endpoints until `done()` holds or the budget runs
    // out. Everything the scripted cells do happens here, on this thread.
    template <typename Done>
    bool drive(Done done, int timeoutMs)
    {
        const auto deadline = Clock::now() + std::chrono::milliseconds(timeoutMs);
        while (Clock::now() < deadline)
        {
            while (pumpSource())
            {
            }
            while (pumpTap())
            {
            }
            m_target->poll();
            pumpSgw();
            pumpApplication();
            if (done())
                return true;
            std::this_thread::sleep_for(std::chrono::milliseconds(2));
        }
        return done();
    }

    bool driveUntilSourceAttachComplete(int timeoutMs = 8000)
    {
        return drive([this] { return m_attachComplete; }, timeoutMs);
    }

    bool driveUntilDedicatedConfirmed(const std::vector<uint8_t> &ebis, int timeoutMs = 8000)
    {
        return drive(
            [&] {
                for (const uint8_t ebi : ebis)
                    if (m_activated.count(ebi) == 0)
                        return false;
                return true;
            },
            timeoutMs);
    }

    bool driveUntilIdleReleased(int timeoutMs = 8000)
    {
        return drive([this] { return m_idleReleased; }, timeoutMs);
    }

    bool driveUntilTargetInitialUeMessage(int timeoutMs = 12000)
    {
        return drive([this] { return m_targetWire.count(kInitialUeMessage) == 1; }, timeoutMs);
    }

    bool driveUntilTargetRejects(int timeoutMs = 8000)
    {
        return drive([this] { return m_target->recoveryCounters().staleMessagesRejected >= 1; }, timeoutMs);
    }

    bool driveUntilUplinkNasTransport(int timeoutMs = 8000)
    {
        return drive([this] { return m_targetWire.count(kUplinkNasTransport) >= 1; }, timeoutMs);
    }

    // The production UE has created its TUN and confirmed the default bearer
    // towards the serving cell. The interface exists by the time this frame
    // leaves the UE, so it is also the earliest point a real socket may be
    // bound to the assigned PDN address.
    bool driveUntilBearerReady(int timeoutMs = 8000)
    {
        return drive([this] { return m_readySeen; }, timeoutMs);
    }

    bool driveUntilHeldUplink(size_t count, int timeoutMs = 8000)
    {
        return drive([&] { return m_held.size() >= count; }, timeoutMs);
    }

    // Blocks on the UE's own log line while the UE is still running. Nothing on
    // the network side needs pumping at that point.
    bool waitForUeLine(const std::string &needle, int timeoutMs = 8000)
    {
        return m_capture && m_capture->waitFor(needle, timeoutMs);
    }

    // ---- privileged-case transport ----

    // While held, uplink radio frames the production UE writes are recorded and
    // queued instead of being handed to the target eNB. It is a delay on a real
    // radio link, not a substitution: the queued octets are the UE's own and
    // releaseHeld() forwards them unmodified. It is what lets a case observe
    // the target in the window between its restoration notifications and the
    // UE's confirmations of them.
    void holdUplink(bool hold) { m_holdUplink = hold; }

    // Releases the first `count` queued frames to the real target, the very
    // octets the production UE wrote. Releasing one at a time is what lets a
    // case see the target between the default bearer's confirmation and the
    // dedicated bearer's.
    void releaseHeld(size_t count)
    {
        if (!m_tap)
            return note("no target radio relay is configured");
        if (count > m_held.size())
            count = m_held.size();
        while (count-- > 0)
        {
            m_tap->Send(m_targetRadio, m_held.front().data(), m_held.front().size());
            m_held.erase(m_held.begin());
        }
    }

    void releaseHeld() { releaseHeld(m_held.size()); }

    // Delivers one radio frame to the real target through the same dispatcher
    // its own radio endpoint feeds. Only rejection probes are built this way: a
    // positive bearer transport confirmation must come from the running UE.
    void injectRadio(const InetAddress &peer, link::MessageType type, std::vector<uint8_t> payload)
    {
        const auto frame = link::Encode({type, m_config.ueId, std::move(payload)});
        m_target->handleRadioFrame(frame.data(), frame.size(), peer);
    }

    void injectRadio(link::MessageType type, std::vector<uint8_t> payload)
    {
        if (!m_tap)
            return note("no target radio relay is configured");
        injectRadio(m_tap->LocalAddress(), type, std::move(payload));
    }

    // The network-side teardown: a real UE Context Release Command on the live
    // target association. It drops the access transport and every local GTP-U
    // TEID of the UE while retaining the logical EPS bearer identities, which
    // is what an ECM-IDLE release is supposed to do.
    void deliverUeContextRelease(uint32_t mmeUeS1apId = 500)
    {
        const auto *entry = m_target->registry().find(m_config.ueId);
        if (entry == nullptr)
            return note("the target registry holds no entry for the UE");
        const auto pdu = s1ap::EncodeUeContextReleaseCommand(mmeUeS1apId, entry->enbUeS1apId, "radioNetwork", 20);
        m_target->handleS1ap(pdu.data(), pdu.size(), 1);
    }

    // The test application is a real kernel UDP socket bound to the PDN
    // address the network assigned: a datagram it sends is routed by the kernel
    // into the UE's TUN, and a datagram the UE writes into that TUN is routed
    // back to it. It cannot be bound before the TUN exists, because until then
    // the address is not local to this host.
    bool openApplicationSocket()
    {
        if (m_appFd >= 0)
            return true;
        m_appFd = socket(AF_INET, SOCK_DGRAM, 0);
        if (m_appFd < 0)
        {
            note("the test application could not create a UDP socket");
            return false;
        }
        sockaddr_in address{};
        address.sin_family = AF_INET;
        address.sin_port = htons(kApplicationPort);
        address.sin_addr.s_addr = htonl(0x0A000001u); // 10.0.0.1, the assigned PDN address
        if (bind(m_appFd, reinterpret_cast<const sockaddr *>(&address), sizeof(address)) != 0)
        {
            note("the test application could not bind the assigned PDN address");
            close(m_appFd);
            m_appFd = -1;
            return false;
        }
        return true;
    }

    void closeApplicationSocket()
    {
        if (m_appFd >= 0)
        {
            close(m_appFd);
            m_appFd = -1;
        }
    }

    bool sendApplicationDatagram(const std::vector<uint8_t> &payload)
    {
        if (m_appFd < 0)
            return false;
        sockaddr_in destination{};
        destination.sin_family = AF_INET;
        destination.sin_port = htons(kPeerPort);
        destination.sin_addr.s_addr = htonl(0xC6120002u); // 198.18.0.2, reachable only through the TUN
        const ssize_t sent = sendto(m_appFd, payload.data(), payload.size(), 0,
                                    reinterpret_cast<const sockaddr *>(&destination), sizeof(destination));
        return sent == static_cast<ssize_t>(payload.size());
    }

    // The test SGW endpoint. It binds exactly the address and port every E-RAB
    // item authored here names as its transport layer, so the target's S1-U
    // forwards uplink GTP-U to it and accepts downlink GTP-U from it.
    void enableTestSgw() { m_sgw.emplace("127.0.0.2", 2152); }

    void sendSgwDownlink(uint32_t teid, const std::vector<uint8_t> &ipPacket)
    {
        if (!m_sgw)
            return note("the test SGW endpoint was never enabled");
        const auto datagram = gtpu::EncodeTPdu(teid, ipPacket.data(), ipPacket.size());
        m_sgw->Send(m_target->s1uAddress(), datagram.data(), datagram.size());
    }

    [[nodiscard]] const std::vector<std::vector<uint8_t>> &radioUplink() const { return m_radioUplink; }
    [[nodiscard]] const std::vector<std::vector<uint8_t>> &heldUplink() const { return m_held; }
    [[nodiscard]] const std::vector<std::vector<uint8_t>> &sgwDatagrams() const { return m_sgwDatagrams; }
    [[nodiscard]] const std::vector<std::vector<uint8_t>> &applicationDatagrams() const { return m_appDatagrams; }
    [[nodiscard]] bool readySeen() const { return m_readySeen; }
    [[nodiscard]] uint8_t readyEbi() const { return m_readyEbi; }
    [[nodiscard]] std::array<uint8_t, 4> readyIpv4() const { return m_readyIpv4; }

    // A network-authored Initial Context Setup Request against the live target
    // registry entry the UE's own mobility uplink created.
    void deliverIcsr(const std::vector<s1ap::ErabToBeSetupItem> &erabs, uint32_t mmeUeS1apId = 500)
    {
        const auto *entry = m_target->registry().find(m_config.ueId);
        if (entry == nullptr)
            return note("the target registry holds no entry for the UE");
        s1ap::InitialContextSetupRequest request{};
        request.mmeUeS1apId = mmeUeS1apId;
        request.enbUeS1apId = entry->enbUeS1apId;
        request.ueAmbrUl = 1000;
        request.ueAmbrDl = 2000;
        request.erabs = erabs;
        const auto pdu = s1ap::EncodeInitialContextSetupRequest(request);
        m_target->handleS1ap(pdu.data(), pdu.size(), 1);
    }

    // A network-authored E-RAB Setup Request adding one dedicated bearer on top
    // of the default one the target already established.
    void deliverErabSetup(const s1ap::ErabToBeSetupItem &item, uint32_t mmeUeS1apId = 500)
    {
        const auto *entry = m_target->registry().find(m_config.ueId);
        if (entry == nullptr)
            return note("the target registry holds no entry for the UE");
        s1ap::ErabSetupRequest setup{};
        setup.mmeUeS1apId = mmeUeS1apId;
        setup.enbUeS1apId = entry->enbUeS1apId;
        setup.erabs = {item};
        const auto pdu = s1ap::EncodeErabSetupRequest(setup);
        m_target->handleS1ap(pdu.data(), pdu.size(), 1);
    }

    // A protected downlink NAS message from the same EPS peer that performed
    // the Attach, delivered through the real target eNB's Downlink NAS
    // Transport. The COUNT it uses is the one the UE is waiting for.
    void deliverProtectedDownlink(const std::vector<uint8_t> &plain, uint32_t mmeUeS1apId = 500)
    {
        const auto *entry = m_target->registry().find(m_config.ueId);
        if (entry == nullptr)
            return note("the target registry holds no entry for the UE");
        const auto pdu = s1ap::EncodeDownlinkNasTransport(mmeUeS1apId, entry->enbUeS1apId, ProtectDownlink(plain, /*newContext=*/false));
        m_target->handleS1ap(pdu.data(), pdu.size(), 1);
    }

    // Rebuilds the protected uplink the UE sends towards the target: the same
    // plain message, the same security context and the very next uplink NAS
    // COUNT. Matching against it is how the test reads the protected NAS back
    // out of an S1AP message that has no public decoder. It advances the
    // network's view of the uplink COUNT exactly as consuming the real message
    // would, because that uplink went to the target rather than to this cell.
    std::vector<uint8_t> expectedProtectedUplink(const std::vector<uint8_t> &plain)
    {
        auto predict = m_security;
        predict.ulNasCount = (m_security.ulNasCount + 1U) & 0xFFFFFFU;
        auto message = nas::Protect(predict, true, false, plain);
        m_security.ulNasCount = predict.ulNasCount;
        return message;
    }

    // The plain Tracking Area Update Request the production sender is expected
    // to protect: the same call the reselection branch of Run() makes, rebuilt
    // here from the bearer identities the network itself activated.
    std::vector<uint8_t> expectedTauRequest() const
    {
        std::vector<uint8_t> identities{kDefaultEbi};
        identities.insert(identities.end(), m_activate.begin(), m_activate.end());
        return nas::EncodeTauRequest(m_security.ksi, assignedGuti(), identities, false);
    }

    // The GUTI the Attach Accept assigned, in the eleven-octet form the UE
    // keeps and the Tracking Area Update Request is identified by.
    std::array<uint8_t, 11> assignedGuti() const
    {
        const auto plmn = s1ap::EncodePlmn(m_config.plmn);
        return {0xF6, plmn[0], plmn[1], plmn[2], 0x00, 0x01, kMmeCode, 0xC0, 0x00, 0x01, 0x8E};
    }

    [[nodiscard]] std::vector<uint8_t> tauAccept() const { return TauAccept(); }

    [[nodiscard]] const Config &config() const { return m_config; }
    [[nodiscard]] EnbMultiplexer &target() { return *m_target; }
    [[nodiscard]] CaptureSender &targetWire() { return m_targetWire; }
    [[nodiscard]] int exitCode() const { return m_exit; }
    [[nodiscard]] const std::vector<std::string> &problems() const { return m_problems; }
    // The UE log so far: live while the capture owns std::cout, copied after
    // finish() has released it.
    [[nodiscard]] std::string captureText() const { return m_capture ? m_capture->text() : log; }

    std::string log;

  private:
    static constexpr uint8_t kInitialUeMessage = 12;
    static constexpr uint8_t kUplinkNasTransport = 13;

    void note(const std::string &reason) { m_problems.push_back(reason); }

    // One datagram from the UE to the serving cell, or a quiet tick.
    bool pumpSource()
    {
        uint8_t buffer[link::MaxDataPduSize + link::HeaderSize];
        InetAddress peer;
        const int received = m_source.Receive(buffer, sizeof(buffer), 1, peer);
        if (received <= 0)
            return false;
        link::Message frame{};
        try
        {
            frame = link::Decode(buffer, static_cast<size_t>(received));
        }
        catch (const std::exception &e)
        {
            note(std::string("the serving cell received a malformed radio frame: ") + e.what());
            return true;
        }
        if (frame.ueId != m_config.ueId)
        {
            note("radio frame carried an unexpected UE identity");
            return true;
        }
        m_uePeer = peer;
        handleSource(frame);
        return true;
    }

    // One datagram at the target radio relay. Everything the UE writes is
    // recorded and forwarded verbatim to the real target eNB, and everything
    // the target produces is relayed back to the UE's own endpoint, so the UE
    // still sees its frames come from the cell it is attached to.
    bool pumpTap()
    {
        if (!m_tap)
            return false;
        uint8_t buffer[link::MaxDataPduSize + link::HeaderSize];
        InetAddress peer;
        const int received = m_tap->Receive(buffer, sizeof(buffer), 1, peer);
        if (received <= 0)
            return false;
        if (peer == m_targetRadio)
        {
            if (m_tapUeKnown)
                m_tap->Send(m_tapUePeer, buffer, static_cast<size_t>(received));
            return true;
        }
        if (!m_tapUeKnown)
        {
            m_tapUePeer = peer;
            m_tapUeKnown = true;
        }
        else if (!(peer == m_tapUePeer))
        {
            note("the target radio relay saw an uplink from an unexpected endpoint");
            return true;
        }
        std::vector<uint8_t> frame(buffer, buffer + received);
        m_radioUplink.push_back(frame);
        if (m_holdUplink)
        {
            m_held.push_back(std::move(frame));
            return true;
        }
        m_tap->Send(m_targetRadio, frame.data(), frame.size());
        return true;
    }

    void pumpSgw()
    {
        if (!m_sgw)
            return;
        uint8_t buffer[link::MaxDataPduSize + link::HeaderSize];
        for (int budget = 4; budget > 0; --budget)
        {
            InetAddress peer;
            const int received = m_sgw->Receive(buffer, sizeof(buffer), 0, peer);
            if (received <= 0)
                return;
            m_sgwDatagrams.emplace_back(buffer, buffer + received);
        }
    }

    void pumpApplication()
    {
        if (m_appFd < 0)
            return;
        uint8_t buffer[2048];
        for (int budget = 4; budget > 0; --budget)
        {
            const ssize_t received = recv(m_appFd, buffer, sizeof(buffer), MSG_DONTWAIT);
            if (received <= 0)
                return;
            m_appDatagrams.emplace_back(buffer, buffer + received);
        }
    }

    void sendToUe(link::MessageType type, std::vector<uint8_t> payload)
    {
        const auto frame = link::Encode({type, m_config.ueId, std::move(payload)});
        m_source.Send(m_uePeer, frame.data(), frame.size());
    }

    void sendNasToUe(std::vector<uint8_t> nas) { sendToUe(link::MessageType::NAS_DOWNLINK, std::move(nas)); }

    void handleSource(const link::Message &frame)
    {
        if (frame.type == link::MessageType::S1_CONTEXT_RELEASE_REQUEST)
        {
            // The controlled idle trigger: the serving cell answers with the S1
            // context release that puts the UE into ECM-IDLE.
            if (m_idleReleased)
                return note("the UE asked for a second idle transition");
            m_idleReleased = true;
            sendToUe(link::MessageType::S1_CONTEXT_RELEASED,
                     link::EncodeBearerRestoration(kDefaultEbi, /*generation=*/1));
            return;
        }
        if (frame.type == link::MessageType::BEARER_ACTIVATED)
        {
            if (frame.payload.size() != 1)
                return note("a bearer activation confirmation did not name one EPS bearer identity");
            m_activated.insert(frame.payload[0]);
            return;
        }
        if (frame.type == link::MessageType::BEARER_READY)
        {
            // The real initial Attach is over and the production UE reports the
            // bearer its own NAS confirmed, beside the local user plane it has
            // just built. It is the only honest source for that identity: the
            // serving cell never chose it.
            if (frame.payload.size() != 5)
                return note("a bearer-ready frame did not name one EPS bearer identity and one IPv4 address");
            if (m_readySeen)
                return note("the UE confirmed its default bearer twice");
            m_readyEbi = frame.payload[0];
            m_readyIpv4 = {frame.payload[1], frame.payload[2], frame.payload[3], frame.payload[4]};
            m_readySeen = true;
            return;
        }
        if (frame.type != link::MessageType::NAS_UPLINK)
            return note("the serving cell received a radio frame it does not script");
        const auto &payload = frame.payload;
        if (payload.size() < 2)
            return note("truncated NAS uplink at the serving cell");
        if (payload[0] == 0x07 && payload[1] == 0x41)
        {
            // Derive the same EPS AKA context the UE will, so both sides agree
            // on RES, CK, IK and KASME without consulting any credential store.
            const auto challenge = AuthRequestBytes();
            m_security = nas::Authenticate(m_config, nas::DecodeAuthenticationRequest(challenge.data(),
                                                                                     challenge.size()))
                             .context;
            m_security.advertisedSecurityCapabilities.assign(m_config.networkCapability.begin(),
                                                             m_config.networkCapability.end());
            sendNasToUe(challenge);
            return;
        }
        if (payload[0] == 0x07 && payload[1] == 0x53)
        {
            sendNasToUe(SecurityModeCommand());
            return;
        }
        std::vector<uint8_t> plain;
        uint32_t count = 0;
        try
        {
            const auto parsed = nas::ParseProtectedHeader(payload.data(), payload.size());
            const bool fresh = nas::StartsNewContext(parsed.headerType);
            count = fresh ? parsed.sequenceNumber : nas::EstimateNasCount(m_security.ulNasCount, parsed.sequenceNumber);
            if (!fresh && count <= m_security.ulNasCount)
                return note("the serving cell saw a replayed uplink NAS COUNT");
            plain = nas::UnprotectBody(m_security, true, parsed.headerType, parsed.sequenceNumber, parsed.mac,
                                       parsed.plain);
        }
        catch (const std::exception &e)
        {
            return note(std::string("the serving cell could not unprotect an uplink: ") + e.what());
        }
        m_security.ulNasCount = count;
        if (plain.size() >= 2 && plain[0] == 0x07 && plain[1] == 0x5E)
        {
            // Security Mode Complete: the serving cell now assigns the bearer
            // and the GUTI the reselected cell will be addressed by.
            sendNasToUe(ProtectDownlink(AttachAccept(), /*newContext=*/false));
            return;
        }
        if (plain.size() >= 2 && plain[0] == 0x07 && plain[1] == 0x43)
        {
            m_attachComplete = true;
            for (const uint8_t ebi : m_activate)
                sendNasToUe(ProtectDownlink(ActivateDedicated(ebi), /*newContext=*/false));
            return;
        }
        // Anything else is the Activate Dedicated EPS Bearer Context Accept, and
        // the radio frame beside it is what records the confirmation.
    }

    std::vector<uint8_t> ProtectDownlink(const std::vector<uint8_t> &plain, bool newContext)
    {
        auto message = nas::Protect(m_security, /*uplink=*/false, newContext, plain);
        m_security.dlNasCount = (m_security.dlNasCount + 1U) & 0xFFFFFFU;
        return message;
    }

    // The Security Mode Command must reach the UE on the integrity-only "new
    // EPS security context" header so its information elements stay readable in
    // the clear. nas::Protect with a fresh context always selects the ciphered
    // new-context header, and this fixture negotiates EEA0, so the protected
    // body is already the plain message and only the header nibble has to be
    // corrected. The MAC covers sequenceNumber||body and is unchanged.
    std::vector<uint8_t> SecurityModeCommand()
    {
        const std::vector<uint8_t> plain{0x07, 0x5D, 0x02, 0x00, 0x02, 0xA0, 0x20};
        const auto command = nas::DecodeSecurityModeCommand(plain.data(), plain.size());
        nas::ValidateSecurityModeCommand(m_config, command, m_security);
        m_security.kNasInt = nas::DeriveKnasInt(m_security.kasme, m_security.integrity);
        m_security.kNasEnc = nas::DeriveKnasEnc(m_security.kasme, m_security.ciphering);
        m_security.keysDerived = true;
        auto envelope = ProtectDownlink(plain, /*newContext=*/true);
        envelope[0] = static_cast<uint8_t>(
            (static_cast<uint8_t>(SecurityHeaderType::INTEGRITY_PROTECTED_WITH_NEW_CONTEXT) << 4U) | 0x07U);
        return envelope;
    }

    static std::vector<uint8_t> AuthRequestBytes()
    {
        return {0x07, 0x52, 0x07,
                0x23, 0x55, 0x3C, 0xBE, 0x96, 0x37, 0xA8, 0x9D, 0x21, 0x8A, 0xE6, 0x4D, 0xAE, 0x47, 0xBF, 0x35,
                0x10, 0x55, 0xF3, 0x28, 0xB4, 0x35, 0x77, 0xB9, 0xB9, 0x4A, 0x9F, 0xFA, 0xC3, 0x54, 0xDF, 0xAF,
                0xB3};
    }

    // Attach Accept with a full tracking area list for the served PLMN/TAC and
    // the GUTI the Tracking Area Update Request is later identified by.
    std::vector<uint8_t> AttachAccept() const
    {
        const auto plmn = s1ap::EncodePlmn(m_config.plmn);

        // Activate Default EPS Bearer Context Request: the assigned default
        // EBI, PTI 1, QCI 5, APN "internet", PDN address 10.0.0.1.
        const std::vector<uint8_t> esm{static_cast<uint8_t>((kDefaultEbi << 4U) | 0x02U), 0x01, 0xC1,
                                       0x01, 0x05,
                                       0x09, 0x08, 0x69, 0x6E, 0x74, 0x65, 0x72, 0x6E, 0x65, 0x74,
                                       0x05, 0x01, 0x0A, 0x00, 0x00, 0x01};

        std::vector<uint8_t> out{0x07, 0x42,
                                 0x01, // EPS attach result
                                 0x30, // GPRS timer T3412
                                 0x06, // TAI list length
                                 0x40, plmn[0], plmn[1], plmn[2], 0x00, 0x01};
        out.push_back(static_cast<uint8_t>(esm.size() >> 8U));
        out.push_back(static_cast<uint8_t>(esm.size()));
        out.insert(out.end(), esm.begin(), esm.end());

        // GUTI optional IE: MMEC 1, M-TMSI 0xC000018E.
        out.push_back(0x50);
        out.push_back(0x0B);
        out.push_back(0xF6);
        out.insert(out.end(), plmn.begin(), plmn.end());
        out.insert(out.end(), {0x00, 0x01, kMmeCode, 0xC0, 0x00, 0x01, 0x8E});
        return out;
    }

    // A network-authored Activate Dedicated EPS Bearer Context Request: EBI,
    // PTI, linked default EBI, a one-octet EPS QoS and an empty TFT. The UE
    // accepts it into its own bearer runtime and from then on owns the identity.
    static std::vector<uint8_t> ActivateDedicated(uint8_t ebi)
    {
        return {static_cast<uint8_t>((ebi << 4U) | 0x02U), 0x01, 0xC5, kDefaultEbi, 0x01, 0x09, 0x00};
    }

    // A Tracking Area Update Accept the network itself would author: the plain
    // EPS-only "TA updated" result this procedure performs, a periodic timer, a
    // tracking area list for the reselected cell's PLMN/TAC and a fresh GUTI.
    std::vector<uint8_t> TauAccept() const
    {
        const auto plmn = s1ap::EncodePlmn(m_config.plmn);
        std::vector<uint8_t> out{0x07, 0x49, 0x00};
        out.push_back(0x5A); // GPRS timer T3412, type-1 optional IE
        out.push_back(0x30);
        out.insert(out.end(), {0x54, 0x06, 0x40, plmn[0], plmn[1], plmn[2], 0x00, 0x02});
        out.push_back(0x50); // GUTI optional IE with a new M-TMSI
        out.push_back(0x0B);
        out.push_back(0xF6);
        out.insert(out.end(), plmn.begin(), plmn.end());
        out.insert(out.end(), {0x00, 0x01, kMmeCode, 0xC0, 0x00, 0x01, 0x8F});
        return out;
    }

    std::unique_ptr<lte::test::LogCapture> m_capture;
    udp::UdpServer m_source;
    CaptureSender m_targetWire;
    std::unique_ptr<EnbMultiplexer> m_target;
    Config m_config;
    SecurityContext m_security{};
    InetAddress m_uePeer;
    std::vector<uint8_t> m_activate;
    std::set<uint8_t> m_activated;
    std::vector<std::string> m_problems;
    bool m_attachComplete{};
    bool m_idleReleased{};
    std::atomic_bool m_shutdown{false};
    int m_exit{-1};
    std::thread m_ue;

    // Privileged-case transport, all inert in the ordinary cases.
    InetAddress m_targetRadio;
    std::optional<udp::UdpServer> m_tap;
    std::optional<udp::UdpServer> m_sgw;
    InetAddress m_tapUePeer;
    bool m_tapUeKnown{};
    bool m_holdUplink{};
    std::vector<std::vector<uint8_t>> m_radioUplink;
    std::vector<std::vector<uint8_t>> m_held;
    std::vector<std::vector<uint8_t>> m_sgwDatagrams;
    std::vector<std::vector<uint8_t>> m_appDatagrams;
    int m_appFd{-1};
    bool m_readySeen{};
    uint8_t m_readyEbi{};
    std::array<uint8_t, 4> m_readyIpv4{};
};

} // namespace

// ---------------------------------------------------------------------------
// The real UE opens a real target eNB and completes a Tracking Area Update
// ---------------------------------------------------------------------------

TEST_CASE("lte/ue_mobility_target: a real UE reselection reaches a real target eNB and completes a TAU there")
{
    Lab lab(47341, 47342);
    lab.scriptDedicated({6, 9});
    lab.startUe();

    // The serving cell brings the EPS session up: real AKA, a real Attach, and
    // two dedicated bearers the network activates on top of the default one.
    const bool attached = lab.driveUntilSourceAttachComplete();
    const bool dedicated = lab.driveUntilDedicatedConfirmed({6, 9});
    const bool idle = lab.driveUntilIdleReleased();

    // The UE reselects the target cell and opens it with its own mobility
    // uplink. The target eNB is a real EnbMultiplexer, so what appears on its
    // MME association is a real Initial UE Message built by production code.
    const bool arrived = lab.driveUntilTargetInitialUeMessage();
    const auto initial = lab.targetWire().first(12);
    const auto probe = s1ap::ProbeS1apPdu(initial.data(), initial.size());

    // The NAS PDU inside it is the genuine protected Tracking Area Update
    // Request the production sender built. It is recovered by rebuilding the
    // very message the UE's reselection branch builds — same plain, same
    // context, the one uplink NAS COUNT that opens the procedure — and matching
    // it against what actually left the UE.
    const auto expectedNas = lab.expectedProtectedUplink(lab.expectedTauRequest());
    const bool nasCarried = Contains(initial, expectedNas);

    // The Initial UE Message addresses the session by the S-TMSI of the GUTI
    // the UE's own NAS holds, not by anything the source cell allocated.
    const bool sTmsiCarried = Contains(initial, kExpectedSTmsi);

    // The target registry was empty before the UE arrived and now holds exactly
    // the declaration the UE made: the network-assigned default plus both
    // dedicated identities, on a fresh eNB-UE-S1AP-ID of this cell.
    auto *entry = lab.target().registry().find(lab.config().ueId);
    const bool registered = entry != nullptr;
    const bool declaredDefault = registered && entry->declaredBearers.has_value() &&
                                entry->declaredBearers->defaultEbi == kDefaultEbi;
    const bool declaredDedicated = registered && entry->declaredBearers.has_value() &&
                                   entry->declaredBearers->dedicatedEbis == std::vector<uint8_t>{6, 9};
    const bool pending = registered && entry->s1 == UeS1State::CONTEXT_PENDING && entry->mobilityBootstrap &&
                         entry->enbUeS1apId != 0;

    // The network restores the default bearer first. The declared dedicated
    // bearers are named in the declaration and are restored when the network
    // later asks for them, never guessed from the E-RAB list.
    lab.deliverIcsr({Erab(kDefaultEbi, 9, 30)});
    const bool established = registered && entry->s1 == UeS1State::CONTEXT_ESTABLISHED &&
                             entry->bearer.signalingEstablished() && entry->bearer.restorationPending() &&
                             !entry->bearer.active() && entry->bearer.parameters().erabId == kDefaultEbi &&
                             entry->dedicatedBearers.empty();

    // The UE accepts the target's generation-bound bearer restoration and only
    // then stops treating the cell as new.
    const bool restored = lab.waitForUeLine("bearer signaling restored in control-plane-only mode");
    const bool reselected = Contains(lab.captureText(), "ECM-IDLE cell reselection 460/02/1 -> 460/02/2");

    // The network answers the update over the real target eNB. The UE accepts
    // it only because its NAS security context survived the cell change, and it
    // owes the network a protected TAU Complete for the new GUTI.
    lab.deliverProtectedDownlink(lab.tauAccept());
    const bool accepted =
        lab.waitForUeLine("Tracking Area Update accepted; context preserved; TAU Complete sent for new GUTI");

    // That Complete leaves through the real target eNB as an ordinary Uplink NAS
    // Transport, which is the routing the correction deliberately preserved.
    const bool completed = lab.driveUntilUplinkNasTransport();
    const auto uplink = lab.targetWire().first(13);
    const bool completeCarried = Contains(uplink, lab.expectedProtectedUplink(nas::EncodeTauComplete()));

    lab.shutdownUe();
    REQUIRE(lab.problems().empty());
    REQUIRE(attached);
    REQUIRE(dedicated);
    REQUIRE(idle);
    REQUIRE(arrived);
    CHECK(probe.kind == s1ap::S1apPdu::Kind::INITIATING);
    CHECK(probe.procedureCode == 12);
    CHECK(nasCarried);
    CHECK(sTmsiCarried);
    REQUIRE(registered);
    CHECK(pending);
    CHECK(declaredDefault);
    CHECK(declaredDedicated);
    CHECK(established);
    CHECK(restored);
    CHECK(reselected);
    CHECK(accepted);
    REQUIRE(completed);
    CHECK(completeCarried);
    CHECK(lab.exitCode() == 0);

    // The declared dedicated bearer is later restored on top of the default
    // one, as a restoration of a bearer the UE's own NAS already confirmed
    // rather than as a brand-new one, and with target transport that is not the
    // source cell's. The UE-side confirmation of that transport needs the local
    // user plane and is covered at the target in test/lte/mobility_target.cpp.
    lab.deliverErabSetup(ErabWithNas(6, 7, 36));
    REQUIRE(lab.problems().empty());
    REQUIRE(entry->dedicatedBearers.size() == 1);
    const auto &dedicated6 = entry->dedicatedBearers.front();
    CHECK(dedicated6.parameters().erabId == 6);
    CHECK(dedicated6.parameters().linkedDefaultEbi == kDefaultEbi);
    CHECK(dedicated6.kind() == BearerKind::DEDICATED);
    CHECK(dedicated6.signalingEstablished());
    CHECK(dedicated6.restorationPending());
    CHECK_FALSE(dedicated6.active());
    CHECK(dedicated6.parameters().localTeid != entry->bearer.parameters().localTeid);
}

// ---------------------------------------------------------------------------
// A retransmission is a repeat of the frozen frame, and the target treats it
// as one
// ---------------------------------------------------------------------------

TEST_CASE("lte/ue_mobility_target: a repeated mobility uplink is refused by the target without disturbing its context")
{
    Lab lab(47343, 47344, /*procedureTimeoutMs=*/200, /*maxRetries=*/1);
    lab.scriptDedicated({6});
    lab.startUe();

    const bool attached = lab.driveUntilSourceAttachComplete();
    const bool dedicated = lab.driveUntilDedicatedConfirmed({6});
    const bool idle = lab.driveUntilIdleReleased();
    const bool arrived = lab.driveUntilTargetInitialUeMessage();

    auto *entry = lab.target().registry().find(lab.config().ueId);
    REQUIRE(entry != nullptr);
    const uint32_t enbUeS1apId = entry->enbUeS1apId;
    const bool hadDefault = entry->declaredBearers.has_value();
    const uint8_t declaredDefaultEbi = hadDefault ? entry->declaredBearers->defaultEbi : 0;
    const std::vector<uint8_t> declaredDedicated =
        hadDefault ? entry->declaredBearers->dedicatedEbis : std::vector<uint8_t>{};

    // The network never answers, so the production retransmission path is what
    // runs. The retry repeats the frozen frame, and the real target refuses to
    // let it open a second S1 connection on top of the one already pending.
    const bool rejected = lab.driveUntilTargetRejects();
    const size_t initials = lab.targetWire().count(12);
    const uint64_t stale = lab.target().recoveryCounters().staleMessagesRejected;

    // The pending context is untouched by the rejected repeat.
    auto *after = lab.target().registry().find(lab.config().ueId);
    const bool intact = after == entry && entry->s1 == UeS1State::CONTEXT_PENDING &&
                        entry->enbUeS1apId == enbUeS1apId && entry->declaredBearers.has_value() == hadDefault &&
                        (!hadDefault || (entry->declaredBearers->defaultEbi == declaredDefaultEbi &&
                                         entry->declaredBearers->dedicatedEbis == declaredDedicated));

    lab.finish();
    REQUIRE(lab.problems().empty());
    REQUIRE(attached);
    REQUIRE(dedicated);
    REQUIRE(idle);
    REQUIRE(arrived);
    CHECK(rejected);
    CHECK(initials == 1);
    CHECK(stale == 1);
    CHECK(intact);
    CHECK(lab.exitCode() == 1);
    CHECK(Contains(lab.log, "ECM-IDLE cell reselection 460/02/1 -> 460/02/2"));
    CHECK(Contains(lab.log, "Retransmitted TAU_NORMAL_PENDING, retry=1"));
    CHECK(Contains(lab.log, "TAU_NORMAL_PENDING timed out after bounded retransmissions"));
    CHECK_FALSE(Contains(lab.log, "Tracking Area Update accepted"));
}

// ---------------------------------------------------------------------------
// The privileged case: a real kernel TUN and a real IPv4 round trip through it
// ---------------------------------------------------------------------------

TEST_CASE("lte/ue_mobility_target: real TUN mobility restoration and user-plane round trip" * doctest::skip())
{
    // This case must never be able to report itself as passed without having
    // run. doctest::skip() keeps it out of the ordinary non-root suite, the
    // privileged job forces it with --no-skip plus the marker checked below,
    // and without that marker the body refuses outright rather than quietly
    // doing nothing. The three things the run physically needs are verified
    // before anything is built, so a machine that cannot be privileged fails
    // here and leaves nothing behind.
    if (std::getenv("UNIRANSIM_RUN_PRIVILEGED_TUN_TESTS") == nullptr)
        FAIL("the privileged TUN integration case requires UNIRANSIM_RUN_PRIVILEGED_TUN_TESTS=1");
    if (geteuid() != 0)
        FAIL("the privileged TUN integration case must run as root");
    if (access("/dev/net/tun", R_OK | W_OK) != 0)
        FAIL("the privileged TUN integration case needs a usable /dev/net/tun");
    std::fprintf(stderr, "UNIRANSIM-PRIVILEGED-TUN-EXECUTED\n");

    const auto defaultRoutesBefore = DefaultRouteLines();
    const auto netnsBefore = ListNetworkNamespaces();

    // Declared before the lab so the lab is destroyed first: whatever a failed
    // assertion leaves running is still undone by the guard's destructor. A
    // clean run removes nothing and records nothing.
    TunSweepGuard sweep;
    if (!ListInterfaces(kTunPrefix).empty())
        FAIL("the privileged TUN integration case needs an unused TUN name prefix");

    LabOptions options;
    options.procedureTimeoutMs = 30000;
    options.maxRetries = 2;
    options.tunBlock = kPrivilegedTun;
    options.radioTap = true;
    Lab lab(47345, 47346, options);
    lab.enableTestSgw();
    lab.scriptDedicated({6});
    lab.startUe();

    // A real EPS AKA, a real Attach, and a kernel TUN interface the production
    // UE builds out of its own Attach Accept. The bearer-ready frame it then
    // sends is the running UE's own report of the local user plane it just
    // made; nothing in this test hands it a bearer transport confirmation.
    const bool attached = lab.driveUntilSourceAttachComplete();
    const bool bearerReady = lab.driveUntilBearerReady();

    // What the kernel actually holds. The name is observed rather than
    // predicted because the allocator picks the first free index for the
    // configured prefix; the address, its prefix length, the MTU and the
    // explicit route are exactly the ones the production code asked for.
    const auto interfacesAfterAttach = ListInterfaces(kTunPrefix);
    const bool oneTunCreated = interfacesAfterAttach.size() == 1;
    const std::string tunName = oneTunCreated ? interfacesAfterAttach.front() : std::string{};
    const auto tunAddress = InterfaceIpv4(tunName);
    const bool tunAddressed = tunAddress.has_value() && tunAddress->address == kPdnIpv4 &&
                              tunAddress->prefixLength == 32;
    const auto tunMtu = InterfaceMtu(tunName);
    const bool tunMtuSet = tunMtu.has_value() && *tunMtu == kTunMtu;
    const bool tunRouted = RouteExists(kPeerIpv4, tunName);
    const bool bearerNamed = lab.readySeen() && lab.readyEbi() == kDefaultEbi && lab.readyIpv4() == kPdnIpv4;

    // The network activates one dedicated bearer on top of the default one and
    // then releases the UE into ECM-IDLE, where it reselects into the target
    // cell and opens it with its own mobility uplink.
    const bool dedicated = lab.driveUntilDedicatedConfirmed({6});
    const bool idle = lab.driveUntilIdleReleased();
    const bool arrived = lab.driveUntilTargetInitialUeMessage();

    // The interface survives the reselection: replacing the access replaces the
    // S1 connection and the transport of the cell being left, not the local
    // user plane of the EPS session.
    const bool tunSurvivedReselection = InterfaceExists(tunName);

    // The mobility uplink is the production UE's own, and the bearer inventory
    // it declares is what the target restores against. Nothing about the UE's
    // session exists on the target before that frame arrives.
    std::optional<link::Message> mobilityContext;
    for (const auto &frame : lab.radioUplink())
    {
        const auto decoded = DecodeRadio(frame);
        if (decoded && decoded->type == link::MessageType::NAS_UPLINK_MOBILITY_CONTEXT)
            mobilityContext = decoded;
    }
    const bool mobilityDeclared = mobilityContext.has_value();
    auto *entry = lab.target().registry().find(lab.config().ueId);
    const bool registered = entry != nullptr;
    const bool inventoryDeclared = registered && entry->declaredBearers.has_value() &&
                                   entry->declaredBearers->defaultEbi == kDefaultEbi &&
                                   entry->declaredBearers->dedicatedEbis == std::vector<uint8_t>{6};
    const bool freshTargetAccess =
        registered && entry->mobilityBootstrap && entry->enbUeS1apId != 0 && entry->accessGeneration == 1;

    // One network-authored Initial Context Setup Request naming both the
    // default bearer and the dedicated bearer the UE declared, deliberately
    // listed dedicated-first: the target establishes the default first
    // whatever order the MME lists its E-RABs in, and then the dedicated one
    // on top of it. The UE's two transport confirmations are held at the relay
    // so the window between the target's restoration and the UE's confirmation
    // of it can be inspected; they are the UE's own octets and are forwarded
    // unmodified when that window closes.
    lab.holdUplink(true);
    lab.deliverIcsr({Erab(6, 7, 36), Erab(kDefaultEbi, 9, 30)});
    const bool notificationsHeld = lab.driveUntilHeldUplink(2);

    // Both held frames are the running UE's own, and it produced the default
    // bearer's confirmation first because it answers the default restoration
    // before the dedicated one that follows it.
    std::optional<link::BearerTransportReady> firstReady;
    std::optional<link::BearerTransportReady> secondReady;
    if (notificationsHeld && lab.heldUplink().size() >= 2)
    {
        const auto first = DecodeRadio(lab.heldUplink()[0]);
        const auto second = DecodeRadio(lab.heldUplink()[1]);
        if (first && first->type == link::MessageType::BEARER_TRANSPORT_READY)
        {
            try
            {
                firstReady = link::DecodeBearerTransportReady(first->payload.data(), first->payload.size());
            }
            catch (const std::exception &)
            {
            }
        }
        if (second && second->type == link::MessageType::BEARER_TRANSPORT_READY)
        {
            try
            {
                secondReady = link::DecodeBearerTransportReady(second->payload.data(), second->payload.size());
            }
            catch (const std::exception &)
            {
            }
        }
    }
    const bool confirmationsAreTheUes =
        firstReady && secondReady && firstReady->ebi == kDefaultEbi && firstReady->generation == 1 &&
        firstReady->ueIpv4 == kPdnIpv4 && secondReady->ebi == 6 && secondReady->generation == 1 &&
        secondReady->ueIpv4 == kPdnIpv4;

    entry = lab.target().registry().find(lab.config().ueId);
    const bool restorationWindow = entry != nullptr && entry->bearer.signalingEstablished() &&
                                   entry->bearer.restorationPending() && !entry->bearer.active() &&
                                   entry->dedicatedBearers.size() == 1 &&
                                   entry->dedicatedBearers.front().signalingEstablished() &&
                                   entry->dedicatedBearers.front().restorationPending() &&
                                   !entry->dedicatedBearers.front().active();
    const uint32_t defaultLocalTeid = entry != nullptr ? entry->bearer.parameters().localTeid : 0;
    const uint32_t dedicatedLocalTeid =
        (entry != nullptr && !entry->dedicatedBearers.empty()) ? entry->dedicatedBearers.front().parameters().localTeid
                                                              : 0;
    const uint64_t rejectedBefore = lab.target().recoveryCounters().staleMessagesRejected;

    // Every probe below is a frame the running UE cannot produce, injected at
    // the target's own dispatcher purely to be refused while both bearers are
    // established and still awaiting the confirmation the UE is holding. A
    // stale access generation, a bearer it never requested, an identity its
    // declaration does not contain, a dedicated confirmation offered before
    // the default bearer is ready, a generation the target never issued, a
    // confirmation naming no UE address at all, user-plane data offered before
    // any bearer is active, and a frame from an endpoint that does not own
    // this UE identity.
    if (entry != nullptr)
    {
        lab.injectRadio(link::MessageType::BEARER_TRANSPORT_READY,
                        link::EncodeBearerTransportReady(kDefaultEbi, 2, kPdnIpv4));
        lab.injectRadio(link::MessageType::BEARER_TRANSPORT_READY,
                        link::EncodeBearerTransportReady(9, 1, kPdnIpv4));
        lab.injectRadio(link::MessageType::BEARER_TRANSPORT_READY,
                        link::EncodeBearerTransportReady(7, 1, kPdnIpv4));
        lab.injectRadio(link::MessageType::BEARER_TRANSPORT_READY, link::EncodeBearerTransportReady(6, 1, kPdnIpv4));
        lab.injectRadio(link::MessageType::BEARER_TRANSPORT_READY,
                        link::EncodeBearerTransportReady(kDefaultEbi, 0, kPdnIpv4));
        lab.injectRadio(link::MessageType::BEARER_TRANSPORT_READY, link::EncodeBearerRestoration(kDefaultEbi, 1));
        lab.injectRadio(link::MessageType::DATA_UPLINK,
                        BuildUdpIpv4(kPdnIpv4, kPeerIpv4, kApplicationPort, kPeerPort, {'p', 'r', 'e'}));
        lab.injectRadio(InetAddress("127.0.0.1", 47351), link::MessageType::BEARER_TRANSPORT_READY,
                        link::EncodeBearerTransportReady(kDefaultEbi, 1, kPdnIpv4));
    }
    // A downlink GTP-U T-PDU under a TEID that resolves nowhere on this eNB:
    // the class of TEID the cell the UE left held, which must never resolve on
    // the cell it arrived at.
    lab.sendSgwDownlink(0x51CE0001u, BuildUdpIpv4(kPeerIpv4, kPdnIpv4, kPeerPort, kApplicationPort, {'x'}));

    // The two confirmations the running UE really produced, in the order it
    // produced them: the default bearer's first, because the UE answers the
    // default restoration before the dedicated one that follows it.
    lab.releaseHeld(1);
    const bool defaultConfirmed = lab.drive(
        [&] {
            auto *e = lab.target().registry().find(lab.config().ueId);
            return e != nullptr && e->bearer.active();
        },
        8000);

    // With the default bearer ready and the dedicated one still pending, the
    // remaining two probes reach the checks they are named after instead of
    // being refused earlier.
    lab.injectRadio(link::MessageType::BEARER_TRANSPORT_READY,
                    link::EncodeBearerTransportReady(6, 1, std::array<uint8_t, 4>{10, 0, 0, 99}));
    lab.injectRadio(link::MessageType::BEARER_TRANSPORT_READY, link::EncodeBearerTransportReady(kDefaultEbi, 1, kPdnIpv4));

    lab.releaseHeld(1);
    const bool bothActive = lab.drive(
        [&] {
            auto *e = lab.target().registry().find(lab.config().ueId);
            return e != nullptr && e->bearer.active() && !e->dedicatedBearers.empty() &&
                   e->dedicatedBearers.front().active();
        },
        8000);
    // The observation window is over: from here on the relay is a plain wire
    // again and every frame the UE writes reaches the target without delay.
    lab.holdUplink(false);

    entry = lab.target().registry().find(lab.config().ueId);
    const uint64_t rejectedByProbes =
        lab.target().recoveryCounters().staleMessagesRejected - rejectedBefore;
    const bool probesLeftBearersIntact =
        entry != nullptr && entry->bearer.active() && entry->dedicatedBearers.size() == 1 &&
        entry->dedicatedBearers.front().active() && entry->bearer.parameters().localTeid == defaultLocalTeid &&
        entry->dedicatedBearers.front().parameters().localTeid == dedicatedLocalTeid &&
        entry->bearer.counters().uplinkPackets == 0 && entry->bearer.counters().downlinkPackets == 0 &&
        entry->counters.simulatedUplinkPackets == 0 && entry->counters.simulatedDownlinkPackets == 0 &&
        lab.applicationDatagrams().empty() && lab.sgwDatagrams().empty();

    // Real IPv4 uplink: the test application sends from the PDN address the
    // network assigned, the kernel routes the datagram into the UE's own TUN,
    // the production UE forwards it over the simulated radio link and the
    // target encapsulates it for the SGW endpoint the E-RAB named.
    const bool applicationOpen = lab.openApplicationSocket();
    const std::string uplinkText = "uniransim lte user plane uplink";
    const std::vector<uint8_t> uplinkPayload(uplinkText.begin(), uplinkText.end());
    const bool applicationSent = applicationOpen && lab.sendApplicationDatagram(uplinkPayload);
    const bool uplinkArrived = lab.drive([&] { return !lab.sgwDatagrams().empty(); }, 8000);

    std::optional<link::Message> uplinkFrame;
    for (const auto &frame : lab.radioUplink())
    {
        const auto decoded = DecodeRadio(frame);
        if (decoded && decoded->type == link::MessageType::DATA_UPLINK)
            uplinkFrame = decoded;
    }
    std::optional<lte::ip::PacketInfo> uplinkIp;
    if (uplinkFrame)
    {
        try
        {
            uplinkIp = lte::ip::Validate(uplinkFrame->payload.data(), uplinkFrame->payload.size(), 2048);
        }
        catch (const std::exception &)
        {
        }
    }
    const bool uplinkAddressed =
        uplinkIp.has_value() && uplinkIp->source == kPdnIpv4 && uplinkIp->destination == kPeerIpv4 &&
        uplinkIp->protocol == 17;
    const bool uplinkCarriedApplication = uplinkFrame.has_value() &&
                                          uplinkFrame->payload.size() == 28 + uplinkPayload.size() &&
                                          std::equal(uplinkPayload.begin(), uplinkPayload.end(),
                                                     uplinkFrame->payload.begin() + 28);

    std::optional<gtpu::Packet> uplinkGtp;
    if (!lab.sgwDatagrams().empty())
    {
        try
        {
            uplinkGtp = gtpu::Decode(lab.sgwDatagrams().front().data(), lab.sgwDatagrams().front().size());
        }
        catch (const std::exception &)
        {
        }
    }
    const bool uplinkFramed = uplinkGtp.has_value() && uplinkGtp->messageType == gtpu::TPdu;
    const bool uplinkOnSgwTeid = uplinkGtp.has_value() && uplinkGtp->teid == 30;
    const bool uplinkByteIdentical =
        uplinkGtp.has_value() && uplinkFrame.has_value() && uplinkGtp->payload == uplinkFrame->payload;

    // The transport the target restored is its own: both local GTP-U TEIDs are
    // freshly allocated for this access, distinct from each other and from the
    // SGW-side TEIDs the network's E-RAB items named, so nothing the cell the
    // UE left was using can resolve here.
    const bool targetTeidsFresh = defaultLocalTeid != 0 && dedicatedLocalTeid != 0 &&
                                  defaultLocalTeid != dedicatedLocalTeid && defaultLocalTeid != 30 &&
                                  defaultLocalTeid != 36 && dedicatedLocalTeid != 30 && dedicatedLocalTeid != 36;

    entry = lab.target().registry().find(lab.config().ueId);
    const bool uplinkCounters = entry != nullptr && entry->bearer.counters().uplinkPackets == 1 &&
                                entry->bearer.counters().uplinkBytes == (uplinkFrame ? uplinkFrame->payload.size() : 0) &&
                                entry->counters.simulatedUplinkPackets == 1 && entry->counters.s1uUplinkPackets == 1;

    // Real IPv4 downlink: the SGW endpoint sends a GTP-U T-PDU under the
    // target's own local TEID, the target hands it to the UE over the simulated
    // radio link, and the UE writes it into the kernel TUN, where the kernel
    // delivers it to the application socket it is addressed to.
    const std::string downlinkText = "uniransim lte user plane downlink";
    const std::vector<uint8_t> downlinkPayload(downlinkText.begin(), downlinkText.end());
    const auto downlinkIp = BuildUdpIpv4(kPeerIpv4, kPdnIpv4, kPeerPort, kApplicationPort, downlinkPayload);
    const uint32_t downlinkTeid = entry != nullptr ? entry->bearer.parameters().localTeid : 0;
    lab.sendSgwDownlink(downlinkTeid, downlinkIp);
    const bool downlinkArrived = lab.drive([&] { return !lab.applicationDatagrams().empty(); }, 8000);
    const bool downlinkDelivered = !lab.applicationDatagrams().empty() &&
                                   lab.applicationDatagrams().front() == downlinkPayload;
    const bool downlinkOnFreshTeid = downlinkTeid != 0 && downlinkTeid != 30;

    entry = lab.target().registry().find(lab.config().ueId);
    const bool downlinkCounters = entry != nullptr && entry->bearer.counters().downlinkPackets == 1 &&
                                  entry->bearer.counters().downlinkBytes == downlinkIp.size() &&
                                  entry->counters.simulatedDownlinkPackets == 1 &&
                                  entry->counters.s1uDownlinkPackets == 1;

    lab.closeApplicationSocket();
    lab.shutdownUe();
    const bool cleanShutdown = lab.exitCode() == 0 && Contains(lab.log, "LTE UE shutdown complete");
    const bool userPlaneReported =
        Contains(lab.log, "User-plane statistics: tun-ul=1/") && Contains(lab.log, " tun-dl=1/");

    // Nothing the scenario built survives it. The UE released its own
    // interface and its route when it shut down, and the network-side release
    // of the access drops both TEIDs while retaining the logical bearer
    // identities an idle UE is supposed to keep.
    const bool tunReleased = tunName.empty() || !InterfaceExists(tunName);
    const bool routeReleased = !RouteExists(kPeerIpv4, tunName);
    lab.deliverUeContextRelease();
    entry = lab.target().registry().find(lab.config().ueId);
    const bool targetTransportGone =
        entry != nullptr && !entry->bearer.signalingEstablished() && !entry->bearer.active() &&
        entry->dedicatedBearers.size() == 1 && !entry->dedicatedBearers.front().signalingEstablished() &&
        !entry->dedicatedBearers.front().active();
    const bool teidsReleased = defaultLocalTeid != 0 && dedicatedLocalTeid != 0 &&
                               lab.target().registry().findBearerByLocalTeid(defaultLocalTeid).entry == nullptr &&
                               lab.target().registry().findBearerByLocalTeid(dedicatedLocalTeid).entry == nullptr;
    lab.target().shutdown();
    const bool noOrphanTun = ListInterfaces(kTunPrefix).empty();
    const bool heldReleased = lab.heldUplink().empty();
    const bool defaultRouteUntouched = DefaultRouteLines() == defaultRoutesBefore;
    const bool namespacesUntouched = ListNetworkNamespaces() == netnsBefore;
    const bool nothingSwept = sweep.swept.empty();

    // The complete production log of the run, on stderr beside the sentinels.
    // The UE logs through a stream the harness captures so its assertions stay
    // visible, and a privileged run whose transcript is missing is not evidence
    // of anything, so it is published here rather than only asserted against.
    std::fprintf(stderr, "=== production log ===\n%s=== end of production log ===\n", lab.log.c_str());

    REQUIRE(lab.problems().empty());
    REQUIRE(attached);
    REQUIRE(bearerReady);
    REQUIRE(oneTunCreated);
    CHECK(tunAddressed);
    CHECK(tunMtuSet);
    REQUIRE(tunRouted);
    REQUIRE(bearerNamed);
    REQUIRE(dedicated);
    REQUIRE(idle);
    REQUIRE(arrived);
    CHECK(mobilityDeclared);
    REQUIRE(registered);
    CHECK(inventoryDeclared);
    CHECK(freshTargetAccess);
    CHECK(targetTeidsFresh);
    CHECK(tunSurvivedReselection);
    REQUIRE(notificationsHeld);
    CHECK(confirmationsAreTheUes);
    REQUIRE(restorationWindow);
    CHECK(rejectedByProbes == 10);
    REQUIRE(defaultConfirmed);
    REQUIRE(bothActive);
    CHECK(probesLeftBearersIntact);
    REQUIRE(applicationOpen);
    REQUIRE(applicationSent);
    REQUIRE(uplinkArrived);
    CHECK(uplinkFrame.has_value());
    CHECK(uplinkAddressed);
    CHECK(uplinkCarriedApplication);
    CHECK(uplinkFramed);
    CHECK(uplinkOnSgwTeid);
    CHECK(uplinkByteIdentical);
    CHECK(uplinkCounters);
    REQUIRE(downlinkArrived);
    REQUIRE(downlinkDelivered);
    CHECK(downlinkOnFreshTeid);
    CHECK(downlinkCounters);
    REQUIRE(cleanShutdown);
    CHECK(userPlaneReported);
    REQUIRE(tunReleased);
    REQUIRE(routeReleased);
    REQUIRE(targetTransportGone);
    REQUIRE(teidsReleased);
    REQUIRE(noOrphanTun);
    CHECK(heldReleased);
    CHECK(defaultRouteUntouched);
    CHECK(namespacesUntouched);
    CHECK(nothingSwept);

    std::fprintf(stderr, "UNIRANSIM-PRIVILEGED-TUN-COMPLETE\n");
}
