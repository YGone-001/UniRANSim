//
// This file is a part of UERANSIM project.
// Copyright (c) 2027 ALİ GÜNGÖR.
//
// https://github.com/aligungr/UERANSIM/
// See README, LICENSE, and CONTRIBUTING files for licensing details.
//

// Phase 18-D: the isolated two-eNB connected handover acceptance.
//
// This is the end-to-end sequence of the work order's section 14, driven
// through the production interfaces of both eNBs and of the running UE:
//
//   * a real source `EnbMultiplexer` and a real target `EnbMultiplexer`, each
//     with its own simulated-radio endpoint and its own shared S1-U receiver;
//   * the real `lte::ue::Run()` on its own thread, attaching over its own UDP
//     socket and executing the handover command in its own receive path;
//   * an isolated, deterministic MME that relays real encoded S1AP PDUs
//     between the two eNBs through `IsolatedMmeRelay`.
//
// The MME side of the *attach* is a scripted EPS peer: it consumes the NAS the
// source eNB's real S1AP dispatcher hands it and answers with network-authored
// Initial Context Setup Request, Downlink NAS Transport and E-RAB Setup
// Request. That is the same scripted peer the accepted UE mobility cases use,
// moved up one layer from the radio link to S1AP so that a real `EnbMultiplexer`
// stands at the source as well as at the target.
//
// The case needs a kernel TUN device, and therefore root and a private network
// namespace, because section 14 requires active default and dedicated bearers
// at the source before the trigger and section 15 requires real user plane in
// both directions. The production UE only announces bearer readiness and only
// forwards user plane once its TUN exists, so a control-plane-only run cannot
// reach the state this acceptance is about. It is therefore a skipped case,
// exactly as the Phase 17 user-plane restorations are, and is run by the
// privileged job as its own invocation with its own log and its own sentinels.

#include <ext/doctest/doctest.h>
#include "log_capture.hpp"

#include <algorithm>
#include <array>
#include <atomic>
#include <chrono>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <map>
#include <memory>
#include <optional>
#include <set>
#include <sstream>
#include <string>
#include <thread>
#include <utility>
#include <vector>

#include <arpa/inet.h>
#include <ifaddrs.h>
#include <net/if.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <unistd.h>

#include <lib/udp/server.hpp>
#include <lte/enb/codec.hpp>
#include <lte/enb/gtpu.hpp>
#include <lte/enb/handover_admission.hpp>
#include <lte/enb/handover_orchestration.hpp>
#include <lte/enb/handover_preparation.hpp>
#include <lte/enb/multiplexer.hpp>
#include <lte/enb/s1u_endpoint.hpp>
#include <lte/enb/ue_registry.hpp>
#include <lte/enb/user_plane.hpp>
#include <lte/ue/app.hpp>
#include <lte/ue/config.hpp>
#include <lte/ue/nas.hpp>
#include <lte/ue/radio_link.hpp>
#include <lte/ue/security.hpp>

namespace
{

using namespace lte::enb;
using namespace lte::enb::s1ap;
namespace link = lte::ue::link;
namespace nas = lte::ue::nas;
using Clock = std::chrono::steady_clock;
using UeSecurityContext = lte::ue::SecurityContext;

// --- Cell and subscriber identities ---------------------------------------
//
// The two cells are the two the work order names. Both are in the one PLMN the
// UE is provisioned for, and their tracking areas differ so that the target is
// distinguishable from the source by TAI alone.

constexpr uint32_t SourceEnbId = 0x0012345u;
constexpr uint32_t TargetEnbId = 0x00ABCDEu;
constexpr uint32_t MmeUeS1apId = 201;
constexpr uint32_t UeRadioId = 7;

const Plmn &TestPlmn()
{
    static const Plmn plmn{"460", "02"};
    return plmn;
}

EnbIdentity SourceIdentity() { return EnbIdentity{TestPlmn(), SourceEnbId, 1}; }
EnbIdentity TargetIdentity() { return EnbIdentity{TestPlmn(), TargetEnbId, 2}; }

EutranCgi CgiOf(const EnbIdentity &id)
{
    return EutranCgi{id.plmn, (id.enbId & 0xFFFFFU) << 8U};
}

// The PDN address the Attach Accept assigns. The whole acceptance keys off it:
// the source's confirmed session address, the record's `pdnAddress`, the
// arrival's `ueIpv4` and the destination of every user-plane packet are this
// one value.
constexpr std::array<uint8_t, 4> PdnIpv4{10, 0, 0, 1};
// The peer the UE's TUN route names. It is not a local address: it is reached
// only through the TUN, which is what makes the routing leg real.
constexpr std::array<uint8_t, 4> PeerIpv4{198, 18, 0, 2};
constexpr uint16_t ApplicationPort = 47401;
constexpr uint16_t PeerPort = 47402;
constexpr uint16_t UeLocalPort = 47403;
// The UDP pair the dedicated bearer's captured TFT names. The uplink filter
// takes local port 7000 to remote port 5000 and the downlink filter takes
// remote port 7000 to local port 5000, so the dedicated uplink is sent from the
// first socket and the dedicated downlink is addressed to the second.
constexpr uint16_t DedicatedLocalPort = 7000;
constexpr uint16_t DedicatedPeerPort = 5000;

// The test-owned SGW endpoint. Every E-RAB authored here names its address as
// the transport layer address, so the source's uplink GTP-U reaches it and its
// downlink GTP-U is accepted by whichever eNB is serving the UE.
constexpr std::array<uint8_t, 4> SgwAddress{127, 0, 0, 2};

constexpr uint8_t DefaultEbi = 5;
constexpr uint8_t DedicatedEbi = 6;
constexpr uint8_t DefaultQci = 9;
constexpr uint8_t DedicatedQci = 7;
constexpr uint32_t SgwDefaultTeid = 30;
constexpr uint32_t SgwDedicatedTeid = 36;

std::string Ipv4Text(const std::array<uint8_t, 4> &address)
{
    char text[24];
    std::snprintf(text, sizeof(text), "%u.%u.%u.%u", address[0], address[1], address[2], address[3]);
    return text;
}

// --- Test-owned SGW endpoint ----------------------------------------------

// A real UDP endpoint bound to the address and port every E-RAB here names, so
// the uplink G-PDUs the eNB forwards are genuine datagrams that left the eNB's
// own S1-U socket and the downlink G-PDUs it accepts are genuine datagrams this
// endpoint sent. A packet that never left a socket pair is not user-plane
// evidence, so nothing in this file substitutes a method call for either leg.
class SgwEndpoint
{
  public:
    SgwEndpoint() : m_socket(Ipv4Text(SgwAddress), 2152) {}

    void sendDownlink(const InetAddress &destination, uint32_t teid, const std::vector<uint8_t> &ipPacket)
    {
        const auto datagram = gtpu::EncodeTPdu(teid, ipPacket.data(), ipPacket.size());
        m_socket.Send(destination, datagram.data(), datagram.size());
    }

    // Drains every G-PDU that reached this endpoint since the last call.
    std::vector<std::vector<uint8_t>> drain()
    {
        std::vector<std::vector<uint8_t>> out;
        for (int i = 0; i < 64; ++i)
        {
            uint8_t buffer[2048];
            InetAddress from;
            const int received = m_socket.Receive(buffer, sizeof(buffer), 0, from);
            if (received <= 0)
                break;
            out.emplace_back(buffer, buffer + received);
        }
        return out;
    }

  private:
    udp::UdpServer m_socket;
};

// --- Kernel observation ---------------------------------------------------

// The privileged case moves real IPv4 through a real kernel TUN, so it has to
// be able to see what the kernel did. Everything here is read-only observation
// of the running kernel; the only interface this file ever creates is the one
// the production UE allocates for itself.

const char *const kTunPrefix = "u18d";

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

// --- User-plane application endpoint -------------------------------------

// A real UDP socket bound to the UE's PDN address. Uplink the UE forwards is
// routed by the kernel into its TUN and out to the peer; downlink the UE writes
// into its TUN is routed by the kernel back to this socket. Both directions are
// therefore genuine kernel-delivered IPv4, not a socket pair this file made up.

int OpenBoundSocket(uint16_t port, const std::array<uint8_t, 4> &address)
{
    const int fd = ::socket(AF_INET, SOCK_DGRAM, 0);
    if (fd < 0)
        return -1;
    int reuse = 1;
    ::setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &reuse, sizeof(reuse));
    sockaddr_in bindAddress{};
    bindAddress.sin_family = AF_INET;
    bindAddress.sin_port = htons(port);
    bindAddress.sin_addr.s_addr = htonl((uint32_t(address[0]) << 24U) | (uint32_t(address[1]) << 16U) |
                                       (uint32_t(address[2]) << 8U) | uint32_t(address[3]));
    if (::bind(fd, reinterpret_cast<sockaddr *>(&bindAddress), sizeof(bindAddress)) != 0)
    {
        ::close(fd);
        return -1;
    }
    timeval timeout{};
    timeout.tv_sec = 0;
    timeout.tv_usec = 20000;
    ::setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout));
    return fd;
}

bool SendDatagram(int fd, uint16_t port, const std::array<uint8_t, 4> &address, const std::vector<uint8_t> &payload)
{
    if (fd < 0)
        return false;
    sockaddr_in destination{};
    destination.sin_family = AF_INET;
    destination.sin_port = htons(port);
    destination.sin_addr.s_addr = htonl((uint32_t(address[0]) << 24U) | (uint32_t(address[1]) << 16U) |
                                       (uint32_t(address[2]) << 8U) | uint32_t(address[3]));
    return ::sendto(fd, payload.data(), payload.size(), 0, reinterpret_cast<sockaddr *>(&destination),
                    sizeof(destination)) == static_cast<ssize_t>(payload.size());
}

// One datagram an application socket received, with the peer the kernel saw it
// come from. The kernel only hands a datagram to a socket after it has checked
// the IPv4 header and the UDP checksum of the whole datagram the UE wrote into
// its TUN, so the payload plus the source four-tuple is what a delivered
// datagram is: a datagram whose header or checksum differed would not have
// arrived here at all.
struct Datagram
{
    std::vector<uint8_t> payload;
    std::array<uint8_t, 4> source{};
    uint16_t sourcePort{};
};

std::vector<Datagram> DrainSocket(int fd)
{
    std::vector<Datagram> out;
    if (fd < 0)
        return out;
    for (int i = 0; i < 32; ++i)
    {
        uint8_t buffer[2048];
        sockaddr_in from{};
        socklen_t length = sizeof(from);
        const ssize_t received =
            ::recvfrom(fd, buffer, sizeof(buffer), 0, reinterpret_cast<sockaddr *>(&from), &length);
        if (received <= 0)
            break;
        Datagram datagram;
        datagram.payload.assign(buffer, buffer + received);
        const uint32_t address = ntohl(from.sin_addr.s_addr);
        datagram.source = {static_cast<uint8_t>(address >> 24U), static_cast<uint8_t>(address >> 16U),
                           static_cast<uint8_t>(address >> 8U), static_cast<uint8_t>(address)};
        datagram.sourcePort = ntohs(from.sin_port);
        out.push_back(std::move(datagram));
    }
    return out;
}

// --- The scripted EPS peer behind the source eNB --------------------------

// The S-TMSI the Attach Accept assigns.
constexpr uint8_t kMmeCode = 1;
constexpr uint32_t kMTmsi = 0xC000018Eu;

// The 3GPP TS 35.208 test-set RAND the challenge below carries. The scripted
// peer derives the whole AKA context from it and the UE does the same, so the
// two agree without this file ever holding a key of its own choosing.
std::vector<uint8_t> AuthRequestBytes()
{
    return {0x07, 0x52, 0x07,
            0x23, 0x55, 0x3C, 0xBE, 0x96, 0x37, 0xA8, 0x9D, 0x21, 0x8A, 0xE6, 0x4D, 0xAE, 0x47, 0xBF, 0x35,
            0x10, 0x55, 0xF3, 0x28, 0xB4, 0x35, 0x77, 0xB9, 0xB9, 0x4A, 0x9F, 0xFA, 0xC3, 0x54, 0xDF, 0xAF,
            0xB3};
}

// The TFT value field of a real Open5GS MME Activate Dedicated EPS Bearer
// Context Request captured during Phase 7 and decoded in test/lte/tft.cpp. It
// is a CREATE_NEW TFT carrying two directed UDP packet filters:
//
//   filter 0, precedence 0, uplink only   — local port 7000 -> remote port 5000
//   filter 1, precedence 1, downlink only — remote port 7000 -> local port 5000
//
// so the dedicated bearer takes exactly the UDP 7000<->5000 flow and every
// other datagram falls back to the default bearer. The dedicated application
// sockets below are bound and addressed to that flow for exactly this reason.
//
// Evidence provenance. What is captured is this TFT value field and the bearer
// identity metadata that came beside it: the activation carried EBI 6 linked to
// default EBI 5 with QCI 7, and the S1AP E-RAB Setup Request that carried the
// same E-RAB also named QCI 7. What is *not* captured is the enclosing NAS
// message: ActivateDedicated() below builds that envelope in this file, and the
// S1AP E-RAB items are built here too. The production UE then decodes the
// constructed envelope through its own NAS decoder and stores what it decoded.
// No packet capture is claimed to exist for the envelope and no byte-for-byte
// equivalence with one is claimed; the capture-backed facts are the TFT octets
// and the EBI 6 / linked EBI 5 / QCI 7 bearer identity.
const std::vector<uint8_t> kDedicatedTft{
    0x22, 0x20, 0x00, 0x11, 0x30, 0x11, 0x10, 0x00, 0x00, 0x00, 0x00, 0xFF,
    0xFF, 0xFF, 0xFF, 0x40, 0x1B, 0x58, 0x50, 0x13, 0x88, 0x11, 0x01, 0x08,
    0x30, 0x11, 0x50, 0x1B, 0x58, 0x40, 0x13, 0x88};

// The network-authored dedicated-bearer activation: EBI and message type, the
// linked default EBI, the QCI this bearer is given, and the TFT value field.
// The QCI travels per bearer rather than as one value for the whole list, so a
// case with two dedicated bearers plays two QCIs and they cannot blur together.
std::vector<uint8_t> ActivateDedicated(uint8_t ebi, const std::vector<uint8_t> &tft, uint8_t linkedEbi, uint8_t qci)
{
    std::vector<uint8_t> out{static_cast<uint8_t>((ebi << 4U) | 0x02U), 0x01, 0xC5,
                             linkedEbi, 0x01, qci};
    out.push_back(static_cast<uint8_t>(tft.size()));
    out.insert(out.end(), tft.begin(), tft.end());
    return out;
}

// A network-authored E-RAB item. The transport layer is the test SGW endpoint
// above, so the bearer's uplink really reaches a socket this file owns. A real
// MME puts the NAS message that activates the bearer in this item's NAS-PDU
// (TS 36.413 §9.1.4.2), and the production eNB forwards it to the UE from
// there, so the caller supplies that message rather than a placeholder.
s1ap::ErabToBeSetupItem ErabItem(uint8_t ebi, uint8_t qci, uint32_t sgwTeid,
                                 std::vector<uint8_t> nasPdu = {})
{
    s1ap::ErabToBeSetupItem item{};
    item.erabId = ebi;
    item.qci = qci;
    item.transportLayerAddress = SgwAddress;
    item.gtpTeid = TeidToBytes(sgwTeid);
    if (!nasPdu.empty())
    {
        item.nasPduPresent = true;
        item.nasPdu = std::move(nasPdu);
    }
    return item;
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
// The ports are what select the bearer on the way up: the running UE matches
// every uplink datagram against the TFT each dedicated bearer was given, and a
// datagram no filter names belongs to the default bearer.
std::vector<uint8_t> BuildUdpIpv4(const std::array<uint8_t, 4> &source, const std::array<uint8_t, 4> &destination,
                                  uint16_t sourcePort, uint16_t destinationPort, const std::string &payload)
{
    const std::vector<uint8_t> body(payload.begin(), payload.end());
    const size_t udpLength = 8 + body.size();
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
    std::copy(body.begin(), body.end(), packet.begin() + 28);

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

// The two octets of the IPv4 identification field and the two of the IPv4
// header checksum are the only octets this fixture does not choose on a
// datagram the kernel itself built on the way into a TUN: the kernel picks the
// identification and recomputes the checksum over it. Clearing those four on
// both sides leaves a whole-buffer comparison that is still exact about the
// addressing, the ports and the payload.
std::vector<uint8_t> WithoutKernelOwnedIpFields(std::vector<uint8_t> packet)
{
    if (packet.size() >= 12)
    {
        packet[4] = packet[5] = 0;
        packet[10] = packet[11] = 0;
    }
    return packet;
}

} // namespace

// The acceptance lab. It owns both eNBs, the isolated MME relay, the scripted
// EPS peer, the test SGW endpoint, the application endpoint and the running UE.
namespace
{

class AcceptanceLab
{
  public:
    // Which SGW this lab owns. The Phase 18-D case sends its own downlink
    // datagrams to an endpoint it names; the Phase 18-E case needs the
    // isolated SGW whose forwarding map decides where a downlink goes. Only one
    // of them can hold the SGW address, so the lab owns exactly one.
    enum class SgwMode
    {
        RAW,
        ISOLATED
    };

    explicit AcceptanceLab(const std::string &tunBlock, SgwMode mode = SgwMode::RAW)
        : m_capture(std::make_unique<lte::test::LogCapture>()), m_sourceMme(m_relay, false),
          m_targetMme(m_relay, true)
    {
        if (mode == SgwMode::RAW)
            m_sgw = std::make_unique<SgwEndpoint>();
        else
            m_isolatedSgw =
                std::make_unique<IsolatedSgw>(ExecutionMode::ISOLATED_SIMULATOR, Ipv4Text(SgwAddress), 2152);
        EnbConfig source = TestEnbConfig(SourceEnbId, "127.0.0.1", 1);
        EnbConfig target = TestEnbConfig(TargetEnbId, "127.0.0.3", 2);
        m_source = std::make_unique<EnbMultiplexer>(source, m_sourceMme);
        m_target = std::make_unique<EnbMultiplexer>(target, m_targetMme);
        m_targetRadio = m_target->ueLinkAddress();
        m_config = lte::ue::ParseConfig(
            UeYaml(m_source->ueLinkAddress().getPort(), m_targetRadio.getPort(), tunBlock));
    }

    ~AcceptanceLab()
    {
        m_shutdown = true;
        if (m_ue.joinable())
            m_ue.join();
        if (m_appFd >= 0)
            ::close(m_appFd);
        if (m_dedicatedFd >= 0)
            ::close(m_dedicatedFd);
        if (m_dedicatedSinkFd >= 0)
            ::close(m_dedicatedSinkFd);
        // A run that failed before `finish()` has its whole transcript still
        // held by the capture, and doctest's own failure report went into the
        // same buffer. Spilling it to stderr here is the only way that report
        // is visible at all, and it is never printed on a run that finished.
        if (m_capture)
            std::cerr << m_capture->text();
        for (const auto &problem : m_problems)
            std::cerr << "[acceptance] scripted-peer problem: " << problem << "\n";
    }

    void startUe() { m_ue = std::thread([this] { m_exit = lte::ue::Run(m_config, m_shutdown); }); }

    // Joins the UE and releases std::cout so every later assertion is visible.
    void finish()
    {
        m_shutdown = true;
        if (m_ue.joinable())
            m_ue.join();
        m_source->poll(64, 64);
        m_target->poll(64, 64);
        if (m_capture)
        {
            log = m_capture->text();
            m_capture.reset();
        }
    }

    const lte::ue::Config &config() const { return m_config; }
    EnbMultiplexer &source() { return *m_source; }
    EnbMultiplexer &target() { return *m_target; }
    IsolatedMmeRelay &relay() { return m_relay; }
    HandoverCoordinator &coordinator() { return m_relay.coordinator(); }
    SgwEndpoint &sgw() { return *m_sgw; }
    IsolatedSgw &isolatedSgw() { return *m_isolatedSgw; }
    // Every S1AP PDU the target eNB really transmitted to its MME endpoint.
    const std::vector<std::vector<uint8_t>> &targetMmeWire() const { return m_targetMme.received(); }
    const InetAddress &targetRadio() const { return m_targetRadio; }
    int exitCode() const { return m_exit; }
    std::string log;

    // The default bearer's application endpoint. Its UDP pair is named by no
    // filter of the dedicated bearer's TFT, so everything sent here belongs to
    // the default bearer by the running UE's own matching.
    bool openApplication() { return (m_appFd = OpenBoundSocket(ApplicationPort, PdnIpv4)) >= 0; }
    bool sendApplication(const std::string &text)
    {
        return SendDatagram(m_appFd, PeerPort, PeerIpv4, std::vector<uint8_t>(text.begin(), text.end()));
    }
    std::vector<Datagram> applicationDatagrams() { return DrainSocket(m_appFd); }

    // The dedicated bearer's two endpoints. The uplink socket speaks the exact
    // UDP 7000 -> 5000 flow the captured TFT's uplink filter names, so the
    // running UE selects the dedicated bearer for it and nothing else; the sink
    // socket is what the captured TFT's downlink filter addresses, so a
    // downlink datagram that filter names lands there and nowhere else.
    bool openDedicatedApplication()
    {
        m_dedicatedFd = OpenBoundSocket(DedicatedLocalPort, PdnIpv4);
        m_dedicatedSinkFd = OpenBoundSocket(DedicatedPeerPort, PdnIpv4);
        return m_dedicatedFd >= 0 && m_dedicatedSinkFd >= 0;
    }
    bool sendDedicatedApplication(const std::string &text)
    {
        return SendDatagram(m_dedicatedFd, DedicatedPeerPort, PeerIpv4,
                            std::vector<uint8_t>(text.begin(), text.end()));
    }
    std::vector<Datagram> dedicatedSinkDatagrams() { return DrainSocket(m_dedicatedSinkFd); }

    // Drives every simulated endpoint until `done()` holds or the budget runs
    // out. The scripted EPS peer answers on this thread, exactly as the
    // accepted UE mobility cases do.
    template <typename Done>
    bool drive(Done done, int timeoutMs)
    {
        const auto deadline = Clock::now() + std::chrono::milliseconds(timeoutMs);
        while (Clock::now() < deadline)
        {
            pumpMme();
            m_source->poll(64, 64);
            m_target->poll(64, 64);
            if (done())
                return true;
            std::this_thread::sleep_for(std::chrono::milliseconds(2));
        }
        return done();
    }

    // The scripted EPS peer. It consumes the NAS the source eNB's production
    // S1AP dispatcher produced and answers with network-authored S1AP and NAS.
    bool attachComplete() const { return m_attachComplete; }
    bool dedicatedConfirmed() const { return m_dedicatedConfirmed; }
    uint32_t enbUeS1apId() const { return m_enbUeS1apId; }

  private:
    static EnbConfig TestEnbConfig(uint32_t enbId, const std::string &address, uint32_t tac)
    {
        EnbConfig config{};
        config.plmn = TestPlmn();
        config.enbId = enbId;
        config.tac = static_cast<uint16_t>(tac);
        config.localAddress = address;
        config.mmeAddress = "127.0.0.1";
        config.ueLinkAddress = address;
        config.ueLinkPort = 0;
        config.s1uAddress = address;
        config.s1uPort = 2152;
        config.allowLoopbackS1u = true;
        config.maxUes = 8;
        return config;
    }

    static std::string UeYaml(uint16_t sourceRadioPort, uint16_t targetRadioPort, const std::string &tunBlock)
    {
        std::ostringstream out;
        out << R"(ueId: )"
            << UeRadioId << R"(
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
  localPort: )"
            << UeLocalPort << R"(
  address: 127.0.0.1
  port: )"
            << sourceRadioPort << R"(
  tac: 1
  enbId: )"
            << SourceEnbId << R"(
  targetCell:
    mcc: '460'
    mnc: '02'
    tac: 2
    address: 127.0.0.3
    port: )"
            << targetRadioPort << R"(
    enbId: )"
            << TargetEnbId << R"(
  timeoutMs: 10000
tun:
)"
            << tunBlock << R"(
lifecycle:
  scenario: attach-only
  triggerAfterMs: 1000
  procedureTimeoutMs: 30000
  maxRetries: 2
  pagingWaitMs: 30000
  recoveryDelayMs: 0
  recoveryRetryMs: 5000
  recoveryMaxAttempts: 0
)";
        return out.str();
    }

    void pumpMme()
    {
        const auto &rx = m_sourceMme.received();
        while (m_seen < rx.size())
        {
            const std::vector<uint8_t> pdu = rx[m_seen++];
            S1apPdu probe{};
            try
            {
                probe = ProbeS1apPdu(pdu.data(), pdu.size());
            }
            catch (const std::exception &e)
            {
                note(std::string("the scripted peer could not probe an uplink: ") + e.what());
                continue;
            }
            // Only the two messages that carry a UE's NAS uplink are this
            // peer's business. Everything else the source eNB sends — the
            // Initial Context Setup Response, the E-RAB Setup Response — is an
            // outcome of a message this peer authored and needs no answer.
            if (probe.kind != S1apPdu::Kind::INITIATING)
                continue;
            if (probe.procedureCode != kProcedureInitialUeMessage && probe.procedureCode != kProcedureUplinkNasTransport)
                continue;
            UplinkNas uplink{};
            try
            {
                uplink = DecodeUplinkNas(pdu.data(), pdu.size());
            }
            catch (const std::exception &e)
            {
                note(std::string("the scripted peer could not read a NAS uplink: ") + e.what());
                continue;
            }
            m_enbUeS1apId = uplink.enbUeS1apId;
            onNas(uplink.nasPdu);
        }
    }

    // Everything the scripted peer could not do, so a silent skip is never
    // mistaken for a message that never arrived.
    [[nodiscard]] const std::vector<std::string> &problems() const { return m_problems; }
    void note(const std::string &text) { m_problems.push_back(text); }

    void onNas(const std::vector<uint8_t> &payload)
    {
        if (payload.size() >= 2 && payload[0] == 0x07 && payload[1] == 0x41)
        {
            const auto challenge = AuthRequestBytes();
            m_security = nas::Authenticate(m_config,
                                           nas::DecodeAuthenticationRequest(challenge.data(), challenge.size()))
                             .context;
            m_security.advertisedSecurityCapabilities.assign(m_config.networkCapability.begin(),
                                                             m_config.networkCapability.end());
            sendNas(challenge);
            return;
        }
        if (payload.size() >= 2 && payload[0] == 0x07 && payload[1] == 0x53)
        {
            sendNas(SecurityModeCommand());
            return;
        }
        std::vector<uint8_t> plain;
        uint32_t count = 0;
        try
        {
            const auto parsed = nas::ParseProtectedHeader(payload.data(), payload.size());
            const bool fresh = nas::StartsNewContext(parsed.headerType);
            count = fresh ? parsed.sequenceNumber
                          : nas::EstimateNasCount(m_security.ulNasCount, parsed.sequenceNumber);
            if (!fresh && count <= m_security.ulNasCount)
                return note("the scripted peer saw a replayed uplink NAS COUNT");
            plain = nas::UnprotectBody(m_security, true, parsed.headerType, parsed.sequenceNumber, parsed.mac,
                                       parsed.plain);
        }
        catch (const std::exception &e)
        {
            return note(std::string("the scripted peer could not unprotect an uplink: ") + e.what());
        }
        m_security.ulNasCount = count;
        if (plain.size() >= 2 && plain[0] == 0x07 && plain[1] == 0x5E)
        {
            // Security Mode Complete. The network now assigns the default
            // bearer and the GUTI the session is addressed by, and it does so
            // through the source eNB's real Initial Context Setup entry point.
            sendNas(ProtectDownlink(AttachAccept(), false));
            sendIcsr();
            return;
        }
        if (plain.size() >= 2 && plain[0] == 0x07 && plain[1] == 0x43)
        {
            m_attachComplete = true;
            // The dedicated bearer is established by the network's own E-RAB
            // Setup Request, and that request is what carries the Activate
            // Dedicated EPS Bearer Context Request to the UE. The confirmation
            // the UE sends back therefore resolves against a bearer this eNB
            // already holds.
            sendErabSetup();
            return;
        }
        // Anything else is the Activate Dedicated EPS Bearer Context Accept.
        m_dedicatedConfirmed = true;
    }

    void sendNas(std::vector<uint8_t> nas)
    {
        const auto pdu = EncodeDownlinkNasTransport(MmeUeS1apId, m_enbUeS1apId, nas);
        m_source->handleS1ap(pdu.data(), pdu.size(), 1);
    }

    void sendIcsr()
    {
        InitialContextSetupRequest request{};
        request.mmeUeS1apId = MmeUeS1apId;
        request.enbUeS1apId = m_enbUeS1apId;
        request.ueAmbrUl = 1000;
        request.ueAmbrDl = 2000;
        request.erabs = {ErabItem(DefaultEbi, DefaultQci, SgwDefaultTeid)};
        const auto pdu = EncodeInitialContextSetupRequest(request);
        m_source->handleS1ap(pdu.data(), pdu.size(), 1);
    }

    void sendErabSetup()
    {
        ErabSetupRequest request{};
        request.mmeUeS1apId = MmeUeS1apId;
        request.enbUeS1apId = m_enbUeS1apId;
        request.erabs = {ErabItem(DedicatedEbi, DedicatedQci, SgwDedicatedTeid,
                                  ProtectDownlink(
                                      ActivateDedicated(DedicatedEbi, kDedicatedTft, DefaultEbi, DedicatedQci),
                                      false))};
        const auto pdu = EncodeErabSetupRequest(request);
        m_source->handleS1ap(pdu.data(), pdu.size(), 1);
    }

    std::vector<uint8_t> ProtectDownlink(const std::vector<uint8_t> &plain, bool newContext)
    {
        auto message = nas::Protect(m_security, /*uplink=*/false, newContext, plain);
        m_security.dlNasCount = (m_security.dlNasCount + 1U) & 0xFFFFFFU;
        return message;
    }

    // The Security Mode Command must reach the UE on the integrity-only "new
    // EPS security context" header so its information elements stay readable in
    // the clear. nas::Protect with a fresh context selects the ciphered
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
            (static_cast<uint8_t>(lte::ue::SecurityHeaderType::INTEGRITY_PROTECTED_WITH_NEW_CONTEXT) << 4U) | 0x07U);
        return envelope;
    }

    std::vector<uint8_t> AttachAccept() const
    {
        const auto plmn = EncodePlmn(TestPlmn());
        const std::vector<uint8_t> esm{static_cast<uint8_t>((DefaultEbi << 4U) | 0x02U), 0x01, 0xC1,
                                       0x01, 0x05,
                                       0x09, 0x08, 0x69, 0x6E, 0x74, 0x65, 0x72, 0x6E, 0x65, 0x74,
                                       0x05, 0x01, 0x0A, 0x00, 0x00, 0x01};
        std::vector<uint8_t> out{0x07, 0x42, 0x01, 0x30, 0x06, 0x40, plmn[0], plmn[1], plmn[2], 0x00, 0x01};
        out.push_back(static_cast<uint8_t>(esm.size() >> 8U));
        out.push_back(static_cast<uint8_t>(esm.size()));
        out.insert(out.end(), esm.begin(), esm.end());
        out.push_back(0x50);
        out.push_back(0x0B);
        out.push_back(0xF6);
        out.insert(out.end(), plmn.begin(), plmn.end());
        out.insert(out.end(), {0x00, 0x01, kMmeCode, 0xC0, 0x00, 0x01, 0x8E});
        return out;
    }

    // TS 36.413 procedure codes. Initial UE Message is 12 and Uplink NAS
    // Transport is 13; both are read out of the real envelope by the real
    // probe, and neither number is invented here.
    static constexpr uint16_t kProcedureInitialUeMessage = 12;
    static constexpr uint16_t kProcedureUplinkNasTransport = 13;

    std::unique_ptr<lte::test::LogCapture> m_capture;
    HandoverCoordinator m_coordinator{ExecutionMode::ISOLATED_SIMULATOR};
    IsolatedMmeRelay m_relay{m_coordinator};
    IsolatedMmeRelay::Endpoint m_sourceMme;
    IsolatedMmeRelay::Endpoint m_targetMme;
    std::unique_ptr<SgwEndpoint> m_sgw;
    std::unique_ptr<IsolatedSgw> m_isolatedSgw;
    std::unique_ptr<EnbMultiplexer> m_source;
    std::unique_ptr<EnbMultiplexer> m_target;
    InetAddress m_targetRadio;
    lte::ue::Config m_config;
    std::thread m_ue;
    std::atomic_bool m_shutdown{false};
    int m_exit{-1};
    int m_appFd{-1};
    int m_dedicatedFd{-1};
    int m_dedicatedSinkFd{-1};

    size_t m_seen{0};
    uint32_t m_enbUeS1apId{};
    UeSecurityContext m_security{};
    bool m_attachComplete{false};
    bool m_dedicatedConfirmed{false};
    std::vector<std::string> m_problems;
};

// The security material the isolated MME relay states about the UE for the
// handover. It is fixture data carried verbatim into the Handover Request, not
// a key this file derives: the request's security material comes from
// signalling and is never generated.
IsolatedUeSecurity TestSecurity()
{
    IsolatedUeSecurity security;
    security.encryptionAlgorithms = {0x80, 0x00};
    security.integrityAlgorithms = {0x40, 0x00};
    security.context.nextHopChainingCount = 3;
    for (size_t i = 0; i < security.context.nextHopParameter.size(); ++i)
        security.context.nextHopParameter[i] = static_cast<uint8_t>(0xA0 + i);
    return security;
}

HandoverTargetBinding TargetBinding(const InetAddress &radioEndpoint)
{
    HandoverTargetBinding binding;
    binding.identity = TargetIdentity();
    binding.cgi = CgiOf(TargetIdentity());
    binding.tai = Tai{TestPlmn(), TargetIdentity().tac};
    binding.radioEndpoint = radioEndpoint;
    binding.s1uAddress = SgwAddress;
    binding.encryptionAlgorithms = {0x80, 0x00};
    binding.integrityAlgorithms = {0x40, 0x00};
    binding.associationEpoch = 1;
    binding.permittedSource = SourceIdentity();
    binding.ready = true;
    return binding;
}

} // namespace

TEST_CASE("lte/handover/acceptance: a connected-mode handover executes end to end between two real eNBs" *
          doctest::skip())
{
    if (std::getenv("UNIRANSIM_RUN_PRIVILEGED_TUN_TESTS") == nullptr)
        FAIL("the phase 18-D acceptance requires UNIRANSIM_RUN_PRIVILEGED_TUN_TESTS=1");

    // The TUN name prefix is swept before the run so a run that died before the
    // production UE could release its interface cannot be mistaken for one that
    // never made one.
    if (!ListInterfaces(kTunPrefix).empty())
        FAIL("the acceptance needs an unused TUN name prefix");

    std::vector<std::string> steps;
    auto step = [&steps](int number, const std::string &text) {
        steps.push_back(std::to_string(number) + ": " + text);
        MESSAGE("step " << number << " — " << text);
    };

    AcceptanceLab lab("  required: true\n"
                      "  namePrefix: \"u18d\"\n"
                      "  mtu: 1400\n"
                      "  routes:\n"
                      "    - \"198.18.0.2/32\"");

    // --- Step 1: one UE is connected to the Source. ----------------------
    lab.startUe();
    const bool attached = lab.drive([&] { return lab.attachComplete() && lab.dedicatedConfirmed(); }, 20000);
    REQUIRE(attached);
    const bool bearerActive = lab.drive(
        [&] {
            const auto *entry = lab.source().registry().find(UeRadioId);
            return entry != nullptr && entry->bearer.active() && !entry->dedicatedBearers.empty() &&
                   entry->dedicatedBearers.front().active();
        },
        10000);
    REQUIRE(bearerActive);
    auto *sourceEntry = lab.source().registry().find(UeRadioId);
    REQUIRE(sourceEntry != nullptr);
    step(1, "the running UE is attached to the source eNB and holds an S1 connection");

    // --- Step 2: active default and dedicated bearers. -------------------
    REQUIRE(sourceEntry->bearer.kind() == BearerKind::DEFAULT);
    REQUIRE(sourceEntry->dedicatedBearers.size() == 1);
    const auto &sourceDedicated = sourceEntry->dedicatedBearers.front();
    REQUIRE(sourceDedicated.kind() == BearerKind::DEDICATED);
    REQUIRE(sourceEntry->bearer.parameters().erabId == DefaultEbi);
    REQUIRE(sourceDedicated.parameters().erabId == DedicatedEbi);
    REQUIRE(sourceDedicated.parameters().linkedDefaultEbi == DefaultEbi);
    REQUIRE(sourceEntry->bearer.ueIpv4() == PdnIpv4);
    const uint32_t sourceDefaultTeid = sourceEntry->bearer.parameters().localTeid;
    const uint32_t sourceDedicatedTeid = sourceDedicated.parameters().localTeid;
    const uint32_t sourceGeneration = sourceEntry->accessGeneration;
    REQUIRE(sourceDefaultTeid != 0);
    REQUIRE(sourceDedicatedTeid != 0);
    step(2, "the default and the dedicated bearer are both active on the source");

    // --- Section 15, before the trigger: real traffic on the source's active
    //     bearers. The application socket feeds the packet into the UE's own
    //     TUN, the running UE forwards it over the simulated radio link and the
    //     source encapsulates it for the SGW endpoint the E-RAB named. It is a
    //     real G-PDU that left the source's own S1-U socket.
    // The application endpoint binds the UE's own PDN address, which only
    // becomes local once the production UE has configured its TUN with it.
    const std::string defaultUplinkText = "uniransim phase 18-D default uplink";
    const std::string dedicatedUplinkText = "uniransim phase 18-D dedicated uplink";
    REQUIRE(lab.openApplication());
    REQUIRE(lab.openDedicatedApplication());
    REQUIRE(lab.sendApplication(defaultUplinkText));
    REQUIRE(lab.sendDedicatedApplication(dedicatedUplinkText));
    // Two independent uplink flows, one per bearer. The default flow is a UDP
    // pair the dedicated bearer's TFT names nothing about; the dedicated flow
    // is exactly the UDP 7000 -> 5000 pair its uplink filter names, so the
    // running UE's own TFT matching is what selects that bearer. Each must
    // leave the source's own S1-U socket as a G-PDU on the SGW TEID of the
    // bearer it belongs to, and neither may borrow the other's.
    std::vector<uint8_t> defaultUplinkPacket;
    std::vector<uint8_t> dedicatedUplinkPacket;
    const bool uplinkArrived = lab.drive(
        [&] {
            for (const auto &datagram : lab.sgw().drain())
            {
                const auto packet = gtpu::Decode(datagram.data(), datagram.size());
                if (packet.messageType != gtpu::TPdu)
                    continue;
                if (packet.teid == SgwDefaultTeid)
                    defaultUplinkPacket = packet.payload;
                else if (packet.teid == SgwDedicatedTeid)
                    dedicatedUplinkPacket = packet.payload;
            }
            return !defaultUplinkPacket.empty() && !dedicatedUplinkPacket.empty();
        },
        8000);
    REQUIRE(uplinkArrived);
    {
        const auto expectedDefault = BuildUdpIpv4(PdnIpv4, PeerIpv4, ApplicationPort, PeerPort, defaultUplinkText);
        const auto expectedDedicated =
            BuildUdpIpv4(PdnIpv4, PeerIpv4, DedicatedLocalPort, DedicatedPeerPort, dedicatedUplinkText);
        REQUIRE(WithoutKernelOwnedIpFields(defaultUplinkPacket) == WithoutKernelOwnedIpFields(expectedDefault));
        REQUIRE(WithoutKernelOwnedIpFields(dedicatedUplinkPacket) == WithoutKernelOwnedIpFields(expectedDedicated));
    }

    // --- Step 3: a verified trigger selects the Target. ------------------
    // The trigger is the harness's own decision, but the selection is the
    // production one: an explicit inventory with exactly one authorized
    // target, chosen by the target's own eNB identifier. Nothing is scanned
    // and no address the UE named is consulted.
    // The only way a verified session comes into existence is out of the live
    // source registry. This is the production extractor, not a record this
    // file assembled, so a fact the registry does not hold refuses the whole
    // session rather than appearing as a plausible blank.
    const SourceSession session = ExtractSourceSession(*sourceEntry, SourceIdentity(), CgiOf(SourceIdentity()),
                                                       lab.source().associationEpoch());
    REQUIRE(session.isVerified());
    REQUIRE(session.ueIpv4 == PdnIpv4);
    REQUIRE(session.roles.size() == 2);
    REQUIRE(session.roles[0].role == BearerRole::DEFAULT);
    REQUIRE(session.roles[1].role == BearerRole::DEDICATED);
    REQUIRE(session.roles[1].linkedDefaultErabId == DefaultEbi);
    REQUIRE(session.roles[0].qci == DefaultQci);
    REQUIRE(session.roles[1].qci == DedicatedQci);

    const HandoverTargetBinding binding = TargetBinding(lab.targetRadio());
    const std::vector<HandoverTargetBinding> inventory{binding};
    const HandoverTargetBinding *selected = nullptr;
    CoordinationRefusalRecord selectFailure;
    REQUIRE(HandoverCoordinator::SelectTarget(session, inventory, TargetEnbId, selected, &selectFailure));
    REQUIRE(selected != nullptr);
    step(3, "the verified source session selected the one authorized target from the explicit inventory");

    // --- Step 4: the Source emits a Handover Required. -------------------
    CoordinationRecord opened;
    CoordinationRefusalRecord openFailure;
    REQUIRE(lab.coordinator().openTransaction(session, *selected, MmeUeS1apId, lab.source().associationEpoch(),
                                              binding.associationEpoch, std::chrono::seconds{30}, &opened,
                                              &openFailure));
    REQUIRE(opened.transaction.associationEpoch == lab.source().associationEpoch());
    const HandoverTransactionId transaction = opened.transaction;

    HandoverRequired required;
    CoordinationRefusalRecord requiredFailure;
    REQUIRE(BuildHandoverRequired(session, TargetIdentity(), "radioNetwork",
                                  CauseHandoverDesirableForRadioReasons, &required, &requiredFailure));
    const auto requiredPdu = EncodeHandoverRequired(required);
    REQUIRE_FALSE(requiredPdu.empty());
    const auto requiredAgain = DecodeHandoverRequired(requiredPdu.data(), requiredPdu.size());
    REQUIRE(requiredAgain.mmeUeS1apId == MmeUeS1apId);
    REQUIRE(requiredAgain.handoverType == HandoverType::INTRA_LTE);
    step(4, "the source's production codec produced a Handover Required naming the selected target");

    // --- Steps 5 to 8: the isolated MME relays the preparation. ----------
    const PreparationHop hop =
        lab.relay().relayPreparation(requiredPdu, transaction, binding, TestSecurity(), lab.target(),
                                     binding.associationEpoch);
    REQUIRE(hop.delivered);
    REQUIRE_FALSE(hop.requiredPdu.empty());
    REQUIRE_FALSE(hop.requestPdu.empty());
    REQUIRE_FALSE(hop.acknowledgePdu.empty());
    REQUIRE_FALSE(hop.commandPdu.empty());
    REQUIRE(hop.failurePdu.empty());
    REQUIRE(hop.arrivalToken != 0);
    step(5, "the isolated MME relayed a Handover Request built from the record to the target");
    step(6, "the target admitted the bearer set and committed real transport for it");
    step(7, "the target produced a Handover Request Acknowledge from what it committed");
    step(8, "the isolated MME relayed the Handover Command back to the source");

    // The Acknowledge names the transport the target actually bound, and the
    // Command carries the very container the Acknowledge produced.
    const auto acknowledge = DecodeHandoverRequestAcknowledge(hop.acknowledgePdu.data(), hop.acknowledgePdu.size());
    REQUIRE(acknowledge.admitted.size() == 2);
    REQUIRE(acknowledge.failed.empty());
    const auto command = DecodeHandoverCommand(hop.commandPdu.data(), hop.commandPdu.size());
    REQUIRE(command.dataForwarding.empty());
    REQUIRE(command.targetToSource == acknowledge.targetToSource);
    REQUIRE(IsSimulatedContainer(command.targetToSource));

    // The target's preparation is provisional: a UE that has not arrived.
    const auto *preparedEntry = lab.target().registry().findByEnbUeS1apId(acknowledge.enbUeS1apId);
    REQUIRE(preparedEntry != nullptr);
    REQUIRE(UeRegistry::isProvisional(*preparedEntry));
    REQUIRE(preparedEntry->radioUeId == 0);
    REQUIRE_FALSE(preparedEntry->bearer.active());
    const uint32_t targetDefaultTeid = preparedEntry->bearer.parameters().localTeid;
    REQUIRE(targetDefaultTeid != 0);
    REQUIRE(targetDefaultTeid != sourceDefaultTeid);
    REQUIRE(preparedEntry->dedicatedBearers.size() == 1);
    const uint32_t targetDedicatedTeid = preparedEntry->dedicatedBearers.front().parameters().localTeid;
    REQUIRE(targetDedicatedTeid != 0);
    REQUIRE(targetDedicatedTeid != sourceDedicatedTeid);

    // Step 15 boundary, before arrival: the prepared bearer is not forwardable
    // yet, and a G-PDU for its own TEID is dropped rather than delivered.
    {
        const auto packet = BuildUdpIpv4(PeerIpv4, PdnIpv4, PeerPort, ApplicationPort, "premature");
        lab.sgw().sendDownlink(lab.target().s1uAddress(), targetDefaultTeid, packet);
        const bool dropped = lab.drive(
            [&] {
                const auto *entry = lab.target().registry().findByLocalTeid(targetDefaultTeid);
                return entry != nullptr && entry->counters.bearerInactiveDrops > 0;
            },
            4000);
        REQUIRE(dropped);
    }

    // --- Step 9: the source sends the simulated handover command. --------
    // It goes over the source's existing production radio sender, to the UE
    // entry the source is already serving. Nothing is released and no TEID is
    // retired at command-send time.
    CommandDelivery delivery = DeliverHandoverCommand(lab.source(), *sourceEntry, lab.coordinator(), transaction,
                                                      command, binding);
    REQUIRE(delivery.delivered);
    REQUIRE(delivery.command.arrivalToken == hop.arrivalToken);
    REQUIRE(delivery.command.targetEnbId == TargetEnbId);
    REQUIRE(delivery.command.mmeUeS1apId == MmeUeS1apId);
    REQUIRE(delivery.command.ueIpv4 == PdnIpv4);
    step(9, "the source's production radio sender delivered the simulated handover command to the UE");

    // The source is untouched: same bearers, same TEIDs, same access epoch.
    // A command-send is not a release, so nothing here may have moved.
    {
        const auto *entry = lab.source().registry().find(UeRadioId);
        REQUIRE(entry != nullptr);
        REQUIRE(entry->bearer.active());
        REQUIRE(entry->bearer.parameters().localTeid == sourceDefaultTeid);
        REQUIRE(entry->dedicatedBearers.front().parameters().localTeid == sourceDedicatedTeid);
        REQUIRE(entry->accessGeneration == sourceGeneration);
        REQUIRE(entry->mmeUeS1apId == MmeUeS1apId);
    }

    // --- Steps 10 to 12: the UE runtime executes the handover. -----------
    // The UE's own receive path validates the command against its configured
    // target cell, relocates to the target's radio endpoint and transmits the
    // Handover Access from its own socket. Nothing in this file writes that
    // frame or calls the target on the UE's behalf.
    const bool arrived = lab.drive([&] { return lab.target().lastVerifiedArrival().has_value(); }, 15000);
    REQUIRE(arrived);
    step(10, "the running UE runtime received the command in its own radio receive path");
    step(11, "the UE changed to the target's authorized radio endpoint");
    step(12, "the UE transmitted the encoded Handover Access from its own socket");

    const auto &verified = *lab.target().lastVerifiedArrival();
    REQUIRE(verified.arrivalToken == hop.arrivalToken);
    REQUIRE(verified.radioUeId == UeRadioId);
    REQUIRE(verified.ueIpv4 == PdnIpv4);
    REQUIRE(verified.source.enbId == SourceEnbId);
    REQUIRE(verified.target.enbId == TargetEnbId);
    step(13, "the target's production radio receive path accepted and verified the arrival");

    // The isolated MME records that same verified arrival as the coordination
    // state machine's TARGET_ARRIVAL_CONFIRMED event. It is not a step of the
    // section 14 sequence and no caller supplies it: the relay reads the
    // target's own lastVerifiedArrival, which is the only arrival evidence it
    // accepts, so nothing here can confirm an arrival the target never proved.
    {
        CoordinationRefusalRecord arrivalFailure;
        REQUIRE(lab.relay().confirmTargetArrival(lab.target(), &arrivalFailure));
    }

    // --- Step 14: the target promotes its original provisional context. --
    // It is a move of one registry entry, not a re-establishment: the same
    // local S1-U TEIDs and the same S1AP identity pair.
    {
        const auto *reached = lab.target().registry().find(UeRadioId);
        REQUIRE(reached != nullptr);
        REQUIRE(reached->radioUeId == UeRadioId);
        REQUIRE(reached->bearer.parameters().localTeid == targetDefaultTeid);
        REQUIRE(reached->dedicatedBearers.front().parameters().localTeid == targetDedicatedTeid);
        REQUIRE(reached->mmeUeS1apId == MmeUeS1apId);
    }
    step(14, "the target promoted its original provisional context to the reached UE");

    // --- Step 15: the prepared bearers are activated and carry user plane.
    {
        const auto *reached = lab.target().registry().find(UeRadioId);
        REQUIRE(reached != nullptr);
        REQUIRE(reached->bearer.active());
        REQUIRE(reached->dedicatedBearers.front().active());
        REQUIRE(reached->bearer.ueIpv4() == PdnIpv4);
    }
    step(15, "the target activated the prepared bearer readiness for the reached UE");

    // Section 15: two test-owned downlink G-PDUs through the isolated
    // production S1-U receiver, each on the original prepared TEID of its own
    // bearer, reach the now target-associated UE. These are packets this file
    // sent into the target's real S1-U socket. It is not a real SGW redirect,
    // no Modify Bearer Request was executed and nothing here claims live EPC
    // continuity.
    //
    // Each downlink addresses the UDP pair its own bearer's flow speaks: the
    // default one is the pair no dedicated filter names and the dedicated one
    // is the pair the captured TFT's downlink filter names. Each therefore
    // lands on its own socket and neither can be mistaken for the other.
    //
    // A delivered datagram is its payload and its source four-tuple: the kernel
    // only hands it to the socket after checking the IPv4 header and the UDP
    // checksum of the whole datagram the UE wrote into its TUN, so anything
    // whose header or checksum differed would not have arrived here at all.
    {
        const std::string text = "uniransim phase 18-D default downlink";
        const std::vector<uint8_t> expected(text.begin(), text.end());
        const auto packet = BuildUdpIpv4(PeerIpv4, PdnIpv4, PeerPort, ApplicationPort, text);
        std::vector<Datagram> received;
        lab.sgw().sendDownlink(lab.target().s1uAddress(), targetDefaultTeid, packet);
        const bool delivered = lab.drive(
            [&] {
                received = lab.applicationDatagrams();
                return !received.empty();
            },
            8000);
        REQUIRE(delivered);
        REQUIRE(received.size() == 1);
        REQUIRE(received.front().payload == expected);
        REQUIRE(received.front().source == PeerIpv4);
        REQUIRE(received.front().sourcePort == PeerPort);
        REQUIRE(lab.dedicatedSinkDatagrams().empty());
    }
    {
        const std::string text = "uniransim phase 18-D dedicated downlink";
        const std::vector<uint8_t> expected(text.begin(), text.end());
        const auto packet = BuildUdpIpv4(PeerIpv4, PdnIpv4, DedicatedLocalPort, DedicatedPeerPort, text);
        std::vector<Datagram> received;
        lab.sgw().sendDownlink(lab.target().s1uAddress(), targetDedicatedTeid, packet);
        const bool delivered = lab.drive(
            [&] {
                received = lab.dedicatedSinkDatagrams();
                return !received.empty();
            },
            8000);
        REQUIRE(delivered);
        REQUIRE(received.size() == 1);
        REQUIRE(received.front().payload == expected);
        REQUIRE(received.front().source == PeerIpv4);
        // The captured TFT's downlink filter is remote port 7000 to local port
        // 5000, so on a downlink datagram the port the uplink filter calls
        // local is the one the peer sends from.
        REQUIRE(received.front().sourcePort == DedicatedLocalPort);
        REQUIRE(lab.applicationDatagrams().empty());
    }

    // No unexpected UE receives traffic: the target serves exactly one UE and
    // the source's UE entry is still the one it always was.
    REQUIRE(lab.target().registry().all().size() == 1);
    REQUIRE(lab.source().registry().find(UeRadioId) != nullptr);

    // --- Step 16: the target sends the Handover Notify. ------------------
    const HandoverNotifyOutcome outcome = lab.target().notifyHandover(transaction);
    REQUIRE(outcome.sent);
    REQUIRE(outcome.message.has_value());
    step(16, "the target sent the Handover Notify over its own S1AP association");

    // --- Step 17: the isolated MME observes the actual encoded Notify. ---
    // The observation happens on the wire as the target sends, because the
    // association is real: the endpoint recorded the bytes and the relay
    // decoded them with the production codec while they arrived. Nothing here
    // assembles a Notify for the relay to read.
    {
        const auto &wire = lab.targetMmeWire();
        REQUIRE_FALSE(wire.empty());
        const auto &notifyPdu = wire.back();
        REQUIRE_FALSE(lab.relay().lastRefusal().has_value());
        const auto notify = DecodeHandoverNotify(notifyPdu.data(), notifyPdu.size());
        REQUIRE(notify.mmeUeS1apId == MmeUeS1apId);
        REQUIRE(notify.enbUeS1apId != 0);
        REQUIRE(notify.cgi.plmn.mcc == TestPlmn().mcc);
        REQUIRE(notify.cgi.plmn.mnc == TestPlmn().mnc);
        REQUIRE(notify.cgi.cellId == CgiOf(TargetIdentity()).cellId);
        REQUIRE(notify.tai.tac == TargetIdentity().tac);

        // A repeat of the same notification is the same event and moves
        // nothing, which is also how a relay that already accepted this one
        // answers a second time.
        CoordinationRefusalRecord notifyFailure;
        REQUIRE(lab.relay().acceptHandoverNotify(notifyPdu, transaction, &notifyFailure));
    }
    step(17, "the isolated MME decoded and accepted the Handover Notify the target really sent");

    // --- Step 18: the transaction reaches the deliberate final state. ---
    const CoordinationRecord *record = lab.coordinator().find(transaction);
    REQUIRE(record != nullptr);
    REQUIRE(record->state == OrchestrationState::AWAITING_CORE_PATH_UPDATE);
    REQUIRE(IsTerminal(record->state));
    step(18, "the transaction reached AWAITING_CORE_PATH_UPDATE");

    // Nothing here claimed a core path update, a source release or a
    // completed handover. The source still holds its own bearers and its own
    // TEIDs, and no UE Context Release was sent.
    {
        const auto *entry = lab.source().registry().find(UeRadioId);
        REQUIRE(entry != nullptr);
        REQUIRE(entry->bearer.parameters().localTeid == sourceDefaultTeid);
        REQUIRE(entry->dedicatedBearers.front().parameters().localTeid == sourceDedicatedTeid);
        REQUIRE_FALSE(entry->bearer.parameters().localTeid == targetDefaultTeid);
    }

    REQUIRE(steps.size() == 18);
    lab.finish();
    REQUIRE(lab.exitCode() == 0);

    // Concrete log observations for the same sequence, read out of the run's
    // own transcript now that its clean shutdown has been observed. A run that
    // exits through a failure path prints no statistics block at all, so the
    // statistics are only read here because the shutdown line is one of the
    // things checked below.
    {
        const std::string &transcript = lab.log;
        const auto contains = [&transcript](const std::string &needle) {
            return transcript.find(needle) != std::string::npos;
        };
        const auto occurrences = [&transcript](const std::string &needle) {
            size_t count = 0;
            for (size_t at = transcript.find(needle); at != std::string::npos; at = transcript.find(needle, at + 1))
                ++count;
            return count;
        };

        // Step 1: the running UE attached to the source and is connected.
        CHECK(contains("State=UE_CONNECTED_TO_ENB"));
        CHECK(contains("EPS Attach complete; persistent IPv4 user plane is active"));
        // Step 2: the default and the dedicated bearer are both active there.
        CHECK(contains("S1-U user plane ready for LTE UE " + std::to_string(UeRadioId) + " IPv4 10.0.0.1"));
        CHECK(contains("Dedicated EPS bearer 6 activated (QCI=7, linked-EBI=5, filters=2)"));
        CHECK(contains("Dedicated EPS bearer 6 ready for forwarding on LTE UE " + std::to_string(UeRadioId)));
        // The S1 context binding the UE checks the command against instead of
        // adopting it out of the command it is to check.
        CHECK(contains("S1 context established (eNB-UE-S1AP-ID=1, MME-UE-S1AP-ID=" + std::to_string(MmeUeS1apId) + ")"));
        // Steps 9-12: the UE consumed the command, moved its radio transport
        // and transmitted the Handover Access from its own socket.
        CHECK(contains("Connected-mode handover command accepted (MME-UE-S1AP-ID=" + std::to_string(MmeUeS1apId) +
                       "); radio transport moved to the authorized target cell 460/02/2"));
        CHECK(contains("SIMULATED_HANDOVER_ACCESS sent to the target cell"));
        // Steps 13-14: the target's production radio receive path proved it.
        CHECK(contains("Verified handover arrival of LTE UE " + std::to_string(UeRadioId) + " to this cell from eNB " +
                       std::to_string(SourceEnbId) + "; MME-UE-S1AP-ID=" + std::to_string(MmeUeS1apId)));
        // One registration and no synthetic Attach or idle Service Request
        // anywhere in the run.
        CHECK(occurrences("State=ATTACH_REQUEST_SENT") == 1);
        CHECK(occurrences("State=ATTACH_COMPLETE_SENT") == 1);
        CHECK_FALSE(contains("compact EPS Service Request"));
        CHECK_FALSE(contains("bearer-inventory Service Request"));
        // The clean shutdown, and what the run reports of its own user plane:
        // two uplink and two downlink TUN datagrams, one of each per bearer.
        CHECK(contains("LTE UE shutdown complete"));
        CHECK(contains("tun-ul=2/"));
        CHECK(contains("tun-dl=2/"));
        CHECK(contains("dedicated-ul=1 dedicated-dl=1"));
    }

    std::fprintf(stderr, "=== production log ===\n%s=== end of production log ===\n", lab.log.c_str());

    // Sentinels the privileged job matches on. A case that never reached its
    // own body prints neither, so the job cannot call that a pass.
    MESSAGE("UNIRANSIM-PHASE18D-PRIVILEGED-EXECUTED");
    MESSAGE("UNIRANSIM-PHASE18D-PRIVILEGED-COMPLETE");
}

TEST_CASE("lte/handover/acceptance: mme-controlled core path migration and source release complete an isolated s1 "
          "handover" *
          doctest::skip())
{
    if (std::getenv("UNIRANSIM_RUN_PRIVILEGED_TUN_TESTS") == nullptr)
        FAIL("the phase 18-E acceptance requires UNIRANSIM_RUN_PRIVILEGED_TUN_TESTS=1");

    // A different TUN name prefix from the Phase 18-D case, so a run that died
    // before the production UE could release its interface cannot be mistaken
    // for one that never made one, and the two cases cannot collide.
    if (!ListInterfaces("u18e").empty())
        FAIL("the phase 18-E acceptance needs an unused TUN name prefix");

    std::vector<std::string> steps;
    auto step = [&steps](int number, const std::string &text) {
        steps.push_back(std::to_string(number) + ": " + text);
        MESSAGE("step " << number << " — " << text);
    };

    AcceptanceLab lab("  required: true\n"
                      "  namePrefix: \"u18e\"\n"
                      "  mtu: 1400\n"
                      "  routes:\n"
                      "    - \"198.18.0.2/32\"",
                      AcceptanceLab::SgwMode::ISOLATED);

    // --- Steps 1 to 2: one connected UE with both bearers active. --------
    lab.startUe();
    const bool attached = lab.drive([&] { return lab.attachComplete() && lab.dedicatedConfirmed(); }, 20000);
    REQUIRE(attached);
    const bool bearerActive = lab.drive(
        [&] {
            const auto *entry = lab.source().registry().find(UeRadioId);
            return entry != nullptr && entry->bearer.active() && !entry->dedicatedBearers.empty() &&
                   entry->dedicatedBearers.front().active();
        },
        10000);
    REQUIRE(bearerActive);
    auto *sourceEntry = lab.source().registry().find(UeRadioId);
    REQUIRE(sourceEntry != nullptr);
    step(1, "the running UE is attached to the source eNB and holds an S1 connection");
    REQUIRE(sourceEntry->bearer.ueIpv4() == PdnIpv4);
    REQUIRE(sourceEntry->dedicatedBearers.size() == 1);
    const uint32_t sourceDefaultTeid = sourceEntry->bearer.parameters().localTeid;
    const uint32_t sourceDedicatedTeid = sourceEntry->dedicatedBearers.front().parameters().localTeid;
    REQUIRE(sourceDefaultTeid != 0);
    REQUIRE(sourceDedicatedTeid != 0);
    step(2, "the default and the dedicated bearer are both active on the source");

    // --- Step 3: the SGW map points at the source. ------------------------
    const IsolatedSessionKey session{MmeUeS1apId, PdnIpv4};
    const std::array<uint8_t, 4> sourceS1u{127, 0, 0, 1};
    std::vector<AcceptedTargetEndpoint> sourceEndpoints;
    {
        AcceptedTargetEndpoint defaultBearer;
        defaultBearer.ebi = DefaultEbi;
        defaultBearer.role = BearerRole::DEFAULT;
        defaultBearer.sgwTeid = SgwDefaultTeid;
        defaultBearer.endpoint = IsolatedDownlinkEndpoint{sourceS1u, sourceDefaultTeid, 2152};
        AcceptedTargetEndpoint dedicated;
        dedicated.ebi = DedicatedEbi;
        dedicated.role = BearerRole::DEDICATED;
        dedicated.linkedDefaultEbi = DefaultEbi;
        dedicated.sgwTeid = SgwDedicatedTeid;
        dedicated.endpoint = IsolatedDownlinkEndpoint{sourceS1u, sourceDedicatedTeid, 2152};
        sourceEndpoints = {defaultBearer, dedicated};
    }
    CorePathRefusalRecord installFailure;
    REQUIRE(lab.isolatedSgw().installSession(session, lab.source().associationEpoch(), sourceEndpoints,
                                             &installFailure));
    REQUIRE(*lab.isolatedSgw().generationOf(session) == 1);
    step(3, "the isolated SGW holds a source downlink mapping for both bearers");


    // --- Steps 4 and 5: SGW-originated traffic reaches the source UE. -----
    // The sender names a bearer and never a destination: the map decides. The
    // application sockets are the ones each bearer's own flow speaks, so a
    // datagram arriving on the wrong bearer's socket would be visible.
    REQUIRE(lab.openApplication());
    REQUIRE(lab.openDedicatedApplication());

    // The two uplink flows, one per bearer, so the source's own forwarding is
    // live before anything moves. Each leaves the source's S1-U socket as a
    // G-PDU on its own bearer's SGW TEID and reaches the SGW's real socket.
    REQUIRE(lab.sendApplication("uniransim phase 18-E default uplink before the switch"));
    REQUIRE(lab.sendDedicatedApplication("uniransim phase 18-E dedicated uplink before the switch"));
    {
        std::vector<IsolatedSgw::ReceivedUplink> uplink;
        REQUIRE(lab.drive(
            [&] {
                for (auto &item : lab.isolatedSgw().drainUplink())
                    uplink.push_back(std::move(item));
                return uplink.size() >= 2;
            },
            8000));
        std::vector<uint32_t> teids;
        for (const auto &item : uplink)
            teids.push_back(item.sgwTeid);
        std::sort(teids.begin(), teids.end());
        CHECK(teids == std::vector<uint32_t>{SgwDefaultTeid, SgwDedicatedTeid});
    }
    {
        const std::string text = "uniransim phase 18-E default downlink before the switch";
        const std::vector<uint8_t> expected(text.begin(), text.end());
        const auto packet = BuildUdpIpv4(PeerIpv4, PdnIpv4, PeerPort, ApplicationPort, text);
        REQUIRE(lab.isolatedSgw().sendDownlink(session, DefaultEbi, packet.data(), packet.size()));
        std::vector<Datagram> received;
        REQUIRE(lab.drive(
            [&] {
                received = lab.applicationDatagrams();
                return !received.empty();
            },
            8000));
        REQUIRE(received.size() == 1);
        CHECK(received.front().payload == expected);
        CHECK(received.front().source == PeerIpv4);
        CHECK(received.front().sourcePort == PeerPort);
        CHECK(lab.dedicatedSinkDatagrams().empty());
    }
    step(4, "the isolated SGW sent a default-bearer downlink that the source UE received");
    {
        const std::string text = "uniransim phase 18-E dedicated downlink before the switch";
        const std::vector<uint8_t> expected(text.begin(), text.end());
        const auto packet = BuildUdpIpv4(PeerIpv4, PdnIpv4, DedicatedLocalPort, DedicatedPeerPort, text);
        REQUIRE(lab.isolatedSgw().sendDownlink(session, DedicatedEbi, packet.data(), packet.size()));
        std::vector<Datagram> received;
        REQUIRE(lab.drive(
            [&] {
                received = lab.dedicatedSinkDatagrams();
                return !received.empty();
            },
            8000));
        REQUIRE(received.size() == 1);
        CHECK(received.front().payload == expected);
        CHECK(received.front().sourcePort == DedicatedLocalPort);
        CHECK(lab.applicationDatagrams().empty());
    }
    step(5, "the isolated SGW sent a dedicated-bearer downlink that the source UE received");

    // --- Steps 6 to 17: the accepted Phase 18-D sequence, unchanged. ------
    const SourceSession sourceSession = ExtractSourceSession(*sourceEntry, SourceIdentity(),
                                                             CgiOf(SourceIdentity()), lab.source().associationEpoch());
    REQUIRE(sourceSession.isVerified());
    const HandoverTargetBinding binding = TargetBinding(lab.targetRadio());
    const std::vector<HandoverTargetBinding> inventory{binding};
    const HandoverTargetBinding *selected = nullptr;
    CoordinationRefusalRecord selectFailure;
    REQUIRE(HandoverCoordinator::SelectTarget(sourceSession, inventory, TargetEnbId, selected, &selectFailure));

    CoordinationRecord opened;
    CoordinationRefusalRecord openFailure;
    REQUIRE(lab.coordinator().openTransaction(sourceSession, *selected, MmeUeS1apId,
                                              lab.source().associationEpoch(), binding.associationEpoch,
                                              std::chrono::seconds{30}, &opened, &openFailure));
    const HandoverTransactionId transaction = opened.transaction;

    HandoverRequired required;
    CoordinationRefusalRecord requiredFailure;
    REQUIRE(BuildHandoverRequired(sourceSession, TargetIdentity(), "radioNetwork",
                                  CauseHandoverDesirableForRadioReasons, &required, &requiredFailure));
    const auto requiredPdu = EncodeHandoverRequired(required);
    step(6, "the source initiated an S1 handover with a Handover Required naming the target");

    const PreparationHop hop = lab.relay().relayPreparation(requiredPdu, transaction, binding, TestSecurity(),
                                                           lab.target(), binding.associationEpoch);
    REQUIRE(hop.delivered);
    REQUIRE(hop.arrivalToken != 0);
    step(7, "the isolated MME coordinated the target's preparation");
    step(8, "the target committed its own local S1-U resources");

    const auto command = DecodeHandoverCommand(hop.commandPdu.data(), hop.commandPdu.size());
    const CommandDelivery delivery =
        DeliverHandoverCommand(lab.source(), *sourceEntry, lab.coordinator(), transaction, command, binding);
    REQUIRE(delivery.delivered);
    step(9, "the source sent the simulated handover command through its own production radio sender");

    const bool arrived = lab.drive([&] { return lab.target().lastVerifiedArrival().has_value(); }, 15000);
    REQUIRE(arrived);
    step(10, "the running UE runtime received the command and changed its radio endpoint");
    step(11, "the target received and verified the UE's arrival in its own production receive path");

    const auto *reached = lab.target().registry().find(UeRadioId);
    REQUIRE(reached != nullptr);
    const uint32_t targetDefaultTeid = reached->bearer.parameters().localTeid;
    const uint32_t targetDedicatedTeid = reached->dedicatedBearers.front().parameters().localTeid;
    REQUIRE(targetDefaultTeid != 0);
    REQUIRE(targetDedicatedTeid != 0);
    REQUIRE(reached->bearer.active());
    REQUIRE(reached->dedicatedBearers.front().active());
    step(12, "the target promoted and activated the prepared bearers for the reached UE");

    {
        CoordinationRefusalRecord arrivalFailure;
        REQUIRE(lab.relay().confirmTargetArrival(lab.target(), &arrivalFailure));
    }
    REQUIRE(lab.target().notifyHandover(transaction).sent);
    REQUIRE_FALSE(lab.relay().lastRefusal().has_value());
    step(13, "the target sent the Handover Notify over its own S1AP association");
    {
        const auto *record = lab.coordinator().find(transaction);
        REQUIRE(record != nullptr);
        REQUIRE(record->state == OrchestrationState::AWAITING_CORE_PATH_UPDATE);
    }
    step(14, "the isolated MME verified the Notify and the transaction reached the phase 18-D boundary");

    // --- Steps 15 to 17: the isolated core moves the whole bearer set. ----
    const CorePathOutcome update = lab.relay().requestCorePathUpdate(lab.isolatedSgw(), lab.target(), transaction);
    REQUIRE(update.committed);
    REQUIRE(update.confirmed);
    REQUIRE(update.state.has_value());
    REQUIRE(*update.state == OrchestrationState::CORE_PATH_UPDATED);
    step(15, "the isolated MME requested the bearer path migration");
    step(16, "the isolated SGW atomically replaced every accepted downlink endpoint");
    CHECK(lab.isolatedSgw().installed(session, DefaultEbi)->endpoint.teid == targetDefaultTeid);
    CHECK(lab.isolatedSgw().installed(session, DedicatedEbi)->endpoint.teid == targetDedicatedTeid);
    CHECK(lab.isolatedSgw().installed(session, DefaultEbi)->originalSource.teid == sourceDefaultTeid);
    CHECK(lab.isolatedSgw().installed(session, DedicatedEbi)->originalSource.teid == sourceDedicatedTeid);
    step(17, "the isolated MME verified the installed mapping against the exact request");

    // The source is untouched by the update: it still holds its context and
    // its transport, because nothing has released it.
    REQUIRE(lab.source().registry().find(UeRadioId) != nullptr);
    CHECK_FALSE(lab.source().registry().isRetiredTeid(sourceDefaultTeid));

    // --- Steps 18 to 20: the same SGW instance now sends to the target. ---
    // The call is identical to steps 4 and 5. Only the map changed.
    {
        const std::string text = "uniransim phase 18-E default downlink after the switch";
        const std::vector<uint8_t> expected(text.begin(), text.end());
        const auto packet = BuildUdpIpv4(PeerIpv4, PdnIpv4, PeerPort, ApplicationPort, text);
        REQUIRE(lab.isolatedSgw().sendDownlink(session, DefaultEbi, packet.data(), packet.size()));
        std::vector<Datagram> received;
        REQUIRE(lab.drive(
            [&] {
                received = lab.applicationDatagrams();
                return !received.empty();
            },
            8000));
        REQUIRE(received.size() == 1);
        CHECK(received.front().payload == expected);
        CHECK(received.front().source == PeerIpv4);
        CHECK(lab.dedicatedSinkDatagrams().empty());
    }
    step(18, "the same SGW instance sent the default downlink to the target's local TEID");
    {
        const std::string text = "uniransim phase 18-E dedicated downlink after the switch";
        const std::vector<uint8_t> expected(text.begin(), text.end());
        const auto packet = BuildUdpIpv4(PeerIpv4, PdnIpv4, DedicatedLocalPort, DedicatedPeerPort, text);
        REQUIRE(lab.isolatedSgw().sendDownlink(session, DedicatedEbi, packet.data(), packet.size()));
        std::vector<Datagram> received;
        REQUIRE(lab.drive(
            [&] {
                received = lab.dedicatedSinkDatagrams();
                return !received.empty();
            },
            8000));
        REQUIRE(received.size() == 1);
        CHECK(received.front().payload == expected);
        CHECK(received.front().sourcePort == DedicatedLocalPort);
        CHECK(lab.applicationDatagrams().empty());
    }
    step(19, "the same SGW instance sent the dedicated downlink to the target's local TEID");
    {
        const auto *moved = lab.target().registry().find(UeRadioId);
        REQUIRE(moved != nullptr);
        CHECK(moved->bearer.ueIpv4() == PdnIpv4);
        CHECK(moved->bearer.parameters().erabId == DefaultEbi);
        CHECK(moved->dedicatedBearers.front().parameters().erabId == DedicatedEbi);
        CHECK(moved->dedicatedBearers.front().parameters().linkedDefaultEbi == DefaultEbi);
        CHECK(lab.source().registry().find(UeRadioId) != nullptr);
    }
    step(20, "the target UE received both through its own S1-U and radio path with its PDN address unchanged");

    // --- Step 21: an old-path End Marker changes no release state. --------
    {
        const uint64_t endMarkersBefore = lab.source().s1uCounters().endMarkers;
        const uint64_t activeBefore = lab.source().s1uCounters().endMarkerActiveTunnels;
        REQUIRE(lab.isolatedSgw().sendEndMarker(session, DefaultEbi));
        const bool recorded =
            lab.drive([&] { return lab.source().s1uCounters().endMarkers > endMarkersBefore; }, 4000);
        REQUIRE(recorded);
        CHECK(lab.source().s1uCounters().endMarkerActiveTunnels == activeBefore + 1);
        // The End Marker released nothing: the source still holds its context
        // and its TEIDs, the core path is still generation 2, and the
        // transaction is still where the core update left it.
        CHECK(lab.source().registry().find(UeRadioId) != nullptr);
        CHECK_FALSE(lab.source().registry().isRetiredTeid(sourceDefaultTeid));
        CHECK(*lab.isolatedSgw().generationOf(session) == 2);
        const auto *record = lab.coordinator().find(transaction);
        REQUIRE(record != nullptr);
        CHECK(record->state == OrchestrationState::CORE_PATH_UPDATED);
    }
    step(21, "the old-path End Marker was recorded as a control message and released nothing");

    // --- Steps 22 to 27: the MME authorizes and the source releases. ------
    SourceReleaseRefusalRecord guardFailure;
    REQUIRE(lab.relay().armSourceRelease(transaction, Clock::now(), std::chrono::milliseconds{50}, &guardFailure));
    {
        const auto *record = lab.coordinator().find(transaction);
        REQUIRE(record != nullptr);
        CHECK(record->state == OrchestrationState::SOURCE_RELEASE_WAIT);
        CHECK_FALSE(SourceReleaseGuardSatisfied(*record, Clock::now()));
    }
    CHECK_FALSE(lab.relay().releaseSource(lab.source(), transaction, Clock::now()).sent);
    CHECK(lab.source().registry().find(UeRadioId) != nullptr);
    step(22, "the source-release guard was armed and the early release was refused");
    std::this_thread::sleep_for(std::chrono::milliseconds{70});

    const SourceReleaseStepOutcome released = lab.relay().releaseSource(lab.source(), transaction, Clock::now());
    REQUIRE(released.sent);
    REQUIRE(released.confirmed);
    step(23, "the isolated MME sent a real encoded UE Context Release Command to the source");
    step(24, "the source validated the original handover identity and association");
    CHECK(lab.source().registry().find(UeRadioId) == nullptr);
    CHECK(lab.source().registry().findByMmeUeS1apId(MmeUeS1apId) == nullptr);
    CHECK(lab.source().registry().isRetiredTeid(sourceDefaultTeid));
    CHECK(lab.source().registry().isRetiredTeid(sourceDedicatedTeid));
    step(25, "the source retired its original local S1-U TEIDs");
    step(26, "the source returned a real encoded UE Context Release Complete");
    {
        const auto *record = lab.coordinator().find(transaction);
        REQUIRE(record != nullptr);
        REQUIRE(record->state == OrchestrationState::ISOLATED_HANDOVER_COMPLETE);
        CHECK(record->sourceRelease.evidence == SourceReleaseEvidence::RELEASE_COMPLETE);
        const auto complete = DecodeUeContextReleaseComplete(record->sourceRelease.completePdu.data(),
                                                             record->sourceRelease.completePdu.size());
        CHECK(complete.mmeUeS1apId == MmeUeS1apId);
        CHECK(complete.enbUeS1apId == record->source.enbUeS1apId);
    }
    step(27, "the isolated MME verified the Release Complete against the transaction");

    // --- Step 28: a delayed G-PDU on an old source TEID is rejected. ------
    {
        const uint64_t retiredBefore = lab.source().s1uCounters().retiredTeidDrops;
        const std::string text = "uniransim phase 18-E delayed old-path packet";
        const auto packet = BuildUdpIpv4(PeerIpv4, PdnIpv4, PeerPort, ApplicationPort, text);
        const auto datagram = gtpu::EncodeTPdu(sourceDefaultTeid, packet.data(), packet.size());
        udp::UdpServer lateSender{"127.0.0.2", 2153};
        lateSender.Send(lab.source().s1uAddress(), datagram.data(), datagram.size());
        const bool rejected =
            lab.drive([&] { return lab.source().s1uCounters().retiredTeidDrops > retiredBefore; }, 4000);
        REQUIRE(rejected);
        // It reached no socket of the UE's.
        CHECK(lab.applicationDatagrams().empty());
    }
    step(28, "a delayed G-PDU for the retired source TEID was rejected as retired");

    // --- Steps 29 to 31: the target keeps working and nothing else moved. -
    {
        const std::string text = "uniransim phase 18-E default downlink after the release";
        const std::vector<uint8_t> expected(text.begin(), text.end());
        const auto packet = BuildUdpIpv4(PeerIpv4, PdnIpv4, PeerPort, ApplicationPort, text);
        REQUIRE(lab.isolatedSgw().sendDownlink(session, DefaultEbi, packet.data(), packet.size()));
        std::vector<Datagram> received;
        REQUIRE(lab.drive(
            [&] {
                received = lab.applicationDatagrams();
                return !received.empty();
            },
            8000));
        REQUIRE(received.size() == 1);
        CHECK(received.front().payload == expected);
    }
    {
        const std::string text = "uniransim phase 18-E dedicated downlink after the release";
        const std::vector<uint8_t> expected(text.begin(), text.end());
        const auto packet = BuildUdpIpv4(PeerIpv4, PdnIpv4, DedicatedLocalPort, DedicatedPeerPort, text);
        REQUIRE(lab.isolatedSgw().sendDownlink(session, DedicatedEbi, packet.data(), packet.size()));
        std::vector<Datagram> received;
        REQUIRE(lab.drive(
            [&] {
                received = lab.dedicatedSinkDatagrams();
                return !received.empty();
            },
            8000));
        REQUIRE(received.size() == 1);
        CHECK(received.front().payload == expected);
    }
    {
        // The target kept exactly what it owned, and the source's cleanup
        // retired nothing there.
        const auto *kept = lab.target().registry().find(UeRadioId);
        REQUIRE(kept != nullptr);
        CHECK(kept->bearer.parameters().localTeid == targetDefaultTeid);
        CHECK(kept->dedicatedBearers.front().parameters().localTeid == targetDedicatedTeid);
        CHECK(kept->bearer.active());
        CHECK(kept->dedicatedBearers.front().active());
        CHECK_FALSE(lab.target().registry().isRetiredTeid(targetDefaultTeid));
        CHECK_FALSE(lab.target().registry().isRetiredTeid(targetDedicatedTeid));
        CHECK(lab.target().registry().all().size() == 1);
        CHECK(lab.source().registry().all().empty());
    }
    // Both uplink flows still leave the target's S1-U socket on their own
    // bearer's SGW TEID after the source context is gone.
    REQUIRE(lab.sendApplication("uniransim phase 18-E default uplink after the release"));
    REQUIRE(lab.sendDedicatedApplication("uniransim phase 18-E dedicated uplink after the release"));
    {
        std::vector<IsolatedSgw::ReceivedUplink> uplink;
        REQUIRE(lab.drive(
            [&] {
                for (auto &item : lab.isolatedSgw().drainUplink())
                    uplink.push_back(std::move(item));
                return uplink.size() >= 2;
            },
            8000));
        std::vector<uint32_t> teids;
        for (const auto &item : uplink)
            teids.push_back(item.sgwTeid);
        std::sort(teids.begin(), teids.end());
        CHECK(teids == std::vector<uint32_t>{SgwDefaultTeid, SgwDedicatedTeid});
    }
    step(29, "the target's default and dedicated bearers still carry traffic after the source release");
    step(30, "no other UE or subscriber context changed");
    step(31, "the transaction reached ISOLATED_HANDOVER_COMPLETE");

    REQUIRE(steps.size() == 31);
    lab.finish();
    REQUIRE(lab.exitCode() == 0);

    // The run's own transcript, read after its clean shutdown.
    {
        const std::string &transcript = lab.log;
        const auto contains = [&transcript](const std::string &needle) {
            return transcript.find(needle) != std::string::npos;
        };
        const auto occurrences = [&transcript](const std::string &needle) {
            size_t count = 0;
            for (size_t at = transcript.find(needle); at != std::string::npos; at = transcript.find(needle, at + 1))
                ++count;
            return count;
        };

        CHECK(contains("Isolated SGW holds the source downlink path of MME-UE-S1AP-ID=" + std::to_string(MmeUeS1apId)));
        CHECK(contains("Isolated SGW published downlink path generation 2"));
        CHECK(contains("Isolated MME confirmed downlink path generation 2"));
        CHECK(contains("Isolated SGW sent an End Marker on the old path"));
        CHECK(contains("GTP-U End Marker for active tunnel TEID"));
        CHECK(contains("Source-release guard armed"));
        CHECK(contains("Isolated MME sent a UE Context Release Command (radioNetwork/successful-handover)"));
        CHECK(contains("Released the source S1 context of LTE UE " + std::to_string(UeRadioId) +
                       " for a completed handover"));
        CHECK(contains("Isolated MME verified the UE Context Release Complete"));
        CHECK(contains("Dropped S1-U T-PDU for retired TEID"));
        CHECK(contains("no idle-release notification was sent"));

        // One registration, and no Attach or Service Request anywhere in the
        // handover or the release.
        CHECK(occurrences("State=ATTACH_REQUEST_SENT") == 1);
        CHECK(occurrences("State=ATTACH_COMPLETE_SENT") == 1);
        CHECK_FALSE(contains("compact EPS Service Request"));
        CHECK_FALSE(contains("bearer-inventory Service Request"));

        // Real user plane through the kernel TUN in both directions: two
        // uplink datagrams from the UE's own sockets, and four downlink ones —
        // two before the switch and two after it.
        CHECK(contains("LTE UE shutdown complete"));
        CHECK(contains("tun-ul=4/"));
        // Two downlinks before the migration, two after it, and two more after
        // the source release.
        CHECK(contains("tun-dl=6/"));
    }

    std::fprintf(stderr, "=== production log ===\n%s=== end of production log ===\n", lab.log.c_str());

    MESSAGE("UNIRANSIM-PHASE18E-PRIVILEGED-EXECUTED");
    MESSAGE("UNIRANSIM-PHASE18E-PRIVILEGED-COMPLETE");
}

