//
// This file is a part of UERANSIM project.
// Copyright (c) 2027 ALİ GÜNGÖR.
//
// Phase 18-F-B6-D7: deterministic SGW-U / PGW-U user-plane endpoint.
//
// This process is test infrastructure, not an EPC. It terminates the real GTP-U
// tunnel that the production eNB opens (UDP, port 2152, G-PDU, TEID) and moves
// the decapsulated IPv4 packets into a real Linux TUN. A packet written to that
// TUN by the kernel is encapsulated again towards the eNB. No IP packet is ever
// passed to or from the eNB by a function call.
//
// The bearer map is a deterministic test control plane (explicitly not S11 or
// GTP-C): the eNB/MME peer writes it atomically after the eNB answered the
// Initial Context Setup, and this process installs the downlink mapping from it.
//
// Usage:
//   lte-uu-sgw-peer --gtpu-address <veth-ip> [--gtpu-port 2152]
//                   --core-tun-prefix <name> --core-ip <ipv4> --ue-ip <ipv4>
//                   [--mtu 1500] --map-file <path> --ready-file <path>
//                   --result-file <path> [--stop-file <path>]
#include <lte/enb/gtpu.hpp>
#include <lte/ip_packet.hpp>
#include <lte/ue/tun.hpp>
#include <lte/ue/types.hpp>
#include <lib/udp/server.hpp>
#include <utils/network.hpp>

#include <atomic>
#include <chrono>
#include <csignal>
#include <cstdint>
#include <cstring>
#include <fstream>
#include <iostream>
#include <map>
#include <optional>
#include <sstream>
#include <string>
#include <vector>

#include <unistd.h>

namespace
{

std::atomic_bool g_stop{false};
void Signal(int) { g_stop = true; }

std::string Trim(const std::string &text)
{
    const auto begin = text.find_first_not_of(" \t\r\n");
    if (begin == std::string::npos)
        return {};
    const auto end = text.find_last_not_of(" \t\r\n");
    return text.substr(begin, end - begin + 1);
}

std::array<uint8_t, 4> ParseIpv4(const std::string &text)
{
    std::array<uint8_t, 4> address{};
    std::istringstream stream(text);
    std::string part;
    int index = 0;
    while (std::getline(stream, part, '.'))
    {
        if (index >= 4)
            throw std::runtime_error("invalid IPv4 address: " + text);
        const int value = std::stoi(part);
        if (value < 0 || value > 255)
            throw std::runtime_error("invalid IPv4 address: " + text);
        address[index++] = static_cast<uint8_t>(value);
    }
    if (index != 4)
        throw std::runtime_error("invalid IPv4 address: " + text);
    return address;
}

uint16_t ParsePort(const std::string &text)
{
    const int value = std::stoi(text);
    if (value <= 0 || value > 65535)
        throw std::runtime_error("invalid UDP port: " + text);
    return static_cast<uint16_t>(value);
}

uint32_t ParseTeid(const std::string &text)
{
    return static_cast<uint32_t>(std::stoul(text, nullptr, 0));
}

struct BearerMap
{
    uint64_t generation{0};
    std::array<uint8_t, 4> ueIpv4{};
    uint8_t ebi{0};
    uint32_t sgwTeid{0};
    uint32_t enbTeid{0};
    std::array<uint8_t, 4> enbAddress{};
    uint16_t enbPort{0};
};

std::optional<BearerMap> ReadMap(const std::string &path)
{
    std::ifstream in(path);
    if (!in)
        return std::nullopt;
    std::map<std::string, std::string> fields;
    std::string line;
    while (std::getline(in, line))
    {
        const auto equals = line.find('=');
        if (equals == std::string::npos)
            continue;
        fields[Trim(line.substr(0, equals))] = Trim(line.substr(equals + 1));
    }
    try
    {
        BearerMap map;
        map.generation = std::stoull(fields.at("generation"));
        map.ueIpv4 = ParseIpv4(fields.at("ue_ip"));
        map.ebi = static_cast<uint8_t>(std::stoi(fields.at("ebi")));
        map.sgwTeid = ParseTeid(fields.at("sgw_teid"));
        map.enbTeid = ParseTeid(fields.at("enb_teid"));
        map.enbAddress = ParseIpv4(fields.at("enb_address"));
        map.enbPort = ParsePort(fields.at("enb_port"));
        if (map.generation == 0 || map.ebi == 0 || map.sgwTeid == 0 || map.enbTeid == 0 ||
            map.ueIpv4 == std::array<uint8_t, 4>{} || map.enbAddress == std::array<uint8_t, 4>{})
            return std::nullopt;
        return map;
    }
    catch (const std::exception &)
    {
        return std::nullopt;
    }
}

struct Counters
{
    uint64_t ulPackets{};
    uint64_t ulBytes{};
    uint64_t dlPackets{};
    uint64_t dlBytes{};
    uint64_t ulTunBytes{};
    uint64_t dlTunBytes{};
    uint64_t malformedDrops{};
    uint64_t unknownTeidDrops{};
    uint64_t retiredTeidDrops{};
    uint64_t wrongPeerDrops{};
    uint64_t wrongSourceDrops{};
    uint64_t wrongDestinationDrops{};
    uint64_t tunDrops{};
    uint64_t mapUpdates{};
};

std::string ResultText(const Counters &counters, const std::optional<BearerMap> &active,
                       const std::vector<uint32_t> &retired, const std::string &tunName, const std::string &failure)
{
    std::ostringstream out;
    out << (failure.empty() ? "result=COMPLETE" : "result=FAILED") << "\n";
    if (!failure.empty())
        out << "reason=" << failure << "\n";
    out << "tun=" << tunName << "\n";
    out << "ul_packets=" << counters.ulPackets << "\n";
    out << "ul_bytes=" << counters.ulBytes << "\n";
    out << "dl_packets=" << counters.dlPackets << "\n";
    out << "dl_bytes=" << counters.dlBytes << "\n";
    out << "ul_tun_bytes=" << counters.ulTunBytes << "\n";
    out << "dl_tun_bytes=" << counters.dlTunBytes << "\n";
    out << "malformed_drops=" << counters.malformedDrops << "\n";
    out << "unknown_teid_drops=" << counters.unknownTeidDrops << "\n";
    out << "retired_teid_drops=" << counters.retiredTeidDrops << "\n";
    out << "wrong_peer_drops=" << counters.wrongPeerDrops << "\n";
    out << "wrong_source_drops=" << counters.wrongSourceDrops << "\n";
    out << "wrong_destination_drops=" << counters.wrongDestinationDrops << "\n";
    out << "tun_drops=" << counters.tunDrops << "\n";
    out << "map_updates=" << counters.mapUpdates << "\n";
    out << "active_sgw_teid=" << (active ? active->sgwTeid : 0) << "\n";
    out << "active_enb_teid=" << (active ? active->enbTeid : 0) << "\n";
    out << "active_generation=" << (active ? active->generation : 0) << "\n";
    out << "retired_teids=";
    for (size_t i = 0; i < retired.size(); ++i)
        out << (i == 0 ? "" : ",") << retired[i];
    out << "\n";
    return out.str();
}

void WriteFile(const std::string &path, const std::string &text)
{
    std::ofstream out(path);
    out << text;
}

} // namespace

int main(int argc, char **argv)
{
    std::string gtpuAddress;
    uint16_t gtpuPort = 2152;
    std::string tunPrefix = "d7core";
    std::string coreIp;
    std::string ueIp;
    int mtu = 1500;
    std::string mapPath;
    std::string readyPath;
    std::string resultPath;
    std::string stopPath;

    try
    {
        for (int i = 1; i < argc; ++i)
        {
            const std::string arg = argv[i];
            auto next = [&]() -> std::string {
                if (i + 1 >= argc)
                    throw std::runtime_error("missing value for " + arg);
                return argv[++i];
            };
            if (arg == "--gtpu-address")
                gtpuAddress = next();
            else if (arg == "--gtpu-port")
                gtpuPort = ParsePort(next());
            else if (arg == "--core-tun-prefix")
                tunPrefix = next();
            else if (arg == "--core-ip")
                coreIp = next();
            else if (arg == "--ue-ip")
                ueIp = next();
            else if (arg == "--mtu")
                mtu = std::stoi(next());
            else if (arg == "--map-file")
                mapPath = next();
            else if (arg == "--ready-file")
                readyPath = next();
            else if (arg == "--result-file")
                resultPath = next();
            else if (arg == "--stop-file")
                stopPath = next();
            else
                throw std::runtime_error("unknown argument " + arg);
        }
        if (gtpuAddress.empty() || coreIp.empty() || ueIp.empty() || mapPath.empty() || readyPath.empty() ||
            resultPath.empty())
            throw std::runtime_error("missing a required argument");
    }
    catch (const std::exception &e)
    {
        std::cerr << "lte-uu-sgw-peer: " << e.what() << std::endl;
        return 1;
    }

    Counters counters;
    std::vector<uint32_t> retired;
    std::optional<BearerMap> active;
    std::string tunName;
    std::string failure;

    try
    {
        const auto coreAddress = ParseIpv4(coreIp);
        const auto ueAddress = ParseIpv4(ueIp);
        lte::ue::TunConfig tunConfig;
        tunConfig.required = true;
        tunConfig.namePrefix = tunPrefix;
        tunConfig.mtu = mtu;
        // The only route the core side needs is the one back to the UE: a
        // packet destined for the UE IP is written into this TUN so it is read
        // here and encapsulated, instead of being routed anywhere else.
        tunConfig.routes.push_back(ueIp + "/32");
        lte::ue::TunDevice tun(tunConfig, coreAddress);
        tunName = tun.name();

        udp::UdpServer gtpu(gtpuAddress, gtpuPort);
        WriteFile(readyPath, "ready\n" + std::string("gtpu=") + gtpuAddress + ":" + std::to_string(gtpuPort) +
                                 "\ntun=" + tunName + "\n");
        std::signal(SIGINT, Signal);
        std::signal(SIGTERM, Signal);

        auto lastMapCheck = std::chrono::steady_clock::now() - std::chrono::hours(1);
        auto lastResult = lastMapCheck;
        uint8_t buffer[2048];
        std::vector<uint8_t> packet;

        while (!g_stop)
        {
            const auto now = std::chrono::steady_clock::now();
            if (!stopPath.empty() && std::ifstream(stopPath).good())
                break;

            if (now - lastMapCheck >= std::chrono::milliseconds(10))
            {
                lastMapCheck = now;
                const auto map = ReadMap(mapPath);
                if (map.has_value() && (!active.has_value() || map->generation > active->generation))
                {
                    if (map->ueIpv4 != ueAddress)
                    {
                        failure = "the bearer map names a different UE address than the Core TUN route";
                        break;
                    }
                    if (active.has_value() && active->sgwTeid != map->sgwTeid)
                        retired.push_back(active->sgwTeid);
                    active = map;
                    ++counters.mapUpdates;
                }
            }

            InetAddress peer;
            for (int gtpuBudget = 0; gtpuBudget < 32; ++gtpuBudget)
            {
                const int length = gtpu.Receive(buffer, sizeof(buffer), gtpuBudget == 0 ? 2 : 0, peer);
                if (length <= 0)
                    break;
                try
                {
                    const auto decoded = lte::enb::gtpu::Decode(buffer, static_cast<size_t>(length));
                    if (decoded.messageType != lte::enb::gtpu::TPdu)
                        throw std::runtime_error("not a G-PDU");
                    if (!active.has_value())
                    {
                        // The first uplink can overtake the periodic map poll;
                        // read the map once now instead of classifying a valid
                        // bearer as an unknown TEID.
                        const auto map = ReadMap(mapPath);
                        if (map.has_value() && map->ueIpv4 == ueAddress)
                        {
                            active = map;
                            ++counters.mapUpdates;
                        }
                    }
                    if (!active.has_value())
                    {
                        ++counters.unknownTeidDrops;
                        continue;
                    }
                    const InetAddress expectedPeer(lte::ue::Ipv4ToString(active->enbAddress), active->enbPort);
                    if (peer != expectedPeer)
                    {
                        ++counters.wrongPeerDrops;
                        continue;
                    }
                    if (decoded.teid != active->sgwTeid)
                    {
                        bool isRetired = false;
                        for (uint32_t value : retired)
                            isRetired |= value == decoded.teid;
                        if (isRetired)
                            ++counters.retiredTeidDrops;
                        else
                            ++counters.unknownTeidDrops;
                        continue;
                    }
                    const auto ipv4 = lte::ip::Validate(decoded.payload.data(), decoded.payload.size(),
                                                        static_cast<size_t>(mtu));
                    if (ipv4.source != ueAddress)
                    {
                        ++counters.wrongSourceDrops;
                        continue;
                    }
                    if (!tun.writePacket(decoded.payload.data(), decoded.payload.size()))
                    {
                        ++counters.tunDrops;
                        continue;
                    }
                    ++counters.ulPackets;
                    counters.ulBytes += decoded.payload.size();
                    counters.ulTunBytes += decoded.payload.size();
                }
                catch (const std::exception &)
                {
                    ++counters.malformedDrops;
                }
            }

            for (int budget = 0; budget < 16 && !g_stop; ++budget)
            {
                if (!tun.readPacket(packet))
                    break;
                if (!active.has_value())
                {
                    ++counters.unknownTeidDrops;
                    continue;
                }
                try
                {
                    const auto ipv4 = lte::ip::Validate(packet.data(), packet.size(), static_cast<size_t>(mtu));
                    if (ipv4.destination != active->ueIpv4)
                    {
                        ++counters.wrongDestinationDrops;
                        continue;
                    }
                    const auto wire = lte::enb::gtpu::EncodeTPdu(active->enbTeid, packet.data(), packet.size());
                    const InetAddress destination(lte::ue::Ipv4ToString(active->enbAddress), active->enbPort);
                    if (!gtpu.TrySend(destination, wire.data(), wire.size()))
                    {
                        ++counters.tunDrops;
                        continue;
                    }
                    ++counters.dlPackets;
                    counters.dlBytes += packet.size();
                    counters.dlTunBytes += packet.size();
                }
                catch (const std::exception &)
                {
                    ++counters.tunDrops;
                }
            }

            if (now - lastResult >= std::chrono::milliseconds(250))
            {
                lastResult = now;
                WriteFile(resultPath, ResultText(counters, active, retired, tunName, failure));
            }
        }
    }
    catch (const std::exception &e)
    {
        failure = failure.empty() ? std::string("SGW-U endpoint failed: ") + e.what() : failure;
    }

    WriteFile(resultPath, ResultText(counters, active, retired, tunName, failure));
    std::cout << "lte-uu-sgw-peer: " << (failure.empty() ? "complete" : failure)
              << " ul=" << counters.ulPackets << " dl=" << counters.dlPackets
              << " retired-teids=" << retired.size() << std::endl;
    return failure.empty() ? 0 : 1;
}
