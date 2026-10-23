//
// This file is a part of UERANSIM project.
// Copyright (c) 2027 ALİ GÜNGÖR.
//
// https://github.com/aligungr/UERANSIM/
// See README, LICENSE, and CONTRIBUTING files for licensing details.
//

#include "config.hpp"

#include <algorithm>
#include <cctype>
#include <cstdio>
#include <stdexcept>

#include <utils/yaml_utils.hpp>
#include <utils/octet_string.hpp>
#include <yaml-cpp/yaml.h>

namespace lte::ue
{
namespace
{
std::string Digits(const YAML::Node &node, const std::string &field, size_t minimum, size_t maximum)
{
    auto value = yaml::GetString(node, field, minimum, maximum);
    if (!std::all_of(value.begin(), value.end(), [](unsigned char c) { return std::isdigit(c) != 0; }))
        throw std::runtime_error("Field '" + field + "' must contain decimal digits only");
    return value;
}

void ValidateApn(const std::string &apn)
{
    size_t start{};
    while (start < apn.size())
    {
        const size_t end = apn.find('.', start);
        const size_t labelEnd = end == std::string::npos ? apn.size() : end;
        const size_t length = labelEnd - start;
        if (length == 0 || length > 63)
            throw std::runtime_error("Field 'apn' must contain labels of 1..63 characters");
        start = labelEnd + 1;
    }
    if (apn.back() == '.')
        throw std::runtime_error("Field 'apn' must not end with an empty label");
}

void ValidateTunNamePrefix(const std::string &name)
{
    if (name.empty() || name.size() > 14 ||
        !std::all_of(name.begin(), name.end(), [](unsigned char c) {
            return std::isalnum(c) != 0 || c == '-' || c == '_';
        }))
        throw std::runtime_error("Field 'tun.namePrefix' must be 1..14 alphanumeric, '-' or '_' characters");
}

void ValidateRoute(const std::string &route)
{
    unsigned a = 0, b = 0, c = 0, d = 0, prefix = 0;
    char extra = 0;
    if (std::sscanf(route.c_str(), "%u.%u.%u.%u/%u%c", &a, &b, &c, &d, &prefix, &extra) != 5 ||
        a > 255 || b > 255 || c > 255 || d > 255 || prefix == 0 || prefix > 32)
        throw std::runtime_error("Field 'tun.routes' must contain IPv4 CIDRs and must not contain a default route");
}

template <size_t N> std::array<uint8_t, N> Hex(const YAML::Node &node, const std::string &field)
{
    auto text = yaml::GetString(node, field, N * 2, N * 2);
    try
    {
        auto bytes = OctetString::FromHex(text);
        if (bytes.length() != static_cast<int>(N)) throw std::runtime_error("bad length");
        std::array<uint8_t, N> value{};
        std::copy(bytes.data(), bytes.data() + N, value.begin());
        return value;
    }
    catch (const std::exception &)
    {
        throw std::runtime_error("Field '" + field + "' must be exactly " + std::to_string(N * 2) + " hexadecimal digits");
    }
}

Config ParseNode(const YAML::Node &root)
{
    Config config{};
    config.imsi = Digits(root, "imsi", 5, 15);
    config.plmn.mcc = Digits(root, "mcc", 3, 3);
    config.plmn.mnc = Digits(root, "mnc", 2, 3);
    const int mcc = std::stoi(config.plmn.mcc);
    const int mnc = std::stoi(config.plmn.mnc);
    if (mcc < 1 || mcc > 999)
        throw std::runtime_error("Field 'mcc' must be in range 001..999");
    if (mnc < 0 || mnc > (config.plmn.mnc.size() == 2 ? 99 : 999))
        throw std::runtime_error("Field 'mnc' is out of range");
    if (config.imsi.rfind(config.plmn.mcc + config.plmn.mnc, 0) != 0)
        throw std::runtime_error("Field 'imsi' must begin with the configured MCC and MNC");
    config.key = Hex<16>(root, "k");
    if (yaml::HasField(root, "op")) config.op = Hex<16>(root, "op");
    if (yaml::HasField(root, "opc")) config.opc = Hex<16>(root, "opc");
    if (config.op.has_value() == config.opc.has_value())
        throw std::runtime_error("Specify exactly one of 'op' or 'opc'");
    config.amf = Hex<2>(root, "amf");
    config.initialSqn = Hex<6>(root, "initialSqn");
    if (yaml::HasField(root, "pdnType")) config.pdnType = yaml::GetString(root, "pdnType", 3, 6);
    if (config.pdnType != "IPv4" && config.pdnType != "IPv6" && config.pdnType != "IPv4v6")
        throw std::runtime_error("Field 'pdnType' must be IPv4, IPv6 or IPv4v6");
    if (yaml::HasField(root, "apn"))
    {
        config.apn = yaml::GetString(root, "apn", 1, 100);
        ValidateApn(*config.apn);
    }
    if (yaml::HasField(root, "networkCapability")) config.networkCapability = Hex<2>(root, "networkCapability");

    if (yaml::HasField(root, "tun"))
    {
        const auto tun = root["tun"];
        if (!tun.IsMap()) throw std::runtime_error("Field 'tun' must be a mapping");
        if (yaml::HasField(tun, "namePrefix"))
            config.tun.namePrefix = yaml::GetString(tun, "namePrefix", 1, 14);
        ValidateTunNamePrefix(config.tun.namePrefix);
        if (yaml::HasField(tun, "mtu")) config.tun.mtu = yaml::GetInt32(tun, "mtu", 576, 2000);
        if (yaml::HasField(tun, "routes"))
        {
            const auto routes = tun["routes"];
            if (!routes.IsSequence()) throw std::runtime_error("Field 'tun.routes' must be a sequence");
            if (routes.size() > 32) throw std::runtime_error("Field 'tun.routes' has too many entries");
            for (const auto &routeNode : routes)
            {
                const std::string route = routeNode.as<std::string>();
                ValidateRoute(route);
                config.tun.routes.push_back(route);
            }
        }
    }

    const auto link = root["enbLink"];
    if (!link || !link.IsMap()) throw std::runtime_error("Field 'enbLink' must be a mapping");
    config.link.localAddress = yaml::GetIpAddress(link, "localAddress");
    config.link.localPort = static_cast<uint16_t>(yaml::GetInt32(link, "localPort", 1, 65535));
    config.link.enbAddress = yaml::GetIpAddress(link, "address");
    config.link.enbPort = static_cast<uint16_t>(yaml::GetInt32(link, "port", 1, 65535));
    if (yaml::HasField(link, "timeoutMs")) config.link.timeoutMs = yaml::GetInt32(link, "timeoutMs", 100, 60000);
    return config;
}
} // namespace

Config ParseConfig(const std::string &yamlText)
{
    try { return ParseNode(YAML::Load(yamlText)); }
    catch (const YAML::Exception &e) { throw std::runtime_error(std::string("Invalid LTE UE YAML: ") + e.what()); }
}

Config LoadConfig(const std::string &path)
{
    try { return ParseNode(YAML::LoadFile(path)); }
    catch (const YAML::Exception &e) { throw std::runtime_error(std::string("Unable to load LTE UE configuration: ") + e.what()); }
}
} // namespace lte::ue
