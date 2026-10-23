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
#include <stdexcept>

#include <utils/yaml_utils.hpp>
#include <yaml-cpp/yaml.h>

namespace lte::enb
{

namespace
{

std::string ReadDigits(const YAML::Node &node, const std::string &field, size_t minimum, size_t maximum)
{
    std::string value = yaml::GetString(node, field, minimum, maximum);
    if (!std::all_of(value.begin(), value.end(), [](unsigned char c) { return std::isdigit(c) != 0; }))
        throw std::runtime_error("Field '" + field + "' must contain decimal digits only");
    return value;
}

EnbConfig ParseNode(const YAML::Node &root)
{
    EnbConfig result{};
    result.plmn.mcc = ReadDigits(root, "mcc", 3, 3);
    result.plmn.mnc = ReadDigits(root, "mnc", 2, 3);

    int mcc = std::stoi(result.plmn.mcc);
    int mnc = std::stoi(result.plmn.mnc);
    if (mcc < 1 || mcc > 999)
        throw std::runtime_error("Field 'mcc' must be in range 001..999");
    if (mnc < 0 || mnc > (result.plmn.mnc.size() == 2 ? 99 : 999))
        throw std::runtime_error("Field 'mnc' is out of range");

    result.enbId = static_cast<uint32_t>(yaml::GetInt64(root, "enbId", 0, 0xFFFFF));
    result.tac = static_cast<uint16_t>(yaml::GetInt32(root, "tac", 0, 0xFFFF));
    if (yaml::HasField(root, "enbName"))
        result.enbName = yaml::GetString(root, "enbName", 1, 150);

    result.localAddress = yaml::GetIpAddress(root, "s1apIp");

    const YAML::Node mme = root["mme"];
    if (!mme || !mme.IsMap())
        throw std::runtime_error("Field 'mme' must be a mapping");
    result.mmeAddress = yaml::GetIpAddress(mme, "address");
    result.mmePort = static_cast<uint16_t>(yaml::GetInt32(mme, "port", 1, 65535));

    result.pagingDrx = yaml::GetInt32(root, "pagingDrx", 32, 256);
    if (result.pagingDrx != 32 && result.pagingDrx != 64 && result.pagingDrx != 128 && result.pagingDrx != 256)
        throw std::runtime_error("Field 'pagingDrx' must be one of 32, 64, 128 or 256");

    if (yaml::HasField(root, "ueLink"))
    {
        const YAML::Node link = root["ueLink"];
        if (!link.IsMap())
            throw std::runtime_error("Field 'ueLink' must be a mapping");
        result.ueLinkAddress = yaml::GetIpAddress(link, "address");
        result.ueLinkPort = static_cast<uint16_t>(yaml::GetInt32(link, "port", 1, 65535));
    }

    if (yaml::HasField(root, "s1u"))
    {
        const YAML::Node s1u = root["s1u"];
        if (!s1u.IsMap())
            throw std::runtime_error("Field 's1u' must be a mapping");
        result.s1uAddress = yaml::GetIpAddress(s1u, "address");
        result.s1uPort = static_cast<uint16_t>(yaml::GetInt32(s1u, "port", 1, 65535));
    }

    if (yaml::HasField(root, "sctp"))
    {
        const YAML::Node sctp = root["sctp"];
        if (!sctp.IsMap())
            throw std::runtime_error("Field 'sctp' must be a mapping");
        if (yaml::HasField(sctp, "maxAttempts"))
            result.retry.maxAttempts = yaml::GetInt32(sctp, "maxAttempts", 1, 100);
        if (yaml::HasField(sctp, "retryDelayMs"))
            result.retry.delayMs = yaml::GetInt32(sctp, "retryDelayMs", 0, 60000);
        if (yaml::HasField(sctp, "responseTimeoutMs"))
            result.retry.responseTimeoutMs = yaml::GetInt32(sctp, "responseTimeoutMs", 100, 60000);
        if (yaml::HasField(sctp, "connectMaxAttempts"))
            result.retry.connectMaxAttempts = yaml::GetInt32(sctp, "connectMaxAttempts", 1, 10);
        if (yaml::HasField(sctp, "connectTimeoutMs"))
            result.retry.connectTimeoutMs = yaml::GetInt32(sctp, "connectTimeoutMs", 100, 60000);
    }

    return result;
}

} // namespace

EnbConfig ParseConfig(const std::string &yamlText)
{
    try
    {
        return ParseNode(YAML::Load(yamlText));
    }
    catch (const YAML::Exception &e)
    {
        throw std::runtime_error(std::string("Invalid LTE eNB YAML: ") + e.what());
    }
}

EnbConfig LoadConfig(const std::string &path)
{
    try
    {
        return ParseNode(YAML::LoadFile(path));
    }
    catch (const YAML::Exception &e)
    {
        throw std::runtime_error(std::string("Unable to load LTE eNB configuration: ") + e.what());
    }
}

} // namespace lte::enb
