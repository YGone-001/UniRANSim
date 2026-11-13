//
// This file is a part of UERANSIM project.
// Copyright (c) 2027 ALİ GÜNGÖR.
//
// https://github.com/aligungr/UERANSIM/
// See README, LICENSE, and CONTRIBUTING files for licensing details.
//

#include "registration_campaign.hpp"

#include <algorithm>
#include <cctype>
#include <cerrno>
#include <cstring>
#include <fcntl.h>
#include <iterator>
#include <set>
#include <sys/stat.h>
#include <sstream>
#include <stdexcept>
#include <unistd.h>

namespace lte::enb
{
namespace
{

bool AllHex(const std::string &value, size_t expectedLength)
{
    if (value.size() != expectedLength)
        return false;
    for (const char c : value)
        if (!((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F')))
            return false;
    return true;
}

bool ParseImsi(const std::string &value, uint64_t &out)
{
    if (value.size() < 5 || value.size() > 15)
        return false;
    uint64_t result = 0;
    for (const char c : value)
    {
        if (c < '0' || c > '9')
            return false;
        result = result * 10 + static_cast<uint64_t>(c - '0');
    }
    out = result;
    return true;
}

std::string ImsiFromUint(uint64_t value, size_t width)
{
    std::string text = std::to_string(value);
    if (text.size() < width)
        text.insert(text.begin(), width - text.size(), '0');
    return text;
}

} // namespace

const char *ToString(InventoryStatus status)
{
    switch (status)
    {
    case InventoryStatus::VERIFIED: return "SUBSCRIBER_RANGE_VERIFIED";
    case InventoryStatus::RANGE_INCOMPLETE: return "SUBSCRIBER_RANGE_INCOMPLETE";
    case InventoryStatus::AUTH_CONFIGURATION_MISMATCH: return "SUBSCRIBER_AUTH_CONFIGURATION_MISMATCH";
    case InventoryStatus::APN_CONFIGURATION_MISMATCH: return "SUBSCRIBER_APN_CONFIGURATION_MISMATCH";
    case InventoryStatus::NOT_VERIFIED: return "SUBSCRIBER_INVENTORY_NOT_VERIFIED";
    }
    return "SUBSCRIBER_INVENTORY_NOT_VERIFIED";
}

InventoryReport VerifySubscriberInventory(const std::vector<SubscriberRecord> &records,
                                          const InventoryExpectation &expectation)
{
    InventoryReport report;
    uint64_t first = 0;
    uint64_t last = 0;
    if (!ParseImsi(expectation.firstImsi, first) || !ParseImsi(expectation.lastImsi, last) || last < first ||
        expectation.expectedCount == 0 || last - first + 1 != expectation.expectedCount)
    {
        report.status = InventoryStatus::NOT_VERIFIED;
        return report;
    }
    report.expected = expectation.expectedCount;
    std::set<std::string> expected;
    for (uint64_t value = first; value <= last; ++value)
        expected.insert(ImsiFromUint(value, expectation.firstImsi.size()));

    std::set<std::string> seen;
    for (const auto &record : records)
    {
        if (expected.count(record.imsi) == 0)
            continue;
        if (!seen.insert(record.imsi).second)
        {
            ++report.duplicates;
            continue;
        }
        ++report.present;
        const bool kOk = AllHex(record.k, 32);
        const bool opcOk = AllHex(record.opc, 32);
        const bool opOk = AllHex(record.op, 32);
        const bool amfOk = AllHex(record.amf, 4);
        // Exactly one of OPc or OP must be usable; both is ambiguous and
        // neither is unusable.
        if (!kOk || (opcOk == opOk) || !amfOk)
            ++report.invalidAuth;
        if (std::find(record.apns.begin(), record.apns.end(), expectation.apn) == record.apns.end())
            ++report.missingApn;
    }
    report.present = seen.size();
    report.missing = report.expected - report.present;
    for (const auto &imsi : expected)
    {
        if (seen.count(imsi) != 0)
            continue;
        if (report.missingSamples.size() < 16)
            report.missingSamples.push_back(imsi);
    }

    if (report.present != report.expected || report.missing != 0 || report.duplicates != 0)
        report.status = InventoryStatus::RANGE_INCOMPLETE;
    else if (report.invalidAuth != 0)
        report.status = InventoryStatus::AUTH_CONFIGURATION_MISMATCH;
    else if (report.missingApn != 0)
        report.status = InventoryStatus::APN_CONFIGURATION_MISMATCH;
    else
        report.status = InventoryStatus::VERIFIED;
    return report;
}

CampaignManifest BuildCampaignManifest(const std::vector<SubscriberRecord> &records,
                                       const InventoryExpectation &expectation, uint32_t baseUeId,
                                       uint16_t baseLocalPort, const std::string &baseTunPrefix)
{
    CampaignManifest manifest;
    const auto inventory = VerifySubscriberInventory(records, expectation);
    if (inventory.status != InventoryStatus::VERIFIED)
    {
        manifest.error = std::string("inventory is not verified: ") + ToString(inventory.status);
        return manifest;
    }
    if (static_cast<size_t>(baseUeId) + inventory.expected > 0xFFFFFFFFULL)
    {
        manifest.error = "UE identity range overflows";
        return manifest;
    }
    if (static_cast<uint32_t>(baseLocalPort) + inventory.expected > 65535ULL)
    {
        manifest.error = "local port range overflows";
        return manifest;
    }
    if (baseTunPrefix.empty() || baseTunPrefix.size() + 5 > 15)
    {
        manifest.error = "TUN prefix cannot produce a bounded interface name";
        return manifest;
    }

    std::vector<SubscriberRecord> selected;
    selected.reserve(records.size());
    const std::set<std::string> allowed = [&] {
        std::set<std::string> set;
        uint64_t first = 0;
        uint64_t last = 0;
        ParseImsi(expectation.firstImsi, first);
        ParseImsi(expectation.lastImsi, last);
        for (uint64_t value = first; value <= last; ++value)
            set.insert(ImsiFromUint(value, expectation.firstImsi.size()));
        return set;
    }();
    for (const auto &record : records)
        if (allowed.count(record.imsi) != 0)
            selected.push_back(record);
    std::sort(selected.begin(), selected.end(),
              [](const SubscriberRecord &a, const SubscriberRecord &b) { return a.imsi < b.imsi; });

    std::set<uint32_t> ueIds;
    std::set<uint16_t> ports;
    std::set<std::string> prefixes;
    for (size_t i = 0; i < selected.size(); ++i)
    {
        ManifestEntry entry;
        entry.index = i;
        entry.imsi = selected[i].imsi;
        entry.ueId = baseUeId + static_cast<uint32_t>(i);
        entry.localPort = static_cast<uint16_t>(baseLocalPort + i);
        entry.tunPrefix = baseTunPrefix + ImsiFromUint(i, 4);
        if (!ueIds.insert(entry.ueId).second || !ports.insert(entry.localPort).second ||
            !prefixes.insert(entry.tunPrefix).second)
        {
            manifest.error = "manifest identity is not unique";
            return manifest;
        }
        manifest.entries.push_back(std::move(entry));
    }
    manifest.valid = true;
    return manifest;
}

bool WriteUeConfiguration(const ManifestEntry &entry, const SubscriberRecord &record,
                          const UeRuntimeConfig &runtime, const std::string &path, std::string &error)
{
    if (entry.imsi != record.imsi)
    {
        error = "manifest identity does not match the subscriber";
        return false;
    }
    if (!AllHex(record.k, 32) || !AllHex(record.amf, 4))
    {
        error = "subscriber authentication material is malformed";
        return false;
    }
    const bool haveOpc = AllHex(record.opc, 32);
    const bool haveOp = AllHex(record.op, 32);
    if (haveOpc == haveOp)
    {
        error = "subscriber must carry exactly one usable OPc or OP";
        return false;
    }

    std::ostringstream yaml;
    yaml << "imsi: '" << record.imsi << "'\n";
    yaml << "mcc: '460'\n";
    yaml << "mnc: '02'\n";
    yaml << "ueId: " << entry.ueId << "\n";
    yaml << "k: '" << record.k << "'\n";
    yaml << (haveOpc ? "opc: '" + record.opc + "'\n" : "op: '" + record.op + "'\n");
    yaml << "amf: '" << record.amf << "'\n";
    yaml << "initialSqn: '" << runtime.initialSqn << "'\n";
    yaml << "pdnType: IPv4\n";
    yaml << "apn: " << runtime.apn << "\n";
    yaml << "networkCapability: 'A020'\n";
    yaml << "lifecycle:\n  scenario: attach-only\n  triggerAfterMs: 3600000\n  procedureTimeoutMs: 10000\n";
    yaml << "  maxRetries: 2\n  pagingWaitMs: 300000\n  switchOff: false\n  recoveryDelayMs: 0\n";
    yaml << "  recoveryRetryMs: 5000\n  recoveryMaxAttempts: 0\n";
    yaml << "enbLink:\n  localAddress: 127.0.0.1\n  localPort: " << entry.localPort << "\n";
    yaml << "  address: " << runtime.enbAddress << "\n  port: " << runtime.enbPort << "\n";
    yaml << "  timeoutMs: " << runtime.timeoutMs << "\n";
    yaml << "tun:\n  required: true\n  namePrefix: " << entry.tunPrefix << "\n  mtu: 1400\n  routes: []\n";
    const std::string text = yaml.str();

    const int fd = ::open(path.c_str(), O_WRONLY | O_CREAT | O_TRUNC, 0600);
    if (fd < 0)
    {
        error = std::string("cannot open the configuration file: ") + std::strerror(errno);
        return false;
    }
    size_t written = 0;
    while (written < text.size())
    {
        const ssize_t n = ::write(fd, text.data() + written, text.size() - written);
        if (n <= 0)
        {
            error = std::string("cannot write the configuration file: ") + std::strerror(errno);
            ::close(fd);
            return false;
        }
        written += static_cast<size_t>(n);
    }
    if (::fchmod(fd, 0600) != 0)
    {
        error = std::string("cannot protect the configuration file: ") + std::strerror(errno);
        ::close(fd);
        return false;
    }
    if (::close(fd) != 0)
    {
        error = "cannot close the configuration file";
        return false;
    }
    return true;
}

bool RegistrationCheckpoint::Complete() const
{
    return requested != 0 && registered == requested && defaultBearers >= requested &&
           ipv4Assigned >= requested && tunCreated >= requested;
}

std::string ClassifyFailureCause(const std::string &text)
{
    std::string lower = text;
    std::transform(lower.begin(), lower.end(), lower.begin(),
                   [](unsigned char c) { return static_cast<char>(std::tolower(c)); });
    const auto has = [&lower](const char *needle) { return lower.find(needle) != std::string::npos; };
    if (has("unknown ue by imsi") || has("subscriber not found"))
        return "subscriber-not-found";
    if (has("mac failure") || has("authentication failure"))
        return "authentication-failure";
    if (has("sqn") || has("synchronization failure") || has("sync failure"))
        return "sqn-synchronization";
    if (has("plmn"))
        return "plmn-mismatch";
    if (has("tai"))
        return "tai-mismatch";
    if (has("apn"))
        return "apn-rejection";
    if (has("address") && has("pool"))
        return "address-pool-exhaustion";
    if (has("s1ap") && has("identity"))
        return "s1ap-identity-conflict";
    if (has("sctp") || has("association"))
        return "sctp";
    if (has("tun allocation") || has("could not be created"))
        return "tun-allocation";
    if (has("file descriptor") || has("too many open"))
        return "fd-exhaustion";
    if (has("out of memory") || has("memory pressure"))
        return "memory-pressure";
    if (has("timed out") || has("timeout"))
        return "registration-delay";
    if (has("udp") || has("drop"))
        return "udp-loss";
    if (has("terminated") || has("exited"))
        return "process-termination";
    if (has("session") && has("max"))
        return "epc-session-exhaustion";
    return "unknown";
}

bool CleanupReport::Complete() const
{
    return ueProcessesStopped && tunInterfacesRemoved && enbContextsCleared && mmeSessionsCleared &&
           smfSessionsCleared;
}

} // namespace lte::enb
