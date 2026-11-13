//
// This file is a part of UERANSIM project.
// Copyright (c) 2027 ALİ GÜNGÖR.
//
// https://github.com/aligungr/UERANSIM/
// See README, LICENSE, and CONTRIBUTING files for licensing details.
//

// The real 512-UE registration campaign's deterministic core.
//
// The live campaign reads an authorized local subscriber inventory, verifies
// the exact designated IMSI set, builds a one-to-one manifest and generates
// protected UE configurations. This module holds the parts that can be tested
// without an EPC or a subscriber secret: range arithmetic, set completeness,
// authentication/APN shape, manifest uniqueness, protected config writing,
// failure classification and cleanup classification.
//
// No function here reads a database, logs a key, OPc or OP, or prints a
// subscriber identity. The inventory is supplied by a local exporter that the
// operator authorizes separately.

#pragma once

#include <cstddef>
#include <cstdint>
#include <map>
#include <string>
#include <vector>

namespace lte::enb
{

enum class InventoryStatus : uint8_t
{
    VERIFIED,
    RANGE_INCOMPLETE,
    AUTH_CONFIGURATION_MISMATCH,
    APN_CONFIGURATION_MISMATCH,
    NOT_VERIFIED
};

const char *ToString(InventoryStatus status);

// One subscriber as read from the authorized local inventory. opc and op are
// alternative authentication inputs; exactly one is expected to be usable.
struct SubscriberRecord
{
    std::string imsi;
    std::string k;
    std::string opc;
    std::string op;
    std::string amf;
    std::vector<std::string> apns;
};

struct InventoryExpectation
{
    std::string firstImsi{"460020000000400"};
    std::string lastImsi{"460020000000911"};
    std::string mcc{"460"};
    std::string mnc{"02"};
    std::string apn{"cmnet"};
    size_t expectedCount{512};
};

struct InventoryReport
{
    InventoryStatus status{InventoryStatus::NOT_VERIFIED};
    size_t expected{};
    size_t present{};
    size_t missing{};
    size_t duplicates{};
    size_t invalidAuth{};
    size_t missingApn{};
    // At most 16 missing identities are retained for diagnostics. The report
    // is about the set, not about exporting subscriber data.
    std::vector<std::string> missingSamples;
};

InventoryReport VerifySubscriberInventory(const std::vector<SubscriberRecord> &records,
                                          const InventoryExpectation &expectation);

// The one-to-one mapping from a campaign index to a subscriber and runtime
// identity. The manifest is ordered by IMSI so the mapping is reproducible.
struct ManifestEntry
{
    size_t index{};
    std::string imsi;
    uint32_t ueId{};
    uint16_t localPort{};
    std::string tunPrefix;
};

struct CampaignManifest
{
    std::vector<ManifestEntry> entries;
    bool valid{};
    std::string error;
};

// Builds the manifest only from a VERIFIED inventory. The per-entry TUN prefix
// is baseTunPrefix followed by a four-digit index, so concurrent processes never
// allocate the same interface name.
CampaignManifest BuildCampaignManifest(const std::vector<SubscriberRecord> &records,
                                       const InventoryExpectation &expectation, uint32_t baseUeId,
                                       uint16_t baseLocalPort, const std::string &baseTunPrefix);

struct UeRuntimeConfig
{
    std::string enbAddress{"127.0.0.1"};
    uint16_t enbPort{};
    int timeoutMs{60000};
    std::string apn{"cmnet"};
    std::string initialSqn{"000000000000"};
};

// Writes one UE YAML with mode 0600. The returned error never contains a key,
// OPc, OP or the IMSI. The caller owns the destination directory and must keep
// it outside Git.
bool WriteUeConfiguration(const ManifestEntry &entry, const SubscriberRecord &record,
                          const UeRuntimeConfig &runtime, const std::string &path, std::string &error);

// Counters observed at one real registration checkpoint.
struct RegistrationCheckpoint
{
    size_t requested{};
    size_t started{};
    size_t attachRequests{};
    size_t authenticationRequests{};
    size_t authenticationResponses{};
    size_t securityModeCommands{};
    size_t attachAccepts{};
    size_t attachCompletes{};
    size_t defaultBearers{};
    size_t ipv4Assigned{};
    size_t tunCreated{};
    size_t registered{};
    std::map<std::string, size_t> failureCauses;

    [[nodiscard]] bool Complete() const;
};

// Classifies a production log line or a transfer cause without inventing a
// success. Unknown stays unknown.
std::string ClassifyFailureCause(const std::string &text);

struct CleanupReport
{
    bool ueProcessesStopped{};
    bool tunInterfacesRemoved{};
    bool enbContextsCleared{};
    bool mmeSessionsCleared{};
    bool smfSessionsCleared{};

    [[nodiscard]] bool Complete() const;
};

} // namespace lte::enb