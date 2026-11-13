//
// This file is a part of UERANSIM project.
// Copyright (c) 2027 ALİ GÜNGÖR.
//
// https://github.com/aligungr/UERANSIM/
// See README, LICENSE, and CONTRIBUTING files for licensing details.
//

// Deterministic checks for the real 512-UE campaign core.
//
// The records here are test-owned fakes. No subscriber secret, database or EPC
// is involved; the live inventory was verified separately through an authorized
// local read-only source.

#include <ext/doctest/doctest.h>

#include <filesystem>
#include <fstream>
#include <iterator>
#include <set>
#include <string>
#include <vector>

#include <lte/enb/registration_campaign.hpp>

namespace
{

using namespace lte::enb;

SubscriberRecord FakeRecord(uint64_t imsi)
{
    SubscriberRecord record;
    record.imsi = std::to_string(imsi);
    record.k = "00112233445566778899aabbccddeeff";
    record.opc = "ffeeddccbbaa99887766554433221100";
    record.amf = "8000";
    record.apns = {"cmnet", "cmwap", "ims"};
    return record;
}

std::vector<SubscriberRecord> FakeInventory()
{
    std::vector<SubscriberRecord> records;
    for (uint64_t imsi = 460020000000400ULL; imsi <= 460020000000911ULL; ++imsi)
        records.push_back(FakeRecord(imsi));
    return records;
}

InventoryExpectation Expectation()
{
    InventoryExpectation expectation;
    expectation.firstImsi = "460020000000400";
    expectation.lastImsi = "460020000000911";
    expectation.expectedCount = 512;
    return expectation;
}

} // namespace

TEST_CASE("lte/registration: the designated imsi set verifies exactly")
{
    const auto report = VerifySubscriberInventory(FakeInventory(), Expectation());
    CHECK(report.status == InventoryStatus::VERIFIED);
    CHECK(report.expected == 512);
    CHECK(report.present == 512);
    CHECK(report.missing == 0);
    CHECK(report.duplicates == 0);
    CHECK(report.invalidAuth == 0);
    CHECK(report.missingApn == 0);
    CHECK(std::string(ToString(report.status)) == "SUBSCRIBER_RANGE_VERIFIED");
}

TEST_CASE("lte/registration: a gap, a duplicate or a malformed range is not verified")
{
    auto records = FakeInventory();
    records.erase(records.begin() + 100);
    auto report = VerifySubscriberInventory(records, Expectation());
    CHECK(report.status == InventoryStatus::RANGE_INCOMPLETE);
    CHECK(report.missing == 1);
    CHECK(report.missingSamples.size() == 1);
    CHECK(report.missingSamples[0] == "460020000000500");

    records = FakeInventory();
    records.push_back(records[10]);
    report = VerifySubscriberInventory(records, Expectation());
    CHECK(report.status == InventoryStatus::RANGE_INCOMPLETE);
    CHECK(report.duplicates == 1);

    // The first and last listed identities are the inclusive boundary. An
    // expectation whose count does not match its range is not usable.
    auto bad = Expectation();
    bad.lastImsi = "460020000000912";
    bad.expectedCount = 512;
    report = VerifySubscriberInventory(FakeInventory(), bad);
    CHECK(report.status == InventoryStatus::NOT_VERIFIED);

    // Records outside the designated range do not fill a missing in-range one.
    records = FakeInventory();
    records.pop_back();
    records.push_back(FakeRecord(460020000000912ULL));
    report = VerifySubscriberInventory(records, Expectation());
    CHECK(report.status == InventoryStatus::RANGE_INCOMPLETE);
    CHECK(report.missing == 1);
}

TEST_CASE("lte/registration: authentication and apn shape are checked separately")
{
    auto records = FakeInventory();
    records[0].k = "0011";
    auto report = VerifySubscriberInventory(records, Expectation());
    CHECK(report.status == InventoryStatus::AUTH_CONFIGURATION_MISMATCH);
    CHECK(report.invalidAuth == 1);

    records = FakeInventory();
    records[0].amf = "80";
    report = VerifySubscriberInventory(records, Expectation());
    CHECK(report.status == InventoryStatus::AUTH_CONFIGURATION_MISMATCH);

    records = FakeInventory();
    records[0].opc.clear();
    report = VerifySubscriberInventory(records, Expectation());
    CHECK(report.status == InventoryStatus::AUTH_CONFIGURATION_MISMATCH);

    records = FakeInventory();
    records[0].op = "ffeeddccbbaa99887766554433221100";
    report = VerifySubscriberInventory(records, Expectation());
    CHECK(report.status == InventoryStatus::AUTH_CONFIGURATION_MISMATCH);

    records = FakeInventory();
    records[0].opc.clear();
    records[0].op = "ffeeddccbbaa99887766554433221100";
    report = VerifySubscriberInventory(records, Expectation());
    CHECK(report.status == InventoryStatus::VERIFIED);

    records = FakeInventory();
    records[0].apns = {"cmwap"};
    report = VerifySubscriberInventory(records, Expectation());
    CHECK(report.status == InventoryStatus::APN_CONFIGURATION_MISMATCH);
    CHECK(report.missingApn == 1);
}

TEST_CASE("lte/registration: the manifest maps every subscriber to one runtime identity")
{
    const auto manifest = BuildCampaignManifest(FakeInventory(), Expectation(), 1, 20000, "p19d");
    REQUIRE(manifest.valid);
    CHECK(manifest.entries.size() == 512);
    CHECK(manifest.entries.front().imsi == "460020000000400");
    CHECK(manifest.entries.back().imsi == "460020000000911");
    CHECK(manifest.entries.front().ueId == 1);
    CHECK(manifest.entries.back().ueId == 512);
    CHECK(manifest.entries.front().localPort == 20000);
    CHECK(manifest.entries.back().localPort == 20511);
    CHECK(manifest.entries[0].tunPrefix == "p19d0000");
    CHECK(manifest.entries[511].tunPrefix == "p19d0511");

    std::set<uint32_t> ids;
    std::set<uint16_t> ports;
    std::set<std::string> prefixes;
    for (const auto &entry : manifest.entries)
    {
        CHECK(ids.insert(entry.ueId).second);
        CHECK(ports.insert(entry.localPort).second);
        CHECK(prefixes.insert(entry.tunPrefix).second);
    }

    // An incomplete inventory cannot produce a manifest.
    auto records = FakeInventory();
    records.pop_back();
    const auto incomplete = BuildCampaignManifest(records, Expectation(), 1, 20000, "p19d");
    CHECK(!incomplete.valid);

    // A port range that would wrap is refused rather than truncated.
    const auto overflow = BuildCampaignManifest(FakeInventory(), Expectation(), 1, 65500, "p19d");
    CHECK(!overflow.valid);
}

TEST_CASE("lte/registration: a generated configuration is protected and carries one identity")
{
    const auto manifest = BuildCampaignManifest(FakeInventory(), Expectation(), 1, 20000, "p19d");
    REQUIRE(manifest.valid);
    const auto directory = std::filesystem::temp_directory_path() / "uniransim-phase19d-config-test";
    std::filesystem::create_directories(directory);
    const auto path = directory / "ue-000.yaml";
    UeRuntimeConfig runtime;
    runtime.enbPort = 4998;
    std::string error;
    REQUIRE(WriteUeConfiguration(manifest.entries[0], FakeInventory()[0], runtime, path.string(), error));
    CHECK(error.empty());

    const auto mode = std::filesystem::status(path).permissions();
    CHECK((mode & std::filesystem::perms::owner_read) != std::filesystem::perms::none);
    CHECK((mode & std::filesystem::perms::owner_write) != std::filesystem::perms::none);
    CHECK((mode & std::filesystem::perms::group_read) == std::filesystem::perms::none);
    CHECK((mode & std::filesystem::perms::others_read) == std::filesystem::perms::none);

    std::ifstream in(path);
    const std::string text((std::istreambuf_iterator<char>(in)), std::istreambuf_iterator<char>());
    CHECK(text.find("imsi: '460020000000400'") != std::string::npos);
    CHECK(text.find("ueId: 1") != std::string::npos);
    CHECK(text.find("namePrefix: p19d0000") != std::string::npos);
    CHECK(text.find("apn: cmnet") != std::string::npos);
    CHECK(text.find("required: true") != std::string::npos);

    // A record with both OPc and OP is refused, and the diagnostic never
    // repeats either value.
    auto ambiguous = FakeInventory()[0];
    ambiguous.op = ambiguous.opc;
    const std::string secret = ambiguous.opc;
    REQUIRE(!WriteUeConfiguration(manifest.entries[0], ambiguous, runtime, path.string(), error));
    CHECK(error.find(secret) == std::string::npos);
    std::filesystem::remove_all(directory);
}

TEST_CASE("lte/registration: failure and cleanup classifications are explicit")
{
    CHECK(ClassifyFailureCause("Unknown UE by IMSI") == "subscriber-not-found");
    CHECK(ClassifyFailureCause("MAC failure") == "authentication-failure");
    CHECK(ClassifyFailureCause("SQN synchronization failure") == "sqn-synchronization");
    CHECK(ClassifyFailureCause("TUN interface 'p19d0000' could not be created") == "tun-allocation");
    CHECK(ClassifyFailureCause("No APN is available") == "apn-rejection");
    CHECK(ClassifyFailureCause("SCTP association lost") == "sctp");
    CHECK(ClassifyFailureCause("Timed out waiting for MME EPS Attach signaling") == "registration-delay");
    CHECK(ClassifyFailureCause("something unexpected") == "unknown");

    RegistrationCheckpoint checkpoint;
    checkpoint.requested = 512;
    checkpoint.registered = 512;
    checkpoint.defaultBearers = 512;
    checkpoint.ipv4Assigned = 512;
    checkpoint.tunCreated = 512;
    CHECK(checkpoint.Complete());
    checkpoint.tunCreated = 511;
    CHECK(!checkpoint.Complete());

    CleanupReport cleanup;
    CHECK(!cleanup.Complete());
    cleanup.ueProcessesStopped = true;
    cleanup.tunInterfacesRemoved = true;
    cleanup.enbContextsCleared = true;
    cleanup.mmeSessionsCleared = true;
    cleanup.smfSessionsCleared = true;
    CHECK(cleanup.Complete());
}