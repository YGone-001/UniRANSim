#!/usr/bin/env python3
"""Independent synthetic S1AP APER fixtures; pycrate==0.8.1.

No simulator codec or subscriber data is used. Run --decode HEX to inspect a PDU.
"""
import copy
import sys
from pycrate_asn1dir import S1AP


def ie(number, name, value, criticality="ignore"):
    return {"id": number, "criticality": criticality, "value": (name, value)}


def encode(kind, name, elements, procedure=9):
    pdu = S1AP.S1AP_PDU_Descriptions.S1AP_PDU
    pdu.set_val((kind, {"procedureCode": procedure, "criticality": "reject",
                        "value": (name, {"protocolIEs": elements})}))
    return pdu.to_aper().hex()


def fixtures():
    ids = [ie(0, "MME-UE-S1AP-ID", 101), ie(8, "ENB-UE-S1AP-ID", 1)]
    qos = {"qCI": 9, "allocationRetentionPriority": {
        "priorityLevel": 15, "pre-emptionCapability": "shall-not-trigger-pre-emption",
        "pre-emptionVulnerability": "not-pre-emptable"}}
    items = [{"e-RAB-ID": ebi, "e-RABlevelQoSParameters": qos,
              "transportLayerAddress": (0x7F000009, 32),
              "gTP-TEID": (0x1000 + ebi).to_bytes(4, "big")} for ebi in (5, 6, 7)]

    def request(values):
        elements = copy.deepcopy(ids)
        for item in elements:
            item["criticality"] = "reject"
        elements += [ie(66, "UEAggregateMaximumBitrate", {
            "uEaggregateMaximumBitRateDL": 1000000, "uEaggregateMaximumBitRateUL": 500000}, "reject"),
            ie(24, "E-RABToBeSetupListCtxtSUReq", [
                ie(52, "E-RABToBeSetupItemCtxtSUReq", value, "reject") for value in values], "reject"),
            ie(107, "UESecurityCapabilities", {"encryptionAlgorithms": (0xA000, 16),
                                                "integrityProtectionAlgorithms": (0x2000, 16)}, "reject"),
            ie(73, "SecurityKey", (0, 256), "reject")]
        return encode("initiatingMessage", "InitialContextSetupRequest", elements)

    def response(ebis, failures=()):
        elements = ids + [ie(51, "E-RABSetupListCtxtSURes", [
            ie(50, "E-RABSetupItemCtxtSURes", {"e-RAB-ID": ebi,
                "transportLayerAddress": (0xC0000201, 32),
                "gTP-TEID": (0x2000 + ebi).to_bytes(4, "big")}) for ebi in ebis])]
        if failures:
            elements.append(ie(48, "E-RABList", [ie(35, "E-RABItem", {
                "e-RAB-ID": ebi, "cause": ("radioNetwork", "unknown-E-RAB-ID")}) for ebi in failures]))
        return encode("successfulOutcome", "InitialContextSetupResponse", elements)

    result = {"request2": request(items[:2]), "request3": request(items),
              "reordered": request([items[2], items[1], items[0]]),
              "duplicate": request([items[0], items[0]]),
              "response2": response((5, 6)), "response3": response((5, 6, 7)),
              "mixed": response((5, 6), (7,)),
              "failure": encode("unsuccessfulOutcome", "InitialContextSetupFailure", ids + [
                  ie(2, "Cause", ("radioNetwork", "radio-resources-not-available"))])}
    ipv6 = copy.deepcopy(items)
    ipv6[1]["transportLayerAddress"] = (0x20010DB8000000000000000000000001, 128)
    result["ipv6"] = request(ipv6)
    result["standalone_failure"] = encode("successfulOutcome", "E-RABSetupResponse", ids + [
        ie(29, "E-RABList", [ie(35, "E-RABItem", {
            "e-RAB-ID": 6, "cause": ("radioNetwork", "radio-resources-not-available")})])], 5)
    result["standalone_success"] = encode("successfulOutcome", "E-RABSetupResponse", ids + [
        ie(28, "E-RABSetupListBearerSURes", [ie(39, "E-RABSetupItemBearerSURes", {
            "e-RAB-ID": 6, "transportLayerAddress": (0xC0000201, 32),
            "gTP-TEID": (0x2006).to_bytes(4, "big")})])], 5)
    return result


if __name__ == "__main__":
    if len(sys.argv) == 3 and sys.argv[1] == "--decode":
        pdu = S1AP.S1AP_PDU_Descriptions.S1AP_PDU
        pdu.from_aper(bytes.fromhex(sys.argv[2]))
        print(pdu.to_asn1())
    elif len(sys.argv) == 2 and sys.argv[1] == "--header":
        print("// Independent pycrate 0.8.1 fixtures; reproduce with tools/lte-restoration-fixtures.py --header.")
        print("#pragma once\nnamespace restoration_fixtures\n{")
        for name, value in fixtures().items():
            print(f'inline constexpr const char *{name} = "{value}";')
        print("}")
    else:
        for name, value in fixtures().items():
            print(name, value)
