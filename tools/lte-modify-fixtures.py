#!/usr/bin/env python3
"""Independent offline S1AP APER fixtures (pip install pycrate==0.8.1).

No simulator encoder is used. All identities, addresses and NAS are synthetic.
Run with --decode HEX to inspect a simulator-produced response independently.
"""
import copy
import sys
from pycrate_asn1dir import S1AP


def ie(number, name, value, criticality="reject"):
    return {"id": number, "criticality": criticality, "value": (name, value)}


def encode(kind, name, elements):
    pdu = S1AP.S1AP_PDU_Descriptions.S1AP_PDU
    pdu.set_val((kind, {"procedureCode": 6, "criticality": "reject",
                        "value": (name, {"protocolIEs": elements})}))
    return pdu.to_aper().hex()


if __name__ == "__main__":
    if len(sys.argv) == 3 and sys.argv[1] == "--decode":
        pdu = S1AP.S1AP_PDU_Descriptions.S1AP_PDU
        pdu.from_aper(bytes.fromhex(sys.argv[2]))
        print(pdu.to_asn1())
        sys.exit(0)
    qos = {"qCI": 7, "allocationRetentionPriority": {
        "priorityLevel": 8, "pre-emptionCapability": "shall-not-trigger-pre-emption",
        "pre-emptionVulnerability": "not-pre-emptable"}}
    item = {"e-RAB-ID": 6, "e-RABLevelQoSParameters": qos,
            "nAS-PDU": bytes.fromhex("6200c95b0107")}

    def request(value, ambr=False):
        elements = [ie(0, "MME-UE-S1AP-ID", 101), ie(8, "ENB-UE-S1AP-ID", 1)]
        if ambr:
            elements.append(ie(66, "UEAggregateMaximumBitrate", {
                "uEaggregateMaximumBitRateDL": 1000000, "uEaggregateMaximumBitRateUL": 500000}))
        elements.append(ie(30, "E-RABToBeModifiedListBearerModReq", [
            ie(36, "E-RABToBeModifiedItemBearerModReq", value)]))
        return encode("initiatingMessage", "E-RABModifyRequest", elements)

    print("qos", request(item))
    print("ambr", request(item, True))
    gbr = copy.deepcopy(item)
    gbr["e-RABLevelQoSParameters"]["gbrQosInformation"] = {
        "e-RAB-MaximumBitrateDL": 256000, "e-RAB-MaximumBitrateUL": 128000,
        "e-RAB-GuaranteedBitrateDL": 64000, "e-RAB-GuaranteedBitrateUL": 32000}
    print("gbr", request(gbr))
    transport = copy.deepcopy(item)
    transport["iE-Extensions"] = [{"id": 185, "criticality": "reject", "extensionValue": (
        "TransportInformation", {"transportLayerAddress": (0xC000020A, 32), "uL-GTP-TEID": b"\x12\x34\x56\x78"})}]
    print("transport", request(transport))
    transport["iE-Extensions"][0]["extensionValue"][1]["transportLayerAddress"] = (0x20010db8000000000000000000000001, 128)
    print("ipv6", request(transport))
    print("response", encode("successfulOutcome", "E-RABModifyResponse", [
        ie(0, "MME-UE-S1AP-ID", 101, "ignore"), ie(8, "ENB-UE-S1AP-ID", 1, "ignore"),
        ie(31, "E-RABModifyListBearerModRes", [ie(37, "E-RABModifyItemBearerModRes", {"e-RAB-ID": 6}, "ignore")], "ignore"),
        ie(32, "E-RABList", [ie(35, "E-RABItem", {"e-RAB-ID": 7, "cause": ("radioNetwork", "unknown-E-RAB-ID")}, "ignore")], "ignore")]))
