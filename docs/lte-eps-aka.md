# LTE UE initial NAS and EPS AKA (Phase 1)

`lte-ue` provides the deliberately small LTE control-plane slice needed to
exercise EPS AKA through an Open5GS MME. It is not an LTE radio stack and it
does not complete EPS Attach.

## Build and run

On a Linux host with SCTP development support:

```bash
cmake -S . -B cmake-build-phase1 -DCMAKE_BUILD_TYPE=Release
cmake --build cmake-build-phase1 --parallel 2
./cmake-build-phase1/lte-enb -c config/open5gs-lte-enb.yaml
./cmake-build-phase1/lte-ue -c config/open5gs-lte-ue.yaml
```

Run the eNB first and wait for `S1_SETUP_ESTABLISHED`. The sample UE
configuration contains synthetic credentials only. A live trial needs a
separate, ignored configuration containing the credentials of an authorized
Open5GS HSS subscriber; never commit K, OP, OPc, packet captures, or HSS data.
Create it with `cp config/open5gs-lte-ue.yaml
config/open5gs-lte-ue.local.yaml`, update only the local copy, and pass that
path to `lte-ue`.

`mcc` and `mnc` remain strings, so `02` is encoded as a two-digit MNC. Specify
exactly one of `op` and `opc`. `initialSqn` is the minimum accepted USIM SQN;
an AUTN below it fails closed. AUTS resynchronization is not implemented.

## Transport and message flow

The LTE-only simulated radio link is a bounded UDP frame with a version,
direction, UE identity, and NAS length. It is independent of UERANSIM's NR RLS
sessions. The Phase 1 eNB accepts exactly one UE identity (`1`) and records its
UDP endpoint only after its first uplink frame.

```
lte-ue -- UDP NAS --> lte-enb -- S1AP Initial UE Message --> MME
lte-ue <-- UDP NAS -- lte-enb <-- S1AP Downlink NAS Transport -- MME
lte-ue -- UDP NAS --> lte-enb -- S1AP Uplink NAS Transport --> MME
```

The initial message is a plain EPS Attach Request containing an IMSI, EPS NAS
KSI set to no available context, UE network capability, and an ESM PDN
Connectivity Request. The eNB constructs the Initial UE Message with
eNB-UE-S1AP-ID, NAS-PDU, TAI, E-UTRAN-CGI, and RRC establishment cause. It
correlates both S1AP UE IDs before accepting or forwarding later NAS traffic.

## EPS AKA behaviour

The UE decodes plain EPS Authentication Request, validates its exact RAND/AUTN
sizes, derives OPc when OP is configured, checks AUTN MAC-A, recovers SQN with
f5 AK, and runs f2/f3/f4 to obtain RES/CK/IK. KASME is then derived with the
TS 33.401 FC `0x10` KDF using `CK || IK`, the 3-octet serving PLMN identity,
and `SQN xor AK` from AUTN. Secrets are never emitted in normal logs.

On a valid challenge, the UE sends plain EPS Authentication Response with RES.
On MAC failure it sends EPS Authentication Failure with the MAC-failure cause.
On SQN synchronization failure it sends no fabricated AUTS and fails closed.
A subsequent plain or security-protected MME Security Mode Command sets `EPS_AKA_ACCEPTED`; it means the
MME accepted EPS AKA, **not** that EPS Attach has completed. The program does
not verify the command MAC and does not send Security Mode Complete; both are
Phase 2 responsibilities.

## Evidence for a live lab run

When capture is authorized, start it before the processes:

```bash
sudo tcpdump -i any -nn -s 0 -w /tmp/uniransim-phase1-epc.pcap 'sctp port 36412'
```

Retain MME logs and a capture only under the lab's secret-handling rules. The
required evidence is S1 Setup acceptance, Initial UE Message, MME
Authentication Request, UE Authentication Response, and a following Security
Mode Command. Sending RES alone is not success evidence.

## Phase boundary

Not implemented: NAS Security Mode Complete, Attach Accept, default bearer,
E-RAB/S1-U, TUN/data plane, paging, mobility, multi-UE operation, or physical
LTE radio. The next phase is **EPS NAS Security Mode and full Attach
completion**.

## Provenance and licensing

The LTE Phase 1 implementation is original project code and reuses the
repository's existing Milenage, SHA-256 KDF, UDP, SCTP, configuration, and
utility modules. Message layouts and criticalities were checked against the
pinned Magma S1APTester and srsRAN 4G references named in the Phase 1 task; no
third-party implementation source was copied. The code remains under the
repository's existing GNU AGPL-3.0 license and preserves upstream attribution.
