# LTE production UE/eNB to a real Open5GS EPC

This record describes the accepted D9 integration: the production `lte-ue` and
`lte-enb` Attach to the live Open5GS EPC, establish the default EPS bearer and
DRB, and carry real bidirectional IP traffic through the real SGW-U/PGW-U. The
Uu remains a software-simulated transport; this is not a claim of a real RF
air interface, a live S1 handover, 512-UE capacity or 1 Gbps.

The measured evidence is in `docs/lte-open5gs-live-acceptance.md`; the phase
report is `reports/PHASE-18-F-B6-D9-FINAL-REPORT.md`.

## 1. Architecture

```
        production lte-ue                         production lte-enb
   NAS / ESM / EPS / TUN                   RRC bridge / SRB1 / DRB
   DRB12 PDCP / LTE RLC AM                 PDCP / RLC AM / S1uEndpoint
        |                                       |             |
        |  simulated Uu (UDP, loopback)         | SCTP        | GTP-U UDP
        +---------------------------------------+             |
                                                |             |
                                    Open5GS MME :36412   Open5GS SGW-U :2152
                                                |             |
                                          HSS / PCRF     SMF / PGW-U / UPF
                                                              |
                                                        ogstun / PDN
```

The live run used one isolated network namespace for the test eNB + UE, a new
veth `10.99.0.0/24` to the host, and the host's existing `10.10.0.139` as the
PDN test endpoint. The eNB's S1-MME source and S1-U endpoint were `10.99.0.2`;
the SGW-U answered to the S1-U F-TEID the eNB advertised. No existing interface,
route, EPC service or subscriber was modified.

The simulated Uu is deliberately loopback-only today: the eNB's Uu socket binds
`127.0.0.1` and treats the configured `uu.address` as the peer address. The
accepted topology therefore places the eNB and UE in the same isolated
namespace. Separating them needs an eNB Uu source-address change, which is not
part of D9.

## 2. S1-MME and S1AP

- `src/lte/enb/app.cpp` owns a real `sctp::SctpClient` (PPID 18), binds the
  configured S1AP local address and connects to the MME's SCTP port. It sends a
  real S1 Setup Request and accepts only a decoded S1 Setup Response before it
  binds the association epoch to `EnbMultiplexer`.
- The live MME accepted the eNB with PLMN 460/02, TAI 1, eNB-ID `0x1AA`, and
  reported `ServedGUMMEIs[0]` group 2 / code 1 and MME name `xcloud-mme0`, with
  10 inbound and 10 outbound streams.
- The same S1AP dispatcher is used for the deterministic MME peer and the live
  MME. No UDP or TCP substitute is used for S1AP.

## 3. EPS Attach, AKA and NAS security

Observed on the production UE against the live MME:

```
Attach Request (RRCConnectionSetupComplete, SRB1)
Authentication Request  -> AKA AUTN/MAC verified, Authentication Response
Security Mode Command   -> NAS security EIA2/EEA0, MAC verified
Security Mode Complete
Attach Accept (ESM: default EPS bearer, EBI 5, QCI 9, APN cmnet)
Attach Complete
EPS_REGISTERED, DEFAULT_BEARER_SIGNALING_COMPLETE, TUN_READY
```

- The authentication is the real HSS vector for the designated test
  subscriber; the UE's SQN was set below the HSS's sequence so the AUTN was
  accepted. No MAC check, NAS security context or subscriber record was
  bypassed or modified.
- The UE's initial SQN is a UE-side configuration value; the HSS was not
  changed. A stale UE SQN fails closed (`AUTN SQN is stale`), as it did on the
  first attempt with the old local value.
- The MME sent a protected EMM message type 97 (GUTI Reallocation Command) after
  the attach. The production UE ignores it; the attach and user plane are
  unaffected, but GUTI reallocation handling is a documented gap.

## 4. Initial Context Setup, E-RAB and DRB

The live MME sent a real Initial Context Setup with the SecurityKey, NAS PDU
and one E-RAB. The eNB decoded the E-RAB identity, QoS and SGW-U transport
address/TEID from that message, allocated its own local S1-U TEID through the
registry allocator and answered with the Initial Context Setup Response. No
TEID, eNB identity or UE address is hardcoded from the D7/D8 deterministic
map.

The production bridge then delivered the RRCConnectionReconfiguration carrying
`drb-ToAddModList` over SRB1; the UE established the DRB12 PDCP and LTE RLC AM,
sent the reconfiguration complete, and the eNB answered the MME. The eNB logged
`DRB configuration sent`, the UE logged `DRB user plane configured`, and the eNB
logged `DRB user plane ready` with the real PDN IPv4 address.

Observed mapping for the accepted run:

| Item | Value |
|---|---|
| EBI | 5 |
| E-RAB | one default bearer (QCI 9) |
| DRB identity | 5 (EBI = E-RAB = DRB in this implementation) |
| APN | `cmnet` |
| UE IP | assigned by Open5GS from 10.45.0.0/16 (10.45.0.168, .170, .171-.176 in successive runs) |
| eNB S1-U | `10.99.0.2:2152` (the address advertised in its F-TEID) |
| SGW-U S1-U | the F-TEID delivered by the live MME's S1AP |

The SGW-U F-TEID is never fixed: a new Initial Context Setup supplies a new
value each attach.

## 5. S1-U, GTP-U and the PDN

`S1uEndpoint` uses the production GTP-U codec: a real G-PDU with the bearer's
SGW TEID on `10.10.0.139:2152`, and the downlink G-PDU is accepted only for the
bearer's local TEID and verified SGW peer. The PDN address is adopted from the
Attach Accept's ESM bearer, never from 10.45.0.2.

UL: UE TUN -> bearer/TFT -> PDCP -> RLC AM -> simulated Uu -> eNB DRB ->
S1uEndpoint -> GTP-U G-PDU -> Open5GS SGW-U -> PGW-U -> ogstun -> the host test
endpoint.

DL: test endpoint -> host route to the UE pool via ogstun -> PGW-U -> SGW-U ->
GTP-U to the eNB's advertised F-TEID -> eNB DRB -> simulated Uu -> UE DRB ->
PDCP -> TUN.

The live test endpoint was the host's existing `10.10.0.139`, not a local
echo written into the UE TUN.

## 6. Test isolation and sensitive data

- The designated test subscriber is `460020000000007` (`cmnet`, IPv4) from the
  owner's private `config/open5gs-lte-ue.local.yaml`. Its K/OPc/AMF were compared
  with the HSS record in memory and never printed.
- The generated test configs are written under `/tmp` with mode 600, are never
  committed and were deleted after the run. `config/*.local.yaml` is mode 600
  and git-ignored.
- The test eNB and UE run in an isolated network namespace with a new veth; the
  namespace and veth are removed after the run.
- No Open5GS service was restarted, reconfigured or modified. No subscriber was
  created, changed or deleted. The detach pass returned the MME/SMF session
  counts to their pre-test baseline of 5.
- The live PCAPs are in `reports/evidence/phase-18-f-b6-d9/` (git-ignored).
  They contain S1AP/NAS/GTP-U payloads but no long-term K/OPc.

## 7. Known limitations

1. **Abnormal UE exit leaves an eNB SRB context.** If the UE process stops
   without an EPS Detach/RRC release, a later Attach from the same radio UE
   identity on the same eNB reuses the eNB's retained SRB RLC state; the new
   SetupComplete's SN is treated as an old/duplicate PDU and the MME never sees
   the Attach Request. A clean Detach releases the SRB and a repeated Attach on
   the same eNB works (verified .174 -> .175). A fresh eNB clears the abnormal
   case. Resetting the SRB RLC on a new RRC connection is not implemented.
2. **ECM-IDLE/Service Request on a live MME is not executed.** Driving the
   network release needs a controlled MME action that this environment does not
   provide without configuration changes; D9-G26 is PARTIAL. The D5/D7
   deterministic ECM-IDLE/SR path remains the functional evidence.
3. **GUTI Reallocation is ignored.** EMM message type 97 is not decoded by the
   production UE; it does not break the attach.
4. **The Uu is loopback-only.** The eNB's Uu endpoint binds `127.0.0.1`; the
   test eNB and UE share an isolated namespace. A separate-namespace eNB would
   need a Uu bind/source-address change.
5. **UDP receive-queue drops remain a transport observation.** In the D8
   deterministic runs the SGW-U and eNB S1-U sockets dropped under bursts; the
   live run at ~19-20 Mbit/s saw 9 cumulative SGW-U drops and 66 eNB S1-U
   receive drops, with zero application drops and zero DRB send failures. The
   counts are not hidden and no buffer is enlarged by default.
6. **The live EPC is a debug build.** Its measured ~19-20 Mbit/s is an EPC-side
   result, not the production UE/eNB limit; the D8 deterministic path measured
   ~70 Mbit/s. No 1 Gbps claim is made.
7. **No live EPC job in GitHub-hosted CI.** The hosted runners have no Open5GS;
   the live acceptance is local evidence. Deterministic CI remains the blocking
   matrix.

## 8. Roadmap

- D9 establishes the real-EPC single-UE Attach and bidirectional user plane.
- Next: D10 multi-UE architecture at 512 scale; D11 single-UE 1 Gbps; later
  NR/5GC integration. The performance roadmap
  (`docs/lte-performance-scalability-roadmap.md`) keeps PERF-P1/P2 deferred and
  is not silently advanced by this integration.
