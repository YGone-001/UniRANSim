# Open5GS S1 handover: source-backed interoperability record

What the real EPC in this laboratory implements for S1-based handover, what
UniRANSim would have to satisfy to interoperate with it, and why the answer is
**NO-GO** for a live handover today.

Three kinds of evidence appear below and are never mixed:

* **SOURCE_VERIFIED** — read out of the Open5GS checkout at the revision named in
  §2, with the file and line.
* **CAPTURED** — read out of a packet capture that already existed, with its
  SHA-256.
* **DETERMINISTIC** — produced by this repository's own tests offline.

Nothing in this record is a live interaction. No handover was attempted against
the EPC, and no new capture was taken.

## 1. Scope

Phase 18-F-A is an interoperability *foundation*: it establishes what the real
MME does, what UniRANSim can safely do with the messages that reach it, and what
is still missing. It does not authorize, attempt or claim a live handover.

## 2. Provenance

### 2.1 Source

| | |
|---|---|
| Checkout | `/usr/local/src/xcloud-5gs` |
| Upstream project | Open5GS 2.8.0 (`meson.build` `version : '2.8.0'`), a fork of upstream Open5GS maintained as `Core-Network` |
| Revision | `6730a25792467b094e2af7b674ce54d9c3db39bc` |
| Describe | `R50V208-29-g6730a2579` (29 commits after tag `R50V208`) |
| Commit date | 2026-11-06 14:34:33 +0800 |
| Working tree | one modified file, `compile.sh` (a build script); every file under `src/` is unmodified |
| Newest tracked source file | `src/pcrf/pcrf-rx-path.c`, 2026-11-06 11:59:27 |

### 2.2 Running process

| | |
|---|---|
| Process | `mmed`, pid 1405246, `./mmed` under `screen -dmS mme` |
| Binary | `/usr/local/src/xcloud-5gs/install/bin/mmed` (2,744,568 bytes, mtime 2026-11-09 18:13:48) |
| Working directory | `/usr/local/src/xcloud-5gs/install/bin` |
| Build tree referenced by the binary | `/usr/local/src/xcloud-5gs/build` (`build.ninja` 2026-11-09 17:52:45; `src/mme/libmme.a` 2026-11-09 17:54:12) |
| Companion daemons observed | `sgwcd`, `sgwud`, `smfd`, `upfd`, each in its own screen session |

**How the binary is related to the source, and the limit of that relation.**
The binary was linked on 2026-11-09 18:13 from
`/usr/local/src/xcloud-5gs/build`, whose objects were compiled at 17:54 that
day. The newest source file in the checkout is from 2026-11-06 11:59, and no
source file has changed since, so the build was made from this checkout at
`6730a257` with nothing stale. The binary embeds the path
`/usr/local/src/xcloud-5gs/build`, which confirms the tree it came from.

The limitation is that no build identifier was read *from the binary itself*:
running `mmed --version` is forbidden in this laboratory because it prints the
version and then starts the daemon. The identity above therefore rests on build
tree, timestamps and source state rather than on a digest. If a later phase
needs a cryptographic link, the deliverable is a build manifest produced at
build time, not a runtime query.

### 2.3 What was not done

No process was started, restarted, reconfigured or signalled. No configuration
was read-modify-written. No `--version` was executed. No subscriber or
authentication data was read. No traffic was sent to the MME, SGW-C or SGW-U.

## 3. MME procedure support matrix

Every row is SOURCE_VERIFIED. "Supported" here means the procedure is
implemented and reachable from the S1AP dispatch table, not that its ASN.1
definition merely exists.

| # | Procedure | Entry point | Behaviour | Evidence |
|---|---|---|---|---|
| 1 | Handover Required reception | `s1ap_handle_handover_required` | Decodes the message, requires MME-UE-S1AP-ID, eNB-UE-S1AP-ID, HandoverType, Cause, TargetID and the Source-ToTarget container; Error Indication on a missing IE | `src/mme/s1ap-handler.c:3421`, dispatch `src/mme/s1ap-sm.c:114` |
| 2 | Target selection | `s1ap_handle_handover_required_intralte` | The target is the eNB named by `TargetID.targeteNB_ID`, resolved with `mme_enb_find_by_enb_id`; an unknown eNB is `radioNetwork/unknown_targetID`. Nothing is discovered by TAC or PLMN | `src/mme/s1ap-handler.c:3335`, `:3364`, `:3368` |
| 3 | Handover Request construction | `s1ap_build_handover_request` | MME-UE-S1AP-ID, HandoverType, Cause, UE-AMBR, E-RABToBeSetupListHOReq, Source-ToTarget container passed through opaquely, UESecurityCapabilities, SecurityContext | `src/mme/s1ap-build.c:2736`, IE construction `:2865`–`:3051` |
| 4 | Handover Request Acknowledge handling | `s1ap_handle_handover_request_ack` | Requires eNB-UE-S1AP-ID, MME-UE-S1AP-ID, E-RABAdmittedList and Target-ToSource container; records each admitted bearer's `target_s1u_ip`/`target_s1u_teid` and stores the container | `src/mme/s1ap-handler.c:3607`, bearer loop `:3739`–`:3895`, `OGS_ASN_STORE_DATA` `:3905` |
| 5 | Handover Preparation Failure | `s1ap_handle_handover_failure` | Fails the source-side context; dispatched on `HandoverResourceAllocation` unsuccessfulOutcome | `src/mme/s1ap-handler.c:3914`, dispatch `src/mme/s1ap-sm.c:196` |
| 6 | Handover Command generation | `s1ap_build_handover_command` + `s1ap_send_handover_command` | MME-UE-S1AP-ID, eNB-UE-S1AP-ID, HandoverType, E-RABSubjecttoDataForwardingList, Target-ToSource container from the stored bytes | `src/mme/s1ap-build.c:2451`, `src/mme/s1ap-path.c:683` |
| 7 | Handover Notify handling | `s1ap_handle_handover_notification` | Requires eNB-UE-S1AP-ID, MME-UE-S1AP-ID, EUTRAN-CGI and TAI; updates the UE's TAI and E-CGI from the notify | `src/mme/s1ap-handler.c:4258`, dispatch `src/mme/s1ap-sm.c:123` |
| 8 | SGW bearer-path update | `s1ap_handle_handover_notification` → `mme_gtp_send_modify_bearer_request` | Copies `target_s1u_ip/teid` into `enb_s1u_ip/teid` for every bearer, then sends an S11 Modify Bearer Request | `src/mme/s1ap-handler.c:4490`–`:4516`, `src/mme/mme-gtp-path.c:314`, SGW-C `src/sgwc/s11-handler.c:449`, PFCP `src/sgwc/sxa-handler.c:1619`, SGW-U `src/sgwu/pfcp-sm.c:267` |
| 9 | Source UE Context Release | `s1ap_send_ue_context_release_command` with `radioNetwork/successful_handover` | Sent from the notify handler, **before** the Modify Bearer Request | `src/mme/s1ap-handler.c:4480`–`:4486` |
| 10 | Failure and timeout handling | `s1ap_handle_handover_cancel`, `s1ap_handle_handover_failure`, the S1AP state machine timers | A cancel or a failure ends the transaction; `TimeToWait` is carried in the failure | `src/mme/s1ap-handler.c:4014`, `:3914`, `src/mme/s1ap-sm.c` |

### 3.1 What the MME does with the source-to-target container

Nothing. It decodes the IE as an OCTET STRING, passes the bytes into the
Handover Request unchanged (`src/mme/s1ap-build.c:2865`), and stores the target's
container to echo into the Handover Command (`OGS_ASN_STORE_DATA`,
`src/mme/s1ap-handler.c:3900`). It never parses RRC. The RRC contract is between
the two eNBs and the UE, which is why UniRANSim cannot lean on the MME to
validate it — and why a simulator container would be delivered to a real target
eNB and a real UE as if it were RRC.

### 3.2 What the MME does with security

`s1ap_handle_handover_required_intralte` increments the NCC and derives a new NH
from KASME before sending the request: `mme_ue->nhcc++; ogs_kdf_nh_enb(mme_ue->kasme, mme_ue->nh, mme_ue->nh);`
(`src/mme/s1ap-handler.c:3411`–`:3412`). The request carries
`nextHopChainingCount` and a 32-octet `nextHopParameter`
(`src/mme/s1ap-build.c:3044`–`:3051`), and the UE's advertised algorithms
(`:3033`, `:3041`). A target that cannot apply NH cannot honour the request, and
the MME has already advanced its NCC when it finds out.

## 4. What this means for UniRANSim

| Requirement | What the MME provides | What UniRANSim has |
|---|---|---|
| Target identity | The target eNB is the recipient of the Handover Request; the MME resolved it by eNB-ID | The target knows itself; nothing to check in the message, and nothing that names the source |
| Source identity at the target | **Nothing.** No S1AP IE names the source eNB; the RRC container carries a `sourcePhysCellId` and a C-RNTI, not an eNB identity the target can verify | The isolated path uses `ExtractSourceSession` over the source's own registry, which a target does not have |
| Bearer inventory | E-RABToBeSetupListHOReq per bearer with QCI/ARP and the **SGW-side** transport | Decodable; the codec and the target's checks exist |
| Target transport | The MME expects the target's own endpoint per admitted bearer in the acknowledge | The target can allocate it, and the isolated commit already does |
| RRC | Opaque; produced by the source, consumed by the UE, echoed by the MME | Implemented: a TS 36.331 V15.6.0 codec (`src/lte/rrc`, UPER) and, since Phase 18-F-B2, the 36.413 container SEQUENCEs (`src/lte/enb/transparent_container.cpp`, APER) that carry them |
| AS security | NCC + NH, derived from KASME by the MME | The UE has KASME and NAS keys only; no KeNB, no NH handling |
| Core path update | S11 Modify Bearer → Sxa → SGW-U, invisible to the eNB | Invisible; the isolated SGW map is not the core's |

## 5. Capture evidence

Two S1AP captures from the Phase 17-B campaign were inspected read-only. Both
are `CAPTURED`; neither contains a handover.

| File | Size | SHA-256 (first 16) | S1AP procedures present | Handover procedures |
|---|---|---|---|---|
| `artifacts/phase-17-b/run-p17b-20261105-112119/s1ap.pcap` | 13,740 | `e642d61970adafcb` | 5, 9, 11, 12, 13, 18, 23 | **none** |
| `artifacts/phase-17-b/run-p17b-20261105-114739/s1ap.pcap` | 53,088 | `1db8e99d7396f63a` | 5, 9, 10, 11, 12, 13, 18, 23 | **none** |

Procedure inventory read with `tshark -r <file> -d sctp.ppi==18,s1ap -Y s1ap`:
InitialUEMessage, InitialContextSetup, Paging, Uplink/DownlinkNASTransport,
E-RABSetup, UEContextReleaseRequest/Command/Complete. There is **no** Handover
Required, Request, Acknowledge, Command, Notify or Failure in either file, so
there is no real S1 handover evidence in this repository at all. Any statement
about a real handover in this project is `NOT_ESTABLISHED` until a capture
contains one.

The two APER fixtures the new ingress tests use were independently re-checked
with tshark 4.2.2 over SCTP (PPID 18, `-d sctp.port==36412,s1ap`) while this
phase was written:

* Handover Request — `initiatingMessage`, `procedureCode: id-HandoverResourceAllocation (1)`,
  MME-UE-S1AP-ID 7, HandoverType intralte, Cause radioNetwork,
  E-RABToBeSetupListHOReq with E-RAB 5 and 6, a Source-ToTarget container,
  UESecurityCapabilities `8000`/`4000`, SecurityContext NCC 3 and a 32-octet NH.
* Handover Command — `successfulOutcome`, `procedureCode: id-HandoverPreparation (0)`,
  MME-UE-S1AP-ID 7, eNB-UE-S1AP-ID 9, HandoverType intralte, a Target-ToSource
  container of four octets.

tshark decodes those containers as `SourceeNB-ToTargeteNB-TransparentContainer`
and `TargeteNB-ToSourceeNB-TransparentContainer` and reports the inner bytes as
`Malformed`, because the fixtures carry test octets rather than RRC. That is the
same observation Phase 18-A recorded, and it is the clearest statement of the
gap: **the wire form expects RRC, and this repository has none.**

## 6. Live GO/NO-GO

**LIVE_S1_HANDOVER_NO_GO.**

| Blocker | Why it blocks | What would close it |
|---|---|---|
| Source provenance at the target | No S1AP field names the source eNB, and this repository refuses to infer one from the peer address, TAC, PLMN, EBI or the container | A defined and verified ownership contract, or a target that trusts the MME's association by an explicitly accepted policy |
| RRC container | Both 36.413 container SEQUENCEs are encoded and dissected, and since Phase 18-F-B3 the runtime supplies the history and target CGI from components that own them (simulator runtime evidence) | Real-RF AS configuration, AS security and UE RRC execution |
| AS security | The UE has no KeNB/NH derivation and no RRC/UP keys | TS 33.401 key derivation and RRC security in the UE runtime |
| UE radio execution | The UE moves on a simulator control frame, not an RRC reconfiguration | An RRC execution path in the UE |
| Core path observability | The eNB cannot see the SGW's map | Nothing on the eNB side; the evidence has to come from the core's own state |
| Live authorization | This phase is not authorized to run a live handover | A fresh, separately scoped authorization naming every resource |

No amount of decoding turns any of these into a pass. The ingress built in this
phase exists so that the first four are visible and fail closed rather than
being discovered at the moment a live message arrives.
