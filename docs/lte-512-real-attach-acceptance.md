# LTE 512-UE real Attach acceptance

This acceptance measured the production LTE UE, eNB, NAS-EPS, S1AP and GTP-U
path against the owner's running Open5GS EPC. This record states what was verified,
what was executed and what remains outside the phase.

**Verdict: `REAL_512_UE_ACCEPTED`.** 512 distinct authorized subscribers
completed genuine EPS-AKA, NAS security, Attach Accept and Attach Complete,
held default EPS bearers with unique PDN IPv4 addresses, and remained
simultaneously registered for a five-minute retention window. Cleanup returned
the EPC to its pre-campaign session baseline.

Environment: xCloud Open5GS install at `10.10.0.139`, PLMN 460/02, TAC 1,
MME/ SMF session bound 1024, host Linux 6.17.0-35, GCC 13 Release build.

## 1. Scope and authorization

| Item | Value |
|---|---|
| Selected IMSI range | 460020000000400 … 460020000000911 inclusive |
| Count | 512 |
| MCC / MNC | 460 / 02 (two-digit MNC preserved) |
| APN | cmnet |
| Checkpoints | 1 → 4 → 16 → 32 → 64 → 128 → 256 → 512 |
| Retention window | 300 s |
| Cleanup | supported UE Detach path, then eNB stop |

The owner authorized the bounded 512 staged campaign. No subscriber was
created, modified or deleted. No EPC service was restarted or reconfigured. No
K, OPc or OP value is recorded here or in Git.

## 2. Subscriber inventory

The running HSS uses the `xcloud` database. Read-only checks against it
returned:

- 512 records in the selected range, 512 distinct IMSIs, zero missing
  identities, zero duplicates.
- Every range endpoint is present; the full expected set was checked, not just
  the count.
- 512 records with a 32-hex K, a 32-hex OPc, a 4-hex AMF and APN `cmnet`.
- The `op` field is present as an Open5GS object; the generated UE
  configurations use the unambiguous OPc value. No record carries both a
  usable OPc and a usable OP as plain material.
- None of the selected IMSIs appeared in the MME log before the campaign; the
  owner's concurrent test used other identities.

Result: `SUBSCRIBER_RANGE_VERIFIED`.

## 3. PLMN, APN and PDN capacity

| Item | Observed |
|---|---|
| MME GUMMEI / TAI | 460/02, TAC 1 and 2 |
| eNB cell | 460/02, TAC 1, eNB-ID 0x19D |
| UE | 460/02, APN cmnet |
| SMF session pools | 10.45.0.0/16, 10.46.0.0/16, 10.47.0.0/16 |
| PDN gateway | 10.45.0.1 (ogstun) |
| Addresses needed | 512, far below one /16 |
| MME / SMF max UE | 1024 |

The campaign used 10.45.0.0/16. No pool was enlarged and no global setting was
changed.

## 4. Generated configurations

512 configurations were generated from the authorized records into a mode-700
directory, each file mode 600 and outside Git. Each configuration carried:

- one IMSI from the verified range, MCC 460 and MNC 02;
- its matching K, OPc and AMF, without printing them;
- `apn: cmnet`, IPv4 PDN, the LTE attach-only lifecycle and a 60 s attach
  timeout;
- a unique radio UE identity, a unique `enbLink.localPort` (30000…30511);
- a unique TUN prefix `p19dNNN` so concurrent allocation cannot collide.

A secret-free manifest recorded the one-to-one index → IMSI → ueId → port →
TUN-prefix mapping. The C++ core in `src/lte/enb/registration_campaign.{hpp,cpp}`
implements and tests the same inventory, manifest, protected-write, failure and
cleanup rules.

## 5. Progressive checkpoint results

Every checkpoint used the production `lte-ue` and `lte-enb` binaries. A
checkpoint advanced only after the previous one had all requested UEs
registered and all TUN/IP resources present.

| Requested | Started | MME registered | Processes | TUNs | Unique IPv4 | UDP drops | RSS sum | PSS sum |
|---:|---:|---:|---:|---:|---:|---:|---:|---:|
| 1 | 1 | 1 | 1 | 1 | 1 | 0 | 5.3 MiB | 1.6 MiB |
| 4 | 4 | 4 | 4 | 4 | 4 | 0 | 21.2 MiB | 3.3 MiB |
| 16 | 16 | 16 | 16 | 16 | 16 | 0 | 84.8 MiB | 9.6 MiB |
| 32 | 32 | 32 | 32 | 32 | 32 | 0 | 169.7 MiB | 17.7 MiB |
| 64 | 64 | 64 | 64 | 64 | 64 | 0 | 339.7 MiB | 33.8 MiB |
| 128 | 128 | 128 | 128 | 128 | 128 | 0 | 680.0 MiB | 65.5 MiB |
| 256 | 256 | 256 | 256 | 256 | 256 | 0 | 1359.6 MiB | 128.4 MiB |
| **512** | **512** | **512** | **512** | **512** | **512** | **0** | **2719.6 MiB** | **253.8 MiB** |

Checkpoint completion from the first UE: 1 at 0 s, 4 at 1.8 s, 16 at 3.8 s,
32 at 6.1 s, 64 at 9.7 s, 128 at 15.8 s, 256 at 26.9 s, 512 at 49.6 s. The
last 256 UEs averaged about 89 ms per UE from process start to registered
state, including TUN creation and the TUN move.

## 6. Genuine EPS-AKA and NAS security

Every selected subscriber traversed the real EPC authentication path. The UE
logs show, per identity:

```text
State=AUTHENTICATION_REQUEST_RECEIVED
State=AUTHENTICATION_RESPONSE_SENT
State=SECURITY_MODE_COMMAND_RECEIVED
NAS security activated: EIA2/EEA0 KSI=0
State=NAS_SECURITY_ACTIVE
State=SECURITY_MODE_COMPLETE_SENT
```

The MME log independently records the Initial UE Message, the Attach request,
the bearer addition and the Attach complete for the same IMSIs. No
authentication result was injected, no MAC check was bypassed and NAS security
was not disabled. No SQN synchronization failure occurred.

## 7. Attach Accept, default bearer and address evidence

For all 512 UEs:

```text
State=ATTACH_ACCEPT_RECEIVED
State=DEFAULT_BEARER_PENDING
Default EPS bearer: EBI=5 QCI=9 APN=cmnet
State=ATTACH_COMPLETE_SENT
State=EPS_REGISTERED
State=DEFAULT_BEARER_SIGNALING_COMPLETE
Assigned EPS bearer EBI=5 IPv4=10.45.x.y
State=TUN_READY
State=USER_PLANE_ACTIVE
```

The 512 assigned IPv4 addresses were distinct. The MME reported 512 registered
eNB-UEs and 513 MME sessions (the owner's one pre-existing session plus the
512 campaign sessions); the SMF reported 513 GTPv2 and 513 PFCP sessions.

## 8. Retention

After the 512 checkpoint the campaign held a 300 s observation window and
sampled every 5 s. All 60 samples reported:

- 512 MME-registered UEs;
- 512 campaign TUN interfaces with 512 unique IP addresses;
- 512 live UE processes;
- 0 eNB radio-socket UDP drops.

No unexpected detach, bearer release, process exit or address change occurred.
The pilot user plane remained usable: three ICMP echo requests through the real
S1-U path received three replies.

## 9. Resource observations

- UE fleet at 512: RSS sum 2719.6 MiB, PSS sum 253.8 MiB, one thread and one
  UDP socket per process, plus one TUN per UE.
- eNB radio socket: 212,992 B receive buffer, zero drops at every checkpoint.
- EPC process RSS at the post-campaign baseline: MME 16,148 KiB, SMF 38,476
  KiB, SGW-U 13,984 KiB, SGW-C 17,868 KiB. EPC CPU during the 512 window was
  not sampled; only session counts and MME metrics are reported for that
  interval.
- No file-descriptor exhaustion, memory-pressure stop or SCTP association loss
  occurred.

## 10. Failure handling and the TUN collision finding

An earlier 32-UE attempt used one shared TUN prefix. Concurrent allocation raced
on the same generated name and one UE failed TUN allocation after a successful
Attach. That attempt was stopped, and its 32 sessions were cleared through the
supported Detach path.

The final campaign uses a unique per-UE prefix (`p19dNNN`) and completed with
zero UE failures, zero TUN failures and zero registration timeouts. The finding
is retained because it is a real concurrency limit of a shared TUN prefix, not
a subscriber or EPC failure.

## 11. Cleanup and rollback

Cleanup used the production UE Detach path for every campaign IMSI, not an EPC
restart. After the detach pass and the eNB stop:

- UE processes: 0;
- campaign TUN interfaces: 0;
- MME eNB-UE count: 0;
- MME sessions: 1 (the owner's baseline);
- SMF GTPv2 and PFCP sessions: 1;
- eNB connections: 1 (the owner's eNB);
- test-owned network namespace: removed;
- no unrelated session was deleted.

The first aborted 32-UE attempt was cleaned the same way before the final
campaign started. After the final campaign, the first detach pass was started
while the old eNB still held all 512 contexts and was rejected as
"registry full"; the eNB was stopped to release its contexts, a fresh eNB was
started, and the detach pass completed. The final state above is from that
successful pass.

## 12. Remaining limitations

1. EPC CPU during the 512 window was not sampled. Session and MME metrics are
   complete; a future campaign can add a CPU sampler without changing the UE
   path.
2. The campaign is a registration and retention acceptance, not a throughput
   acceptance. PERF-P1 remains independent and unmeasured.
3. The owner's inventory contains 1,000 records; this phase used only the
   designated 512 and did not modify any record.
4. User-plane verification is a low-rate pilot check, not 512 simultaneous
   flows.

## 13. Safety

No subscriber record was created, modified or deleted. No K/OPc was printed or
committed. No Open5GS process was restarted or reconfigured. No global sysctl,
route, APN pool or unrelated session was changed. Generated credential-bearing
configurations live only in a protected local directory outside Git.