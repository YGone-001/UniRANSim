# LTE multi-UE architecture (D10)

This record states the multi-UE production architecture, what was measured in
D10 and its 512 continuation, and the limits that remain. On the 6-core /
7.7 GiB laboratory host the isolated production Uu/DRB fleet reached **512
UEs**: 512 attach/bearer/DRB/IP, 1024/1024 zero-loss per-UE probes at the 512
stage and again after the retention window, a 10-minute window at 512 sessions,
and a 512-UE production Detach back to 0. The 60 s concurrent 8/16/32/64 gate
and the same-eNB reattach after an abnormal exit are **not** pass. The real
shared-EPC portion is 256 UEs, not 512; that result is kept separate.

## 1. Ownership model

| State | Owner |
|---|---|
| NAS/ESM, UE PDN address, bearer/TFT, TUN | one production `lte-ue` process |
| RRC/SRB1, DRB/PDCP/RLC AM for one UE | that process plus the eNB's per-association bridge context |
| S1AP identities, E-RAB, local S1-U TEID, peer | `UeRegistry` entry in the eNB |
| SGW-U F-TEID, session, PGW-U/UPF bearer | the isolated Open5GS EPC |
| Uu association | the Uu envelope's association field and the eNB's per-association bridge context |

The eNB manages many UEs through one registry, one SCTP association (10
in/out streams on the live MME), one shared Uu UDP socket and one shared S1-U
socket. UE-associated signalling is routed by the S1AP identity pair; Uu frames
by the association and the UE source port; S1-U by the local TEID and verified
peer. EBI 5, DRB identity 5 and E-RAB identity 5 are the same value on every
UE; they are scoped by the UE context, and no EBI is globally unique.

## 2. Uu and TUN isolation

- The eNB Uu socket is a single loopback endpoint (`127.0.0.1:<port>`). Each
  UE process owns a unique Uu local port; the association is the routing
  identity. 512 UEs coexisted on the one socket in the accepted run.
- Each UE process owns one TUN with a unique name prefix and the PDN address
  the live EPC assigned. 512 TUNs coexisted in one test namespace.
- Per-UE test traffic uses **source policy routing**:
  `ip rule from <UE IP> lookup <table>` and a per-table route to the PDN test
  endpoint via that UE's TUN. A static per-UE route to the same endpoint would
  overwrite the previous UE's route, so the harness installs the rules after
  each TUN is ready.
- Limitation: all UEs are in one namespace, so their PDN addresses are local
  interfaces. The EPC path per UE is verified, but a local application could
  reach another UE's TUN address without the EPC. True L3 isolation needs
  per-UE namespaces/VRFs and an eNB Uu endpoint that binds a concrete address;
  the current eNB Uu is loopback-only. The 512 result is an EPC-path and
  per-UE-flow result, not a claim of hostile-tenant isolation.

## 3. S1AP and SCTP

The real MME accepted the eNB with 10 inbound/outbound streams. 512 UE
contexts shared the one association. The eNB allocates eNB-UE-S1AP-IDs from
the registry; the MME-UE-S1AP-ID is learned from S1AP; every UE-associated
message is dispatched by that pair. The historical 512 attach campaign proved
the same model at 512 contexts; the D10-512 production-Uu run confirms it with
the current code.

## 4. NAS, security, bearer and DRB

Each UE process performs its own EPS AKA, NAS integrity/ciphering and NAS
COUNT. The eNB treats NAS as opaque. Each UE receives EBI 5 / QCI 9 on
`cmnet`; each has its own E-RAB, DRB, PDCP entity, RLC AM entity, TEID pair and
PDN IPv4. The eNB's `m_drbs` map is keyed by radio UE id, so the DRB maps do
not collide across UEs; the registry's TEID allocator keeps local TEIDs unique.

## 5. Isolated EPC

The D10 EPC runs entirely in its own network namespace, with its own mongod
database (`xcloud_d10`), its own address plan (127.0.0.x internal, 10.97.0.1
S1-MME/S1-U), its own `d10tun` and 10.80.0.0/16 pool, and 512 generated test
subscribers (460029900000001..512). The 256 real-subscriber run used the shared
laboratory EPC at 10.10.0.139 read-only and never reconfigured it; its test
sessions were removed through the production Detach, leaving the owner's four
sessions at 17:33. The shared EPC's own logs show its seven daemons terminating
at 17:38 with those four sessions, during the owner's rebuild activity; this
work did not signal or restart it, and a read-only check at 21:09 found it still
down. See `docs/lte-512-ue-scale-testing.md` and
`reports/PHASE-18-F-B6-D10-512-UE-CONTINUATION-FINAL-REPORT.md`.

## 6. Lifecycle and failure isolation

- A UE release through the MME retires its local TEIDs and destroys its DRB,
  PDCP and RLC entities; other UEs are untouched.
- A single UE `SIGKILL` leaves the surviving UEs carrying traffic. In the
  512-UE fleet, after UE 300 was killed its neighbours 299 and 301 answered
  the 1372-byte UDP probe with 0 loss. The killed UE's eNB access is stale.
- D10 added a fresh SRB context for a new RRC connection and a retained-EPS
  release of a stale active access (old local TEIDs retired, old DRB
  destroyed) when the same radio identity reconnects.
- Limitation: a same-eNB reattach after an abnormal exit still times out in
  the bridge/MME stale-context path, even after the SRB/access reset. The
  512-UE run repeated the test: the UE reached RRC_CONNECTED and timed out
  waiting for the MME Attach signalling. That path remains FAILED. A clean
  Detach and a fresh eNB both work.
- GUTI Reallocation (EMM message type 97) is still ignored by the production
  UE. The 512 attaches completed, but GUTI handling remains a gap.

## 7. Measured scale and resource budget

Isolated EPC, host 6 cores / 7.7 GiB, production `lte-ue`/`lte-enb`:

| Total UEs | MME sessions | Stage probes (36 B + 1372 B) | MemAvailable |
|---:|---:|---|---:|
| 1 | 1 | 2/2 | 4964 MB |
| 2 | 2 | 4/4 | 5080 MB |
| 4 | 4 | 8/8 | 5084 MB |
| 8 | 8 | 16/16 | 5078 MB |
| 16 | 16 | 32/32 | 5072 MB |
| 32 | 32 | 64/64 | 5031 MB |
| 64 | 64 | 128/128 | 4976 MB |
| 128 | 128 | 256/256 | 4842 MB |
| 256 | 256 | 512/512 | 4580 MB |
| 320 | 320 | 640/640 | 4444 MB |
| 384 | 384 | 768/768 | 4303 MB |
| 448 | 448 | 896/896 | 4163 MB |
| 512 | 512 | 1024/1024 | 4018 MB |

Each probe is five UDP payloads of 36 or 1372 bytes, one per UE, with per-UE
echo and zero loss/corrupt. The 512 stage and the final all-512 probe both
returned 1024/1024, and the 10-minute window kept `mme_sessions=512`.

The host cost is not the process RSS. A production UE process is about 8.6 MiB
RSS at idle, but its shared pages make the host increment far smaller: the sum
PSS was 1.77 MB/UE at 512 and the cumulative MemAvailable increment 1.96 MB/UE
(4,018 MB available at 512, SwapUsed flat near 2,751 MB). The 8.6 MiB RSS sum
is why the earlier 9 MB/UE estimate wrongly declared 512 blocked; the harness
now separates the two and gates on the host increment with a 3.0 MB/UE model
and a 512 MB floor.

The 60 s concurrent 8/16/32/64 measurement did not pass: the un-paced UDP
clients (200,000 × 36 B per UE) overflowed the per-UE TUN backpressure and the
echo endpoint received 1.51%/0.70%/0.34%/0.004% at 8/16/32/64 UEs. That is
queue loss from a blast, not a paced capacity result; no pass is claimed.

## 8. What is not implemented

- A paced 60-second concurrent 8/16/32/64 traffic test. The un-paced blast is
  measured and does not pass (§7); there is no paced alternative yet.
- Per-UE namespaces/VRFs for hostile-tenant TUN isolation.
- Same-eNB reattach after an abnormal exit through the bridge/MME stale path;
  it still times out waiting for the MME Attach signalling.
- GUTI Reallocation.
- A 512-UE real shared-EPC run; the real portion is 256 UEs.
- Live ECM-IDLE/Service Request (inherited from D9).
