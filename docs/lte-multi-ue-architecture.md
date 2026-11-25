# LTE multi-UE architecture (D10)

This record states the multi-UE production architecture, what was measured in
D10, and the limits that remain. The 512-UE live acceptance is not claimed: on
the 6-core / 7.7 GiB laboratory host the production Uu/DRB fleet stops at 256
UEs and the 512 case is `BLOCKED_RESOURCE_LIMIT`.

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
  identity. 256 UEs coexist on the one socket.
- Each UE process owns one TUN with a unique name prefix and the PDN address
  the live EPC assigned. 256 TUNs coexisted in one test namespace.
- Per-UE test traffic uses **source policy routing**:
  `ip rule from <UE IP> lookup <table>` and a per-table route to the PDN test
  endpoint via that UE's TUN. A static per-UE route to the same endpoint would
  overwrite the previous UE's route, so the harness installs the rules after
  each TUN is ready.
- Limitation: all UEs are in one namespace, so their PDN addresses are local
  interfaces. The EPC path per UE is verified, but a local application could
  reach another UE's TUN address without the EPC. True L3 isolation needs
  per-UE namespaces/VRFs and an eNB Uu endpoint that binds a concrete address;
  the current eNB Uu is loopback-only. The 256 result is an EPC-path and
  per-UE-flow result, not a claim of hostile-tenant isolation.

## 3. S1AP and SCTP

The real MME accepted the eNB with 10 inbound/outbound streams. 256 UE
contexts shared the one association. The eNB allocates eNB-UE-S1AP-IDs from
the registry; the MME-UE-S1AP-ID is learned from S1AP; every UE-associated
message is dispatched by that pair. The historical 512 attach campaign proved
the same model at 512 contexts; D10's 256 production-Uu test confirms it with
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
subscribers (460029900000001..512). The shared laboratory EPC at 10.10.0.139
was not restarted, reconfigured or stressed; its baseline session count was
unchanged. See `docs/lte-512-ue-scale-testing.md`.

## 6. Lifecycle and failure isolation

- A UE release through the MME retires its local TEIDs and destroys its DRB,
  PDCP and RLC entities; other UEs are untouched.
- A single UE `SIGKILL` leaves the surviving UEs carrying traffic (verified at
  2 UEs: the survivor's 1372-byte UDP probe stayed 10/10). The killed UE's
  eNB access is stale.
- D10 added a fresh SRB context for a new RRC connection and a retained-EPS
  release of a stale active access (old local TEIDs retired, old DRB
  destroyed) when the same radio identity reconnects.
- Limitation: a same-eNB reattach after an abnormal exit still times out in
  the bridge/MME stale-context path, even after the SRB/access reset. That
  path remains PARTIAL. A clean Detach and a fresh eNB both work.
- GUTI Reallocation (EMM message type 97) is still ignored by the production
  UE. The 256 attaches completed, but GUTI handling is a D10 gap.

## 7. Measured scale and resource budget

Isolated EPC, host 6 cores / 7.7 GiB, production `lte-ue`/`lte-enb`:

| Total UEs | MME sessions | Per-UE 1372-byte UL/DL probe | MemAvailable |
|---:|---:|---|---:|
| 4 | 4 | 2/2 | - |
| 8 | 8 | 6/6 | - |
| 16 | 16 | 14/14 | - |
| 32 | 32 | 30/30 | - |
| 64 | 64 | 62/62 | 3678 MB |
| 128 | 128 | 64/64 | 3419 MB |
| 256 | 256 | 128/128 | 3053 MB |

Each probe is five 1372-byte UDP payloads (1400-byte IP), one per UE, with
per-UE echo and zero loss/corrupt. A production UE process is about 8.6 MiB
RSS at the measured idle state; the eNB about 8.5 MiB plus its per-UE maps;
the isolated EPC (including its mongod) about 480 MiB.

The 512 target needs about 4.4 GiB just for the UE fleet. With the host's
2926 MB available and the declared reserve, starting 512 would risk the shared
laboratory EPC. The harness therefore reports
`BLOCKED_RESOURCE_LIMIT` and does not start. The 512 gates are BLOCKED, not
PASS; no deterministic or extrapolated number is substituted.

## 8. What is not implemented

- 512 UEs on this host; the 10-minute 512 retention and the 512 data-plane
  smoke.
- Per-UE namespaces/VRFs for hostile-tenant TUN isolation.
- Same-eNB reattach after an abnormal exit through the bridge/MME stale path.
- GUTI Reallocation.
- 60-second concurrent 8/16/32/64 UE traffic and the batch Detach of 256 UEs.
- Live ECM-IDLE/Service Request (inherited from D9).
