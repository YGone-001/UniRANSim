# LTE Performance and Scalability Roadmap

**Document status: `PERF-P2 ACCEPTED - PERF-P1 DL 872 MBPS - DL LOSS CHAIN RESOLVED, PGW-U CPU NEXT`**

Phase 19-A audited the architecture, established the current hard limits,
implemented the reproducible isolated capacity harness and the opt-in
instrumentation, and prepared the benchmark profiles. It did **not** achieve
either goal: PERF-P1 and PERF-P2 both remain unmeasured against a real EPC and
are blocked on authorization. Sections 6–8 below record the baseline state.

This document records two future performance and capacity objectives for the
UniRANSim LTE/EPC simulation path. **Neither objective is implemented,
optimised, benchmarked or claimed as delivered.** They are recorded here so that
the goals survive the current engineering phase and so that the eventual
acceptance criteria are agreed before any optimisation work begins.

Nothing in this document authorises executing either workstream. Both are
**DEFERRED**.

---

## 1. Status and purpose

UniRANSim is an LTE/NR UE and gNB/eNB simulator that drives a real Open5GS EPC
over S1AP and GTP-U. Its correctness work has so far been validated at single-UE
and dual-UE scale: real EPS AKA, real dedicated EPS bearers with network-issued
TFTs, ECM-IDLE mobility, cross-TAI Normal TAU, and per-bearer uplink/downlink
forwarding through actual Linux TUN interfaces and real GTP-U tunnels.

Two performance questions follow naturally from that and are **not answered
here**:

| Workstream | Goal | Status after Phase 19-A |
|---|---|---|
| **PERF-P1** | Single LTE UE sustained user-plane throughput approaching **1 Gbps** | **NOT MEASURED** — harness and profiles ready; `REAL_1GBPS_BENCHMARK_BLOCKED_AUTHORIZATION` |
| **PERF-P2** | **512** concurrent LTE UEs authenticated, registered and retained | **NOT MEASURED** — isolated harness holds 512 contexts; `REAL_512_UE_ACCEPTANCE_BLOCKED_AUTHORIZATION` |

They are recorded as two separate workstreams because they stress entirely
different parts of the system: P1 is a per-packet data-path problem, P2 is a
per-UE state, descriptor and scheduling problem. Solving one does not solve the
other, and a single "make it faster" phase would not be reviewable.

No permanent future phase numbers are assigned here. The names `PERF-P1` and
`PERF-P2` are milestone labels, not phase numbers.

---

## 2. Performance P1 — Single LTE UE 1 Gbps

### 2.1 Target

**1,000 Mbps class sustained user-plane throughput for one LTE UE over the
UniRANSim + real EPC simulation path.**

This is a **project performance target, not a verified capability**. No
measurement exists. The simulator has never been measured against it, and
nothing in the current code base should be read as implying proximity to it.

### 2.2 Future evaluation method

Future evaluation is to use `iperf3` against a real LTE UE whose PDN traffic
traverses the actual EPC user plane. The matrix to be covered:

| Dimension | Cases |
|---|---|
| Direction | TCP uplink, TCP downlink, UDP uplink, UDP downlink |
| Streams | single stream, multiple parallel streams |
| Duration | sustained throughput over a defined window, not a peak sample |

Metrics to record at every checkpoint:

- **Application goodput** (the number the application actually observes).
- **Wire rate** on the GTP-U path and on the TUN interface, reported separately.
- **Packet loss** (UDP), and the loss rate as a function of offered load.
- **Jitter** for UDP.
- **TCP retransmissions** and, where relevant, congestion-window behaviour.
- **Host CPU and memory utilisation** over the run.
- **UE and eNB process CPU and memory**, measured per process rather than for the
  host as a whole.
- **Kernel socket-buffer pressure** — send/receive buffer occupancy, drops
  attributable to full socket queues.
- **GTP-U packet processing overhead** — encap/decap cost per packet.
- **TUN interface throughput** and TUN read/write error counts.
- **Scheduler latency and packet drops**, including drops internal to the
  simulator's event loop.

**Units are to be stated explicitly.** Throughput is quoted in **Mbps =
10^6 bits per second**. Bytes/s figures must be labelled as such and never
presented as Mbps. Where a report quotes both application goodput and wire rate,
each must be named against its own measurement point; the GTP-U encapsulation
overhead (8-byte GTP-U header plus outer IP/UDP) means the two never agree, and
a discrepancy is expected rather than an error.

### 2.3 Required benchmark isolation

The future throughput test must satisfy **all** of the following, or it does not
measure EPC throughput:

1. Use a real LTE UE, not a UDP generator attached to the EPC by hand.
2. Use the actual EPC user-plane path (SGW-U, PGW-U/UPF, `ogstun`).
3. Use real Linux TUN and real GTP-U — no mocked transport.
4. Separate UE-side and server-side network identities: the iperf server must
   not be the same host-local address the UE is bound to.
5. Avoid host-local routing shortcuts. A destination that the kernel answers
   locally measures the kernel's loopback, not the EPC.
6. Avoid loopback-only iperf results being mistaken for EPC throughput.
7. Verify the full actual forwarding path with packet counters **and** packet
   captures at the UE TUN, the eNB S1-U and the PDN-side decapsulation point.
8. Record whether the bottleneck is the simulator, the kernel or the EPC, with
   evidence for the attribution.

> **A successful `iperf3` run entirely within localhost is not a valid 1 Gbps
> EPC acceptance result.** It measures the loopback path and would be reported
> as a simulator-to-simulator number. Both endpoints must be distinct network
> identities and the traffic must be observed inside GTP-U.

### 2.4 P1 engineering analysis

Areas to investigate when — and only when — P1 is authorised. **None of these is
implemented in the current phase, and none may be changed merely because it
appears in this list.**

The first item has now been measured rather than assumed. Phase 19-F-B measured
the real UE downlink receive loop at the rate the accepted DL4 profile offers:
about 61,400 frames per second at a median 30.3% of one core for the
one-frame-per-turn loop, against a single-core ceiling of 244,814-287,274 frames
per second. Bounded receive batches of 8 raise the ceiling to 338,272-398,063
and lower receive CPU by 22%, and they change no deliverable at the operating
point. The receive path is therefore excluded as the downlink limit with at
least 4.0x measured headroom; the remaining downlink candidates are EPC-side.
The record is `docs/lte-downlink-receive-performance.md`.

- Number of packets processed per event-loop iteration, and the latency cost of
  the current one-packet-at-a-time model. **Measured (19-F-B): 4.9 us per frame
  at 62,000 pps, 1.8 us of it in decode, validation and the TUN write; not the
  downlink limit.**
- UDP radio-link packet handling, including per-datagram syscalls.
- Copying and buffer allocation: how many times one datagram is copied between
  the TUN, the radio link and the GTP-U socket.
- GTP-U encapsulation and decapsulation cost per packet.
- TUN read/write batching.
- `sendmmsg` / `recvmmsg` feasibility for the radio and GTP-U paths.
- `epoll` or equivalent event-driven I/O in place of bounded polling.
- Socket buffer sizing (send/receive) for the radio link and GTP-U sockets.
- CPU affinity and worker-thread architecture.
- Packet drop accounting, so that a throughput number is never quoted without
  its loss number.
- MTU and fragmentation, including the interaction between the TUN MTU and the
  GTP-U outer MTU.
- Multicore scaling of the per-UE data path.
- Per-packet logging overhead, which is often the dominant cost in a
  debug-instrumented simulator.

### 2.5 Downlink: what the real EPC actually limits

Phase 19-F-C measured four 60 s DL4 profiles against the real EPC with per-flow
TCP state on both ends and per-socket UDP accounting:

| S1-U / UE radio receive buffer | Receiver goodput | Loss point |
|---|---:|---|
| 212,992 / 212,992 (default) | 298.56 Mbps | not per-socket sampled |
| 212,992 / 212,992 (repeat) | 537.86 Mbps | eNB +27,963, UE +3,345, SGW-U +1,071 |
| 425,984 / 212,992 | 411.12 Mbps | eNB +51, UE +27,262, SGW-U +7,096 |
| 425,984 / 425,984 | **762.64 Mbps** | eNB +1,392, UE +2,185, SGW-U +41,364 |

The sender is congestion-window limited (`cwnd` 15-23 segments at 538 Mbps,
46-62 at 763 Mbps) and never receive-window limited (`rwnd_limited` 0.0-7.7%,
advertised window 350-700 KB). Throughput per flow equals `cwnd x MSS / rtt`.
The cwnd ceiling is set by UDP receive-buffer loss at whichever forwarding socket
is currently narrowest, not by a processing limit in the UE or the eNB.

So the remaining 1-Gbps gap has two components, in order: the UDP receive
budget of the forwarding chain, and then the PGW-U per-thread cost that the
uplink already shows. Neither is a UniRANSim receive-loop problem.

The record is `docs/lte-single-ue-1gbps-benchmark.md` section 13.4.

### 2.6 Opt-in receive buffers

The two UniRANSim-owned sockets that lose downlink packets now have an optional
explicit receive buffer: `s1u.receiveBufferBytes` for the shared eNB S1-U socket and
`enbLink.receiveBufferBytes` for a UE radio socket. Absent means no system call and
the historical behaviour. A request the kernel caps is refused with the
requested and effective values, never reported as applied.

This is capability, and Phase 19-F-E later measured it under a separate host
authorization. The record is `docs/lte-udp-receive-buffer-tuning.md`.

### 2.7 Downlink after the receive-buffer campaign

Under a temporary host authorization (`rmem_max=8388608`,
`rmem_default=4194304`, SGW-U and PGW-U restarted so their sockets inherited
it) the downlink loss chain was resolved: four-stream DL4 reached **871.95
Mbps** with **zero UDP drops at the eNB S1-U, the UE radio, the SGW-U and the
PGW-U**, and TCP retransmissions fell from 18,908-29,894 to about 3,450.

The explicit per-socket option added nothing on top of that default: with 4
MiB inherited everywhere, the run without any buffer field already reached
872 Mbps, and doubling the two UniRANSim sockets to 8 MiB measured 865 Mbps.
The host default, not the option, was the lever, which is why the option is
described as capability and the host change as the experiment.

The next limit is PGW-U CPU: 92.3% average and 98-99% peak of one thread at
872 Mbps, with SGW-U at 79.7%, the eNB at 67.2% and the UE at 57.8%. The
sender held a 108-segment window at a 6.1 ms RTT and was receive-window
limited for 5-12 ms out of 39 s.

PERF-P1 downlink is therefore `PERF_P1_DL_SUSTAINED_BELOW_TARGET` at 871.95
Mbps, and the remaining 1-Gbps gap is a PGW-U per-thread question, not a
buffer one.

---

## 3. Performance P2 — 512 simultaneous LTE UEs

### 3.1 Target

**512 distinct LTE UEs concurrently authenticated, EPS-registered and
maintained against a real EPC.**

### 3.2 Reference and its limits

Reference: <https://github.com/aligungr/UERANSIM/discussions/441>

The upstream UERANSIM author described a theoretical **512 UE limit for one
`nr-ue -n` process**.

This reference must be read carefully:

- It describes a **5G UE simulator** (`nr-ue`), not UniRANSim's LTE path.
- It is a **theoretical** limit of that process architecture, not a measured
  result.
- It is **not** proof of UniRANSim LTE capacity.
- It is **not** proof of Open5GS EPC capacity.

The figure is recorded as a plausible prior, not as a baseline, a target that is
already partly met, or an acceptance threshold.

The current LTE eNB configuration bounds `maxUes` to **1–64** at the audited
baseline. **That limit must not simply be raised to 512 and reported as
support.** Raising a bound is not evidence of capacity; capacity is what the
acceptance definitions below measure.

### 3.3 Future P2 acceptance definitions

The headline 512 result must **not** be based solely on process count or on
Attach Request count. Each of the following is a distinct number and must be
reported separately:

| # | Definition | Why it is distinct |
|---|---|---|
| 1 | UE processes created | A process may never authenticate. |
| 2 | Distinct UE identities loaded | Loaded is not registered. |
| 3 | EPS Attach attempts | Attempts may all fail. |
| 4 | Successful authenticated EPS Attach results | The first meaningful number. |
| 5 | Simultaneously EPS-registered UEs | Registration can decay during the run. |
| 6 | Simultaneously established default EPS bearers | Attach without a bearer is not a session. |
| 7 | UEs holding independently assigned IPv4 addresses | Pool exhaustion shows up here. |
| 8 | UEs maintaining registration over a defined observation window | Short-lived registrations inflate (5). |
| 9 | UEs capable of independent user-plane traffic | Registration without data plane is not capacity. |
| 10 | Successful detach and resource cleanup | A leak makes the next checkpoint invalid. |

A result quoting only (1) or (3) is **not** an acceptance result.

### 3.4 Future P2 scalability analysis

Areas for a dedicated future phase:

- Per-eNB UE registry limits and the cost of its lookup structures.
- Per-UE memory allocation and its steady-state footprint.
- Per-UE sockets and file descriptors.
- Process-per-UE overhead, versus an optional multiplexed UE runtime.
- SCTP association and stream utilisation at the MME.
- S1AP transaction concurrency and the MME's transaction table.
- NAS security and COUNT isolation per UE.
- Independent subscriber identity management at the HSS.
- EPS bearer and TEID indexing at the eNB, SGW-U and PGW-U.
- TUN allocation cost per UE and interface-name exhaustion.
- IP-address pool capacity for the APN.
- HSS lookup capacity.
- MME session capacity.
- SGW-U / PGW-U per-session state.
- Process startup and teardown cost, which bounds how fast a checkpoint can run.
- Registration rate versus sustained online population — these are different
  workloads.
- Backpressure and overload handling.
- Concurrent failure isolation: one failing UE must not cost another UE its
  session.
- Memory / CPU / FD / port exhaustion behaviour.
- Cleanup after partial failure, which is what makes repeated checkpoints safe.

### 3.5 Future benchmark progression

Intended future scaling checkpoints:

```text
1 → 2 → 4 → 8 → 16 → 32 → 64 → 128 → 256 → 512
```

**This is a future validation plan, not authorization to execute it.**

At each checkpoint, future acceptance should record:

- Number attempted.
- Number successfully registered.
- Number simultaneously registered.
- Attach completion latency, including **p50 / p95 / p99**.
- Registration failures and their NAS / S1AP causes.
- CPU utilisation.
- Memory utilisation.
- File descriptor count.
- Network socket count.
- eNB and EPC resource utilisation.
- Registration retention over the observation window.
- Cleanup success.
- UE identity isolation.

A checkpoint is not passed by reaching the number; it is passed by reaching it
with definitions (4)–(10) above all satisfied and cleanup verified.

---

## 4. Authorization boundary

The present laboratory has only **four** previously authorized test subscriber
identities.

- Do not generate, clone, provision or invent additional real HSS subscribers.
- A 512-UE test requires a **separately approved** subscriber provisioning
  strategy and EPC resource budget.
- The future performance phases must obtain **explicit authorization** before
  changing HSS databases, subscriber pools, EPC capacities, routing, or
  production-like services.
- Root access is not authorization. Neither is the existence of this document.

Without that authorization, any capacity measurement must be reported as
**BLOCKED**, not as a partial result.

---

## 5. Deferred milestone recommendation

Two named milestones are recorded and deferred:

| Milestone | Scope | Status |
|---|---|---|
| `PERF-P1 — Single LTE UE 1 Gbps User-Plane Benchmark` | §2 | **DEFERRED** |
| `PERF-P2 — 512 Concurrent LTE UE Registration and Retention` | §3 | **DEFERRED** |

**Neither milestone is started in the current phase.**

Recording these goals does **not** add an `iperf3` runtime dependency to the
project. No benchmark tooling, no throughput optimisation, no bulk UE
registration, and no capacity change is to be introduced merely because these
goals were documented. When either milestone is authorised, it should begin with
the isolation requirements of §2.3 (P1) or the acceptance definitions of §3.3
(P2), not with an optimisation.

---

## 6. Phase 19-A baseline state

### 6.1 Current hard limits

| Limit | Value | Kind |
|---|---|---|
| eNB `maxUes` validation range | `1..64` (`src/lte/enb/config.cpp`) | **configuration validation limit** — the first ceiling a 512-UE goal meets |
| UE Registry capacity | `m_maxUes`, exact bound, refuses beyond | fixed-size bound |
| Radio UE identity | `uint32_t`, non-zero | wide |
| eNB-UE-S1AP-ID / MME-UE-S1AP-ID | `uint32_t` | wide |
| GTP-U local TEID | `uint32_t` allocator | wide |
| SCTP UE-associated streams | `outboundStreams - 1`, shared beyond | negotiated, shared |
| Per-UE context | 640 bytes measured (`sizeof(EnbUeEntry)`), ~1.7 KiB with a full dedicated-bearer set | measured |
| UE process model | **process-per-UE** (`lte-ue -c <config>`), one TUN and one UDP socket per UE | process architecture limit |
| Shared poll budget | `poll(16, 16)` per main-loop iteration | simulated-radio limit |

### 6.2 Capacity accounting

Memory per UE is measured, not assumed: 640 bytes per `EnbUeEntry` plus 136
bytes per bearer context and 48 bytes of index pointers. 512 UEs cost well
under 1 MiB of context, so memory is not the constraint. The eNB's S1-U
endpoint, UDP socket and event loop are O(1) in the UE count; the UE side is
O(N) in processes, TUN devices and sockets because the architecture is
process-per-UE.

### 6.3 Throughput risks (ranked, unmeasured)

| Rank | Candidate | Class |
|---|---|---|
| 1 | Kernel socket buffers 208 KiB (`rmem_max`/`wmem_max`) | `ENVIRONMENT_LIMIT` |
| 2 | Shared poll budget `poll(16, 16)` per iteration | `SOURCE_INFERRED_RISK` |
| 3 | Polling UDP transport rather than an event-driven one | `SOURCE_INFERRED_RISK` |
| 4 | Userspace GTP-U encap/decap per packet | `SOURCE_INFERRED_RISK` |
| 5 | 6 vCPU host shared with the EPC | `ENVIRONMENT_LIMIT` |

None of these is a `MEASURED_BOTTLENECK` yet: no sustained throughput was
measured in this phase.

### 6.4 What a future campaign needs

PERF-P2 needs explicit authorization for subscriber provisioning (508
additional identities beyond the four authorized ones), identity ownership, the
EPC address-pool limits, a traffic rate and a rollback plan. PERF-P1 needs an
authorized real-EPC iperf3 session with distinct UE and server identities and
corroborating packet counters. See `docs/lte-performance-benchmark-profiles.md`
for the exact commands and classification rules.

---

## 7. Phase 19-B capacity foundation

The 64-UE configuration ceiling is gone: `maxUes` accepts `1..512` and the
production registry holds 512 independent contexts with exact-bound refusal,
clean release and no stale index. Production radio ingress registers hundreds
of independently identified peers, and the bounded poll budget shows no
cross-UE starvation. See `docs/lte-512-ue-capacity-foundation.md`.

PERF-P2 remains `REAL_512_UE_BLOCKED_AUTHORIZATION`: isolated context capacity
is not EPS registration, and the laboratory's four authorized subscribers are
untouched. PERF-P1 is unchanged and independent.

---

## 8. Phase 19-C runtime evidence

Phase 19-C measured the actual `lte-ue` executable and the production radio
receive path. It did not measure real EPC throughput or real EPS registration.

### 8.1 What was executed

- The complete process ladder 1 → 2 → 4 → 8 → 16 → 32 → 64 → 128 → 256 → 512
  with the real `lte-ue` binary, test-only configurations and an isolated
  loopback eNB multiplexer. Every checkpoint started, observed and stopped
  cleanly; no checkpoint was resource-limited.
- 512 distinct test-owned radio endpoints through the production receive path
  under the production default `poll(16, 16)`: 512 delivered, 0 dropped.
- Paced, staggered, microburst, hot-peer, teardown and repeated-cycle profiles.
- Nearest-rank latency distributions at two distinct measurement points.

### 8.2 Measured cost at 512

| Metric | Value | Method |
|---|---:|---|
| Processes started / alive | 512 / 512 | real `lte-ue`, `/proc` observation |
| Launcher spawn duration | 400.1 ms | monotonic clock around fork/exec |
| Spawn to first radio frame p50 / p99 | 8.1 / 21.2 ms | first production registry observation |
| RSS sum | 2526.2 MiB | `VmRSS` |
| PSS sum | 247.5 MiB | `smaps_rollup` |
| Threads / file descriptors / UDP sockets | 512 / 2048 / 512 | `/proc` |
| TUN devices before authentication | 0 | `/proc/net/dev` |
| Stable window | 1.5 s | wall clock |
| Shutdown | 34.6 ms | SIGTERM to last reap |
| Orphans / residual sockets | 0 / 0 | pid and `/proc/net/udp` checks |

### 8.3 Process-per-UE decision

`LTE_512_PROCESS_FLEET_FEASIBLE` — `KEEP_PROCESS_PER_UE` for the measured
pre-authentication runtime. The decision does not cover post-authentication TUN
devices, bearer state or user-plane cost, which remain
`BLOCKED_AUTHORIZATION`. A multiplexed LTE UE runtime is **not** implemented.

### 8.4 Status after Phase 19-C

| Milestone | Status |
|---|---|
| PERF-P2 isolated 512-context capacity | `ISOLATED_512_CONTEXTS_ACCEPTED` (Phase 19-B) |
| PERF-P2 512 production radio endpoints | `ISOLATED_512_RADIO_CONTEXTS_ACCEPTED` |
| PERF-P2 512 real UE processes | `LTE_512_PROCESS_FLEET_FEASIBLE` (pre-authentication) |
| PERF-P2 512 authenticated EPS registrations | `REAL_512_UE_BLOCKED_AUTHORIZATION` (superseded by the real Attach campaign) |
| PERF-P1 single-UE 1 Gbps | `PERF_P1_BLOCKED_AUTHORIZATION` |

### 8.5 Next recommendation

The next independent performance phase should be a bounded single-UE throughput
campaign (PERF-P1), not more registration-framework development. The 512-UE
registration campaign subsequently ran in the real Attach campaign; see section 9.
See `docs/lte-ue-runtime-scalability.md` for the Phase 19-C evidence record.

---

## 9. Real 512-UE Attach acceptance

The real Attach campaign ran the designated 512 subscribers through the live
Open5GS EPC.

### 9.1 Result

`REAL_512_UE_ACCEPTED`. 512 distinct authorized subscribers completed genuine
EPS-AKA, NAS security, Attach Accept and Attach Complete, held default EPS
bearers with unique PDN IPv4 addresses, and stayed simultaneously registered for
a 300 s window. Cleanup returned the EPC to its pre-campaign baseline.

### 9.2 What was executed

- Exact set verification of `460020000000400` … `460020000000911` (512
  distinct, no gaps, no duplicates, K/OPc/AMF and APN `cmnet`).
- 512 protected UE configurations with unique radio UE ids, local ports and
  TUN prefixes.
- The real production `lte-enb` and `lte-ue` binaries against the running
  Open5GS MME, SGW-C/SGW-U and SMF/PGW-U.
- Checkpoints 1 → 4 → 16 → 32 → 64 → 128 → 256 → 512, gated on the previous
  checkpoint.
- A 300 s retention window with 60 samples.
- A low-rate user-plane check through the real S1-U path.
- Cleanup through the production Detach path, not an EPC restart.

### 9.3 Measured result at 512

| Metric | Value |
|---|---:|
| MME-registered UEs | 512 |
| Default EPS bearers | 512 |
| Unique PDN IPv4 addresses | 512 |
| TUN interfaces | 512 |
| Live UE processes | 512 |
| MME sessions (owner baseline 1 + campaign) | 513 |
| SMF GTPv2 / PFCP sessions | 513 / 513 |
| eNB radio UDP drops | 0 |
| UE fleet RSS / PSS | 2719.6 / 253.8 MiB |
| Retention samples with 512 registered | 60 / 60 |
| Registration window, 1 → 512 | 49.6 s |

### 9.4 Status after the real Attach campaign

| Milestone | Status |
|---|---|
| PERF-P2 512 isolated contexts | `ISOLATED_512_CONTEXTS_ACCEPTED` |
| PERF-P2 512 production radio endpoints | `ISOLATED_512_RADIO_CONTEXTS_ACCEPTED` |
| PERF-P2 512 real processes | `LTE_512_PROCESS_FLEET_FEASIBLE` |
| PERF-P2 512 authenticated, retained EPS registrations | `REAL_512_UE_ACCEPTED` |
| PERF-P1 single-UE 1 Gbps | `PERF_P1_BLOCKED_AUTHORIZATION` |

The complete operational record is `docs/lte-512-real-attach-acceptance.md`.

---

## 10. Single-UE throughput measurement

The authorized single-UE campaign measured the production UE, eNB, S1-U GTP-U,
SGW-U, PGW-U and a PDN-side iperf3 server. The UE TUN was isolated in a
namespace and its only route to the server was the TUN.

### 10.1 Two measured event-loop ceilings and their correction

| Ceiling | Evidence | Correction |
|---|---|---|
| eNB: 16 packets per 20 ms SCTP wait (about 800 packet/s) | TCP 8.4 Mbps at 1360 B; UDP 100 Mbps lost 97% | Drain radio/S1-U in up to 8 non-empty batches; non-blocking SCTP when busy |
| UE: 16 TUN packets per 50 ms radio wait (about 320 packet/s) | UDP 10 Mbps delivered 3.2 Mbps with 67.9% loss | Non-blocking radio check when the TUN produced uplink |

The bounded drain and timeout policy have deterministic tests.

### 10.2 Measured result

| Profile | Before | After |
|---|---:|---:|
| TCP uplink, 1 stream, 10 s | 8.5 Mbps | **813.0 Mbps** |
| TCP uplink, 4 streams, 10 s | not run | **983.8 Mbps**; best 1 s **999.71 Mbps** |
| UDP uplink, 10 Mbps, 5 s | 3.2 Mbps, 67.9% loss | **10.0 Mbps, 0% loss** |
| UDP uplink, 100 Mbps, 5 s | 3.44 Mbps, 97% loss | 35 Mbps, 65.1% loss |

The UE and eNB each used about 4–6% of one core under the UDP load, so the
original loss was scheduling, not CPU. UDP at 50–100 Mbps still exceeds the
212,992 B eNB radio receive buffer; that is a socket-buffer limit for bursty
UDP, separate from the fixed loop cap.

### 10.3 Verdicts

| Goal | Verdict |
|---|---|
| Peak 1 Gbps | `PERF_P1_PEAK_BELOW_TARGET` — best 1 s interval 999.71 Mbps |
| Sustained 1 Gbps | `PERF_P1_SUSTAINED_NOT_MEASURED` — 60 s run needs about 7.5 GB |
| Engineering | `BLOCKED_EPC_CONFIGURATION` — subscriber OCS balance exhausted |

The OCS balance is 6,442,450,944 bytes total and used, with 0 available. The
SMF removed the PDN session on Gy final-unit action; a later Attach received
Gy 4012 credit-limit-reached. No subscriber or balance was modified. The SMF
also left one residual PDN context after the failed charging attempt; the MME,
eNB and TUNs were clean.

The full record is `docs/lte-single-ue-1gbps-benchmark.md`.

### 10.4 Recovery run: complete 60-second matrix

The owner restored the OCS data allowance to 256 GiB (274,877,906,944 bytes);
the effective balance was verified and a new Gy reservation returned result
code 2001 with granted units. The stale 10.45.0.9 SMF context was released by
the supported production Attach for the same IMSI, which created 10.45.0.27.

| Profile (65 s, 5 s warm-up) | Receiver goodput | Best 1 s | Worst 1 s |
|---|---:|---:|---:|
| TCP uplink, 1 stream | 771.5 Mbps | 830.5 | 704.6 |
| TCP downlink, 1 stream | 562.5 Mbps | 606.1 | 530.6 |
| TCP uplink, 4 streams | **930.5 Mbps** | 962.6 | 757.1 |
| TCP downlink, 4 streams | 655.6 Mbps | 686.8 | 574.6 |
| TCP uplink, 4 streams, repeat | **941.4 Mbps** | 965.7 | 882.9 |

The 60-second rows are complete measured windows, not extrapolations. The
sustained target is `PERF_P1_SUSTAINED_BELOW_TARGET`; the best peak remains
`PERF_P1_PEAK_BELOW_TARGET` (999.71 Mbps in the earlier 10 s diagnostic and
965.73 Mbps in the 60 s repeat).

The measured bottleneck is the EPC PGW-U/UPF process: 89–91% of one core at
the four-stream uplink rate, with SGW-U at 85%, eNB at 79%, and UE at 68% at
their maxima. UDP remained bounded: 10 Mbps had 0% loss in both directions;
50 Mbps delivered 30.36 Mbps uplink (39.28% loss) and 50 Mbps downlink (0%
loss). Cleanup restored the owner baseline: 2 MME sessions, 2 SMF/PFCP
sessions, 1 eNB and 1 eNB-UE, with no campaign TUN or UE process.

### 10.5 Root-cause diagnostic

The 4 GiB OCS offset is a fixed one-time carry in `data_used`: the campaign
session usage is 36,920,333,088 bytes, `data_used` is exactly 2^32 lower, and
`data_available` moved by the full amount. A later 19.07 GB diagnostic moved
both fields together and did not grow the gap. The external OCS code and
balance were not modified.

Time-aligned S1-U captures give the missing per-second wire rates: UL4 uplink
972–993 Mbps (84.6–86.5k pps), DL4 downlink 679–715 Mbps (59.1–62.3k pps).
The application/wire ratio is about 1.05 per direction; the old 1.54 session
ratio was a counter-window artifact.

`pidstat -t` confirms one PGW-U thread at 89.8% average (90% max), system-
heavy, at the 929 Mbps uplink plateau. SGW-U 83.7%, eNB 76.0%, UE 67.0%, while
the host endpoint control reached 42.9 Gbps. The uplink classification is
`PGWU_CPU_LIMIT_CONFIRMED`.

Downlink DL4 was 662.9 Mbps with PGW-U 75.4%, SGW-U 64.9%, eNB 50.9%, UE 44.1%;
no process was saturated. Its root cause is `BOTTLENECK_NOT_ESTABLISHED`; the
strongest source-level candidate is the UE one-frame-per-turn radio receive
path, not yet confirmed. The next experiment is a bounded UE receive batch or
TCP-window/TUN-latency capture, not a data-plane rewrite.