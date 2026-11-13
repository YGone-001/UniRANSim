# LTE Performance and Scalability Roadmap

**Document status: `PHASE 19-A BASELINE — HARNESS IMPLEMENTED — GOALS NOT ACHIEVED`**

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

### 2.4 Future P1 engineering analysis

Likely areas to investigate when — and only when — P1 is authorised. **None of
these is implemented in the current phase, and none may be changed merely
because it appears in this list.**

- Number of packets processed per event-loop iteration, and the latency cost of
  the current one-packet-at-a-time model.
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
