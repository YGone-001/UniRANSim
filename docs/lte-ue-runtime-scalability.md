# LTE UE runtime scalability

Phase 19-C measured the actual `lte-ue` executable and the production eNB radio
receive path at the 512-UE target. This record states what was executed, what
was measured, and what remains authorization-gated. It does not claim 512 real
EPS registrations.

Environment: Intel Core i5-9600K host, 6 vCPU, 7.6 GiB RAM, Linux 6.17.0-35,
GCC 13 Release build, `rmem_max`/`wmem_max` 212,992 bytes, UDP page size 4096.
Measurements taken 2026-11-13.

## 1. Phase 19-B reconciliation

Three defects were inspected and corrected.

| Phase 19-B finding | Phase 19-C correction |
|---|---|
| A synthetic registry checkpoint set `STABLE_REGISTRATION_RETAINED = PASS` after immediate allocation and cleanup | The field now means EPS registration retention only and is `NOT_MEASURED` for registry workloads. Context persistence has its own state, `ISOLATED_CONTEXT_RETAINED`, established over a declared 100 ms window |
| Peak RSS came from one `/proc/self/statm` sample multiplied by a hardcoded 4096 | Current RSS comes from `VmRSS`, peak from `VmHWM`, and PSS/private bytes from `smaps_rollup`; the page size, where a page count is used at all, comes from `sysconf(_SC_PAGESIZE)` |
| Gate G21, real process measurement, was `PARTIAL` | 512 actual `lte-ue` processes were started and measured; the result is reported below |

Historical checkpoint values remain factual records of what they measured; the
older report was not rewritten.

## 2. Corrected classification model

`src/lte/enb/capacity_report.hpp` now distinguishes:

```text
ISOLATED_REGISTRY_CONTEXT_ACTIVE
SIMULATED_RADIO_ENDPOINT_ACTIVE
ACTUAL_LTE_UE_PROCESS_ALIVE
PRE_AUTH_ATTACH_ATTEMPT
SIMULATED_ATTACH_SUCCESS
REAL_EPC_AUTHENTICATED_ATTACH
SIMULTANEOUS_EPS_REGISTRATION
SIMULTANEOUS_DEFAULT_BEARERS
INDEPENDENT_UE_IPV4_ASSIGNMENT
USER_PLANE_READY
ISOLATED_CONTEXT_RETAINED
STABLE_REGISTRATION_RETAINED
CLEANUP_COMPLETE
```

States: `PASS`, `FAIL`, `NOT_MEASURED`, `NOT_APPLICABLE`,
`BLOCKED_AUTHORIZATION`, `BLOCKED_RESOURCE_LIMIT`.

The invariants are asserted, not just documented: a running UE process is not
authenticated; a radio peer is not an EPS bearer; an Attach Request is not an
Attach Accept; context retention is not registration retention; a synthetic
registry is not EPS state; a test cleanup is not an EPS Detach.

## 3. Source-backed runtime resource model

From `src/lte_ue.cpp`, `src/lte/ue/app.cpp`, `src/lte/ue/config.cpp` and
`src/lte/ue/tun.cpp`:

- `lte-ue -c <config>` accepts exactly one configuration file. There is no
  LTE multi-UE option; the 5G `nr-ue -n` mode does not exist here.
- The process binds its simulated-radio UDP socket at the start of `Run` and
  immediately encodes and sends one plain Attach Request. No MME response is
  required for the process to reach this state.
- A TUN device is created only after an accepted Attach supplies an IPv4
  address. Before authentication there is no TUN, no bearer and no user plane.
- Each UE needs a distinct `enbLink.localPort`; the parser refuses port zero.
  The UE identifier (`ueId`) is configuration-local and must be unique among
  concurrently running processes.
- With no MME the process waits for `enbLink.timeoutMs` and then exits with a
  timeout status. That is a genuine pre-authentication profile, not a
  fabricated Attach Accept.
- SIGTERM sets the shutdown flag; the receive loop notices it within one
  iteration and the process exits. Sockets and the TUN descriptor are released
  by destruction.

## 4. Process-fleet test architecture

`src/lte/enb/process_fleet.{hpp,cpp}` launches the real binary.

- One generated YAML per child in a run-private temporary directory.
- Test PLMN 001/01 and generated IMSI/identities, fixed synthetic key material,
  no subscriber secret copied, no EPC address used.
- Each child gets its own local port and points at the caller's isolated
  `EnbMultiplexer` radio endpoint.
- Children are started progressively and the production radio socket is
  drained between spawns. A 512-process start is therefore a sequence of
  bounded arrivals, not an accidental microburst. Without this the kernel drops
  the excess before the first poll and the affected UEs time out.
- Every inherited descriptor is closed in the child. Without that, each UE
  would hold a duplicate of the harness's radio and S1-U sockets.
- Stopping rules: `MemAvailable` reserve (default 512 MiB), file-descriptor
  soft limit, fork/exec failure, and a startup deadline. The reason is reported.
- Cleanup: SIGTERM, a bounded graceful window, SIGKILL for survivors, blocking
  reap, then a residual-socket check per child port.

The fleet is opt-in and local-only:

```bash
UNIRANSIM_RUN_PROCESS_FLEET=1 UNIRANSIM_FLEET_RESERVE_MB=512 \
  ./cmake-build-release/nr-tests --test-case="lte/fleet: progressive*"
```

The short two-process case runs wherever the built binary is present; it is not
part of the 512-process experiment.

## 5. Network isolation guarantees

- All endpoints are `127.0.0.1`; the harness can run inside `unshare --net`.
- The MME address in the generated configuration is the test eNB endpoint, and
  the eNB multiplexer is unbound from any real SCTP association. Initial UE
  Messages are handed to a capturing in-process sender; nothing is transmitted
  to an MME.
- No Open5GS process, HSS record, subscriber, APN pool, route or global sysctl
  was touched.
- Identities are artificial and short-lived; the configurations live under
  `/tmp` and are not committed.

## 6. Attempted checkpoints

Every checkpoint used `maxUes=512`, test-owned loopback endpoints and the real
`lte-ue` executable. A checkpoint was attempted only after the previous one
succeeded with clean teardown.

| Requested | Spawn duration | RSS sum | PSS sum | FDs | UDP sockets | Startup p50 / p99 | Shutdown | Orphans |
|---:|---:|---:|---:|---:|---:|---:|---:|---:|
| 1 | 1.3 ms | 5.0 MiB | 1.4 MiB | 4 | 1 | 5.9 / 5.9 ms | 2.2 ms | 0 |
| 2 | 1.5 ms | 10.0 MiB | 2.0 MiB | 8 | 2 | 3.4 / 3.6 ms | 2.1 ms | 0 |
| 4 | 3.2 ms | 19.8 MiB | 3.1 MiB | 16 | 4 | 4.7 / 5.3 ms | 2.1 ms | 0 |
| 8 | 7.0 ms | 40.2 MiB | 5.2 MiB | 32 | 8 | 5.4 / 8.6 ms | 2.8 ms | 0 |
| 16 | 10.5 ms | 80.2 MiB | 9.2 MiB | 64 | 16 | 9.8 / 19.9 ms | 2.7 ms | 0 |
| 32 | 25.9 ms | 160.1 MiB | 17.2 MiB | 128 | 32 | 5.4 / 13.0 ms | 5.0 ms | 0 |
| 64 | 52.2 ms | 320.1 MiB | 32.9 MiB | 256 | 64 | 7.8 / 26.1 ms | 5.7 ms | 0 |
| 128 | 103.6 ms | 640.5 MiB | 63.8 MiB | 512 | 128 | 9.2 / 34.6 ms | 7.9 ms | 0 |
| 256 | 199.4 ms | 1282.2 MiB | 125.2 MiB | 1024 | 256 | 14.0 / 60.0 ms | 16.4 ms | 0 |
| **512** | **431.7 ms** | **2564.2 MiB** | **247.6 MiB** | **2048** | **512** | **8.7 / 41.2 ms** | **34.6 ms** | **0** |

All values are from one run with the freshly built `lte-ue` binary; the earlier
runs in the same session produced the same structure with small timing
variation. The 512 checkpoint is the acceptance point.

All checkpoints: 0 startup failures, 0 early exits, 0 signals, 0 orphaned
processes, 0 residual sockets, cleanup complete. No checkpoint was stopped by a
resource budget.

## 7. 512 radio endpoints through the production path

Principal acceptance: one production `EnbMultiplexer` with `maxUes=512`, 512
distinct test-owned UDP peers, 512 distinct radio UE identities, real encoded
simulated-radio frames, the production receive/decode path, the production
registry and the production default `poll(16, 16)`.

| Profile | Offered | Delivered | Dropped | Notes |
|---|---:|---:|---:|---|
| Uniform, paced by the production loop | 512 | 512 | 0 | 32 poll iterations; all identities independently addressable |
| Microburst, no receive between sends | 512 | 222 | 290 | `delivered + dropped = 512`, unaccounted 0 |
| Staggered, eight per iteration, three cycles | 512 × 3 | 512 × 3 | 0 | mixed registration/teardown leaves 0 contexts |
| One hot peer + 511 cold | 512 cold + 128 hot | 512 | 0 | every cold peer served within 600 poll iterations |
| Simultaneous teardown | 512 | — | — | registry and both indexes empty |

The paced uniform result is the principal 512-endpoint acceptance. The
microburst is reported separately and is not retried until it looks loss-free.

## 8. Kernel UDP burst-drop investigation

- Production radio socket `SO_RCVBUF`: 212,992 bytes.
- After a 512-datagram burst the receive queue holds 213,120 bytes, i.e. the
  buffer is full and about 936 bytes are accounted per small datagram.
- `/proc/net/udp` reports 290 drops, and 222 datagrams are delivered; the
  identity holds exactly.
- A raw Python probe with no simulator reproduces 222 of 300 for the same
  reason, so this is an environment property.
- `SO_RXQ_OVFL` was requested on a test-owned socket; this kernel did not
  surface an ancillary drop counter, so `/proc/net/udp` is the authoritative
  measurement.
- A per-socket `SO_RCVBUF` request is doubled up to the socket ceiling
  (425,984 bytes); a controlled comparison is exercised in the tests. No global
  `rmem_max`/`wmem_max` or persistent sysctl was changed.
- Consequence: a true 512-datagram microburst cannot be loss-free within the
  maximum per-socket buffer on this host. It needs pacing, a larger host socket
  buffer configured by the operator, or kernel receive batching.

## 9. Event-loop latency (default budget)

512 paced endpoints, 32 poll iterations, one frame per peer. Monotonic clock.

| Measurement point | n | p50 | p95 | p99 | max |
|---|---:|---:|---:|---:|---:|
| Enqueue to handled (synthetic) | 512 | 0.069 ms | 0.120 ms | 0.331 ms | 0.333 ms |
| Multiplexer handle only | 512 | 0.0032 ms | 0.0047 ms | 0.0094 ms | 0.0204 ms |

The enqueue-to-handled number includes the wait in the kernel queue and the
production decode/handler. The handle number starts when `recvfrom` returns.
They are not the same measurement point. Kernel-socket-only latency and the
full `lte-enb` main loop were not exercised; the latter needs a live SCTP
association and is `NOT_MEASURED` here.

## 10. Resource budgets and stopping rules

- Memory reserve: 512 MiB of `MemAvailable`. At the 512 checkpoint 4,116 MiB
  remained, so no checkpoint was resource-limited.
- Descriptor rule: refuse to spawn when the requested count approaches the
  soft `RLIMIT_NOFILE`.
- Startup deadline: 10 s below 256 processes, 30 s at or above 256.
- Startup failure, an unprovable isolation state, or a failed cleanup stops the
  ladder; an unattempted checkpoint is reported as unattempted, not failed.

## 11. Startup and cleanup evidence

- 512 processes in 431.7 ms of launcher time; per-process spawn-to-first-frame
  p50 8.7 ms, p95 23.5 ms, p99 41.2 ms, max 51.1 ms.
- 512 processes held for a 1.5 s stable window with zero exits.
- 512 processes stopped in 34.6 ms; zero orphans, zero residual sockets, all
  children reaped.
- CPU during the idle stable window was below the 10 ms `CLK_TCK` resolution
  of the per-process counter, so it is reported as below resolution rather than
  as a precise zero. The workload is idle waiting for an MME by construction.

Memory attribution: RSS sum overcounts shared library pages; PSS is the better
physical estimate. At 512 processes the RSS sum is 2564.2 MiB while the PSS sum is
247.6 MiB, about 0.48 MiB per process. Per-process RSS p50 is 5.26 MB and the
maximum is 5.34 MB.

## 12. Process-per-UE decision

**`LTE_512_PROCESS_FLEET_FEASIBLE` — `KEEP_PROCESS_PER_UE`.**

The actual binary, not a model of it, ran 512 instances inside the budget with
clean teardown. The resource cost is dominated by shared pages: 247 MiB PSS for
512 processes, 512 threads, 2048 descriptors and 512 UDP sockets. Startup and
shutdown are sub-second and leave no residue. Process-per-UE also keeps NAS
state, security context and a future TUN device naturally isolated, and one
child's failure is not another child's corruption.

Scope of the decision: it covers the measured pre-authentication runtime.
Post-authentication cost (512 TUN devices, bearer state, user-plane goroutines,
EPC-side sessions) was not measured and is authorization-gated. It also assumes
the host-level socket-buffer limit is handled by pacing or by an operator-set
buffer, which is a deployment concern rather than an architecture change.

## 13. Remaining real-EPC registration prerequisites

`REAL_512_UE_BLOCKED_AUTHORIZATION` is unchanged. A genuine campaign still
needs separate approval for: 508 additional subscriber identities beyond the
authorized four, identity ownership, HSS/authentication provisioning, EPC
session and IP-pool capacity, registration rate, a sustained observation window,
independent user-plane verification, cleanup and rollback. No subscriber, IMSI,
K/OPc, HSS record, APN pool or EPC process was touched.

## 14. PERF-P1 independence

No throughput path was modified. GTP-U forwarding, TEID allocation and
retirement, TUN packet handling, TFT selection and the Phase 19-A iperf3 profiles
are unchanged. The socket-buffer and poll-budget observations above are inputs
for PERF-P1, not throughput results. `PERF_P1_BLOCKED_AUTHORIZATION` remains.

## 15. Next benchmark recommendation

Run a bounded single-UE throughput campaign (PERF-P1) next: one authorized UE,
distinct server identity, a 60 s iperf3 window, application goodput and GTP-U
wire rate reported separately, with socket drops, CPU, p50/p95/p99 scheduler
latency and TUN counters recorded. The 512-UE registration campaign should wait
for its own authorization rather than extending the framework further.