# LTE performance benchmark profiles

Reproducible measurement definitions for the two performance goals. Nothing
here has been executed against a real EPC in this phase: the profiles exist so
that a future authorized campaign runs the same commands and records the same
numbers. A harness is not a result.

## 1. What each profile proves

| Profile | Class it can establish | Class it cannot establish |
|---|---|---|
| Isolated loopback or private-namespace run | `ISOLATED_SIMULATOR_THROUGHPUT` | `REAL_EPC_USER_PLANE_THROUGHPUT` |
| A run whose traffic traverses the actual SGW-U and PGW-U and returns through the UE's bearer | `REAL_EPC_USER_PLANE_THROUGHPUT` | — |

An isolated run may not be reported as an EPC throughput number. A run in
which the UE and the iperf3 server share a host-local shortcut that bypasses
the EPC proves nothing about the EPC.

## 2. iperf3 profiles

`iperf3` was **not installed** on the build host during this phase, so none of
these ran. The commands are the ones a future campaign must use.

Sustained window: **60 s** per profile, with the first 5 s discarded as
slow-start. Throughput is quoted in decimal Mbps (10^6 bit/s); any bytes/s
figure is labelled as such.

| Profile | Command (server on the PDN side, client on the UE) | Stream count |
|---|---|---|
| TCP uplink, 1 stream | `iperf3 -c <pdn-server> -t 60 -J` | 1 |
| TCP downlink, 1 stream | `iperf3 -c <pdn-server> -t 60 -R -J` | 1 |
| TCP uplink, 4 streams | `iperf3 -c <pdn-server> -t 60 -P 4 -J` | 4 |
| TCP downlink, 4 streams | `iperf3 -c <pdn-server> -t 60 -R -P 4 -J` | 4 |
| UDP uplink, controlled rate | `iperf3 -c <pdn-server> -u -b <rate>M -t 60 -J` | 1 |
| UDP downlink, controlled rate | `iperf3 -c <pdn-server> -u -b <rate>M -t 60 -R -J` | 1 |

Each profile records: application goodput (decimal Mbps), GTP-U wire
throughput measured at the S1-U interface separately, packet rate, UDP loss and
jitter, TCP retransmissions, host CPU and memory, per-process UE and eNB CPU
and memory, kernel socket drops, TUN and GTP-U packet counters, MTU, CPU
architecture and vCPU count, network interface and route verification, iperf3
version, and the exact command and duration.

The GTP-U encapsulation overhead (8-byte GTP-U header plus outer IP/UDP) means
application goodput and wire rate never agree; a discrepancy is expected.

## 3. UE registration capacity checkpoints

```text
1 → 2 → 4 → 8 → 16 → 32 → 64 → 128 → 256 → 512
```

Each checkpoint is reported against nine separate classifications; only the
first is what the isolated harness establishes:

| Classification | Isolated harness |
|---|---|
| `ISOLATED_CONTEXT_CAPACITY` | yes |
| `SIMULATED_ATTACH_SUCCESS` | no |
| `REAL_EPC_AUTHENTICATED_ATTACH` | no |
| `SIMULTANEOUS_EPS_REGISTRATION` | no |
| `SIMULTANEOUS_DEFAULT_BEARERS` | no |
| `INDEPENDENT_UE_IPV4_ASSIGNMENT` | no |
| `USER_PLANE_READY` | no |
| `STABLE_REGISTRATION_RETAINED` | not measured |
| `CLEANUP_COMPLETE` | not measured |

A synthetic registry entry is isolated context capacity and nothing more. A
mocked NAS authentication outcome never counts as a real EPC Attach.

## 4. What this host can and cannot support

Measured on the build host (2026-11-13): 6 vCPU (Intel i5-9600K @ 3.70 GHz),
7.6 GiB RAM with 3.3 GiB available, kernel 6.17.0-35-generic, soft FD limit
1,048,576, kernel socket buffers `rmem_max`/`wmem_max` 212,992 bytes (208 KiB),
`/dev/net/tun` present, `iperf3` **not installed**.

The 208 KiB socket-buffer ceiling is the single most relevant environment
limit for PERF-P1: at 1 Gbps a 208 KiB buffer holds roughly 1.6 ms of traffic,
which is a very small burst budget for a userspace GTP-U path that polls in
bounded batches. Raising it is a persistent kernel change and is not authorized
here.

A 6-vCPU host with 3.3 GiB available memory is not obviously the constraint for
512 UE contexts (measured context size 640 bytes; ~1.7 KiB per UE with a full
dedicated-bearer set), but it is a real constraint for a 512-process UE
architecture at 1 Gbps class throughput.

## 5. Real-EPC measurement status

| Goal | Status |
|---|---|
| PERF-P1 real 1-Gbps goodput | `REAL_1GBPS_BENCHMARK_BLOCKED_AUTHORIZATION` |
| PERF-P2 512 authenticated EPS registrations | `REAL_512_UE_ACCEPTANCE_BLOCKED_AUTHORIZATION` |

The laboratory holds four authorized test subscribers. No additional
subscribers were created, no IMSI was cloned, no K/OPc was invented, no HSS or
MongoDB record was touched, and no bulk Attach campaign was run against the
live Open5GS EPC.
