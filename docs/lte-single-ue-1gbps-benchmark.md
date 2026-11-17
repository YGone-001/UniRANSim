# LTE single-UE throughput benchmark

This record contains the measured single-UE user-plane campaign against the
running Open5GS EPC. It is not a loopback or simulator-only number: the traffic
entered the production LTE UE TUN, crossed the simulated-radio link, the
production eNB, real S1-U GTP-U, the real SGW-U and PGW-U, and terminated at an
authorized PDN-side iperf3 server.

## 1. Test scope

| Item | Value |
|---|---|
| UE | IMSI 460020000000400, existing authorized record |
| UE address | 10.45.0.8/32 (assigned by the EPC) |
| eNB | production `lte-enb`, PLMN 460/02, TAC 1, eNB-ID 0x19D |
| EPC | xCloud Open5GS at 10.10.0.139 |
| PDN server | 10.45.0.1:5202 (the PGW-U PDN address) |
| APN | cmnet |
| Host | 6 vCPU Intel i5-9600K, 7.6 GiB RAM, Linux 6.17.0-35 |
| iperf3 | 3.16, client and server both installed locally |
| Socket buffers | `rmem_max`/`wmem_max` 212,992 B |
| UE TUN MTU | 1400 |

The server binds the PGW-U PDN address, but the UE TUN lives in a separate
network namespace. The only route from the client to the server is through the
TUN, so the traffic cannot take a host-local shortcut.

## 2. Route and path proof

In the UE namespace:

```text
10.45.0.0/16 dev p19e0 scope link
10.45.0.1 from 10.45.0.8 dev p19e0 uid 0
```

On the host, the return route to the UE is through the PGW-U PDN interface, not
a local UE route:

```text
10.45.0.8 dev ogstun src 10.45.0.1
```

The eNB log recorded the S1-U user-plane-ready event for 10.45.0.8, and the SMF
recorded the PGW session with IPv4 10.45.0.8. The UE log recorded the TUN name
and address, EPS registration, default bearer EBI 5/QCI 9 and user-plane active
state. A pilot ICMP exchange returned through the real S1-U path.

## 3. Baseline before optimization

The first measurements used the unmodified production loops.

| Profile | Result |
|---|---:|
| TCP uplink, 1 stream, 10 s | 8.5 Mbps received, 4 retransmits |
| TCP downlink, 1 stream, 5 s | 8.39 Mbps received |
| UDP uplink, 10 Mbps offered, 5 s | 3.2 Mbps received, 67.9% loss |
| UDP uplink, 100 Mbps offered, 5 s | 3.44 Mbps received, 97% loss |
| UDP downlink, 10 Mbps offered, 5 s | 10.0 Mbps received, 14.3% loss |

The packet rates identify the caps:

- 8.4 Mbps at 1360 B is about 772 packet/s, matching the eNB's 16 packets per
  20 ms SCTP wait (800 packet/s).
- 3.2 Mbps at 1350 B is about 300 packet/s, matching the UE's 16 TUN packets
  per 50 ms radio wait (320 packet/s).

Neither process was CPU-bound: the UE and eNB each used about 4–6% of one core
under the UDP load. The loss was event-loop scheduling, not link capacity.

## 4. Source-level cause and correction

The eNB main loop waited up to 20 ms in `SctpClient::receiveFor` before one
16-packet `EnbMultiplexer::poll(16, 16)`. The UE main loop read up to 16 TUN
packets, then waited up to 50 ms on the radio socket even when there was more
uplink data.

The correction is bounded and local:

- `EnbMultiplexer::poll` now reports whether it handled a radio or S1-U
  datagram. `DrainUserPlane` runs up to 8 non-empty batches per turn.
- While the drain was busy, the SCTP check is non-blocking; an idle turn keeps
  the 1 ms bounded wait. S1AP is still checked every turn.
- The UE uses `RadioReceiveTimeoutMs`: 0 when it just read an uplink TUN
  packet, 50 ms when registered and idle, 250 ms before registration.

The drain policy and the timeout selector have deterministic tests:
`lte/radio-scale: the bounded drain policy serves eight 16-frame batches`,
`lte/radio-scale: a busy user-plane turn does not sleep in SCTP`, and
`lte/ue: continuous uplink does not wait for a downlink`.

## 5. After the correction

| Profile | Result |
|---|---:|
| TCP uplink, 1 stream, 10 s | **813.0 Mbps** received, 1092 retransmits |
| TCP uplink, 4 streams, 10 s | **983.8 Mbps** received; best 1 s interval **999.71 Mbps**; mean including slow start 933.25 Mbps; 4900 retransmits |
| UDP uplink, 10 Mbps offered, 5 s | **10.0 Mbps, 0% loss, 0 eNB radio drops** |
| UDP uplink, 50 Mbps offered, 5 s | 50 Mbps offered, **18.6% loss** |
| UDP uplink, 100 Mbps offered, 5 s | 100 Mbps offered, **65.1% loss** |

The 4-stream result is the measured application-goodput peak for this session.
The aggregate over the 10 s interval is 983.8 Mbps; the best one-second interval
is 999.71 Mbps. Both are below the 1,000 Mbps boundary.

UDP remains burst-sensitive. At 50 and 100 Mbps the eNB radio socket's
`/proc/net/udp` drop counter rises while the UE and eNB use only a few percent
of CPU. The 212,992 B receive buffer is about 230 packets at this size; the
sender's burst exceeds it before the bounded drain catches up. This is a
`SOCKET_BUFFER_LIMIT` for UDP, separate from the fixed event-loop cap. TCP is
flow-controlled and does not show the same loss.

## 6. EPC charging quota

The subscriber's OCS balance is the hard limit on a long high-rate run:

```text
data_total      6,442,450,944 bytes
data_used       6,442,450,944 bytes
data_available  0
```

At 19:39:12 the SMF received a Gy final-unit action and removed the PDN session
(IPv4 10.45.0.8). A later cleanup Attach reached Gy result 4012
(`DIAMETER_CREDIT_LIMIT_REACHED`) and did not produce a usable PDN session.

A 60 s 1 Gbps application-goodput window needs about 7.5 GB. The 6.44 GB balance
cannot carry it even from an empty session. This is an EPC configuration limit,
not a UniRANSim data-path limit. No subscriber, balance or tariff was modified.

## 7. Peak and sustained verdicts (quota-blocked run)

> The 256 GiB recovery run supersedes the quota-blocked verdicts in this
> section; its complete 60-second matrix is in section 11.

- **Peak:** `PERF_P1_PEAK_BELOW_TARGET`. The best measured one-second interval
  was 999.71 Mbps, just below the 1,000 Mbps boundary; the 10 s aggregate was
  983.8 Mbps.
- **Sustained:** `PERF_P1_SUSTAINED_NOT_MEASURED`. The 60 s steady-state window
  could not run because the OCS balance was exhausted; the 65 s matrix was
  interrupted when the session was removed.
- **Engineering:** `BLOCKED_EPC_CONFIGURATION`. The event-loop fix is measured
  and tested, but the mandatory sustained live gate cannot run against a
  6.44 GB per-session charging balance.

## 8. Cleanup and residuals

After the campaign:

- UE processes: 0.
- eNB processes: 0.
- Campaign TUN and network namespace: removed.
- MME eNB-UEs: 0.
- MME sessions: 0.
- SMF GTPv2/PFCP sessions: **1 residual** (IPv4 10.45.0.9) after the Gy 4012
  failure. The MME removed its session, but the SMF context remained. It was
  not cleared by restarting Open5GS, because that is not a cleanup substitute.
- No unrelated subscriber record or session was intentionally deleted.

The residual SMF context is a cleanup debt caused by the charging failure and
must be cleared by the EPC owner before the next high-rate campaign.

## 9. Reproducibility

The exact client command shape was:

```bash
ip netns exec p19e iperf3 -c 10.45.0.1 -B 10.45.0.8 -p 5202 -t 65 -O 5 -J
```

with `-R` for downlink and `-P 4` for four streams. UDP used
`-u -b <rate>M -l 1350`. The 10 s diagnostic runs used `-t 10 -O 2`.
Application throughput is decimal Mbps; S1-U wire rate is not substituted for
it. The iperf3 JSON, interface counters, drop counters and CPU samples remain
local and are not committed.

## 10. Remaining work

1. Restore the OCS data balance or authorize a subscriber/plan with at least a
   7.5 GB session budget, then run the 65 s four-stream matrix.
2. Clear the residual SMF context through the EPC owner's supported procedure.
3. If UDP at 50–100 Mbps matters, measure a controlled per-socket receive-buffer
   test or a paced UDP profile; do not change global sysctls by default.
4. Keep the 512-UE registration acceptance unchanged.

## 11. 256 GiB recovery and complete 60-second matrix

The owner replenished the subscriber's data allowance. The effective OCS state
was verified before load:

```text
data_total      274,877,906,944 bytes (256 GiB)
data_used        32,625,365,792 bytes after the campaign
data_available  237,957,573,856 bytes after the campaign
data_reserved                0 bytes
```

A new Gy reservation returned result code 2001 with granted units and no final
unit. The old residual SMF context (IPv4 10.45.0.9) was released by the
supported production Attach for the same IMSI; the new session used
10.45.0.27. No subscriber, tariff or balance was modified.

### 11.1 Four primary TCP profiles

Each profile was 65 s total with the first 5 s omitted; the 60 measured
one-second intervals are retained locally.

| Profile | Receiver goodput | Best 1 s | Worst 1 s | Retransmits |
|---|---:|---:|---:|---:|
| TCP uplink, 1 stream | 771.5 Mbps | 830.5 | 704.6 | 6,915 |
| TCP downlink, 1 stream | 562.5 Mbps | 606.1 | 530.6 | 2,803 |
| TCP uplink, 4 streams | **930.5 Mbps** | 962.6 | 757.1 | 34,903 |
| TCP downlink, 4 streams | 655.6 Mbps | 686.8 | 574.6 | 36,665 |
| TCP uplink, 4 streams, repeat | **941.4 Mbps** | 965.7 | 882.9 | 34,829 |

The sustained target is not met in any direction. The repeated uplink
four-stream mean is 940.6 Mbps; the two runs span 930.5–941.4 Mbps.

### 11.2 CPU and wire evidence

The EPC is the limiting subsystem at the four-stream uplink rate:

| Process | Average / maximum (% of one core) |
|---|---:|
| PGW-U / `upfd` | 89.2 / 91.0 |
| SGW-U / `sgwud` | ~80 / 85 |
| eNB | 77.0 / 79.0 |
| UE | 66.7 / 68.0 |
| iperf3 server | 33 |
| MME / SMF | 1 / 2 |

The eNB per-UE counters for the session measured 24,887,382,062 bytes and
20,986,849 packets uplink, and 12,032,868,778 bytes and 16,304,838 packets
downlink on S1-U. The UE TUN counters measured 16,209,207,664 bytes uplink and
11,880,146,183 bytes downlink. The S1-U/application ratio is therefore about
1.54 uplink and 1.01 downlink; uplink includes TCP retransmissions and GTP-U/
IP/UDP overhead, so it is not an application-goodput number. No eNB S1-U drop
was recorded.

### 11.3 Bounded UDP validation

| Offered | Delivered | Loss |
|---:|---:|---:|
| 10 Mbps uplink | 10.0 Mbps | 0% |
| 50 Mbps uplink | 30.36 Mbps | 39.28% |
| 10 Mbps downlink | 10.0 Mbps | 0% |
| 50 Mbps downlink | 50.0 Mbps | 0% |

The uplink 50 Mbps step exceeds the 10% loss limit, so no higher UDP rate was
attempted. The asymmetry is consistent with the eNB radio receive buffer on
the uplink path; downlink at 50 Mbps was loss-free.

### 11.4 Cleanup

The final state is the owner's pre-existing baseline:

```text
MME eNB-UEs            1
MME sessions           2
SMF GTPv2 / PFCP       2 / 2
eNB connections        1
campaign UE processes  0
campaign TUNs          0
```

The old 10.45.0.9 context is gone; no Open5GS restart was used.

### 11.5 Verdicts

- Peak: `PERF_P1_PEAK_BELOW_TARGET` — best observed 999.71 Mbps (earlier 10 s
  diagnostic); best in the 60 s repeat 965.73 Mbps.
- Sustained: `PERF_P1_SUSTAINED_BELOW_TARGET` — complete 60 s matrix, best
  four-stream uplink 941.35 Mbps.
- The remaining primary bottleneck is EPC PGW-U CPU, not the UE/eNB loop.
- Engineering acceptance is tied to the final report's cleanup and CI gates;
  the throughput objective itself remains below target.

## 12. Root-cause diagnostic and OCS reconciliation

### 12.1 The 4 GiB OCS offset

The 19-E-R campaign session usage record is 36,920,333,088 bytes. The balance
`data_used` ended at 32,625,365,792 bytes, exactly 4,294,967,296 bytes (2^32)
lower, while `data_available` moved by the full 36,920,333,088 bytes.

The quantum is a 2^32 field-level carry/aliasing artefact, and it is not fixed
to one field. After the 19-F-A diagnostic the balance read `used
51,958,377,335, available 218,624,562,313`, which is `total - used - 2^32`: the
quantum had moved into `available` while `used` had become the exact sum of the
post-provisioning sessions. The current record reads `used 51,958,377,335,
available 222,919,529,609`, which is `total - used` with no quantum at all.
So the balance satisfies `total = used + available + reserved` at some
observation instants and not at others.

The external OCS code was not modified or restarted; the balance was not
repaired, and no balance write was made. Raw ledger records remain local.

The diagnostic's own usage is fully accounted for by the retained records and
does not reproduce the report's 19,070,850,679 figure. See section 13.2.

### 12.2 Per-second wire evidence

A bounded 8 s S1-U capture during each 60 s profile gives the missing
time-resolved series (GTP-U payload plus IPv4/UDP headers; link header excluded):

| Profile | Direction | Packet rate | S1-U wire rate | Application goodput |
|---|---:|---:|---:|---:|
| UL4 | uplink | 84,597–86,482 pps | 971.9–993.5 Mbps | 928.7 Mbps |
| UL4 | downlink ACKs | 39,001–40,244 pps | 27.6–28.4 Mbps | — |
| DL4 | downlink | 59,133–62,263 pps | 679.3–715.3 Mbps | 662.9 Mbps |
| DL4 | uplink ACKs | 24,205–25,534 pps | 17.1–18.1 Mbps | — |

The per-second S1-U/application ratio is about 1.05, not the 1.54 implied by
the older session totals. The 1.54 was a counter-boundary artifact: the eNB
session counter and the UE TUN counter did not cover the same interval. The
corrected evidence is the time-aligned capture.

### 12.3 Per-thread CPU

`pidstat -t` during the 60 s profiles:

| Process / thread | UL4 average / max | DL4 average / max |
|---|---:|---:|
| PGW-U thread 4040 | **89.8 / 90.0%** | 75.4 / — |
| SGW-U thread 3959 | 83.7 / — | 64.9 / — |
| LTE eNB | 76.0 / — | 50.9 / — |
| LTE UE | 67.0 / — | 44.1 / — |
| iperf3 client | 2.1 / — | 21 (earlier) |
| OCS / SMF | below 1–2% | below 1–2% |

PGW-U thread 4040 is system-heavy: 24.1% user, 65.7% system. The process is
not merely "busy"; one thread is at the one-core ceiling at the 929 Mbps
uplink plateau. The host endpoint control (4-stream iperf3 on loopback, no EPC)
reached 42.9 Gbps, so iperf3 and the host stack are not the endpoint limit.

### 12.4 Uplink conclusion

`PGWU_CPU_LIMIT_CONFIRMED` for the four-stream uplink path: one PGW-U thread
saturates at ~90% while the application plateaus at 929 Mbps; SGW-U/eNB/UE are
lower; the endpoint control and host CPU have headroom; retransmissions are
present (34,099 in the 60 s run). The S1-U wire is 972–993 Mbps, so the
application gap is headers/retransmissions, not missing packets.

### 12.5 Downlink conclusion

DL4 reached 662.9 Mbps with PGW-U at 75.4%, SGW-U 64.9%, eNB 50.9% and UE
44.1%; **no process was saturated**. The downlink root cause is
`BOTTLENECK_NOT_ESTABLISHED`. The UE radio socket recorded only 157 drops and
no TUN write failure, so buffer loss alone does not explain the 663 Mbps
plateau.

The one-frame-per-turn receive loop was the strongest source-level candidate at
the time. Section 13 records the controlled measurement that tested it: the loop
sustains 245,000-287,000 frames per second on one core against the 62,000 the
DL4 profile actually offers, so the receive path is excluded with at least 4.0x
headroom.
The remaining candidates are EPC-side.

The UDP anomaly remains a separate environment limit at the 212,992 B eNB
radio receive buffer. It is not used as the TCP explanation.

### 12.6 OCS/Gy behavior

The new 65 s UL4 profile added 819 usage records; DL4 added 590. With 10 MiB
grants this is about 12.6 CCR-Update events per second at 929 Mbps. OCS and SMF
CPU stayed below 1–2% in the same samples; the 10 MiB grant size is a protocol
design cost, not the measured packet-path bottleneck. Per-request CCA latency
was not available from the retained logs and is `NOT_MEASURED`.

The campaign ended with the owner's six sessions, two eNB-UEs and one eNB
untouched; no campaign UE, TUN or process remained. The fixed 4 GiB balance
offset remains for the EPC owner to reconcile; no write was made.

## 13. Downlink receive path: controlled measurement

### 13.1 The one-frame hypothesis

The production UE takes one simulated-radio datagram per main-loop turn. The
controlled experiment in `docs/lte-downlink-receive-performance.md` runs that
loop (Variant A) against a bounded drain (Variant B) over real loopback UDP with
the production codec, validator and TUN writer.

| Load | Variant A | Variant B (8) |
|---|---:|---:|
| 62,000 pps, 10 s | 60,794-61,895 fps, 28.2-32.0% CPU | 61,373-61,904 fps, 21.1-25.2% CPU |
| 200,000 pps, 5 s | 160,553-161,815 fps, 57.8-60.4% | 190,796-193,664 fps, 54.4-56.4% |
| ceiling, one core | 244,814-287,274 fps | 338,272-398,063 fps |

The accepted DL4 profile offers 59,133-62,263 pps. Variant A therefore has
**at least 4.0x headroom** at the operating point and delivers every offered
datagram at about 30% of one core. The hypothesis is rejected as a throughput
limit. The bounded drain lowers receive CPU by 22% and raises the ceiling 1.38x,
which is a per-turn cost being amortised, not a bottleneck being removed.

No production receive-loop change was made: the isolated experiment did not
establish a scheduling restriction, which is the condition the work order sets.
The applied-effect measurement is retained in
`docs/lte-downlink-receive-performance.md` for a later phase.

### 13.2 Diagnostic usage reconciliation

Session `;130` (the 19-F-A diagnostic) recorded `used_total 15,038,044,247`,
which its 1,435 usage records reproduce exactly. The ledger's `data_used` moved
by 19,333,011,543 = 15,038,044,247 + 2^32, so the account-level movement is the
session plus the deferred quantum. The current `data_used 51,958,377,335` is
exactly the sum of the four post-provisioning sessions.

The report's 19,070,850,679 figure is not reproducible from the retained
records; the difference from the session record is 4,032,806,432. The
work order's 262,160,864 residual follows from that figure, not from the ledger.
Status: `OCS_DIAGNOSTIC_USAGE_DELTA_UNRESOLVED`. No record was modified.

### 13.3 Verdict at the end of 19-F-B

- Downlink bottleneck: `DOWNLINK_BOTTLENECK_NOT_ESTABLISHED`; the UE receive
  path is excluded, and the remaining candidates are EPC-side.
- PERF-P1 peak and sustained remain below target in both directions.
- PERF-P2 remains `REAL_512_UE_ACCEPTED`.
- No live throughput run was executed in this phase.

Section 13.4 records the later real-EPC diagnostic that supersedes this
provisional classification.

### 13.4 EPC downlink diagnostic and the real limit

Phase 19-F-C measured the real EPC downlink path with per-flow TCP state on both
ends and per-socket UDP accounting. The path under test:

```text
iperf3 server 10.45.0.1 (host namespace, ogstun)
  -> PGW-U (upfd, 127.0.0.7:2152)
  -> SGW-U (sgwud, 10.10.0.139:2152)
  -> LTE eNB S1-U (127.0.0.5:2152)
  -> simulated radio (127.0.0.1:32000)
  -> LTE UE TUN p19fc0 (moved into netns p19fc, 10.45.0.x/32)
  -> iperf3 client -R in that namespace
```

The client ran inside the UE's network namespace, so its only route is the TUN,
and a bounded `tcpdump` on `udp port 2152` confirmed the GTP-U exchange on the
S1-U at the same time. No host-local shortcut was used.

Four 65 s / 60 s DL4 profiles were run. The first three used the production
socket buffers; the fourth is a counterfactual that raised the two
UniRANSim-owned receive buffers. Nothing was committed from the counterfactual.

| Run | S1-U / UE radio SO_RCVBUF | Receiver goodput | Retransmits | UDP drops eNB / UE / SGW-U |
|---|---|---:|---:|---|
| 1 | default 212,992 | 298.56 Mbps | 18,908 | not per-socket sampled |
| 2 | default 212,992 | 537.86 Mbps | 29,894 | +27,963 / +3,345 / +1,071 |
| 3 | 425,984 / 212,992 | 411.12 Mbps | 29,971 | +51 / +27,262 / +7,096 |
| 4 | 425,984 / 425,984 | **762.64 Mbps** | 40,924 | +1,392 / +2,185 / +41,364 |

Reference from 19-F-A: 662.93 Mbps. It was not reproduced by runs 1-3: the same
production configuration produced 298-538 Mbps in this session. The plateau is
not a stable property of the configuration; it is the result of where the first
UDP receive buffer overflows.

**What the TCP state shows.** At the 538 Mbps plateau the sender's per-flow
`cwnd` was 15-23 segments (20-31 KB) with `ssthresh` 14-23, `rwnd_limited`
0.0-7.7%, and `snd_wnd` 350-700 KB. Throughput per flow equals
`cwnd x 1348 / rtt` to within a few percent. The receiver's window is at least
ten times the in-flight requirement, so the flow is **congestion-window
limited, not receive-window limited**.

**What the loss is.** `TcpRetransSegs` in each run matched the sum of the
per-socket UDP drops within a few percent, and every drop the kernel counted was
a `UdpRcvbufErrors` on a forwarding socket, not an interface error and not an IP
drop. The first and largest loss point in the production configuration is the
eNB S1-U socket. When that buffer is doubled, the loss moves to the UE radio
socket and goodput does not improve (411 Mbps). When both are doubled, the loss
moves to the SGW-U socket and goodput rises to 762.64 Mbps, the best downlink
result measured in this project.

**The counterfactual boundary.** `net.core.rmem_max` is 212,992 on this host, so
a 4 MiB request is capped at 425,984 bytes (2x). A larger buffer needs
`rmem_max` raised, which is a host setting, not a UniRANSim one, and Open5GS's
own sockets are capped by the same value. That is why the loss relocates
instead of disappearing.

**The BDP.** Per-flow requirement at 1 Gbps with the observed 2.3-3.4 ms RTT is
`125e6/4 x 0.0027 = 84 KB` (62 segments). At 763 Mbps the sender held 46-62
segments per flow, which is exactly the requirement for that rate, and the
receiver advertised 523-547 KB. To reach 1 Gbps the sender needs about 62
segments per flow with **no loss events**, which a 1% loss rate does not allow.

**CPU as throughput rises.** At 538 Mbps: SGW-U 23-29%, PGW-U 28-39%, eNB
18-26%, UE 15-22%. At 763 Mbps: SGW-U 65-74%, PGW-U 77-87%. The PGW-U thread
approaches the same one-core ceiling that the uplink already shows, so once the
loss is removed the PGW-U per-packet cost becomes the next wall.

### 13.5 Verdict

- Downlink root cause: `TCP_CWND_LIMIT_CONFIRMED`, driven by UDP receive-buffer
  loss at the chain's narrowest socket.
- Receive window: `TCP_WINDOW_NOT_LIMITING`.
- First loss point in the production configuration: the eNB S1-U socket; with
  UniRANSim's buffers enlarged, the SGW-U socket.
- The 19-F-B UE receive-loop conclusion is unchanged and is not contradicted:
  the loop is not the limit, the buffers ahead of it are.
- PERF-P1 peak and sustained remain below target in both directions.
- PERF-P2 remains `REAL_512_UE_ACCEPTED`.

## 14. Opt-in receive buffers

The two UniRANSim-owned sockets that lose downlink packets now accept an explicit
receive-buffer setting: `s1u.receiveBufferBytes` on the eNB and
`enbLink.receiveBufferBytes` on the UE. Both are optional; absent means no
system call and the historical socket. A request that the kernel caps is refused
with the requested and effective values instead of being reported as applied.

The design, the readback rules, the memory scaling and the isolated socket
measurement are in `docs/lte-udp-receive-buffer-tuning.md`.

On this host `net.core.rmem_max` is 212,992, so the largest request that can be
applied is 212,992 bytes of usable budget (reported as 425,984 by
`getsockopt`). The 4 MiB budget the 19-F-C counterfactual used is not attainable
here without a host change that this phase is not authorized to make.

## 15. Real-EPC re-acceptance status

`BLOCKED_LIVE_AUTHORIZATION`. No new high-rate workload was run in this phase. The
reason is not only authorization: with the host cap at 212,992 the tuning can at
most reproduce the 19-F-C counterfactual, which already measured 762.64 Mbps and
`LOSS_STAGE_RELOCATED` rather than a resolved chain.

A future authorized run should be:

1. raise `net.core.rmem_max` on the laboratory host (an operator action, with
   rollback), so a 4 MiB request is applied rather than capped;
2. restart Open5GS if the SGW-U socket is to inherit the larger default,
   which needs its own approval and a maintenance window;
3. run one DL4 baseline (production defaults) and one DL4 with both opt-in
   values, 65 s each, 5 s warm-up, 60 s measured, four streams;
4. record per-socket drops at all three hops, TCP state on both ends, CPU,
   softirq, wire rate and OCS usage for each run.

Until that exists, the downlink has no 1 Gbps evidence and PERF-P1 stays
`PERF_P1_SUSTAINED_BELOW_TARGET`.
