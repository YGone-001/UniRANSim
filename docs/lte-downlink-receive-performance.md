# LTE downlink receive performance

This is the design and measurement record for the LTE UE's downlink receive
path: what it costs, what it can carry, and why the one-frame-per-turn
structure is not the cause of the single-UE downlink plateau. It closes the
open question that the 19-F-A root-cause diagnostic left behind.

- Scope: the real UE receive loop in `src/lte/ue/app.cpp`, the radio codec in
  `src/lte/ue/radio_link.cpp`, the TUN writer in `src/lte/ue/tun.cpp`, and the
  eNB downlink forwarder in `src/lte/enb/`.
- Not in scope: Open5GS or any EPC component, the OCS, the kernel's global
  networking settings, and the 512-UE registration campaign.
- Verdict: **`DOWNLINK_BOTTLENECK_NOT_ESTABLISHED`**. The UE receive path is
  excluded as the throughput limit: at the rate the accepted DL4 profile
  actually offers it uses about 30% of one core and has a measured ceiling
  at least four times higher. No production receive-loop change is justified, and none
  was made.

## 1. Where this starts

Phase 19-E-R accepted four 60 s TCP profiles. Phase 19-F-A reproduced them and
profiled the path:

| Profile | Receiver goodput | Peak 1 s | Per-thread CPU at the plateau |
|---|---:|---:|---|
| UL4 | 928.69 Mbps | 967.84 Mbps | PGW-U 89.8%, SGW-U 83.7%, eNB 76.0%, UE 67.0% |
| DL4 | 662.93 Mbps | 682.65 Mbps | PGW-U 75.4%, SGW-U 64.9%, eNB 50.9%, UE 44.1% |

The uplink is a confirmed one-thread PGW-U CPU limit. The downlink has no
saturated process at all, and the strongest source-level candidate was the UE
receive loop: it takes exactly one simulated-radio datagram per main-loop turn,
while the uplink TUN path batches up to sixteen packets and the eNB drains up
to sixteen S1-U datagrams per poll. That asymmetry was a candidate, not a
finding. This document is the measurement that tests it.

The Git boundary is unchanged by this work. The current `develop` history is
the rewritten lineage; the pre-rewrite `40ce084` object is not an ancestor and
is not reconstructed here.

## 2. The real downlink execution model

One turn of `lte::ue::Run()` does, in this order:

1. lifecycle and timer checks, one `steady_clock::now()`;
2. up to 16 non-blocking TUN reads (the uplink path), each validated and sent;
3. the radio receive timeout from `RadioReceiveTimeoutMs(registered, tunHadUplink)`;
4. one blocking `UdpServer::Receive`, which is `select()` plus `recvfrom()`;
5. peer check, `link::Decode`, direction and UE identity check;
6. for user-plane frames, `ip::Validate`, the destination check and one
   `TunDevice::writePacket`;
7. back to step 1.

Two consequences matter for the measurement.

A queued datagram never waits for the 50 ms timeout. `Socket::Select` returns as
soon as the descriptor is readable, so the timeout is an idle wait, not a
per-packet delay. The claim that the receive loop adds 50 ms per packet is
false, and the experiment below measures the reality: at 62,000 offered
datagrams per second the p99 receive-and-deliver latency was 0.18-0.25 ms.

The per-turn cost outside the frame is one `read()` on the TUN descriptor, one
clock read and a handful of branches. A turn whose TUN produced an uplink
packet asks the radio socket not to block, so a turn with nothing to do costs
about three syscalls and returns. Batching can only save that per-turn cost; it
cannot make a frame cheaper.

The cost of one frame is therefore:

| Stage | Location | Measured |
|---|---|---:|
| receive syscalls (`select` + `recvfrom`) | `src/lib/udp/server.cpp` | ~2.5 us |
| `link::Decode` (one payload vector) | `src/lte/ue/radio_link.cpp` | 0.13-0.18 us |
| direction, identity, peer checks | `src/lte/ue/app.cpp` | < 0.05 us |
| `ip::Validate` | `src/lte/ip_packet.cpp` | 0.03-0.04 us |
| `TunDevice::writePacket` | `src/lte/ue/tun.cpp` | 1.5-1.8 us |
| turn prologue and loop | `src/lte/ue/app.cpp` | remainder |

The TUN write dominates the in-process work and the kernel entry/exit pair
dominates the syscall work. Neither is a scheduling restriction; both are the
price of moving a packet, and both are present in Variant B as well.

## 3. What the audit found

- Peer identity is checked before anything else, for every frame type, and the
  check is per bearer on the eNB side and per endpoint on the UE side. Nothing
  in this phase moves it.
- The direction and UE identity are checked immediately after decode. An uplink
  frame arriving at the UE radio socket is refused as a routing error.
- A downlink frame is written to the TUN only after `ip::Validate` and the
  destination check. The TUN descriptor is non-blocking, so a write returns
  false on `EAGAIN`/`EINTR` rather than blocking, and a partial write throws.
- The production run recorded **157 radio socket drops and zero TUN write
  failures**: the eNB counted 7,183,403 downlink G-PDUs to this UE and the UE
  counted 7,183,246 delivered TUN packets, a difference of exactly the 157
  drops. So every frame the UE received was written successfully.
- A frame whose bearer has just been released is refused by the ordinary bearer
  lookup, and a frame whose access has just been released is refused by
  `canForwardUserPlane()`. Both checks are read from live state on every frame,
  not captured once per turn.

## 4. Measurement method

The tool is `tools/lte-downlink-receive-experiment.cpp`, built only with
`-DBUILD_EXPERIMENTS=ON`. It never runs in CI.

What it uses from production, unchanged: `udp::UdpServer` (the UE's socket
class), `link::Encode`/`link::Decode`, `link::IsDownlink`, `ip::Validate`,
`TunDevice`/`TunDevice::writePacket` on a real kernel TUN, and
`RadioReceiveTimeoutMs`.

What it models: the main-loop prologue (one clock read, one non-blocking TUN
uplink read that finds nothing) and the turn structure. It does not model NAS
security, the bearer state machine or the eNB. A frame in the tool is a real
encoded DATA_DOWNLINK carrying a 1400-byte IPv4/UDP datagram, delivered over a
real loopback UDP socket, decoded and validated by the production code, and
written into a real TUN.

Variant A reads one datagram per turn, exactly like production. Variant B reads
up to a fixed number per turn, with the first read keeping the runtime timeout
and every later read non-blocking. Both variants run the identical offered
workload from an identical sender.

The sender is a second thread pinned to another core, so it cannot be the
limiter; at 62,000 pps it offered 620,062 datagrams in ten seconds in every run.
The receiver thread's own CPU comes from `getrusage(RUSAGE_THREAD)`, so the
sender's cost is not charged to the receive path.

## 5. Results

### 5.1 At the real DL4 rate

DL4 offered 59,133-62,263 downlink G-PDUs per second, which at 1400-byte
payloads is 679-715 Mbps of S1-U wire. The controlled load below is 62,000 pps,
694 Mbps of IPv4 payload, ten seconds per run, two runs per variant per
invocation, three invocations.

| Variant | Delivered frames/s | Receiver CPU, median (range) | p50 | p95 | p99 |
|---|---:|---:|---:|---:|---:|
| A single-frame | 61,390 (60,794-61,895) | **30.3% (28.2-32.0%)** | 0.113 ms | 0.198 ms | 0.248 ms |
| B bounded 8 | 61,450 (61,373-61,904) | **23.6% (21.1-25.2%)** | 0.077 ms | 0.123 ms | 0.176 ms |
| A untimed control | 61,282-61,372 | 28.1% (26.9-29.2%) | - | - | - |
| B untimed control | 61,469-61,574 | 22.9% (21.5-23.0%) | - | - | - |

Both variants delivered every offered datagram. The receive thread's cost at
this rate is about 4.9 us per frame for A and 3.8 us for B: bounding the turn
removes one syscall and one turn prologue per additional frame, which is 22%
less CPU on the receive thread and a slightly better tail. It is still nowhere
near a limit - about 30% of one core at the exact rate the accepted DL4 profile
produces.

The drop counts are not shown per row because they are a harness artefact: the
sender is a second thread on a shared six-core host, and the loopback socket
pair drops a small fraction under host contention. The production run recorded
157 drops in 65 s (section 3), and no run here lost a frame the sender had
already queued at the rate the receiver could sustain.

### 5.2 Above the real rate

Offered 200,000 pps, five seconds:

| Run | Delivered | CPU | p99 | Kernel drops |
|---|---:|---:|---:|---:|
| A single-frame | 161,815 / 160,553 | 57.8% / 60.4% | 0.32 / 0.34 ms | 190,710 / 197,250 |
| B bounded 8 | 190,796 / 193,664 | 54.4% / 56.4% | 0.241 / 0.241 ms | 46,029 / 31,685 |

At three times the real rate, single-frame delivery starts to fall behind while
bounded delivery keeps up. That is the region where the hypothesis would matter,
and it is 3.2 times above the workload that is actually being measured.

### 5.3 Ceiling

Unthrottled sender, three seconds, so the receiver is the limiter. Six runs per
variant across two host-load conditions (quiet, and a load average of about 2.3
from unrelated processes on the shared six-core host):

| Variant | Delivered frames/s | Receiver CPU |
|---|---:|---:|
| A single-frame | 244,814-287,274 | 96.9-99.9% |
| B bounded 8 | 338,272-398,063 | 99.7-99.9% |
| B bounded 16 | 383,088-411,286 | 99.9% |

The single-frame loop sustains at least 244,000 and up to 287,000 frames per
second on one core; the honest planning number is the lower one. The accepted
DL4 profile needs 62,000. That is **4.0-4.6x headroom**, and it is the number
that decides this phase: a path with at least four times the required capacity
at the operating point is not the thing that is holding the operating point
down. Bounding the receive loop raises the ceiling to 338,000-398,000 (1.38x)
and then flattens - sixteen per turn is no better than eight - which is what a
per-turn-cost hypothesis predicts and a per-frame-cost hypothesis does not.

### 5.4 Instrumentation cost

The timed runs carry three stage clocks and a latency sample per frame; the
untimed control carries none and pays for none. The medians are 30.3% against
28.1% for A (about 2 percentage points, 7% of the thread) and 23.6% against
22.9% for B (under 1 point). At saturation the timed runs are 2-3% slower. The
instrumentation is therefore bounded and measurable, and it never changes the
conclusion it is used to reach.

## 6. Hypothesis, tested

| Question from the work order | Answer |
|---|---|
| Continuously receiving queued datagrams at high rate? | Yes: zero empty receives in every saturating run |
| Does the socket accumulate a backlog? | Only above the delivered rate; at 62k pps the queue is drained every turn |
| Does a turn leave a backlog behind? | No: latency p99 stays at 0.18-0.25 ms at the real rate |
| Limited by unrelated lifecycle checks? | No: the prologue is one clock read and one TUN read per turn |
| Does the TUN write block or fail? | No: non-blocking descriptor, 157 drops and 0 write failures in the production run |
| Measurable loss caused by this stage? | No: 157 of 7,183,403 frames (0.002%) |
| Is the client TCP window the limit? | `NOT_MEASURED` - no inner-flow window/RTT capture was retained; retransmissions were 36,917 and the ACK rate was 24.2-25.5k pps against 59-62k downlink pps |
| Is the EPC producing a lower rate before the UE sees it? | Consistent with the data: S1-U wire 679-715 Mbps, application 663 Mbps, UE never saturated |
| Are radio and TUN counters consistent? | Yes: 7,183,403 - 157 = 7,183,246 exactly |
| Does changing only the receive scheduling improve the workload? | It lowers receive CPU by 22% and raises the ceiling 1.38x, and it does not raise goodput at 62k pps because there is nothing to recover |

The one-frame-per-turn hypothesis is **rejected as a throughput limit** and
confirmed as a **per-turn cost**: the loop pays a syscall and a prologue per
frame that a bounded drain would amortise. That is an efficiency fact, not a
bottleneck.

## 7. Why no production patch was applied

The work order allows a production change only after the isolated experiment
establishes a real scheduling restriction. It did not. The measured facts are:

- 4.0-4.6x headroom at the exact offered rate; and
- 22% lower receive-thread CPU for a bounded drain that is bounded by
  construction.

Applying the batch would buy CPU headroom that the path does not need, in a
900-line dispatch that also carries NAS, bearer, paging, TAU, handover and
shutdown behaviour, with no authorized live run to show that any of it converts
into goodput. The measured effect of the change is recorded here so a later
phase can apply it deliberately, with the invariants in section 8, if a
downlink workload ever reaches the region where it matters.

If it is applied, the smallest correct form is: the first receive of a turn uses
`RadioReceiveTimeoutMs`, each additional receive uses a zero timeout, the turn
stops after a fixed number of frames, and the loop still returns to the TUN
uplink read between turns. The experiment's Variant B is exactly that shape.

## 8. Invariants any future batch must keep

The tests in `test/lte/downlink_receive.cpp` pin these against the production
codec and the production state predicates:

1. an empty socket ends the turn instead of polling again;
2. one frame is accepted with its IPv4 header intact;
3. a burst keeps arrival order;
4. the frame budget bounds a burst and leaves the rest queued, with no loss and
   no duplicate;
5. NAS and data frames keep their order inside one burst;
6. a malformed frame is refused without ending the burst;
7. an unexpected peer, a wrong UE identity and an uplink frame are each
   refused, and the next frame is still served;
8. a downlink destination that is not the UE's own address is refused;
9. a refused TUN write is counted and not delivered;
10. a shutdown observed mid-cycle stops the cycle before the budget is spent;
11. released access refuses user plane while signalling still flows;
12. a released dedicated bearer, and a dedicated bearer that is not
    access-ready, refuse their traffic instead of falling back to the default;
13. a paging indication inside a data burst is decoded in place;
14. a turn with no downlink traffic costs one non-blocking poll;
15. the receive endpoints release their descriptors.

Frame order is preserved because the batch is a sequential drain of the same
socket: a bearer released by one frame is already gone when the next frame is
looked up, so a batch cannot deliver data under a context a preceding control
frame released. Message order is never rearranged to improve throughput, and no
TEID or EBI meaning changes.

## 9. OCS reconciliation

Two findings remain visible and neither was repaired.

**The 2^32 quantum moves between fields.** At 06:12:38Z the balance read
`total 274877906944, used 32625365792, available 237957573856` while the
campaign session `;102` recorded `used_total 36920333088`. `used` was exactly
2^32 below the session record; `available` equalled `total - session usage`.
After the 19-F-A diagnostic the balance read
`used 51958377335, available 218624562313`, which is `total - used - 2^32`: the
quantum had moved into `available` while `used` had become the exact sum of the
post-provisioning sessions. The current record reads
`used 51958377335, available 222919529609`, which is `total - used` with no
quantum at all.

So the discrepancy is a 2^32 field-level carry/aliasing artefact, not lost
credit and not a permanent offset in one field. `data_total`, `data_used` and
`data_available` do not satisfy conservation at every observation instant and
do satisfy it at others. The external OCS code is outside this repository;
nothing here repaired it, and no balance was written.

**The diagnostic usage delta.** The 19-F-A report stated the later diagnostic
consumed 19,070,850,679 bytes while the ledger moved by 19,333,011,543 and the
work order derives a residual of 262,160,864. The retained records do not
reproduce the first number:

- session `;130` `used_total` = 15,038,044,247, and its 1,435 usage records sum
  to exactly that (input 8,801,928,087 + output 6,236,116,160);
- the ledger delta 19,333,011,543 = 15,038,044,247 + 4,294,967,296 exactly, so
  the account-level movement is the diagnostic session plus the deferred
  quantum, with nothing unexplained;
- the current `data_used` 51,958,377,335 is exactly the sum of the four
  post-provisioning sessions `;102`, `;104`, `;130`, `;132`
  (36,920,333,088 + 0 + 15,038,044,247 + 0).

The remaining difference is between the historical report's figure and the
retained session record (4,032,806,432), not a gap in the accounting data.
Status: **`OCS_DIAGNOSTIC_USAGE_DELTA_UNRESOLVED`** - the report's
19,070,850,679 cannot be reconstructed from the retained records, and the
work order's 262,160,864 residual follows from that figure rather than from the
ledger. Nothing was modified to make the two agree.

## 10. What this means for PERF-P1 and PERF-P2

- PERF-P1 peak: `PERF_P1_PEAK_BELOW_TARGET` (best historical 1 s 999.71 Mbps).
- PERF-P1 sustained uplink: `PERF_P1_SUSTAINED_BELOW_TARGET` (928.69 Mbps this
  diagnostic, 941.35 Mbps best).
- PERF-P1 sustained downlink: `PERF_P1_SUSTAINED_BELOW_TARGET` (662.93 Mbps),
  and the limit is **not** in the UE receive path.
- PERF-P2: `REAL_512_UE_ACCEPTED`, unchanged. The receive path is per-UE and
  per-process, and nothing in this phase changed it.

No live throughput run was executed in this phase, so no post-change goodput
exists to report, and none is implied.

## 11. Next step

UniRANSim-side downlink optimization stops here: the receive path is excluded
with at least 4.0x measured headroom. The next experiment must be EPC-side and needs its
own authorization. In order of expected value:

1. a per-hop RTT and queueing measurement along PGW-U, SGW-U and eNB, with a
   concurrent `ss -ti` sample of the inner TCP flow, to decide whether the
   plateau is a window/BDP limit rather than a packet-rate limit;
2. a PGW-U worker/affinity experiment (the uplink already shows one thread at
   the one-core ceiling, and the downlink profile also shows the highest
   per-packet cost of any process in the chain);
3. only after 1 and 2, revisit any UniRANSim-side change, and then with the
   bounded drain in section 7 rather than a rewrite.