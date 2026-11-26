# LTE multi-UE user plane: paced concurrency, TCP and capture (D10-512-R1)

This record describes how the multi-UE user plane is exercised and measured
after D10-512. It separates three questions that the D10 report had run
together: a calibrated lossless profile, a capacity sweep, and an uncontrolled
stress study.

## 1. Why the D10 concurrent result was not a gate

The D10 concurrency test sent 200,000 UDP datagrams of 36 bytes per UE as fast
as the client loop could, waited a single 180 s deadline and read the echoes
only afterwards. Its echo endpoint received 1.51%, 0.70%, 0.34% and 0.004% at
8/16/32/64 UEs. The loss was queue loss: the production UE pauses its TUN
reader at 64 unacknowledged DRB PDUs, UDP has no application backpressure, and
the kernel TUN queue drops the excess. The client-side RTT reached about 163 s,
which is backlog, not a control-plane failure. `reports/
PHASE-18-F-B6-D10-512-R1-CONCURRENT-AUDIT.md` records the full audit.

That test belongs to `UNPACED_STRESS` and is never a pass/fail gate.

## 2. Paced traffic

`tools/lte-paced-traffic.py` implements the R1 traffic model.

- `send` is one per-UE sender inside the UE namespace. It paces with absolute
  monotonic deadlines at a configured packets-per-second rate; accumulated
  `sleep()` calls are not used. A bounded catch-up records schedule drift and
  never turns into an unbounded burst.
- Every payload is `seq(4) || hash(4) || tag(4) || pattern`. The tag is the
  sender's UE index; a cross-UE delivery therefore fails the tag check instead
  of looking like a legitimate echo. The hash covers the tag and the pattern;
  sequence gaps, duplicates, reordering and corruption are counted separately.
- The sender reports sent/received/loss/duplicate/out-of-order/corrupt,
  nearest-rank RTT p50/p95/p99, schedule drift, catch-up skips and its warmup
  packet count.
- `run` orchestrates one level: a unique echo port per level (the D10 PCAP
  zero-byte failure was a port still held by the previous level), a ready file
  and a process check, the warmup, a 60 s measured window, a bounded drain and
  an aggregate summary. The UL goodput uses the echo server's measured bytes
  minus the senders' warmup bytes; the DL goodput uses the senders' received
  bytes. TUN queue statistics and MemAvailable are recorded with the level.
- `capacity` repeats the sender at increasing per-UE rates for the capacity
  sweep. A sweep with loss is a result, not a lossless-gate failure.

### Calibrated lossless profile

The pilot used 1/2/4/8 UEs at 50 datagrams/s/UE (1372 bytes, about 0.55 Mbit/s
per UE) for 10 s, then 8 UEs for 60 s. Every pilot level and the 8×60 s level
reported sent == received, loss 0, duplicate 0, corrupt 0, out-of-order 0, with
UL and DL goodput equal to the offered 4.39 Mbit/s at 8 UEs. This is the R1
lossless baseline: 50 pps/UE, 1372 B, 60 s, all active UEs online while the
rest of the fleet stays registered.

The 512-UE run repeats the lossless levels at 8/16/32/64 UEs with the full 512
fleet online; its table is in the R1 final report.

## 3. Backpressure and queue observation

The D8 production backpressure is preserved: the UE's TUN reader pauses at 64
unacknowledged DRB PDUs and resumes at 16. No queue was enlarged and no
backpressure was removed to make a test pass.

Observation points, never interchangeable:

| Observation | Source |
|---|---|
| TUN queue and drops | `ip -s link show <tun>` before/after a level |
| Outstanding DRB PDUs | the UE DRB runtime (the backpressure signal itself) |
| RLC AM transmissions/retransmissions | the UE DRB RLC counters |
| Per-UE UL/DL packet and byte counters | eNB user-plane statistics |
| Schedule drift | the paced sender |
| RTT | the paced sender's measured echoes |

A loopback or private-namespace number is simulator throughput, not RF and not
a live-EPC rate.

## 4. TCP full-duplex tool

The D10 1 MB TCP failure was a tool defect: the client sent the whole payload
and only then read the echo, so both directions' socket buffers could fill and
deadlock. The R1 client is a non-blocking poll loop that sends and receives in
16 KiB chunks concurrently, handles partial send/receive, half-closes after
the last send and reads until the echo is complete or a bounded timeout
expires. It reports sent/received bytes, the SHA-256 of both streams, duration
and application goodput.

Validated end to end through the production UE:

| Size | Result | SHA-256 |
|---:|---|---|
| 64 KiB | COMPLETE | equal |
| 256 KiB | COMPLETE | equal |
| 1 MiB | COMPLETE | equal |
| 4 MiB | COMPLETE | equal |

The 8-UE run measured 8.6–9.7 Mbit/s application goodput at these sizes; the
64 KB local-loopback test is the tool self-check. The tool has a
`sha256-selftest` mode with the `abc` vector.

## 5. PCAP capture preflight

`tools/lte-pcap-capture.py` captures representative UEs (1, 2, 64, 128, 256,
384, 512) on the S1-MME/S1-U veth, the PDN TUN, the S1-U UE veth, the Uu
loopback port and one representative UE TUN. It refuses to report evidence
unless:

- `tcpdump` exists, the evidence directory has at least 200 MB free and both
  network namespaces exist;
- the echo server has bound a unique port and written its ready file;
- every representative UE has a logged IP and its probe succeeds;
- every capture file is non-zero bytes **and** has a non-zero `tcpdump -r`
  packet count. A formally present but empty capture is a failure.

The capture summary records each file's interface, namespace, filter, byte
size, packet count and a decoded sample. The files stay under the git-ignored
`reports/evidence/` tree; no authentication material is captured or written.

## 6. Known limits

- The Uu is a loopback UDP envelope; the numbers are simulator throughput.
- The concurrent test does not establish RF capacity or live-EPC capacity.
- GUTI Reallocation, live ECM-IDLE/Service Request and S1 handover remain
  outside this work.
- The capacity sweep is exploratory; only the calibrated lossless profile is a
  gate.

## 7. R1 measured at 512

The 8-UE lossless profile, the TCP sizes and the PCAP capture pass. At 512
online UEs the same paced levels fail for a specific reason: the active UE
pauses its TUN reader at 75 outstanding DRB PDUs (one pause, 405,583 paused
turns) and never resumes. The eNB's main loop ticks every one of the 512 DRB
runtimes and every one of the 512 SRB contexts per elapsed millisecond; the
resulting per-context load starves the RLC AM STATUS/ACK that would drain the
one active window back below the 16-PDU resume watermark. The senders then
fill and overflow the kernel TUN queue, which is why the echo endpoint
receives nothing. This is a scheduling/ACK starvation at the 512-context tick
load, not a backpressure relaxation candidate: the fix is to tick only
entities with outstanding PDUs or recent activity, keeping the D8 watermarks
and RLC windows unchanged. `LTE_512_UE_SCALE_ACCEPTED` stays false until that
change is measured.
