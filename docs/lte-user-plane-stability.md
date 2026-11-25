# LTE production UE user-plane stability (D8)

Phase 18-F-B6-D8 took the accepted D7 three-process user plane (real TUNs,
real Uu UDP, real GTP-U) and asked why a sustained UL TCP/iperf3 flow stopped
after its first second. This record states the measured root causes, the fixes
and the remaining boundaries. It does not claim a live EPC path, a 1 Gbps run
or a failure-recovery capability that was not implemented.

## What was reproduced

The D7 evidence recorded 76.5-82.8 Mbps in the first one-second interval and
then zero. The D8 baseline reproduction used the production `lte-ue`, the
production `EnbMultiplexer` with a deterministic MME peer and a deterministic
SGW-U/PGW-U in two network namespaces, a real UE TUN and a real Core TUN. With
`UNIRANSIM_DRB_TRACE=1` each second printed the DRB AM state, VT(A)/VT(S)/VR(R),
the outstanding PDU count, transmissions, retransmissions, STATUS and poll
counters, and the failure SN.

The stall was reproduced with both AM entities ending in `FAILED` (the trace
prints `state=1`). In the first baseline the eNB Uu receive socket had already
dropped 947 UL datagrams; a later run with application backpressure removed
that loss but the entities still failed, which moved the investigation from the
socket queue to the RLC timers.

## Root causes

1. **AM timers were driven by loop iterations, not milliseconds.** The AM
   entity has no clock: `t-PollRetransmit`, `t-Reordering` and `t-StatusProhibit`
   are counted in ticks and `MapAmRlcConfiguration` maps one tick to one
   millisecond. The UE application called `uuDrbs->Tick()` on every main-loop
   turn and those turns run at more than one million per second when the legacy
   receive is non-blocking or the TUN is busy. A 15-tick poll timer therefore
   expired within microseconds, the oldest unacknowledged PDU was retransmitted
   again and again, and `maxRetxThreshold` (5-9 transmissions) was reached long
   before a peer STATUS could return. The entity then stopped both directions.
   `EnbMultiplexer::pollUu` ticked the DRBs once per `poll`, which is only
   correct while the caller happens to poll at 1 kHz.

2. **The RRC connection completed only on an exact acknowledgement value.**
   `UeSrb1Runtime::Tick` moved to `RRC_CONNECTED` only when
   `bearer_->VtA() == expectedAck_`. The UE may submit further SRB1 PDUs (for
   example an uplink NAS transport) before the eNB's STATUS for the
   RRCConnectionSetupComplete arrives, so VT(A) can pass `expectedAck_`. The UE
   then remained `RRC_CONNECTION_COMPLETE_PENDING`, and a downlink DRB
   reconfiguration was refused by `OnRrc`, leaving the user plane unconfigured.

3. **A legitimate early reconfiguration was refused.** The eNB sends the
   RRCConnectionReconfiguration as soon as the Initial Context Setup is
   answered; it can share a downlink batch with the PDUs that complete the
   connection. The runtime refused any reconfiguration received before
   `RRC_CONNECTED`, so a timing race could lose the only configuration the eNB
   would send.

4. **The DRB RLC configuration asked for a poll on almost every PDU.** The D8
   pre-fix setting was `t-PollRetransmit ms15`, `pollPDU p32`, `pollByte kB125`
   and `maxRetxThreshold t8`. `PollByteCount` stores the kB enumerator's
   *number* and the entity compares it with a byte count, so index 4 was 125
   bytes, not 125 KiB: every ~1500-byte PDU carried a poll. Each poll invited a
   STATUS, and the periodic poll timer retransmitted the oldest PDU. The D7
   setting used `pollByte` index 14 (kBinfinity) and `pollPDU` index 7
   (p128); the D8 change to a finite `pollPDU` was correct, the `pollByte`
   change was not.

5. **The receive drains were too shallow for a user-plane burst.** The eNB's
   Uu path drained 16 frames per `poll`; the SGW peer read one GTP-U datagram
   per loop and then processed up to 16 Core-TUN packets. With the default
   208 KiB `SO_RCVBUF`, bursts above roughly 140 Uu frames or 140 GTP-U
   datagrams overflowed: measured maxima were 624-847 drops on the eNB Uu
   socket and 1062-1643 on the SGW GTP-U socket. The eNB's S1-U receive
   dropped 514-878 (the UL runs' DL ACK path) and 92-138 in the DL runs.

6. **The TUN/PDCP/RLC interface had no application backpressure.** The D7 UE
   read its TUN in a 16-packet batch and submitted every packet to the RLC,
   whose only limit is the standard 512-PDU AM window. A TCP burst filled the
   Uu socket queue before the window could apply backpressure. The congested
   path also used a zero legacy-receive timeout, producing a busy spin (tens of
   millions of turns in the first D8 attempt).

7. **PollByte units remain a known table inconsistency.** `PollByteCount` in
   `srb1_rlc_config.cpp` is documented as kB25..kB3000 but stores 25..3000 and
   the mapper uses it as bytes. The unit tests assert the historical value
   (`srb1_runtime.cpp`: `am.pollByte == 50` for kB50). D8 does not change that
   contract: the DRB and SRB configurations both use kBinfinity, so the field
   is not an active poll trigger, and `pollPDU` is the finite trigger. A later
   change that uses a finite pollByte must correct the table and its test
   together.

## Fixes

- `src/lte/ue/app.cpp`: the Uu pump waits at most 1 ms on the Uu socket, and
  `uuTransport->Tick()`/`uuDrbs->Tick()` run on elapsed milliseconds with at
  most 20 catch-up ticks per turn. The legacy receive is non-blocking in Uu
  mode. The TUN reader pauses while the DRB has 64 or more unacknowledged PDUs
  and resumes at 16; pause/release events and paused turns are logged.
- `src/lte/enb/multiplexer.cpp`: `pollUu` drains up to 64 Uu frames and ticks
  the DRBs on elapsed milliseconds with the same 20-tick bound. The SRB tick
  stays per poll because the deterministic SRB1 tests rely on that cadence.
- `src/lte/rrc-runtime/rrc_srb1_runtime.cpp`: the connection completes when
  VT(A) has passed the SetupComplete SN (a nonzero distance inside the AM
  window); a reconfiguration received while pending is held and delivered by
  `Tick` after the transition. The application's existing deferral until the
  TUN exists is unchanged.
- `src/lte/rrc-runtime/rrc_drb_config.cpp` and the eNB's local mapper:
  `t-PollRetransmit ms40`, `pollPDU p32`, `pollByte kBinfinity`,
  `maxRetxThreshold t32`, `t-Reordering ms5`, `t-StatusProhibit ms5`. The AM
  window remains 512.
- `src/lte/ue/uu_transport.cpp`: one blocking wait plus up to 63 non-blocking
  Uu receives per pump.
- `tools/lte-uu-sgw-peer.cpp`: up to 32 GTP-U receives per loop (first with a
  2 ms wait, the rest non-blocking) before its Core-TUN batch.
- `tools/lte-uu-user-plane-peer.cpp`: the production `poll(16, 16)` budget.
- `src/lte/rrc-runtime/lte_am.hpp/.cpp`, `lte_am_bearer.*`, `drb_runtime.*`:
  STATUS sent/received, poll sent/received, the failure SN and Uu send failures
  are observable. No counter carries an IMSI or key material.
- `src/lte/enb/s1u_endpoint.cpp` and `ue_registry.hpp`: an S1-U `TrySend`
  refusal is counted as `s1uSendDrops` and reported as `send-drops=...` on the
  per-UE shutdown line (appended, never replacing an existing field).
- `test/lte/production_uu_user_plane.cpp`: the privileged acceptance now also
  requires the restored DRB RLC to be ACTIVE (`rlc_state == 0`), so the global
  CI job fails if the sustained-stall signature returns.

## Measured baseline

Local, root, two network namespaces, real TUNs, with the D8 fixes. Values
are iperf3 application goodput; the S1-U GTP-U wire rate is not the same
number. RLC state 0 means ACTIVE at the end of the run.

| Run | Direction | Sender | Receiver | TCP retx | RLC tx/retx/oow | App drops | Backpressure pauses |
|---|---|---|---|---|---|---|---|
| ul1 | UL 30 s | 241 MB, 67.4 Mbit/s | 239 MB, 65.7 Mbit/s | 1495 | 174880/153/1 | 0 | 37 |
| ul2 | UL 30 s | 249 MB, 69.6 Mbit/s | 246 MB, 68.8 Mbit/s | 1728 | 180472/149/1 | 0 | 24 |
| ul3 | UL 30 s | 251 MB, 70.1 Mbit/s | 248 MB, 68.9 Mbit/s | 1152 | 180926/146/1 | 0 | 25 |
| ul60 | UL 60 s | 445 MB, 62.2 Mbit/s | 442 MB, 61.7 Mbit/s | 2504 | 322918/319/5 | 0 | 84 |
| dl1 | DL 30 s | 200 MB, 55.9 Mbit/s | 199 MB, 54.0 Mbit/s | 96 | 76887/94/1 | 0 | 0 |
| dl2 | DL 30 s | 187 MB, 52.3 Mbit/s | 186 MB, 52.1 Mbit/s | 110 | 72462/115/0 | 0 | 0 |
| dl3 | DL 30 s | 183 MB, 51.1 Mbit/s | 182 MB, 50.8 Mbit/s | 149 | 69813/88/0 | 0 | 0 |
| dl60 | DL 60 s | 375 MB, 52.4 Mbit/s | 374 MB, 52.3 Mbit/s | 227 | 142791/182/1 | 0 | 0 |
| bidir | UL 30 s (shared) | 209 MB, 58.5 Mbit/s | 206 MB, 57.7 Mbit/s | 1849 | 161076/146/0 | 0 | 12 |
| bidir | DL 30 s (shared) | 23.2 MB, 6.50 Mbit/s | 22.8 MB, 6.36 Mbit/s | 124 | (same pair) | 0 | 12 |

The bidirectional DL portion is starved by the shared path; it is reported as
such, not as an independent DL capability. The first one-second interval of a
run is not quoted as the stable rate.

One 30 s UL run (186 MB, 52.0 Mbit/s) sampled over 30.7 s showed UE 44.9% of one
core, eNB 45.8% and the SGW peer 11.7%; peak RSS was 8.5 MiB (UE), 8.3 MiB
(eNB) and 4.5 MiB (SGW). CPU is `(utime+stime)/CLK_TCK` over the sampled window;
RSS is `VmRSS`/`VmHWM` from `/proc`.

## Per-stage accounting (UL run ul1)

| Stage | Packets | Bytes |
|---|---|---|
| UE TUN uplink reads / DRB submits | 174,727 | 262,059,575 |
| eNB radio uplink / S1-U uplink | 174,727 | 262,059,575 |
| SGW GTP-U received / Core TUN writes | 173,288 | (1,439 GTP-U lost at the SGW socket) |
| SGW downlink GTP-U sent | 91,828 | |
| eNB S1-U downlink / radio downlink | 91,198 | 4,792,183 |
| UE DRB downlink / TUN writes | 91,198 | 4,792,183 |

The SGW's missing 1,439 UL datagrams are exactly its GTP-U socket drop count;
they never reached the Core TUN. The SGW's `unknown_teid_drops=1` is the first
uplink that overtakes the initial map read, and `tun_drops=3` are Core-TUN
write refusals at the start of the run. The UE's `malformed=4` are TUN reads
that were not IPv4 (the kernel's own IPv6/ND traffic on the interface), not
user data.

## Failure injection

All three injections removed one real resource 8 s into a 30 s UL flow.

- **Uu peer exit** (`kill -9` of the production eNB peer): the UE's DRB RLC
  reached `FAILED` (`state=1`, failed after 64 outstanding, backpressure
  engaged) and the flow stopped. The UE process stayed alive and shut down
  cleanly on SIGTERM. Bounded failure: yes. Recovery: not implemented.
- **SGW-U exit**: the UE and eNB cannot observe it; the eNB keeps accepting
  uplink GTP-U datagrams, the UE's RLC stays ACTIVE and the process shuts down
  cleanly on SIGTERM. The core-exit is `NOT_DETECTABLE` in this build.
- **UE TUN deletion** (`ip link del d8ue0`): the next TUN read failed with
  `EBADFD`; the UE printed `ERROR: LTE TUN read failed: File descriptor in bad
  state` and exited through its failure path. Bounded, but no graceful
  statistics block (a failed run prints none by design).

Bearer-restoration failure injection was not executed; it remains
`NOT_EXECUTED`. No RRC re-establishment or DRB recovery follows an AM failure.

## Boundaries

- The MME and SGW-U/PGW-U remain deterministic fixtures in two namespaces.
  Nothing here is Open5GS, S11, GTP-C, a live EPC path update or a subscriber.
- The measured numbers are local application goodput. No 1 Gbps claim is made;
  `LTE_SINGLE_UE_1GBPS_ACCEPTED`, `LTE_OPEN5GS_ATTACH_ACCEPTED` and the 512-UE
  scale flags stay false.
- The SGW-U and eNB S1-U sockets still drop under burst; the counts are
  classified, not hidden, and TCP recovers. The receive buffers are not
  enlarged by default.
- The `PollByteCount` unit table is not changed; a future finite pollByte use
  must fix the table and its test together.
- The D7 privileged acceptance (three processes, real TUNs) passes 78/78 under
  these changes, and its new `rlc_state == 0` assertion makes a regression a
  blocking CI failure.
