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

## 7. Peak and sustained verdicts

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
