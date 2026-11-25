# LTE production UE/eNB live Open5GS acceptance (D9)

- Date: 2026-11-25
- Source: `8b54dfe` plus the D9 capability/documentation commit
- Branch: `develop`
- Environment: xCloud Open5GS 2.8.0 at `10.10.0.139`; MME `:36412`; SGW-U
  `:2152`; PLMN 460/02; TAC 1/2; SMF APN `cmnet`, pool `10.45.0.0/16`, gateway
  `10.45.0.1`, MTU 1400.
- Test subscriber: the designated `460020000000007` (`cmnet`, IPv4); its
  K/OPc/AMF matched the HSS record (compared without printing).
- Topology: production `lte-enb` and `lte-ue` in one isolated namespace, a new
  veth `10.99.0.2` to the host `10.99.0.1`, the host's existing `10.10.0.139`
  as the PDN test endpoint.

## S1-MME and Attach

The live MME accepted the production eNB's S1 Setup twice in separate runs:

```
SCTP association established (inbound-streams=10, outbound-streams=10)
Valid S1 Setup Response received
ServedGUMMEIs[0]: PLMN=460/02 group-id=0x0002 mme-code=0x01
MME name=xcloud-mme0
S1 Setup accepted, State=S1_SETUP_ESTABLISHED
```

A production UE Attach then followed:

```
State=AUTHENTICATION_REQUEST_RECEIVED
State=AUTHENTICATION_RESPONSE_SENT
State=SECURITY_MODE_COMMAND_RECEIVED
NAS security activated: EIA2/EEA0 KSI=...
State=NAS_SECURITY_ACTIVE
State=SECURITY_MODE_COMPLETE_SENT
State=ATTACH_ACCEPT_RECEIVED
Default EPS bearer: EBI=5 QCI=9 APN=cmnet
State=ATTACH_COMPLETE_SENT
State=EPS_REGISTERED
Assigned EPS bearer EBI=5 IPv4=10.45.0.168 S-TMSI{...} TAI-list=460/02/1
State=TUN_READY
State=USER_PLANE_ACTIVE
DRB user plane configured for EBI(s)=5 generation=0 IPv4 10.45.0.168
```

The eNB logged the matching `SRB1 UE association ... bound`,
`DRB configuration sent`, `DRB configuration 0 acknowledged` and
`DRB user plane ready ... IPv4 10.45.0.168`.

The first attempt with the old local SQN (0x120) failed closed with
`AUTN SQN is stale`; setting the test UE's `initialSqn` to 0 (a UE-side
configuration value, no HSS change) produced the genuine AKA above.

## PDN addresses

Successive real assignments from the live pool:

| Run | IPv4 |
|---|---|
| user-plane (first binary) | 10.45.0.168 |
| detach / first clean session | 10.45.0.169 |
| current-code user plane | 10.45.0.170 |
| three clean cycles | 10.45.0.171 / .172 / .173 |
| same-eNB clean repeat | 10.45.0.174 / .175 |
| current-code bidirectional + detach | 10.45.0.176 |

No fixed 10.45.0.2 is used.

## End-to-end IP

Current-code eNB (`10.45.0.170`):

| Test | Result |
|---|---|
| ICMP UL 64 B, 4 packets | 4/4, 0% loss, 2.3-3.1 ms |
| ICMP DL 64 B, 4 packets | 4/4, 0% loss, 1.6-2.6 ms |
| ICMP UL 1400 B IP (1372 payload), 3 | 3/3, 0% loss, 4.5-5.3 ms |
| ICMP DL 1400 B IP (1372 payload), 3 | 3/3, 0% loss, 2.5-4.7 ms |
| UDP UL 64 B x100 | 100/100, loss 0, duplicate 0, ooo 0, corrupt 0 |
| UDP UL 1372 B x100 | 100/100, loss 0 |
| UDP DL 64 B x100 | 100/100, loss 0 |
| UDP DL 1372 B x100 | 100/100, loss 0 |
| TCP UL 256 KiB | 262144/262144, hash 3965492677 = expected |
| TCP DL 256 KiB | 262144/262144, hash 3965492677 = expected |

A 1400-byte UDP **payload** (1428-byte IP, above the 1400 PDN MTU) was
rejected/dropped on the downlink as an MTU-exceeding case; the 1372-byte
payload (exactly 1400 IP) passes in both directions.

## iperf3 (30 s)

Current-code eNB, real EPC:

| Direction | Sender | Receiver | TCP retx |
|---|---|---|---|
| UL | 66.5 MB, 18.6 Mbit/s | 64.5 MB, 17.9 Mbit/s | 44 |
| DL | 72.6 MB, 20.3 Mbit/s | 72.4 MB, 20.2 Mbit/s | 33 |

Earlier run on the same live EPC with the then-current eNB build: UL 69.0 MB /
19.3 Mbit/s (18.3 receiver), DL 69.9 MB / 19.5 Mbit/s (19.5 receiver),
100/33 retransmissions.

Simultaneous bidirectional on the current code (10 s, 5 Mbit/s each):
UL 6.00 MB 5.03 Mbit/s sender and receiver, DL 6.00 MB 5.03 Mbit/s sender and
receiver, followed by a clean Detach.

The ~19-20 Mbit/s is the live EPC's debug user-plane result, not a production
UE/eNB limit; the D8 deterministic path measured ~70 Mbit/s. No 1 Gbps claim.

## Counters and drops (current-code user-plane session)

| Counter | Value |
|---|---|
| UE UL / DL | 83,438 packets / 73,412,376 B; 86,814 / 81,451,772 B |
| eNB S1-U UL / DL | 83,438 / 73,412,376; 86,814 / 81,451,772 |
| UE application drops | 0 (malformed 5 = non-IPv4/MTU kernel traffic) |
| eNB S1-U send drops | 0 |
| UE DRB RLC | tx 83,443, retx 5, out-of-window 665, ACTIVE |
| UE Uu socket drops | 0 |
| eNB Uu socket drops | 0 |
| eNB S1-U receive drops (`/proc/net/udp`) | 66 |
| SGW-U GTP-U receive drops (host socket) | 9 cumulative |

The SGW-U and eNB S1-U receive-queue drops are the D8 transport observation at
the live EPC; they are classified, not hidden, and no buffer was enlarged.

## Lifecycle

Three `Attach -> default bearer -> DRB -> UL/DL ICMP -> Detach` cycles, each
with a fresh test eNB, used 10.45.0.171/.172/.173; every cycle's UL and DL ping
was 0% loss and every Detach returned the MME/SMF session count to the pre-test
baseline of **5**. Two further cycles on the **same eNB after a clean Detach**
used .174/.175 and also returned to 5, proving repeated Attach on one eNB works
for the clean path.

An earlier sequence stopped the user-plane UE with SIGTERM (no Detach) and then
tried to Attach three times on that same eNB: all three timed out because the
eNB's retained SRB RLC state was not reset and the new SetupComplete's SN was
treated as old. A fresh eNB or a clean Detach clears it. This is a documented
limitation, not a hidden pass.

## Cleanup

After the acceptance: no test `lte-enb`/`lte-ue` processes, no test TUN, the
isolated namespace and veth removed, MME sessions 5, SMF GTPv2/PFCP sessions 5
(the pre-test baseline; the owner's five sessions). No EPC service was
restarted or reconfigured and no subscriber was changed. The HSS's
`mme_host`/`purge_flag` metadata for the test IMSI can remain set after a
UE-initiated Detach; the MME/SMF session counts are the authoritative cleanup
check and are at baseline.

## Evidence files

`reports/evidence/phase-18-f-b6-d9/` (git-ignored):

- `s1-d8.pcap`, `uu-d8.pcap`, `tun-d8.pcap` — current-code S1-MME/S1-U, Uu and
  UE TUN captures (bounded samples).
- `e5-enb.log`, `e5-ue.log`, `e5-probes.txt`, `e5-iperf-*.log` — attach,
  counters, UDP/TCP and iperf.
- `c1-*`..`c3-*`, `same-*`, `bidir-*` — lifecycle and bidirectional evidence.
- `open5gs-environment.json` — secret-free environment audit.
