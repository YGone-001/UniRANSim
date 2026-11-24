# LTE production UE TUN-backed DRB user plane (Phase 18-F-B6-D7)

This record describes the three-process, two-namespace acceptance that connects
the D6 DRB components to the real production UE process, a real Linux UE TUN, a
real Core-side TUN and an independent deterministic SGW-U/PGW-U. It records what
was measured and what is deliberately not claimed.

## Processes and namespaces

```
netns d7ran-<pid>                              netns d7core-<pid>
+--------------------------------+             +--------------------------------+
| production lte-ue              |             | deterministic SGW-U / PGW-U    |
|   NAS/ESM, UE TUN 10.45.0.2    |             |   GTP-U UDP 192.168.77.2:2152  |
|   TFT, DRB, PDCP, RLC AM       |             |   Core TUN 10.45.0.1           |
|   Uu UDP 127.0.0.1:<port>      |             |   route 10.45.0.2/32 -> CoreTun|
|                                |             |                                |
| production EnbMultiplexer      |             |                                |
|   EnbRrcBridge, DRB, S1-U      |             |                                |
|   S1-U 192.168.77.1:2152       |             |                                |
| deterministic MME (in-process) |             |                                |
+---------------+----------------+             +----------------+---------------+
                |       veth 192.168.77.0/24                   |
                +-----------------------------------------------+
                   GTP-U UDP :2152 (real G-PDU, real TEID)
```

The UE and the eNB share the `d7ran` namespace because the simulated Uu is a
loopback UDP endpoint; the Uu envelope and the SRB/DRB payloads are unchanged.
The SGW-U/PGW-U is in `d7core` and the only path between the namespaces is the
veth carrying real GTP-U datagrams. The UE TUN and the Core TUN are therefore in
different namespaces and cannot be short-circuited by the kernel.

## Data paths

Uplink:

```
UE TUN -> production app (bearer selection) -> DRB PDCP (DRB12/EEA2)
       -> RLC AM -> Uu DTCH (UDP loopback) -> eNB RLC AM -> eNB PDCP
       -> production S1uEndpoint -> GTP-U G-PDU -> veth :2152
       -> SGW-U (TEID/bearer map) -> Core TUN -> Linux IP stack
```

Downlink is the exact reverse. The UE TUN address, the Core TUN address and the
PDN address are the same one the NAS Attach Accept assigned (10.45.0.2); the
Core TUN route to that address is what turns a core-side IP packet into a
decapsulated downlink G-PDU.

## Deterministic EPC boundary

- The eNB is the production `EnbMultiplexer`; the Initial Context Setup and the
  Service Request restoration travel through the production S1AP codec and the
  bridge. The MME is a deterministic fixture, not Open5GS.
- The SGW-U/PGW-U is test infrastructure. It terminates the real GTP-U tunnel,
  validates the TEID and the peer, writes to a real Core TUN and encapsulates
  packets read from it. It is not an S11/S5 endpoint and no GTP-C message is
  encoded anywhere.
- The bearer map is an explicitly labelled simulator-internal control file. The
  eNB/MME peer writes it atomically from the eNB's own Initial Context Setup
  Response (the eNB's local TEID and S1-U address); the SGW installs the
  downlink mapping from it. It is not a 3GPP message.
- TEIDs are fresh per access. On the Service Request restoration the map moves
  to generation 2 with a new SGW TEID and a new eNB TEID; the SGW retires the
  old TEID and drops a late UL G-PDU for it as retired traffic. The eNB retires
  the old local TEID through the normal registry lifecycle.

## Production integration fixes found by D7

1. A Uu UE that reconnects for a Service Request keeps its retained registry
   entry; the multiplexer reuses it instead of calling `registerPeer` again, so
   the EPS bearer contexts and the access epoch survive while a new RRC
   connection binds a fresh eNB-UE-S1AP-ID.
2. The UE's RRC DRB configuration can arrive in the same Uu batch as the Attach
   Accept, before the application has processed the NAS and created the TUN.
   The application defers such a configuration and applies it immediately after
   the NAS queue creates the TUN. A lost configuration is never acknowledged.
3. The Uu receive path is drained in a bounded batch on both ends (and the DRB
   RLC entities are ticked each turn). Without the ticks no STATUS was generated
   and a lost RLC PDU was never retransmitted; without the bounded drain a TCP
   burst overflowed the loopback UDP queue.
4. The AM PDU bound is a local DRB profile, not an RRC value. The UE decoder
   left it at the 128-octet SRB default while the eNB used 1700, so every IP
   packet was fragmented into 128-octet PDUs on the UE. The `DrbBearer`
   normalizes the bound on both ends.
5. The production multiplexer delegates a Uu UE Context Release to the bridge:
   the RRCConnectionRelease is sent, exactly one Release Complete is emitted,
   the DRB user plane is destroyed and the EPS bearer context is retained.

## User-plane lifecycle

The new `user-plane` lifecycle scenario attaches, keeps the TUN and DRB user
plane, accepts a network-triggered release, restores the same EPS session with
the compact Service Request over a new RRC connection and keeps running. It does
not exit on a successful restoration and does not re-Attach. The access epoch is
advanced by the UE on the RRC release and by the eNB when the released access
carried a confirmed bearer transport, so the DRB READY of the new access names
the same epoch.

## Acceptance evidence

`test/lte/production_uu_user_plane.cpp` (privileged, `doctest::skip()`, its own
CI job). It runs:

- ICMP both directions with 56 and 1400-byte payloads.
- UDP echo both directions (sequenced payloads, FNV hash, loss/duplicate/order/
  corrupt counters; small and near-MTU).
- TCP echo both directions (256 KiB, payload hash equality).
- iperf3 is attempted when installed. In the recorded local run the UL reached a
  peak of about 78.6 Mbit/s in the first interval and then the sustained TCP
  flow stalled; the DL iperf3 connection did not establish. The baseline is
  therefore reported PARTIAL, with the observed peak and the stall, and no
  fabricated throughput.
- ECM-IDLE: a network release, a compact Service Request, a map generation 2
  with a fresh TEID pair, the old SGW TEID retired, and ICMP/UDP traffic
  resumed on the same EBI.
- Per-direction counters from the player processes, CPU ticks and VmHWM from
  `/proc` (sampled inside a private PID namespace with a private `/proc`), and
  PCAPs on the Uu loopback, the S1-U veth, the UE TUN and the Core TUN when
  `tcpdump` is available.

Evidence is written under `reports/evidence/phase-18-f-b6-d7/` (git-ignored):
`uu.pcap`, `s1u-gtpu.pcap`, `ue-tun.pcap`, `core-tun.pcap`, the three process
logs, `peer.result`, `sgw.result`, `bearer.map` and `traffic-summary.json`. No
key material is recorded.

## Commands

```bash
cmake -S . -B cmake-build-d7 -DCMAKE_BUILD_TYPE=Release
cmake --build cmake-build-d7 --target nr-tests lte-ue lte-uu-user-plane-peer \
  lte-uu-sgw-peer lte-uu-traffic-probe --parallel "$(nproc)"

sudo unshare --net --mount --pid --fork --mount-proc -- bash -c '
  ip link set lo up
  export UNIRANSIM_RUN_PRIVILEGED_TUN_TESTS=1
  ./cmake-build-d7/nr-tests --no-skip \
    --test-case="lte/d7/acceptance: the production ue carries tun ip traffic over drb and gtpu end to end"'
```

The GitHub Actions job `Production UE DRB TUN End-to-End User Plane
(multi-process, blocking)` runs exactly that and requires both sentinels and the
evidence summary.

## Not claimed

- No live Open5GS or live EPC user plane; the MME/SGW are deterministic.
- The iperf3 baseline is PARTIAL; no sustained single-UE throughput number is
  claimed.
- IPv6/dual-stack, RLC UM, DRX, TAU, Recovery, the standard DRB release RRC
  message and 512-UE/1 Gbps acceptance remain out of scope.
- The simulator READY/DTCH control messages are not 3GPP RRC or NAS.
