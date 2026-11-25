# Isolated Open5GS multi-UE scale testing (D10)

The D10 scale environment is a private Open5GS instance, its own database and
address plan, and generated test subscribers. The shared laboratory EPC is out
of bounds for the scale work.

## 1. Isolation

- `d10epc` namespace: HSS, MME, SGW-C, SGW-U, SMF (PGW-C), PCRF and UPF, plus
  an isolated `mongod`. Internal 127.0.0.x, S1-MME/S1-U on `10.97.0.1`.
- `d10ue` namespace: the production eNB and production UE processes; a direct
  veth to `d10epc` (`10.99.0.2` / `10.97.0.1`).
- PDN: UPF `d10tun` `10.80.0.1/16`; the test endpoint is `10.98.0.1` in the
  EPC namespace.
- No existing interface or route is changed; the temporary namespace/veth/mongod
  are removed after the run. The shared EPC at 10.10.0.139 is not touched.

## 2. Subscribers

512 generated subscribers, IMSI `460029900000001`..`460029900000512`, APN
`cmnet`, IPv4, QCI 9, each with a generated K/OPc/AMF. The manifest is mode 600
outside Git and is never printed. They are inserted only into the isolated
`xcloud_d10` HSS database. No shared subscriber is created, changed or deleted.

## 3. Harness

`tools/lte-multi-ue-scale.py --subs <manifest> --target N --start M` starts the
production `lte-ue` in the UE namespace in batches, waits for
`DRB user plane configured`, adopts the assigned IPv4 and TUN, installs and
verifies the per-UE source policy route to the test endpoint, and runs per-UE
UDP echo probes. The D10-512 continuation replaced the single 9 MB/UE estimate
with an explicit host-memory model:

- 3.0 MB/UE host increment drives the gate; the 8.6 MiB process RSS is an
  observation only. At 512 UEs the measured sum PSS was 1.77 MB/UE and the
  cumulative host increment 1.96 MB/UE, so the 3.0 model is conservative.
- The floor is 512 MB `MemAvailable`, checked before and after every batch.
  Material `SwapUsed` growth (64 MB/batch), material paging (64 MB with
  positive `SwapUsed` growth), memory PSI (some 30 / full 5 avg10) and an
  EPC health failure each have their own auditable stop.
- The measured estimate is adopted only once the fleet is at least 128 UEs and
  only from the cumulative cost since the pre-fleet baseline (median of the
  recent stage samples). Below that, a 100 MB page-cache swing is several
  MB/UE of noise; one such sample once ratcheted the projection to 32.6 MB/UE.
- The one-second monitor records MemAvailable, MemFree, Cached, SwapUsed,
  SwapFree, pswpin/pswpout, memory PSI, UE and EPC RSS, UE and EPC PSS and the
  MME session gauge.
- A stale rule at a UE's priority is deleted before the new rule is installed;
  the rule and the test-endpoint route are then verified. A UE without them is
  a failed UE, not a silent probe failure.
- A started UE whose process exited is reported and stops the batch; duplicate
  starts are refused. Test UEs and long-lived daemons are started with
  `setsid` so a tool-shell process-group cleanup cannot kill them.
- The 40 unit tests in `tools/tests/` cover the prechecks, the floor, material
  and background swap, PSI transients, the measured-versus-RSS separation, the
  128-UE adoption rule, route verification and process reconciliation.

The eNB is the production `lte-enb` with the isolated EPC's MME/S1-U addresses
and the Uu loopback endpoint. The isolated EPC is the private Open5GS instance
described in §1–§2; the shared laboratory EPC is never its MME, SGW-U or PGW-U.

## 4. Measured result

On 2026-11-25 the isolated fleet reached **512 production UEs in one window**:
512 MME sessions, each UE with the default EPS bearer EBI 5, a DRB and its own
`10.80.x` PDN address. Every stage's 36/1372-byte probes returned zero loss and
zero corrupt (the 512 stage is 1024/1024); the final all-512 probe again
returned 1024/1024. The 10-minute retention window contains 95 one-second
samples, all at `mme_sessions=512`. Memory at 512: 4018 MB MemAvailable,
SwapUsed flat at about 2751 MB, 1.77 MB/UE PSS, 1.96 MB/UE cumulative host
increment. The production Detach then removed all 512 sessions and returned the
gauge to 0 with no UE process left.

The 60 s concurrent 8/16/32/64 test is **NOT PASS**. The probe clients are
un-paced UDP senders (200,000 × 36 bytes per UE); the UE TUN backpressure drops
the excess, and the echo endpoint received only 1.51% (8 UEs), 0.70% (16),
0.34% (32) and 0.004% (64). This is a queue-loss measurement, not a paced
capacity result, and it is not reported as a pass. The same-eNB reattach after
an abnormal UE exit remains **FAILED** (the UE reaches RRC_CONNECTED and then
times out waiting for the MME Attach signalling).

The real shared-EPC portion is separate: the owner-designated real subscribers
`460020000000401`–`656` reached 256 test sessions beside the owner's 4, with
zero-loss per-UE probes, and were removed through the production Detach. It is
not a 512 real-EPC claim. See
`reports/PHASE-18-F-B6-D10-512-UE-CONTINUATION-FINAL-REPORT.md`.

## 5. Cleanup

The isolated UEs, eNB, EPC daemons, mongod, `d10tun`, veth pair, namespaces and
the per-UE policy rules/tables are test-owned and were stopped/removed after
the run: 0 UE processes, 0 MME sessions and no `d10epc`. The isolated
subscribers exist only in `xcloud_d10`; no row was written to the shared HSS
and no shared service was reconfigured.

The 256 real-EPC test sessions were removed through the production Detach; at
17:33 the shared MME/GTP-U/PFCP gauges were back to the owner's 4 sessions. At
17:38:48–17:38:54 the shared EPC's own logs record a graceful termination of its
seven daemons with those four sessions, during the owner's rebuild activity.
This work sent no signal to them and did not restart the EPC. A read-only
check at 21:09 found no MME process, no listener on 36412 and no metrics
endpoint: the shared EPC remains down after its owner's shutdown.
