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
`DRB user plane configured`, adopts the assigned IPv4 and TUN, installs the
per-UE source policy route to the test endpoint, and runs a per-UE
1372-byte UDP echo probe. It stops before a target whose estimated footprint
would cross the `--reserve-mb` `MemAvailable` reserve and reports
`BLOCKED_RESOURCE_LIMIT`; it never substitutes a deterministic UE for a
production one.

The eNB is the production `lte-enb` with the isolated EPC's MME/S1-U addresses
and the Uu loopback endpoint. The 512 test subscribers are the only identities
used.

## 4. Measured result

On 2026-11-25, 6-core / 7.7 GiB host, the stages reached **256 UEs online in
one window** with 256 MME and SMF/PFCP sessions, 256 unique PDN addresses, and
per-UE 1372-byte bidirectional probes at every stage with zero loss/corrupt.
The 512 target was not started: the measured ~8.6 MiB per UE gives ~4.4 GiB
for the fleet, while 2926 MB was available and the reserve must be kept. The
512 gates are `BLOCKED_RESOURCE_LIMIT`; this is not a 512 pass.

See `reports/evidence/phase-18-f-b6-d10/` (git-ignored) for the environment
JSON, the stage table, the eNB/MME/SMF/UPF logs and the 2-UE data probes.

## 5. Cleanup

The isolated UEs, eNB, EPC daemons, mongod, `d10tun`, veth pair and namespaces
are test-owned and are stopped/removed after the run. The shared EPC's session
count remains at its pre-test baseline (5). A 256-UE production Detach pass was
not executed; that gate is PARTIAL.
