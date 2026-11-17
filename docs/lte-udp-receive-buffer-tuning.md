# LTE UDP receive-buffer tuning

This is the design and operational record for the two opt-in receive buffers the
LTE path owns: the shared eNB S1-U socket and the per-UE radio socket. It exists
because Phase 19-F-C measured the real downlink and found the plateau was set by
UDP receive-buffer loss rather than by processing.

- Code: `src/lib/udp/server.cpp` (`ConfigureReceiveBuffer`),
  `src/lte/enb/s1u_endpoint.cpp`, `src/lte/ue/app.cpp`,
  `src/lte/enb/config.cpp`, `src/lte/ue/config.cpp`.
- Tests: `test/lte/socket_buffers.cpp`.
- Experiment: `tools/lte-socket-buffer-experiment.cpp`, built only with
  `-DBUILD_EXPERIMENTS=ON`.

## 1. What was confirmed before this work

Phase 19-F-C measured four 60 s DL4 profiles against the real EPC with per-flow
TCP state on both ends and per-socket UDP accounting:

| S1-U / UE radio buffer | Receiver goodput | Loss point |
|---|---:|---|
| default (212,992) | 298.56 Mbps | not per-socket sampled |
| default (212,992) | 537.86 Mbps | eNB +27,963, UE +3,345, SGW-U +1,071 |
| 425,984 / 212,992 | 411.12 Mbps | eNB +51, UE +27,262, SGW-U +7,096 |
| 425,984 / 425,984 | 762.64 Mbps | eNB +1,392, UE +2,185, SGW-U +41,364 |

The sender was congestion-window limited and never receive-window limited, and
the window was small because about 1% of downlink packets were dropped by a full
UDP receive buffer. The loss moved to the next narrowest socket as each buffer
grew: **`LOSS_STAGE_RELOCATED`**, not `LOSS_CHAIN_RESOLVED`.

That diagnosis is unchanged. What this work adds is a supported way to set those
two buffers, with verification, instead of a local counterfactual build.

## 2. The settings

Both are optional and both default to the historical behaviour.

```yaml
# LTE eNB configuration
s1u:
  address: 127.0.0.5
  port: 2152
  allowLoopback: true
  receiveBufferBytes: 212992     # optional; absent means "no request"

# LTE UE configuration
enbLink:
  localAddress: 127.0.0.1
  localPort: 32000
  address: 127.0.0.1
  port: 4998
  receiveBufferBytes: 212992     # optional; absent means "no request"
```

The same value in each means the same thing, but they are independent settings
for independent sockets: the eNB's is one shared socket for all served UEs, the
UE's is one socket per UE process.

## 3. Default compatibility

When the field is absent, the configured value is 0 and no system call is made at
all. The socket is exactly the one the kernel creates, with
`net.core.rmem_default`. This is not "set it to the default value"; it is
"do not touch it", which is what keeps every existing configuration and the
512-UE acceptance identical.

## 4. Validation

The parser accepts an integer in `1 .. 67108864` (64 MiB). It rejects zero,
negative values, non-integers, floats and anything above the documented
application limit. The socket layer repeats the check, so a caller that bypasses
the parser cannot make an unbounded request either.

## 5. Linux readback semantics

`setsockopt(SO_RCVBUF)` on Linux stores the requested value, capped at
`net.core.rmem_max`, and doubles it for accounting; `getsockopt` returns
**the doubled value**. Therefore:

- a socket that was never configured reads back `rmem_default`, not twice it:
  the default is stored as the accounting value directly;
- an applied request reads back as twice the request;
- a request that the kernel capped reads back as twice `rmem_max`, which is
  less than twice the request.

`usableBytes` is therefore the *nominal requested budget*, not a capacity for
that many payload bytes. Linux charges each queued datagram its skb truesize,
which for a 1,408-byte datagram is about 2,290 bytes on this kernel, so a
212,992-byte budget holds about 93 datagrams, not 151. The isolated experiment
below shows exactly that ratio.

`ConfigureReceiveBuffer` classifies the readback against the request and
reports `requestedBytes`, `effectiveBytes` (the readback),
`usableBytes` (the readback halved) and an error string. A capped request is
**not** applied:

```text
SO_RCVBUF request of 425984 bytes was capped: effective 425984 bytes
(212992 bytes usable) means net.core.rmem_max is lower than the request
```

and both the eNB and the UE refuse to start with that configuration rather than
claiming a budget they did not get. `SO_RCVBUFFORCE` is not used and no sysctl
is written.

## 6. Isolated measurement

`tools/lte-socket-buffer-experiment.cpp` sends a bounded burst into a real
loopback socket and drains what survived, for three cases: default, an explicit
request at the host cap, and an explicit request above it.

On this laboratory host (`rmem_max` 212,992), 2,000 datagrams of 1,408 bytes:

| Case | Requested | Effective | Applied | Delivered | Kernel drops |
|---|---:|---:|---|---:|---:|
| default | 0 | 212,992 | no request | 93 | 1,907 |
| at cap | 212,992 | 425,984 | yes | 185 | 1,815 |
| above cap | 425,984 | 425,984 | **no** | 0 | 0 |

The explicit request at the cap doubles what one burst can hold, which is the
expected effect of doubling `sk_rcvbuf`. The request above the cap is refused
with the diagnostic above and makes no partial change.

This is a socket-level measurement, not a throughput result, and it is not
evidence of 1 Gbps.

## 7. Per-UE resource scaling

`SO_RCVBUF` is a **limit**, not an allocation: the kernel charges memory as
skbs actually queue, so a socket that is idle costs nothing beyond its control
block.

- With the field absent (the default), nothing changes: 512 UEs cost what they
  cost today.
- On this host the attainable usable budget is 212,992 bytes per socket, so
  even a fully tuned 512-UE fleet is bounded by roughly
  `512 x 213 KB = 109 MB` of queued payload in the worst case.
- On a host whose `rmem_max` allowed a 4 MiB request, each UE socket would
  carry a 4 MiB usable limit and an 8 MiB accounting value, so 512 UEs would be
  bounded by about `512 x 4 MiB = 2 GiB` of payload in the worst case, and by
  twice that in accounting terms.

A large UE buffer is therefore never enabled by default and never applied to
every UE automatically. An operator who tunes 512 UEs is asking for that
exposure deliberately, and the honest way to state it is "up to N MiB per UE",
not "N MiB resident".

## 8. Ownership boundaries

| Socket | Owner | Configurable here |
|---|---|---|
| eNB S1-U (one, shared) | this repository | yes, `s1u.receiveBufferBytes` |
| UE radio (one per UE process) | this repository | yes, `enbLink.receiveBufferBytes` |
| eNB radio link (uplink only) | this repository | no, and it is not a loss point |
| SGW-U GTP-U | Open5GS | no |
| PGW-U GTP-U | Open5GS | no |
| NR/gNB sockets | this repository | no (unchanged class, untouched by default) |

Raising `rmem_max` is a **host** action and is not performed by this code or by
this phase.

Open5GS 2.8.0 does not request a receive buffer at all. Its socket helper
(`lib/core/ogs-sockopt.c`) sets only `SO_REUSEADDR`, `TCP_NODELAY`,
`SO_LINGER` and `SO_BINDTODEVICE`; the only `SO_RCVBUF`/`SO_SNDBUF`
references in the tree belong to the bundled freeDiameter SCTP code; and no
buffer key exists in the YAML schema. A GTP-U socket therefore takes
**`net.core.rmem_default` at creation time** and keeps it for its lifetime.

Two consequences follow, and neither can be assumed away:

1. raising `rmem_max` does nothing for Open5GS, because it never asks for more
   than the default it was given;
2. the only lever is `net.core.rmem_default`, and it only applies to sockets
   created **after** the change, so the SGW-U (and PGW-U) process has to be
   recreated. That is a service lifecycle action with its own approval.

On this host all three GTP-U sockets report `rb212992`, which is exactly
`rmem_default`, and their cumulative drop counters (59,525 for the PGW-U,
60,547 for the SGW-U) are the residue of the 19-F-C campaign.

## 9. Status

- Implementation: complete and opt-in.
- Default behaviour: unchanged, verified by a test that asserts two unconfigured
  sockets report the same buffer.
- Real-EPC re-acceptance: **performed under separate authorization**. With the
  host temporarily at `rmem_default=4194304` and `rmem_max=8388608`, DL4
  reached 871.95 Mbps with zero UDP drops at every hop; the explicit
  per-socket request added nothing on top of that default. The results are in
  `docs/lte-single-ue-1gbps-benchmark.md` section 16, and the host change was
  rolled back afterwards.
- PERF-P1: still below target in both directions.
- PERF-P2: `REAL_512_UE_ACCEPTED`, untouched.
