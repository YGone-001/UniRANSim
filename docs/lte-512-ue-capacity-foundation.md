# LTE 512-UE capacity foundation

What Phase 19-B established about holding 512 independent LTE UE contexts on
one eNB, and what it deliberately did not claim.

## 1. Capacity bound

The production configuration now accepts `maxUes` in `1..512`
(`src/lte/enb/config.cpp`). The default of 8 is unchanged, and zero, negative,
non-integer and 513 are refused. This is a configuration bound, not a
scalability claim: what establishes that 512 contexts can be held is the
runtime evidence below, not the parser.

## 2. Registry architecture and ownership

`UeRegistry` keys a UE on five indexes — radio identity, UDP peer, eNB-UE-S1AP-ID,
MME-UE-S1AP-ID and local TEID — plus a provisional map. A context is created by
`registerPeer` and destroyed by `remove`; the capacity bound counts reached and
provisional contexts together. Measured per context: 640 bytes for
`EnbUeEntry`, 136 bytes per bearer context and 48 bytes of index pointers.

## 3. Actual 512-context evidence

The complete ladder 1 → 2 → 4 → … → 512 runs against the production registry.
At every checkpoint all contexts are created, every radio identity and peer
resolves to the same entry, the bound is exact (a further registration is
refused), every context is released and no index entry survives. The 512
checkpoint creates 512 real `EnbUeEntry` objects; it is not a `capacity()`
call.

Classification: `ISOLATED_CONTEXT_CAPACITY = PASS`, `ISOLATED_REGISTRY_CONTEXT_ACTIVE = PASS`,
`ISOLATED_CONTEXT_RETAINED = PASS` (the same contexts still resolved after a
declared 100 ms observation window), `CLEANUP_COMPLETE = PASS`. Every EPS
classification is `NOT_APPLICABLE` or `BLOCKED_AUTHORIZATION`: no NAS procedure
runs, so nothing here is a simulated Attach, let alone a real EPS registration.

**Phase 19-C correction.** Phase 19-B recorded `STABLE_REGISTRATION_RETAINED =
PASS` at this point. That was a misclassification: a synthetic registry that is
filled and emptied is not an EPS registration and retains nothing. The field now
means EPS registration retention only and is `NOT_MEASURED` for every
registry-only checkpoint. Context persistence has its own state,
`ISOLATED_CONTEXT_RETAINED`, and is never equated with registration.

## 4. Multi-index integrity

Duplicate radio identities, duplicate peers and zero identities are refused and
cost no slot. Teardown in random order leaves no stale index and the identities
are reusable. Repeated 512-context allocation and cleanup cycles leave no
residue. A provisional context consumes a capacity slot and a full registry
still accepts releases.

## 5. Production radio ingress at scale

A production `EnbMultiplexer` receives real UDP radio frames from independently
identified test-owned peers; every frame is decoded and every peer is registered
and independently addressable. Phase 19-B exercised 300 peers with an enlarged
poll budget. Phase 19-C extends this to **512 peers under the production default
`poll(16, 16)`**, with the production receive path, registry and Initial UE
Message encoder: 512 delivered, 0 dropped, 128 default-budget
calls with at most four frames offered per call, and all 512 identities
independently addressable. This is
`SIMULATED_RADIO_ENDPOINT_ACTIVE`: a radio frame is not an authenticated UE.

An environment observation worth recording: the socket's receive buffer is
212,992 bytes and the kernel accounts roughly 936 bytes per small datagram in
that queue. Queuing 512 datagrams before any receive therefore delivers 222 and
drops 290, with the socket's own `/proc/net/udp` drop counter equal to 290 and
`delivered + dropped = 512` exactly. A raw socket probe reproduces it without
the simulator in the path. That is a burst behaviour of the environment, not a
simulator defect: sending is paced by the production loop for the uniform
profile, and an unpaced microburst is reported separately with its drops. No
sysctl was changed; a per-socket `SO_RCVBUF` variation is allowed and measured.

## 6. Fairness and the poll budget

With one hot UE sending a burst and twenty idle UEs sending one frame each,
every idle UE is still served under the bounded `poll(8, 8)` budget. No
cross-UE starvation was demonstrated. The poll budget remains a
`SOURCE_INFERRED_RISK` for throughput, not a measured capacity defect.

## 7. SCTP and S1AP

UE-associated signalling maps `enbUeS1apId` onto `outboundStreams - 1`
negotiated streams and shares streams beyond that. The eNB-UE-S1AP-ID space is
24 bits with monotonic allocation and collision avoidance. Association epochs
isolate a UE context from a later association.

## 8. UE process-per-UE

The LTE UE remains process-per-UE. Per-UE process cost is one process, one TUN
interface and one UDP socket. Phase 19-B did not measure processes on this host.
Phase 19-C did: 512 actual `lte-ue` processes started, stayed alive and
established 512 production radio endpoints with zero startup failures, zero
orphans and zero residual sockets. The measured pre-authentication cost is
about 5.2 MB RSS and 0.51 MB PSS per process, 1 thread, 4 file descriptors and
1 UDP socket; aggregate PSS for 512 processes is 259.5 MB. No multiplexed UE
runtime is implemented. The decision is `KEEP_PROCESS_PER_UE` for the measured
pre-authentication runtime; post-authentication TUN and user-plane cost remain
unmeasured and authorization-gated. See `docs/lte-ue-runtime-scalability.md`.

## 9. Real EPS registration

`REAL_512_UE_BLOCKED_AUTHORIZATION`. The laboratory holds four authorized test
subscribers. No subscriber was created, no IMSI cloned, no K/OPc invented and
no bulk Attach campaign run. A successful isolated 512-context acceptance does
not authorize a 512-subscriber real EPC campaign.

## 10. Independence from PERF-P1

Nothing in the throughput path was modified (Phase 19-C included: the radio
scheduler's default budget was measured, not changed). GTP-U semantics, TEID retirement,
TUN behaviour, TFT matching and the Phase 19-A benchmark profiles are
untouched. The event-loop observations above are recorded for PERF-P1 but no
1-Gbps optimisation was attempted.