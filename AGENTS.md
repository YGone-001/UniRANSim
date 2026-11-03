# AGENTS.md

Development and safety requirements for working in this repository. It records
only what the repository itself establishes: the build and test entry points,
what must never be committed, the commit style used on `develop`, the GTP-U
message-handling rules the eNB receive path must keep, and the constraints that
apply when the LTE path is driven against a live EPC.

## Layout

| Path | Contents |
|---|---|
| `src/` | NR and LTE simulator sources (`src/lte/` is the LTE path) |
| `test/` | doctest suites, driven through `ctest` |
| `config/` | example configurations; `*.local.yaml` are private and git-ignored |
| `docs/` | design records for the LTE slices |
| `tools/` | fixture generators and protocol references |
| `.github/workflows/test.yml` | the five-job CI matrix |

`docs/lte-performance-scalability-roadmap.md` tracks the deferred performance
milestones. It is a roadmap, not a task list: its milestones stay
`DEFERRED — NOT IMPLEMENTED — NOT BENCHMARKED` until they are deliberately
taken on, and it is otherwise left alone.

`docs/gtpu-end-marker-retired-tunnel-lifecycle.md` is the design record for the
eNB GTP-U receive path: message types, End Marker rules, tunnel lifecycle and
TEID reuse protection.

## Build and test

```bash
make build          # Release build; copies the run binaries into build/
make test           # Release build of the test binary, then ctest
```

`make build` clears `build/` first and reconfigures `cmake-build-release`. The
test binary is `cmake-build-release/nr-tests`; it accepts doctest filters:

```bash
./cmake-build-release/nr-tests --no-version --test-case="lte/paging/wait:*"
```

The CI matrix is the acceptance bar. A change is not done until all five jobs
pass on the exact pushed commit:

1. Build and test (GCC).
2. Build and test (Clang).
3. Test (ASan + UBSan).
4. Coverage.
5. Privileged LTE Mobility TUN Integration.

The local equivalents are a Release build per compiler, a Debug build with
`-DUERANSIM_SANITIZE=address,undefined`, a Debug build with
`-DUERANSIM_COVERAGE=ON`, and the privileged case run under `unshare --net`
with `UNIRANSIM_RUN_PRIVILEGED_TUN_TESTS=1`. On a machine where the sanitizer
build faults on `vm.mmap_rnd_bits`, that sysctl step can be skipped locally; CI
sets it.

A `doctest::skip()` case has no `ctest` entry at all, so the ordinary suite
cannot run it. That is what makes a privileged case safe to keep in the tree.

## Testing rules

- Do not assert on a `LogCapture` while it is still capturing: a failed
  assertion prints into the captured buffer and becomes invisible. Record
  observations, `finish()` the capture, then assert.
- A test that ends a production run must use the run's own clean shutdown. A
  run that exits through a failure path prints no statistics block, so a
  missing statistics line is not evidence of anything.
- Tests may not close a requirement with a hand-built success state that skips
  the production transition under test.

## GTP-U message handling

The eNB S1-U receive path is `S1uEndpoint::handleDatagram`, and its dispatch is
a safety boundary. These rules are what a change must not weaken.

- `gtpu::Decode` accepts exactly four message types: Echo Request (1), Echo
  Response (2), End Marker (254) and G-PDU (255). Anything else is rejected at
  decode. Do not widen the whitelist without a rule for the new type in the
  dispatch switch below.
- The dispatch switch sends Echo Request to `handleEchoRequest`, End Marker to
  `handleEndMarker`, and **only** G-PDU to `handleGPdu`. A G-PDU is the only
  message type that may reach the UE link, the frame encoders or the user-plane
  packet counters. Do not let a control message fall through into forwarding.
- An End Marker carries the TEID of the tunnel whose payload stream is ending.
  It is not a release, not a bearer transition and not a handover
  authorisation: handling one must never release a bearer, advance an access
  generation, or start any procedure. It is recorded and nothing else moves.
  No code path generates or transmits an End Marker.
- TEID rules differ per message type and must stay that way. A G-PDU needs a
  non-zero TEID and a non-empty payload and may contain no information element.
  An End Marker needs a non-zero TEID and, beyond an empty information-element
  area, only well-formed Private Extension TLVs (type `0xFF`). Echo carries a
  zero TEID. Reject rather than guess at anything else.
- A local S1-U TEID is active (in `UeRegistry::m_byLocalTeid`), retired (in the
  `RetiredTeidLedger`), or unknown. Every path that stops a tunnel from
  resolving goes through `UeRegistry::retireLocalTeid`, so an identifier cannot
  become unresolvable without also becoming identifiable as retired.
- `UeRegistry::allocateLocalTeid` must keep refusing an identifier that is zero,
  live, or still recorded as retired. That last rule is what stops a delayed
  packet of an old tunnel from resolving against the new tunnel a re-used
  identifier would name. The retired-TEID record is bounded and holds only the
  identifier and its retirement order — no UE identity, peer address or
  subscriber information.
- A G-PDU whose TEID does not resolve is dropped and classified: retired TEID
  is traffic that outlived its tunnel, unknown TEID is a packet that never had
  one. Neither may create or disturb any bearer or UE state.
- Peer identity is validated per bearer against `sgwAddress:2152` before
  anything else happens, for control messages as well as for G-PDUs. Do not
  move that check after a state change.

The detail, including the genuine wire vector the tests are anchored on and the
known limitation that an End Marker does not drain an active tunnel, is in
`docs/gtpu-end-marker-retired-tunnel-lifecycle.md`. The cases live in
`test/lte/gtpu_end_marker.cpp` and drive `handleDatagram` against loopback UDP
endpoints:

```bash
./cmake-build-release/nr-tests --no-version --test-case="lte/gtpu/*,lte/enb/retired-teid*"
```

## What must never be committed

- `config/*.local.yaml` — private laboratory configurations, including
  subscriber authentication material. They are git-ignored and mode 600.
- `reports/` and `artifacts/` — generated phase reports and packet captures.
  They are git-excluded and local only.
- Credentials, packet captures, or any generated acceptance evidence.

## Commit style on `develop`

Work goes directly on `develop` as normal forward-only commits. No feature
branches, pull requests, rebase, reset, amend, force push or history rewrite;
`master` is frozen.

The subject is one sentence, imperative and lowercase, with a `type: summary`
prefix — `fix:`, `feat:`, `test:`, `docs:`, `refactor:`. Keep it to what the
change does. Do not put phase or stage markers, or any external project name,
in the subject, and do not append an attribution trailer. A short body is
optional and should say why, not restate the diff.

## Live EPC laboratory

The LTE path can be driven against a real Open5GS EPC. When it is:

- Never run an Open5GS binary with `--version`. It prints the version and then
  starts the daemon, which collides with the live sockets.
- Never restart or reconfigure the EPC, change the MME served TAI list, or
  modify HSS authentication data, as part of development work.
- Preserve pre-existing laboratory resources. An empty-looking resource is
  still not ours to delete; removing one needs ownership established first and
  separate authorization.
- A policy change such as a PCC rule is separately authorization-gated. Do not
  apply or reapply one just to reproduce an earlier result.
- Subscriber provisioning, `maxUes`, and throughput benchmarking are outside
  the scope of ordinary development work.

## Design records

`docs/` holds one design record per LTE slice rather than a single manual. When
behaviour is verified, update the relevant record to describe what was actually
observed, and correct a record only for a demonstrated inconsistency.
