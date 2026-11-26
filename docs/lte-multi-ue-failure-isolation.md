# LTE multi-UE failure isolation and same-eNB reattach (D10-512-R1)

This record covers what happens when one production LTE UE in a multi-UE fleet
stops without a Detach, and what lets the same eNB and the same MME accept it
again without restarting either. It is simulator behaviour layered on the
production NAS/RRC/S1AP path; the only simulator-specific frame is the Uu
keepalive described below.

## 1. The problem

D10-512 measured a real failure: at 512 UEs, one UE was SIGKILLed; its
neighbours kept working, but restarting the UE with the same configuration on
the same eNB reached `RRC_CONNECTED` and then timed out waiting for the MME
Attach signalling. The eNB held an active access for a radio peer that no
longer existed, and the MME held the EPS session of the old access.

## 2. Uu peer liveness

The Uu transport is a shared UDP socket with per-UE peer endpoints. UDP has no
peer lifecycle: a silent socket is indistinguishable from a dead process, and
an idle UE sends no RLC data. The R1 adds one internal frame:

- `uu::LogicalChannel::KEEPALIVE`, direction uplink, empty payload. It is
  **not** RRC, **not** NAS and carries no identity or security material; it is
  simulator routing metadata. It never leaves the simulator's radio layer.
- The production UE application sends one every second while its RRC
  connection exists (`UuNasTransport::SendKeepalive`).
- The eNB's `EnbSrb1Runtime::Pump` reports every received frame to a liveness
  callback. Only a peer that has sent at least one keepalive is eligible for
  the timeout, so a deterministic test peer that does not implement keepalives
  is never released by this mechanism.
- `EnbMultiplexer::checkUuLiveness` runs at most once a second. A Uu UE whose
  last frame is more than ten seconds old, whose S1 context is active and
  whose MME-UE-S1AP-ID is known gets one real S1AP UE Context Release Request
  with `radioNetwork` / `radio-connection-with-UE-lost` (21). `releaseRequested`
  prevents a second request for the same silence.

## 3. The release path

The request is a standard S1AP procedure 18 message produced by the production
codec. The MME answers with a UE Context Release Command; the eNB's existing
release path handles it: the RRC connection is released on SRB1, the UE Context
Release Complete is sent, the DRBs and the access transport are destroyed, and
`UeRegistry::releaseS1` moves the context to `IDLE_RETAINED`.

Two facts must be stated precisely:

- **The MME keeps the EPS session.** An S1 release is an ECM-IDLE transition,
  not a Detach. The MME's session gauge does not drop; the S1 eNB-UE context
  does. The same-eNB reattach relies on the new Attach replacing that session.
  The eNB's `releaseS1` retires the local TEIDs, destroys the DRBs and retains
  only the logical EPS identity and QoS, as in any idle release.
- **The access generation advances.** `releaseS1` increments the entry's
  access generation when the released S1 context was bearer-active. A UE
  process that was restarted begins again at generation 0. The eNB therefore
  treats a generation-0 DRB READY on a newly established S1 context as the
  fresh process's new-access baseline and adopts the address that READY
  restates. A same-process ECM-IDLE restoration keeps its advanced generation
  and must match it; a mismatch that is not a fresh-process bootstrap is still
  refused. The adoption is logged as `Fresh UE process restored its access at
  generation 0`.

## 4. What the same-eNB reattach proves

The R1 eight-UE validation performed three complete rounds:

1. Attach, default bearer, DRB, UL/DL (paced lossless traffic).
2. SIGKILL of one UE.
3. The eNB detects the silent peer after 10 s, sends the S1AP Release Request,
   receives the Command and releases the access; the MME keeps the EPS session.
4. The killed UE's neighbour answers a 1372-byte probe with 0 loss.
5. The UE is restarted with its original configuration (same IMSI, radio
   identity, ports, TUN prefix).
6. It reaches Attach/AKA/NAS security/default bearer/DRB and answers its own
   UL/DL probe with 0 loss; the eNB's per-UE statistics show inactive drops 0.

All three rounds passed. The instrumented first round measured 5.0 s with the earlier
five-second threshold; the final threshold is ten seconds, and the 512-UE run
uses it. The 512-UE run repeats the same scenario once
at full fleet size, with the other 511 UEs online; its result is recorded in
the R1 final report.

## 5. Boundaries and risks

- The keepalive is a simulator liveness signal, not a 3GPP message. It must
  never be described as RRC, NAS or a heartbeat defined by a standard.
- The eNB does not read, decrypt or rewrite NAS. The fresh-process adoption
  trusts the PDN address restated by the READY; the SGW/PGW session for the new
  Attach is what makes that address usable. A hostile UE in this simulator
  could restate another address; the core session, not the eNB, is the
  authority that would reject the traffic.
- A stale generation-0 READY from a dead process is theoretically possible in
  the narrow window after the new context is established; the peer's socket is
  reused by the new process, so a queued datagram could be delivered. The
  adoption is bounded to an inactive, signalling-established bearer with a new
  S1 context and is logged; no production EPC claim is made.
- No MME database edit, no Detach, no EPC restart and no manual session
  deletion is used anywhere in this path.
- GUTI Reallocation remains unhandled (EMM 97).

## 6. Tests

- `test/lte/rrc_paging.cpp`: the internal keepalive channel round-trips with
  an empty payload and an unknown channel is still refused.
- `test/lte/enb.cpp`: the UE Context Release Request with
  `radioNetwork/radio-connection-with-UE-lost` (21) encodes procedure 18 and
  decodes back to the lost-peer cause.
- The full `nr-tests` suite (1022 cases) passes with the liveness callback and
  the fresh-process READY baselines.
- `reports/evidence/phase-18-f-b6-d10-512-r1/` holds the 8-UE rounds and the
  512-UE recovery evidence.
