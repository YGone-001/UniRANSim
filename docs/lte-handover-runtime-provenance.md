# LTE handover runtime provenance

Where a running source eNB gets the values a handover container carries: the
UE's serving-cell history, the target cell identity, and the AS configuration
fields. The codecs in `src/lte/rrc` and `src/lte/enb/transparent_container`
turn typed data into octets; this record is about the typed data's origin.

## 1. Trusted versus decoded provenance

Provenance is the spine. Two enums carry it:

* `EutranCgiProvenance` — `FIXTURE`, `SIMULATOR_CELL`, `RUNNING_TARGET_CELL`,
  `CALLER_UNVERIFIED`, `WIRE_UNVERIFIED`.
* `HistoryProvenance` — `RUNTIME_OBSERVED`, `FIXTURE`, `MISSING`, `STALE`,
  `UNKNOWN_PREDECESSOR`, `WIRE_UNVERIFIED`.

Decoding is not verification. The TS 36.413 wire message carries no
provenance, so a decoded container's history and CGI are always
`WIRE_UNVERIFIED`: what a peer asserted and nothing more. No decoded value
becomes `RUNTIME_OBSERVED` or `RUNNING_TARGET_CELL` automatically, and a
fixture does not become runtime data because a decoder processed it. A test
harness may label its own fixture before encoding; that label is harness
metadata, not a wire attribute.

Provenance is raised only by the runtime authority that owns the fact:
`OwnCellIdentity` for this eNB's cell, `TargetInventory::Resolve` for an
authorized target, and `ServingCellHistory` for an observed stay. Matching a
PLMN, a TAC, a cell identifier, a transaction identifier or a well-formed
ASN.1 structure raises nothing.

## 2. Source UE session ownership

The session is read out of the live registry by `ExtractSourceSession`, which
refuses a partially established entry. The history and the snapshot belong to
that session and its serving-cell lifecycle; they are never process-global and
never shared between UEs. No persistent subscriber database is involved.

## 3. UE history lifecycle

`ServingCellHistory` records one EPS session's cells on a monotonic clock:

| Event | Effect |
|---|---|
| Attach completing / idle reselection arriving / handover arriving | `BeginVisit(cell, now)` |
| ECM-IDLE access release / source-context release / Detach | `EndCurrentVisit(now)` — completes the interval, starts none |
| A genuine change of cell | `ReselectTo(cell, now)` — completes and opens in one call |
| A fresh Attach | `StartNewEpsSession(cell, now)` — closes the old session, starts the new one |

Re-establishing access in the cell the session is already recorded in is not a
new cell visit: it opens no entry and does not restate the recorded stay. A
routine S1 access release never counts as a cell change, and no event invents
an earlier cell.

## 4. Monotonic residence time

`Time-UE-StayedInCell` is seconds in `0..4095`, measured as
`steady_clock` durations. Tests inject explicit time points and never sleep.
A stay beyond the range is reported as 4095 with `saturated = true`; a
saturated value is not the measured duration and is not presented as one.

## 5. Target CGI authority

A target identity is only real when an authority owns it. `OwnCellIdentity`
reads this eNB's cell from its `EnbConfig`; `TargetInventory` holds the
simulator's authorized target cells and resolves by **complete** E-UTRAN CGI
(PLMN plus the 28-bit cell identity). A physical cell identity alone is not a
globally unique CGI. Nothing derives a target from a TAC, a PLMN, a UDP
address, a TEID, "the first reachable eNB" or a hardcoded value.

## 6. Inventory generations

`TargetInventory::AdvanceGeneration` invalidates every earlier entry. A stale
entry never resolves, so a snapshot built against an older generation cannot
authorize a later transaction. The snapshot records the inventory generation
it was built against.

## 7. Source AS-Config field inventory

| RRC field | Runtime source | Authority | Status |
|---|---|---|---|
| Source C-RNTI | verified serving UE context | source eNB | available |
| Source CGI | this eNB's own configuration | source eNB | available |
| Source MIB/SIB1/SIB2 | configured radio profile | cell owner | **unavailable** — this simulated radio has no broadcast configuration |
| Source measurements | runtime RRC measurement state | source eNB/UE | **unavailable** |
| Source dedicated radio configuration | runtime bearer/radio state | source eNB | **unavailable** |
| UE capability | UE-provided capability data | verified UE state | caller-supplied |
| Target CGI | authorized target inventory | simulator inventory | available |
| Target mobility configuration | target cell context | target eNB | **unavailable** |

`AS_RUNTIME_FIELD_UNAVAILABLE` is the honest answer for the unavailable rows;
nothing is invented to make an assessment complete. `AssessAsConfigCompleteness`
names the same gaps in code.

## 8. Runtime handover snapshot API

`BuildSourceHandoverRuntimeSnapshot` is the only way a
`SourceHandoverSnapshot` exists: its constructor is not public and the inputs
are live runtime objects (`EnbConfig`, a verified `SourceSession`, a
`ServingCellHistory`, a `TargetInventory`). A missing or mismatched input is
named in `missingInputs` and nothing is built — no default, no fixture, no
container, no S1 signalling, no TEID allocation.

The snapshot is bound to the source context generation and the inventory
generation. A stale snapshot cannot authorize a new transaction.

## 9. Runtime handover builder

`BuildRuntimeHandoverPreparation` consumes a snapshot and the RRC message and
produces the complete source-to-target container through the accepted codecs.
It reuses `EncodeHandoverPreparationInformation` and
`EncodeSourceToTargetTransparentContainer`; there is no second encoder. Its
output is offline bytes that authorize nothing.

## 10. Conformant versus legacy HandoverCommand

`EncodeHandoverCommandPayload` / `DecodeHandoverCommandPayload` are the
conformant form (`handoverCommandMessage` carries a `DL-DCCH-Message`) and are
the only form the live path may use. `EncodeHandoverCommandLegacy` /
`DecodeHandoverCommandLegacy` are the Phase 18-F-B1 form, kept for their
pinned vectors, named so they cannot be mistaken for it, and refused by the
conformant decoder.

## 11. Valid nested UE-EUTRA-Capability fixture

A synthetic but structurally valid `UE-EUTRA-Capability` (rel8, category 1,
one supported band, one measurement band entry) is built from the asn1c
TS 36.331 V15.6.0 types, carried in a `HandoverPreparationInformation`, wrapped
in the source-to-target container and embedded in an S1AP Handover Required.
Wireshark dissects every nested layer with zero malformation. It is labelled
synthetic: no band support, MIMO capability or feature set in it is a real UE
measurement.

## 12. Source/target isolation

History, snapshots and inventories are per session and per eNB. A failed
target preparation for one UE leaves another UE's session and history
untouched; a matching TAC, PLMN or numeric TEID never selects a context.

## 13. Security boundary

No KeNB, NH, NCC, KRRCint, KRRCenc or KUPenc exists, and none is fabricated.
History records carry no IMSI, KASME, NAS key or AS key.
`HANDOVER_SECURITY_READY` stays false.

## 14. Live readiness semantics

Implemented codecs, verified simulator runtime inputs, missing real-RF
configuration, missing AS security, missing UE RRC execution, missing live
core-path evidence and missing live authorization are separate statements.
`liveExecutionReady()` is false. The live ingress remains fail-closed and no
command-line flag changes that.

## 15. Phase 18-F-B4 security prerequisites

The next phase needs: the SecurityContext the MME sends, KeNB/NH derivation
per TS 33.401, NCC handling, RRC and UP key derivation, and an independently
validated test vector for each. The runtime snapshot deliberately carries no
secret material to make that integration convenient.
