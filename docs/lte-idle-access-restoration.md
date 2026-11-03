# LTE ECM-IDLE access epochs and Paging restoration

This record describes how an already EPS-registered LTE UE returns to
ECM-CONNECTED more than once without re-Attaching, and how the radio message
that opens each access epoch is chosen. It follows the same convention as the
other `docs/` records: it documents behaviour that is exercised by the test
suites and by a live laboratory campaign, not a proposal.

## 1. The states that must not be conflated

One "the UE is registered" is not one state. The following are tracked
independently, and no decision may be made from one of them in place of
another.

| # | State | Owner |
|---|---|---|
| 1 | EPS registration (EMM) | UE |
| 2 | Logical bearer retention (EBI, linked EBI, TFT) | UE |
| 3 | Logical bearer retention and confirmed bearer roles | serving eNB |
| 4 | MME-authorized EPS session continuity | MME |
| 5 | Currently allocated S1AP identities | eNB and MME |
| 6 | Current access generation | UE and serving eNB |
| 7 | Current GTP-U transport readiness | eNB and UE |

A UE Context Release ends states 5 and 7 for that access and leaves 1, 2, 4 and
6 alone. That is what "ECM-IDLE with the session retained" means in this code
base, and it is why a later Service Request can restore a bearer instead of
establishing a new one.

## 2. Access generations

An access generation numbers the access epochs of one UE *as seen by one eNB*.

- `beginNewAttach()` sets it to 0: the Attach is about to open the first epoch.
- `onCellReselected()` forces it to 1 and, with it, drops the bearer-role
  retention of the cell being left. The new cell has never carried this
  session, so nothing about the old cell's access may be presented there.
- `acceptAccessRelease(ebi, generation)` accepts exactly `generation ==
  accessGeneration + 1`, and only while the access is connected or a Service
  Request is pending. It advances the number to the generation that is ending.
- `validateAccessRestoration(ebi, generation)` accepts exactly `generation ==
  accessGeneration`. A confirmation for any other epoch is a stale one.

Because the generation is shared with the serving eNB and is only advanced by a
real access transition, a stale confirmation cannot be replayed into a later
epoch, and an unsuccessful procedure does not advance anything.

## 3. Choosing the radio message form

A Paging answer is either the compact four-octet EPS Service Request, or that
same Service Request preceded by the retained bearer inventory
(`NAS_UPLINK_MOBILITY_CONTEXT`). The inventory is additive: the identity prefix
and the NAS tail stay exactly the nine octets of the compact frame, so the MME
answers the procedure it already knows.

The choice is made from `MobilityContext::accessBootstrap`, which records what
the endpoint being answered has already been *confirmed* to hold:

- `ROLES_RETAINED` — the cell carried this session's Attach, or any later
  confirmed bearer access, and has since released it. It still knows which
  E-RAB is the default bearer, so a compact Service Request is enough.
- `DECLARE_REQUIRED` — the cell has never completed such an access. A cell
  reached by an ECM-IDLE reselection is the usual case: the Tracking Area
  Update that arrived there established no bearer, and the MME's Initial
  Context Setup Request marks no roles in its E-RAB list. The cell is told the
  roles here rather than left to infer them from QCI or from the order of that
  list.

The classification is built only from network-confirmed transitions:

| Transition | Effect |
|---|---|
| `onBearerTransportEstablished`, `onUserPlaneReady`, `onServiceRestored`, `onTauAccessRestored` | `ROLES_RETAINED` |
| `beginNewAttach`, `onCellReselected` | `DECLARE_REQUIRED` |
| `acceptAccessRelease`, `onS1ContextReleased` | unchanged — this is what retains the roles |

Notably, `onAttachComplete` does **not** set `ROLES_RETAINED`. A control-plane
only Attach never confirms the bearer roles at the eNB, and the eNB refuses to
restore a session whose roles it has not confirmed. A local flag that claimed
otherwise would be an unauthenticated radio claim about somebody else's state.

The numerical access generation is deliberately not used for this decision. It
numbers access epochs; it says nothing about whether the endpoint still knows
which E-RAB is the default bearer. A cell at generation 1 that has never
confirmed the roles needs the declaration, and a cell at generation 3 that has
confirmed them does not.

## 4. What the eNB accepts

A compact `SERVICE_REQUEST` is refused unless the entry has a confirmed bearer
on this cell or a retained session (`logicalConfirmed() || sessionRetained`),
and refused again while an S1 context is pending or active, so a duplicate
Service Request cannot replace a live one. The compact form declares no
bearers: it is answered from what the cell already holds.

A `NAS_UPLINK_MOBILITY_CONTEXT` carries the inventory and is what a fresh cell
is given. Role resolution then takes the declared default EBI rather than
guessing, and an E-RAB list that disagrees with the declaration is a
`radioNetwork/25` or `radioNetwork/29` failure rather than a silently
mis-assigned bearer.

## 5. Repeated access epochs

Each epoch is: ECM-IDLE → network Paging → protected Service Request → Initial
Context Setup → fresh transport → bearer readiness confirmation. Between
epochs the network drops the access again, exactly as it would on user
inactivity. The UE's EPS registration, security context, GUTI, logical bearers,
TFT and TUN survive every epoch; only S1AP identities, access TEIDs and the
access generation move.

What must hold in every epoch:

- **NAS security.** One uplink NAS COUNT per Paging answer. A retransmission
  repeats the frozen message and consumes none of its own. The security context
  is never reset because access transport was released.
- **S1AP identities.** Each epoch gets a fresh eNB-UE-S1AP-ID. No identifier of
  a previous epoch is presented again.
- **GTP-U transport.** Each restoration allocates fresh eNB receiving TEIDs,
  and every TEID of the previous epoch is invalidated when that access ends.
  SGW receiving TEIDs may be unchanged — the bearer is the same bearer, and
  inventing SGW relocation would be wrong.
- **Bearer readiness.** No user-plane forwarding happens before the bearer's
  own generation-bound readiness confirmation, and a dedicated bearer that is
  not ready is dropped rather than sent over the default bearer.

## 6. Driving more than one epoch

The lifecycle scenarios in `lifecycle.scenario` perform `lifecycle.idleRounds`
controlled idle periods (default 1, maximum 8). Each round ends when the access
it opened has genuinely been restored, so the rounds are consecutive epochs of
one registration and never overlap. Only `paging` and `idle-reselection`
repeat; a round there ends in a network-triggered restoration, and for
`idle-reselection` only the first round moves to the configured target cell.

A spontaneous recovery that ran on its own timer is not a round the driver
asked for: it neither counts as one nor skips one.

## 7. Where this is verified

The deterministic coverage lives in `test/lte/lifecycle.cpp` (the
classification itself), `test/lte/mobility_target.cpp` (the eNB side, including
the compact form at a retained cell and the declaration at a fresh one),
`test/lte/restoration.cpp` (retained-idle state that must not be mistaken for a
confirmed session) and `test/lte/ue_paging_wait.cpp` (the production
`lte::ue::Run()` through first, second and third Paging restoration).
