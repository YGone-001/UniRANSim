# LTE Access-Stratum security context and key hierarchy

Phase 18-F-B4 implements the TS 33.401 Annex A key hierarchy for the LTE UE and
the S1 target eNB. This document records what exists, what it refuses, and what
it deliberately does not do.

The phase derives and validates keys. It does **not** activate RRC or PDCP
security, does not execute a radio handover, and does not change the live S1AP
ingress, which still refuses to execute. `LIVE_S1_HANDOVER_NO_GO` stands.

## 1. Two contexts, two owners

| | EPS NAS security context | EPS AS security context |
|---|---|---|
| Type | `lte::ue::SecurityContext` | `lte::security::AsSecurityContext` |
| Owns | KASME, eKSI, NAS algorithms, NAS COUNT state, validity | KeNB, NH, NCC position, KeNB* candidate, AS algorithm identities, RRC/UP keys, AS generation |
| Created | on a successful EPS AKA | when NAS security activates |
| Destroyed | on deregistration or a fresh AKA | on a fresh AKA, deregistration, or UE destruction |
| Lifetime | survives a radio connection release | tied to the AS security lifetime |

The AS context is built *from* the NAS context and never writes back into it. A
radio access release destroys the AS context and leaves the NAS context alone,
because TS 24.301 requires the NAS context to survive an ECM-IDLE transition.

Key material lives only in these two objects. It never enters
`SourceHandoverSnapshot`, `SourceSession`, `ServingCellHistory`,
`TargetInventory`, a provenance manifest, a log line, a metric, a JSON
diagnostic or a packet-capture note. `AsSecurityContext::Describe()` is the only
string it produces, and it names the lifecycle state only.

## 2. UL NAS COUNT provenance

`KeNB = KDF(KASME, FC 0x11, UL NAS COUNT)` is only correct if the COUNT is the
one the standard names. This implementation does not take "whichever count is at
hand":

* the Security Mode Complete travels with `ulNasCount` and `SendProtected`
  advances the counter after the send;
* the value used for the KeNB is read **before** that send, at the call site, so
  it is the COUNT of the message that activated NAS security
  (TS 33.401 7.2.1, 7.2.4);
* the value is passed into `AsSecurityContext::Create` explicitly and stored in
  the context's provenance rather than recomputed later.

A COUNT outside the 24-bit range is refused (`INVALID_UL_NAS_COUNT`), and an
all-zero KASME is treated as absent (`MISSING_KASME`) instead of being used.

## 3. KDF

`lte::security::Kdf` wraps the project's single 3GPP KDF
(`crypto::CalculateKdfKey`, HMAC-SHA-256) and exposes the encoded input
`S = FC || P0 || L0 || P1 || L1 ...` for testability. Lengths are two-byte big
endian.

```text
KeNB   = KDF(KASME, 0x11, UL NAS COUNT (4 bytes))
NH     = KDF(KASME, 0x12, SYNC (32 bytes))
KeNB*  = KDF(base, 0x13, PCI (2 bytes), EARFCN-DL (2 or 3 bytes))
K_alg  = KDF(KeNB, 0x15, distinguisher (1 byte), algorithm id (1 byte))[16..31]
```

`EncodeEarfcnDl` implements the A.5 backward-compatibility rule: two bytes for
0-65535, three bytes above. `EncodeKdfInput` is exposed so a test can pin the
encoding rather than only the digest.

## 4. NH chain and NCC

* The initial KeNB sits at the virtual NH position of **NCC 0**.
* `NH_1 = KDF(KASME, 0x12, KeNB_initial)` is derived eagerly and belongs to
  absolute chain position 1, NCC 1. Both the eager and the delayed model are
  permitted by the standard; this implementation uses the eager one and the
  observable state transitions are identical.
* `NH_{n+1} = KDF(KASME, 0x12, NH_n)`.
* **NCC is not an input to the NH KDF.** It labels the chain position; it does
  not contribute to the derivation.
* NCC is three bits. The context keeps an absolute chain index as well, so a
  repeated three-bit value after eight advances is a different position with a
  different key.

The context tracks:

| Field | Meaning |
|---|---|
| `kenb_` | the active KeNB |
| `kenbIndex_` | absolute chain position of the active KeNB (0 for the initial one) |
| `nh_` | the highest NH derived so far |
| `nhIndex_` | its absolute position |
| `pending_` | a staged handover candidate, or nothing |

## 5. Horizontal and vertical KeNB*

On a handover whose received NCC equals the active KeNB's NCC:

```text
KeNB* = KDF(active KeNB, 0x13, target PCI, target EARFCN-DL)     (horizontal)
```

Otherwise the context walks forward to the **next** chain position carrying that
NCC:

```text
target = kenbIndex + ((receivedNCC - (kenbIndex & 7) + 8) mod 8)
NH     = chain forward from (nh_, nhIndex_) to target      (at most 7 steps)
KeNB*  = KDF(NH_target, 0x13, target PCI, target EARFCN-DL)      (vertical)
```

A request that would land *behind* the current chain position is refused
(`STALE_NH`) rather than realised by walking backwards, so an NH is never
reused. Because the walk is bounded by seven steps, no synchronisation loop can
spin.

A repeated NCC after a wrap is therefore honoured as a *later* position: at
position 8 (NCC 0) a request for NCC 2 lands on position 10, not position 2, and
the derived key differs from NH_2's.

## 6. Transactional handover state

`PrepareHandover` stages a candidate; nothing on the active context moves. Only
`CommitHandover` installs it and advances the AS generation. `DiscardHandover`
drops the candidate and leaves the active key, its NCC and the NH chain exactly
where they were. A rejected preparation leaves no partial state behind, and a
second preparation without a commit is refused
(`HANDOVER_ALREADY_PENDING`).

The staged candidate is destroyed by a fresh NAS security context, so a
generation that is no longer current can never be committed.

## 7. Algorithm keys

TS 33.401 A.7, keyed by KeNB:

| Key | Distinguisher |
|---|---:|
| K_RRCenc | 0x03 |
| K_RRCint | 0x04 |
| K_UPenc | 0x05 |
| K_UPint | 0x06 |

The algorithm identity is a four-bit field; a value above 15 has the reserved
bits set and is refused (`INVALID_ALGORITHM_ID`) rather than masked. The 128-bit
key is the least significant half of the KDF output.

**Algorithm selection is not guessed.** This simulator has no RRC security mode
procedure, so no AS algorithm has been selected. A runtime context is created
with `AsAlgorithmSet::negotiated == false` and `DeriveAccessKeys()` refuses
(`UNSUPPORTED_ALGORITHM`) instead of copying the NAS selection into a role the
standard gives to a different procedure. K_UPint is implemented and tested
because Annex A.7 defines it, but the LTE UE profile here has no relay role and
therefore derives none at runtime.

## 8. Target eNB

`DeriveTargetKenbStar(nh, ncc, TargetRadioConfig)` validates the received NH
(32 bytes, non-zero), the NCC (0-7) and the target's own PCI (0-503) and
EARFCN-DL (0-262143), then derives KeNB* from the MME-provided NH. The target
never sees KASME.

The target **cannot** call it today: `lte::enb::TargetContext` carries the eNB
identity, the S1-U address and the supported algorithm sets, but no PCI and no
EARFCN-DL. `TargetRadioConfig::available` exists for exactly that reason - a
target with no verified cell configuration gets `MISSING_TARGET_RADIO_CONFIG`
instead of a fabricated PCI.

## 9. Independent validation

Every expected value in `test/lte/as_security.cpp` comes from a Python
`hmac`/`hashlib` implementation of Annex A that shares no code with the C++
project. The inputs are synthetic and test-only: KASME is `00 01 ... 1f`.

| Vector group | Pinned |
|---|---|
| KDF encoding (FC/length) | `EncodeKdfInput` exact octets; a two-parameter generic KDF |
| KeNB | COUNT 0 and COUNT 0x00ABCDEF |
| Initial NH / chained NH | NH_1, NH_2, NH_3 |
| KeNB* horizontal | from the initial KeNB |
| KeNB* vertical | from NH_1 |
| EARFCN-DL encoding | two-byte (1650) and three-byte (100000) |
| K_RRCint / K_RRCenc / K_UPenc / K_UPint | EIA2 / EEA2 / EEA1 vectors |
| NCC lifecycle | vertical advance, horizontal, eight-step wrap, no backward reuse |
| UE/target consistency | both sides derive the same KeNB* from independent inputs |

## 10. Failure behaviour

Every refusal is a typed `AsSecurityError` and an exception; there is no partial
state and no silent default:

`NO_ACTIVE_CONTEXT`, `MISSING_KASME`, `INVALID_KASME_LENGTH`,
`MISSING_UL_NAS_COUNT`, `INVALID_UL_NAS_COUNT`, `MISSING_NH`,
`INVALID_NH_LENGTH`, `INVALID_NCC`, `INVALID_PCI`, `INVALID_EARFCN_DL`,
`MISSING_TARGET_RADIO_CONFIG`, `INVALID_ALGORITHM_ID`, `UNSUPPORTED_ALGORITHM`,
`STALE_NAS_GENERATION`, `STALE_NH`, `IMPOSSIBLE_NCC_TRANSITION`,
`CROSS_UE_CONTEXT`, `HANDOVER_ALREADY_PENDING`, `NO_PENDING_HANDOVER`.

A context is bound to one UE id and one NAS generation. Using it for another UE
is `CROSS_UE_CONTEXT`; using it with an older NAS generation is
`STALE_NAS_GENERATION`. A context that is reset or moved refuses everything.

## 11. Secret lifecycle

* Keys are held in fixed-size arrays owned by the context, which is move-only;
  through the UE runtime it is a `std::optional` that is replaced, not copied.
* Destruction goes through a volatile store loop that the optimiser cannot
  remove, and runs on reset, replacement, move-out and destruction.
* `Describe()` never contains key material; a test asserts that neither the
  KASME nor the KeNB hex appears in it.
* Nothing is persisted to disk and nothing reaches a log.

## 11.1 Continuation: initial AS security mode (Phase 18-F-B5)

Phase 18-F-B5 adds algorithm negotiation, the TS 36.331 SecurityMode messages
and PDCP protection on top of this hierarchy. See
`docs/lte-as-security-activation.md`; this document remains the record of the key
hierarchy itself.

## 12. Capability boundary

| Capability | State |
|---|---|
| `AS_KEY_DERIVATION_READY` | **true** - the hierarchy exists and is independently verified |
| `HANDOVER_SECURITY_READY` | **false** - no AS algorithm selection, no RRC/PDCP activation, no radio move |
| `UE_RADIO_EXECUTION_READY` | false |
| `LIVE_HANDOVER_EXECUTION_READY` | false |

Making key derivation correct does not make a handover executable, and this
build does not pretend otherwise.
