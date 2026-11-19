# LTE initial AS security mode procedure

Phase 18-F-B5 turns the Phase 18-F-B4 key hierarchy into an initial AS security
mode procedure: algorithm negotiation, the three TS 36.331 SecurityMode
messages, and the PDCP protection that carries them.

It does **not** activate security in a running radio stack, because this
simulator has no RRC connection and no SRB1 transport. What exists is the real
procedure, real messages and real PDCP security, exercised end to end
in-process and covered by tests. The capability table at the end says exactly
where that line is.

## 1. Algorithm selection

`lte::security::SelectAsAlgorithms` takes two inputs and returns one algorithm
per direction:

| Input | Owner | Meaning |
|---|---|---|
| `UeAlgorithmCapabilities` | UE | the 16-bit EEA/EIA bitmaps of `UESecurityCapabilities` |
| `AlgorithmAllowlist` (per direction) | operator | an **ordered** list; the order is the priority |
| `nasIntegrityAlgorithm` | network | needed for the EIA0 restriction |

Rules, each of which is a test:

1. The selection is the **first allowlist entry** the UE advertises and this
   build implements. Numeric order is irrelevant: an allowlist of `{1, 2}`
   picks EEA1 even though EEA2 has the larger identity.
2. The UE bitmap alone never selects anything, and the allowlist is never
   reordered to match it.
3. Refusals are typed: `UE_CAPABILITIES_MISSING`, `UE_CAPABILITIES_MALFORMED`
   (a present but empty bitmap), `ALLOWLIST_EMPTY`, `NO_COMMON_ALGORITHM`,
   `INVALID_ALGORITHM_IDENTITY` (> 15), `STALE_CONFIGURATION` (a generation that
   does not match the expected one), and `EIA0_WITHOUT_NULL_NAS_INTEGRITY`.
4. **EIA0** is refused when the NAS integrity algorithm is not null, and the
   refusal is not a quiet skip to the next entry.
5. **No silent downgrade.** A UE that supports only EEA1/EIA1 against a policy
   that offers only EEA2/EIA2 is `NO_COMMON_ALGORITHM`, not EEA0.
6. A null algorithm is never described as protection: `AlgorithmSelection`
   carries `cipheringNull`/`integrityNull` and `Describe()` spells it out.

The selection result records the configuration generation it was made against.

## 2. Messages

| Message | Direction | Encoding |
|---|---|---|
| `SecurityModeCommand` | DL-DCCH | `30 02 20` for transaction 0, EEA2/EIA2 |
| `SecurityModeComplete` | UL-DCCH | `28 00` for transaction 0 |
| `SecurityModeFailure` | UL-DCCH | `30 00` for transaction 0 |

Encoded and decoded with the accepted asn1c LTE RRC UPER codec
(`asn_DEF_DL_DCCH_Message`, `asn_DEF_UL_DCCH_Message`). A wrong message type,
a truncated PDU, or an algorithm identity above 3 does not decode.

## 3. PDCP security: two bearer profiles

Phase 18-F-B5-R1 corrected this section. The B5 text below the heading used one
PDU shape for every bearer and stated that the MAC-I is never ciphered; both are
wrong for LTE. `PdcpSecurityEntity` now has two explicit profiles.

### 3.1 Control plane, SRB (TS 36.323 6.2.2)

```text
header = [3 reserved bits = 0][PDCP SN: 5 bits]      1 octet, NO D/C bit
PDU    = header || data || MAC-I(32)
MAC-I  = EIA(K, COUNT || BEARER || DIRECTION || 0^26 || header||data)
```

* SN 5 bits, HFN 27 bits, `COUNT = HFN || SN`.
* The MAC-I field is **always present**; when integrity is not configured it is
  zero and is still ciphered with the data.
* Ciphering covers **data || MAC-I**. The header is never ciphered.
* Receiver: parse the clear header, rebuild the COUNT, decipher data and MAC-I,
  recompute the MAC-I over the clear header and the recovered data, compare, and
  deliver only on success.

### 3.2 User plane, DRB 12-bit (TS 36.323 6.2.3)

```text
header = [D/C = 1][3 reserved bits = 0][PDCP SN: 12 bits]   2 octets
PDU    = header || data
```

* SN 12 bits, HFN 20 bits.
* **No MAC-I field** for the ordinary UE profile; a DRB entity refuses to be
  created with an integrity algorithm (`UNSUPPORTED_PROFILE`).
* Ciphering covers the data field only; the header is clear.

### 3.3 Bearer identity

The value handed to EEA/EIA is the **radio bearer identity minus one**
(TS 36.323 6.3.5, TS 33.401 5.1.3.2): SRB1 → BEARER 0, SRB2 → 1, DRB 3 → 2.
`RadioBearerIdentity` holds the RB identity and `BearerField()` produces the
algorithm input, so the two numbers cannot drift apart. B5 passed `1` for SRB1
and its pinned MAC-I was therefore for the wrong bearer; it has been
recalculated (section 3.4).

### 3.4 Independent evidence

| Vector | Value | Reproduced with |
|---|---|---|
| SRB1 UL MAC-I (BEARER 0, DIR 0, COUNT 0, PDU `00 2800`) | `7527c93b` | OpenSSL CMAC over `00000000 00 000000 002800` |
| SRB1 UL PDU (data + MAC-I ciphered) | `00 2b39107a6b9d` | OpenSSL AES-128-CTR, IV octet `00` |
| SRB1 DL MAC-I (DIR 1) | `c159e70a` | OpenSSL CMAC over `00000000 04 000000 002800` |
| SRB1 DL PDU | `00 803d834dcc49` | OpenSSL AES-128-CTR, IV octet `04` |
| DRB (RB 3 → BEARER 2, DIR 0) ciphertext of `2800` | `f81f` | OpenSSL AES-128-CTR, IV octet `10` |

The IV octet is `(BEARER << 3) | (DIRECTION << 2)`; getting that shift wrong was
the first error this independent check caught, and using the uplink MAC-I for the
downlink vector was the second. Both are corrected here.

COUNT reconstruction: `COUNT = HFN || SN` per profile, with the HFN advanced
when the SN wraps below the last accepted value. A PDU whose COUNT is not
greater than the last accepted one is `REPLAY_DETECTED`.

INDEPENDENT EVIDENCE. The SRB1 test vector

```text
key 2f6e105d4dda7c910c988fcadc7b4844, bearer 1, direction uplink, count 0
PDU before MAC 80002800  ->  transmitted 800028006a5f5c9f
```

was reproduced with `openssl mac -macopt cipher:AES-128-CBC CMAC` over
`00000000 08 000000 80002800`, giving `6a5f5c9f` as the leading half. The EEA2
ciphertext `4c02` was reproduced with `openssl enc -aes-128-ctr` and the
TS 33.401 IV (`count || bearer || direction || 0^26 || counter`). Neither value
was produced by the code under test.

## 4. The procedure

`EnbAsSecurityProcedure` and `UeAsSecurityProcedure` are explicit state
machines:

| State | Reached by |
|---|---|
| `AS_SECURITY_UNINITIALIZED` | an object with no context |
| `AS_SECURITY_KEY_PREPARED` | UE listening, context active |
| `AS_SECURITY_ALGORITHM_SELECTED` | (selection inside Start) |
| `AS_SECURITY_COMMAND_PENDING` | eNB transmitted the command |
| `AS_SECURITY_UE_VERIFIED` | UE verified the command's MAC-I |
| `AS_SECURITY_COMPLETE_PENDING` | UE built and sent the completion |
| `AS_SECURITY_ACTIVE` | completion verified / UE confirmed the send |
| `AS_SECURITY_FAILED` | any rejection |

Sequence:

1. eNB selects algorithms, applies them to the KeNB context, derives KRRCint
   and KRRCenc, builds the command and protects it with **integrity only**.
2. UE parses the command (it is not ciphered, and it names the algorithm that
   selects the key it will be verified with), applies the algorithm set,
   derives the keys, and verifies the MAC-I.
3. On success the UE sends `SecurityModeComplete`, integrity protected and
   **not ciphered**, and only after that activates ciphering.
4. The eNB verifies the completion and only then activates ciphering in both
   directions.

A failure at step 2 sends `SecurityModeFailure` under the protection state the
UE already had (none), leaves the context untouched and keeps ciphering off. A
failure at step 4 leaves the eNB in `AS_SECURITY_FAILED` with no ciphering.

A command too broken to decode has no transaction identifier to answer with, so
it is refused (`MALFORMED_MESSAGE`) rather than answered with a failure.

## 5. Key ownership and lifecycle

The procedure reuses the B4 context unchanged: move-only, per-UE, bound to a NAS
generation, wiped with a volatile store on reset, replacement, move-out and
destruction. `ApplyAsAlgorithms` adds the negotiated algorithm set; it does not
make the context "active" in any protocol sense - that is the state machine's
job.

## 5.1 UP integrity capability audit (Phase F)

The B5 report justified having no K_UPint by "this profile is not a Relay Node".
That is not sufficient: TS 36.331 Release 18 also carries a UE capability for
user-plane integrity protection.

Audit result: **the simulator has no such capability information at all.** The
UE's `networkCapability` is a two-octet *NAS* algorithm bitmap
(`EPS encryption/integrity algorithm`), it is not a `UE-EUTRA-Capability`
message, and nothing in `src/lte` carries a user-plane integrity indication or a
relay-node indication. The profile therefore falls into case (3) - no capability
information - and cannot claim UP integrity in either direction.

Consequences, which are the honest ones:

* `AsAlgorithmSet::upIntegrity` stays empty and no K_UPint is derived at runtime;
* `PDCP_UP_INTEGRITY_READY` is **false** and no DRB entity accepts an integrity
  algorithm;
* the exact missing input is a `UE-EUTRA-Capability`-derived user-plane
  integrity indication (plus relay-node operation) that this simulator does not
  model.

## 6. What is missing

- **No RRC connection and no SRB1.** The bytes the procedure produces have no
  peer to travel to; the simulator carries NAS in its own link frames, not in
  RRC over PDCP.
- **No PDCP entity attached to a bearer.** The security entity is a library; no
  SRB1 or DRB in the running UE/eNB owns one.
- Consequently `AS_SMC_RUNTIME_READY` and
  `AS_INITIAL_SECURITY_ACTIVATION_READY` are **false**, and
  `HANDOVER_SECURITY_READY` stays false.

## 7. Capability table

| Capability | State | Evidence |
|---|---|---|
| `AS_KEY_DERIVATION_READY` | true | B4 hierarchy, independent vectors |
| `AS_ALGORITHM_SELECTION_READY` | true | selector + refusal tests |
| `AS_SMC_CODEC_READY` | true | pinned UPER encodings |
| `PDCP_RRC_INTEGRITY_READY` | true | OpenSSL-reproduced MAC-I |
| `PDCP_RRC_CIPHERING_READY` | true | OpenSSL-reproduced ciphertext |
| `PDCP_UP_CIPHERING_READY` | true | DRB12 profile, K_UPenc, BEARER = RB-1 |
| `PDCP_UP_INTEGRITY_READY` | **false** | no UE capability to support or refuse it |
| `AS_SMC_RUNTIME_READY` | **false** | no SRB1 transport |
| `AS_INITIAL_SECURITY_ACTIVATION_READY` | **false** | depends on the above |
| `HANDOVER_SECURITY_READY` | false | target KeNB* runtime and RRC execution absent |
| `LIVE_HANDOVER_EXECUTION_READY` | false | unchanged |
