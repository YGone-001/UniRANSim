# LTE RRC handover codec (TS 36.331, UPER)

What this repository implements for the two LTE RRC messages an S1 handover
carries, where the ASN.1 came from, how it is regenerated, and what is still
missing between these octets and a working live handover.

## 1. Encoding rules are not interchangeable

LTE RRC is encoded with **Unaligned** Packed Encoding Rules (UPER). S1AP is
encoded with **Aligned** PER (APER). The layers nest:

```
3GPP TS 36.331 RRC ASN.1
        |
        v   UPER        src/lte/rrc/rrc_handover.cpp (asn1c-generated types)
LTE RRC message octets
        |
        v   OCTET STRING inside a 36.413 container
S1AP transparent container
        |
        v   APER        src/lte/enb/codec.cpp
3GPP TS 36.413 S1AP PDU
```

Nothing may encode an RRC message with the S1AP writer or decode an S1AP octet
string as if it were an RRC PDU. The codec library (`lte-rrc`) is separate from
the S1AP codec for exactly this reason.

## 2. Pinned release

| | |
|---|---|
| Specification | 3GPP TS 36.331, V15.6.0 (Release 15) |
| Module | `EUTRA-RRC-Definitions` and the inter-node definitions it contains |
| File in this repository | `tools/lte-rrc-15.6.0.asn1` |
| SHA-256 | `9f85c0ef5bc1a9fa2f18b783daacbd80ef779c502f6b6f36cdfd622bc3034a94` |
| Size | 676,235 bytes |
| Obtained from | the OpenAirInterface mirror of the 3GPP module (`openair2/RRC/LTE/MESSAGES/ASN.1/lte-rrc-15.6.0.asn1`), unmodified |

The file is the ASN.1 as 3GPP publishes it; no field, constraint or extension
marker was edited to make a compiler accept it.

### Why not Release 16

Release 16 (V16.13.0) cannot be compiled by the available ASN.1 toolchain. The
module uses extension-addition groups (`[[ ... ]]`) inside a **CHOICE**
(`PosSystemInformation-r15-IEs`, line 2777 of V16.13.0), and asn1c's grammar
admits `[[ ... ]]` only in a `ComponentTypeLists` (a SEQUENCE). Stock asn1c
0.9.28, the OpenAirInterface asn1c fork (0.9.24) and upstream master all fail on
it with `syntax error, unexpected TOK_VBracketLeft`. V15.6.0 is the newest
release every one of them parses, and it matches the release the repository
already vendors for NR RRC (`tools/rrc-15.6.0.asn1`).

The S1AP container is an opaque OCTET STRING as far as 36.413 is concerned, so
the release of the RRC message inside it does not have to equal the release of
the S1AP message around it.

## 3. Generation

```bash
asn1c -fcompound-names -pdu=all -findirect-choice -fno-include-deps \
      -gen-PER -no-gen-OER -no-gen-example -D src/asn/lte-rrc \
      tools/lte-rrc-15.6.0.asn1
```

* Compiler: asn1c 0.9.29 (upstream `vlm/asn1c`, commit `8a274c3`), built locally
  with autotools. The generated headers record the same command line.
* Output: 4,734 files (2,366 `.c` and 2,368 `.h`) in `src/asn/lte-rrc`, built as
  the `asn-lte-rrc` library over the vendored `src/asn/asn1c` runtime.
* The output is generated, not hand-edited. Regenerating from the same
  `tools/lte-rrc-15.6.0.asn1` with the same compiler and flags reproduces it.
* Licensing: asn1c is BSD-2-Clause and its output carries that header; 3GPP
  technical specifications are published for implementation use. The ASN.1 file
  is kept in `tools/` next to the NR RRC and NGAP modules the repository already
  vendors.

## 4. What the codec produces

`src/lte/rrc/rrc_handover.{hpp,cpp}`.

### 4.1 Source to target

`HandoverPreparationInformation` — the inter-node message carried in the
source-to-target container. Encoded with the `criticalExtensions` →
`c1` → `handoverPreparationInformation-r8` choice.

Supported:

* `ue-RadioAccessCapabilityInfo`: one or more `UE-CapabilityRAT-Container`
  entries (RAT-Type and the container's octets, carried verbatim).
* `as-Config` when supplied: `sourceSecurityAlgorithmConfig`,
  `sourceUE-Identity` (C-RNTI), `sourceMasterInformationBlock`,
  `sourceSystemInformationBlockType1`, `sourceSystemInformationBlockType2`,
  `antennaInfoCommon` and `sourceDl-CarrierFreq`.

The MIB, SIB1 and SIB2 models carry their **mandatory** members; the optional
members of those structures are not modelled and are omitted by the encoder,
which is legal for each of them. `sourceMeasConfig` and
`sourceRadioResourceConfig` are encoded as empty structures: the specification
makes every member of both optional, and this phase does not model their
contents. That is a named limitation, not a fabricated measurement
configuration.

`rrm-Config`, `as-Context` and `nonCriticalExtension` are not modelled and are
omitted.

### 4.2 Target to source

The container carries an RRC `HandoverCommand` message whose
`handoverCommandMessage` field is an `RRCConnectionReconfiguration` encoded as an
OCTET STRING. The codec produces both layers: the reconfiguration with
`mobilityControlInfo`, wrapped in the `HandoverCommand` message.

Supported inside `mobilityControlInfo`: `targetPhysCellId`, `t304`,
`newUE-Identity` (the target C-RNTI), and the mandatory members of
`radioResourceConfigCommon` — `prach-Config`'s root sequence index,
`pusch-ConfigCommon` (n-SB, hopping mode, hopping offset, 64QAM, and the UL
reference-signal parameters) and `ul-CyclicPrefixLength`.

`carrierFreq`, `carrierBandwidth`, `additionalSpectrumEmission`,
`rach-ConfigDedicated` and the optional members of `radioResourceConfigCommon`
are not modelled and are omitted. `measConfig`, `radioResourceConfigDedicated`
and `securityConfigHO` are not modelled either.

## 5. The container boundary is one layer deeper than it looks

The S1AP IE is an OCTET STRING, but its **contents** are not the RRC message
directly. TS 36.413 §9.2.1.39 defines:

```
SourceeNB-ToTargeteNB-TransparentContainer ::= SEQUENCE {
    rRC-Container                 RRC-Container,          -- the RRC message
    e-RABInformationList          OPTIONAL,
    targetCell-ID                 EUTRAN-CGI,             -- mandatory
    subscriberProfileIDforRFP     OPTIONAL,
    uE-HistoryInformation         UE-HistoryInformation,  -- mandatory
    iE-Extensions                 OPTIONAL, ... }

TargeteNB-ToSourceeNB-TransparentContainer ::= SEQUENCE {
    rRC-Container                 RRC-Container,
    iE-Extensions                 OPTIONAL, ... }
```

This repository does not encode those two SEQUENCEs. The S1AP codec carries the
container as an opaque string, which is right at the S1AP layer, and the RRC
codec produces the `rRC-Container` payload — which is one layer inside what a
real MME delivers to a target eNB.

Wireshark demonstrates the gap: wrapping the codec's octets in a real S1AP
Handover Required and dissecting the frame, tshark decodes the container as
`SourceeNB-ToTargeteNB-TransparentContainer`, reads a nonsense
`rRC-Container` from the first length octet, and reports the rest as
`Malformed`. That is the correct dissection of what this repository currently
sends, and it is why the S1AP-container capability stays false.

Closing it is Phase 18-F-B2 work: a 36.413 codec for the two container
SEQUENCEs, which also needs `uE-HistoryInformation` (real UE history) and
`targetCell-ID` from the source, not invented values.

## 6. Validity is not executability

`RrcReadiness` names five separate things: the octets decode
(`RRC_CODEC_VALID`), the configuration is complete
(`RRC_CONFIGURATION_VALID`), the values came from live state
(`RRC_RUNTIME_INPUT_AVAILABLE`), the AS keys exist (`RRC_SECURITY_READY`), and
the UE can execute the reconfiguration (`RRC_UE_EXECUTION_READY`). This phase
delivers the first; the others remain false, and nothing in the codec claims
otherwise.

A valid `newUE-Identity` is not proof that a target allocated it. A decoded
security algorithm configuration is not proof that keys exist. A correct
container is not a handover.

## 7. Tests

`test/lte/rrc_handover.cpp`, eight cases:

* round trips for both messages with every modelled field checked;
* byte-stable re-encoding across sixteen repetitions;
* two pinned vectors, dissected with tshark 4.2.2, decoded and re-encoded;
* the S1AP boundary: the RRC octets survive a real S1AP PDU unchanged, and an
  RRC message is refused by the S1AP decoder and vice versa;
* negative vectors: empty, truncated, trailing octets, oversized, the simulator
  container, the wrong message type, a flipped octet, and out-of-range inputs;
* the semantic check that a valid container does not make a handover executable.

## 8. The container layer around the RRC message (Phase 18-F-B2)

The RRC message is not the transparent container. TS 36.413 defines a SEQUENCE
around it, and `src/lte/enb/transparent_container.{hpp,cpp}` is that SEQUENCE,
encoded and decoded with the same aligned-PER primitives the S1AP message codec
uses (`src/lte/enb/aper_bits.hpp`, extracted from `codec.cpp` so both agree bit
for bit).

### 8.1 Target-to-source

`TargeteNB-ToSourceeNB-TransparentContainer ::= SEQUENCE { rRC-Container,
iE-Extensions OPTIONAL, ... }`. The supported profile carries the mandatory
`rRC-Container` and omits `iE-Extensions`; supplying it is refused rather than
dropped. The container is 2 prefix bits, an octet-aligned length determinant
and the RRC octets — 15 octets around a 13-octet RRC message.

### 8.2 Source-to-target

`SourceeNB-ToTargeteNB-TransparentContainer ::= SEQUENCE { rRC-Container,
e-RABInformationList OPTIONAL, targetCell-ID, subscriberProfileIDforRFP
OPTIONAL, uE-HistoryInformation, iE-Extensions OPTIONAL, ... }`. The supported
profile carries the mandatory fields plus `subscriberProfileIDforRFP`;
`e-RABInformationList` and `iE-Extensions` are refused if supplied.

`targetCell-ID` is an `EUTRAN-CGI` (PLMN plus a 28-bit cell identifier), and
`uE-HistoryInformation` is a `SEQUENCE (SIZE (1..16)) OF LastVisitedCell-Item`
whose e-UTRAN alternative carries `global-Cell-ID`, `cellType` (a `Cell-Size`
enumeration) and `time-UE-StayedInCell` (INTEGER 0..4095).

### 8.3 A defect found in the B1 layer

TS 36.331 V15.6.0 defines `HandoverCommand-r8-IEs.handoverCommandMessage` as
`OCTET STRING (CONTAINING DL-DCCH-Message)`: the octet string holds a
`DL-DCCH-Message` whose `c1` carries the `rrcConnectionReconfiguration`.
Phase 18-F-B1's `EncodeHandoverCommand` stores the bare reconfiguration in that
field.

That codec and its pinned vectors are preserved untouched as historical
evidence. `EncodeHandoverCommandPayload` and `DecodeHandoverCommandPayload`
produce and parse the form the specification states, and the transparent
container carries those octets. The independent dissection in section 8.4 is
what found the difference.

### 8.4 Independent dissection

The two pinned container vectors were dissected with Wireshark's S1AP and LTE
RRC dissectors (tshark 4.2.2):

* source container — `SourceeNB-ToTargeteNB-TransparentContainer`, `rRC-Container`
  carrying a `HandoverPreparationInformation`, `targetCell-ID` cell identity
  `0x0abcde0`, `subscriberProfileIDforRFP` 42, and two `LastVisitedCell-Item:
  e-UTRAN-Cell` entries (`cell-Size: medium`, `time-UE-StayedInCell: 1200s`;
  cell `0x0123456`, `small`, `4095s`);
* target container — `TargeteNB-ToSourceeNB-TransparentContainer`,
  `rRC-Container` carrying a `HandoverCommand`, its `handoverCommandMessage`
  carrying a `DL-DCCH-Message` with `c1: rrcConnectionReconfiguration (4)`,
  whose `mobilityControlInfo` reports `targetPhysCellId: 42`, `t304: ms150`,
  `newUE-Identity: 1234` and the `radioResourceConfigCommon` values.

The innermost structure of the *source* fixture is a 5-octet UE capability
container of fixture data; the dissector reports the `UE-EUTRA-Capability`
inside it as malformed. That is a labelled limitation of the fixture, not of
the container layer.

## 9. AS-Config completeness

`AssessAsConfigCompleteness` names what the AS-Config model covers and what it
does not. `sourceMeasConfig` and `sourceRadioResourceConfig` are encoded as
empty structures (the specification makes every member of both optional), and
the optional members of MIB, SIB1, SIB2 and `RadioResourceConfigCommonSIB` are
omitted. A message can therefore be syntactically valid and still be an
incomplete runtime handover configuration; the assessment is what says so, and
it cannot be made complete by a fixture.

## 10. Decoder resource bounds

The LTE RRC decoder runs with `max_stack_size = 0` because asn1c's stack-depth
heuristic (measured against the codec context's own address) reports an overflow
under sanitizers long before the message is exhausted. What bounds the decoder
instead: the 4096-byte input bound, the fixed nesting of the exposed message
types, and the ASN.1's own `SEQUENCE (SIZE (1..16))` bounds. Truncation at every
prefix length and 2000 repeated decode-and-cleanup passes over corrupted input
are exercised under Release, ASan and UBSan.
