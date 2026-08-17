# PQ-EDHOC in lakers — draft analysis and prototype plan2

Target: `draft-papon-lake-pq-edhoc-00`, "Post-Quantum EDHOC — Initiator and Responder using
signature and/or KEM", Clément Papon & Cristina Onete (XLIM UMR CNRS 7252, Limoges),
1 March 2026, expires 2 September 2026.
<https://datatracker.ietf.org/doc/draft-papon-lake-pq-edhoc/>

**Repo state this document was checked against:** branch `sigstat-statsig` at `b919bb3`,
2026-08-14. Line references are from that commit. Where the previous revision of this document
was wrong about the code, the correction is called out inline (§4.3, §5.3, §5.7, §7) rather
than silently applied.

## Context and goal

lakers implements all five currently-defined EDHOC methods — `EDHOCMethod`
(`shared/src/lib.rs:375`) has `SigSig = 0`, `SigStat = 1`, `StatSig = 2`, `StatStat = 3`,
`PSK = 4` — and as of this branch all five complete an end-to-end handshake in the test
suite (`test_handshake`, `_sigsig`, `_sigstat`, `_statsig`, `_psk`, plus tampered-signature
rejection cases; 73/73 pass under `cargo test -p lakers --features lakers-crypto/rustcrypto`).
This document assesses what it would take to add the post-quantum methods from
draft-papon-lake-pq-edhoc.

**The goal is explicitly not a production implementation.** The draft is at design-sketch
maturity: no CBOR encodings, no test vectors, no method code points, no IANA actions, and
several internal contradictions (see "Spec gaps"). A conforming implementation cannot exist
yet, because there is nothing concrete to conform to.

The goal is instead to **prototype alongside the draft and feed implementation experience
back into it**. That inverts the usual priority order: the deliverable is not a fast, small,
verified state machine, but a working reference that (a) forces every under-specified
detail into the open, (b) produces the first concrete byte encodings and test vectors, and
(c) measures the real message and memory cost on a constrained-device codebase. Each of
those is a contribution the draft currently lacks and cannot easily get any other way.

This reframing changes the engineering constraints substantially — see "Prototype
constraints" — and makes the project tractable, where a production implementation would not
be.

---

## 1. What the draft proposes

Five protocol variants across two families, all replacing Diffie-Hellman with a KEM and
ECDSA/EdDSA with a PQ signature.

### Family A — PQ-EDHOC-IKR (§2)

"Initiator Knows Responder": the Initiator already holds the Responder's static KEM public
key, so it can encapsulate to it in message_1. Builds on `draft-pocero-authkem-ikr-edhoc`.

- **I authenticates with:** signature · **R authenticates with:** KEM

```
 I                                                            R
 |     METHOD, SUITES_I, kem.pk_eph, kem.ct_R, C_I, EAD_1     |
 +------------------------------------------------------------>   message_1
 | kem.ct_eph, Enc(KEYSTREAM_2, C_R, ID_CRED_R, MAC_2, EAD_2) |
 <------------------------------------------------------------+   message_2
 |             AEAD(ID_CRED_I, SIGNATURE_3, EAD_3)            |
 +------------------------------------------------------------>   message_3
 |                         AEAD(EAD_4)                        |
 <- - - - - - - - - - - - - - - - - - - - - - - - - - - - - - +   message_4 (optional)
```

### Family B — KEM & Signature combinations (§3)

Four variants, each the PQ analogue of one RFC 9528 method. Builds on
`draft-pocero-authkem-edhoc`.

| §   | Analogue of   | I auth     | R auth       | msg_4         | Extra wire elements                                |
| --- | ------------- | ---------- | ------------ | ------------- | -------------------------------------------------- |
| 3.2 | method 1      | sign       | KEM + sign   | optional      | `kem.ct_R` in msg_3                                |
| 3.3 | method 2      | KEM + sign | sign         | **mandatory** | `kem.ct_I` in msg_4                                |
| 3.4 | method 3 (v1) | KEM + sign | **KEM only** | **mandatory** | `kem.ct_R` in msg_3, `kem.ct_I` + `MAC_2` in msg_4 |
| 3.5 | method 3 (v2) | KEM + sign | KEM + sign   | **mandatory** | `kem.ct_R` in msg_3, `kem.ct_I` in msg_4           |

```
§3.2  I signs — R KEM & signs
 |            METHOD, SUITES_I, kem.pk_eph, C_I, EAD_1            |
 |kem.ct_eph, Enc(KEYSTREAM_2, C_R, ID_CRED_R, EAD_2, SIGNATURE_2)|
 |          kem.ct_R, AEAD(ID_CRED_I, SIGNATURE_3, EAD_3)         |
 |                          AEAD(EAD_4)                           |   optional

§3.3  I KEM & signs — R signs
 |            METHOD, SUITES_I, kem.pk_eph, C_I, EAD_1            |
 |kem.ct_eph, Enc(KEYSTREAM_2, C_R, ID_CRED_R, EAD_2, SIGNATURE_2)|
 |               AEAD(ID_CRED_I, EAD_3, SIGNATURE_3)              |
 |                      kem.ct_I, AEAD(EAD_4)                     |   MANDATORY

§3.4  both KEM & sign, v1
 |            METHOD, SUITES_I, kem.pk_eph, C_I, EAD_1            |
 |      kem.ct_eph, Enc(KEYSTREAM_2, C_R, ID_CRED_R, EAD_2)       |
 |         kem.ct_R, AEAD(ID_CRED_I, EAD_3, SIGNATURE_3)          |
 |                 kem.ct_I, AEAD(EAD_4, MAC_2)                   |   MANDATORY

§3.5  both KEM & sign, v2
 |            METHOD, SUITES_I, kem.pk_eph, C_I, EAD_1            |
 |kem.ct_eph, Enc(KEYSTREAM_2, C_R, ID_CRED_R, EAD_2, SIGNATURE_2)|
 |         kem.ct_R, AEAD(ID_CRED_I, EAD_3, SIGNATURE_3)          |
 |                      kem.ct_I, AEAD(EAD_4)                     |   MANDATORY
```

The design axis across §3.2–3.5 is _where the cost lands_: §3.2 and §3.5 authenticate the
Responder early (SIGNATURE_2 in message_2, so the Initiator can abort before doing work),
at the price of a 2420-byte signature in message_2. §3.4 removes SIGNATURE_2 entirely and
defers Responder authentication to a MAC_2 carried in message_4 — the smallest message_2 of
the set, but the Initiator commits to the exchange before knowing who it is talking to.

---

## 2. Changes compared with RFC 9528

### 2.1 Cryptographic substitution

| RFC 9528                          | PQ-EDHOC                                 | Note               |
| --------------------------------- | ---------------------------------------- | ------------------ |
| `G_X` (ephemeral DH pubkey, 32 B) | `kem.pk_eph` (ML-KEM-512 ek, 800 B)      | in message_1       |
| `G_Y` (ephemeral DH pubkey, 32 B) | `kem.ct_eph` (ML-KEM-512 ct, 768 B)      | in message_2       |
| `G_XY` (ephemeral-ephemeral ECDH) | `ss_eph` (decapsulated, 32 B)            | IKM for `PRK_2e`   |
| `G_RX` (static R × ephemeral I)   | `ss_R` (encapsulated to `kem.pk_R`)      | IKM for `PRK_3e2m` |
| `G_IY` (static I × ephemeral R)   | `ss_I` (encapsulated to `kem.pk_I`)      | IKM for `PRK_4e3m` |
| ES256 / EdDSA signature (64 B)    | ML-DSA-44 signature (2420 B)             |                    |
| SHA-256                           | SHAKE256 (per `draft-spm-lake-pqsuites`) |                    |
| AES-CCM-16-64-128                 | AES-CCM-16-128-128 or A256GCM            |                    |

The critical structural asymmetry: **DH is non-interactive, a KEM is not.** In RFC 9528 both
peers can compute `G_RX` and `G_IY` as soon as they hold the counterpart's static public key.
With a KEM, the shared secret only exists once one side has _encapsulated and transmitted a
ciphertext_. That single fact drives every remaining difference below.

### 2.2 Message structure

1. **New cleartext wire elements.** `kem.ct_R` (768 B) rides in message_3 and `kem.ct_I`
   (768 B) in message_4, outside the AEAD, prefixing the ciphertext. RFC 9528 message_3 is
   a bare `CIPHERTEXT_3` and message_4 a bare `CIPHERTEXT_4`; both grow a new field.
2. **message_4 becomes mandatory in §3.3, §3.4, §3.5.** In RFC 9528 message*4 is an
   optional key-confirmation. Here it \_carries key material* (`kem.ct_I`), so the handshake
   is genuinely 4-flight. This is the largest state-machine change.
3. **The Responder cannot encapsulate to the Initiator until message_3**, because
   `ID_CRED_I` — and hence `kem.pk_I` — is only revealed there. Hence `kem.ct_I` in
   message_4, and hence `PRK_4e3m` cannot exist before message_4.
4. **IKR carries `kem.ct_R` in message_1** (§2), which is only possible because the
   Initiator knows the Responder's credential a priori.

### 2.3 Key schedule

`TH_2 = H(kem.ct_eph, H(message_1))` replaces `TH_2 = H(G_Y, H(message_1))` — same shape.
`PRK_out`, the exporter and `EDHOC_KDF` label numbering are unchanged. What changes:

| Variant     | `PRK_2e`                | `PRK_3e2m`                 | `PRK_4e3m`                 | `PRK_out` from              |
| ----------- | ----------------------- | -------------------------- | -------------------------- | --------------------------- |
| RFC 9528 m3 | `Extract(TH_2, G_XY)`   | `Extract(SALT_3e2m, G_RX)` | `Extract(SALT_4e3m, G_IY)` | `PRK_4e3m`                  |
| §2 IKR      | `Extract(TH_2, ss_eph)` | `Extract(SALT_3e2m, ss_R)` | — (unused)                 | `PRK_3e2m`                  |
| §3.2        | `Extract(TH_2, ss_eph)` | `Extract(SALT_3e2m, ss_R)` | — (unused)                 | `PRK_3e2m`                  |
| §3.3        | `Extract(TH_2, ss_eph)` | = `PRK_2e` (R only signs)  | `Extract(SALT_4e3m, ss_I)` | `PRK_4e3m`                  |
| §3.4        | `Extract(TH_2, ss_eph)` | `Extract(SALT_3e2m, ss_R)` | `Extract(SALT_4e3m, ss_I)` | `PRK_4e3m`                  |
| §3.5        | `Extract(TH_2, ss_eph)` | `Extract(SALT_3e2m, ss_R)` | `Extract(SALT_4e3m, ss_I)` | `PRK_4e3m` (but see gap G6) |

Two consequences that break the current lakers API shape:

- **`PRK_4e3m` moves from message_3 to message_4.** In RFC 9528 the Initiator derives
  `PRK_4e3m` when preparing message_3 and the Responder when verifying it; `prk_out` is
  available at the end of message_3 on both sides. In §3.3/3.4/3.5, `ss_I` does not exist
  until the Responder encapsulates during message_4 preparation, so **`prk_out` is only
  available after message_4**.
- **In §3.3, `SALT_4e3m` is expanded from `PRK_2e`** (`EDHOC_KDF(PRK_2e, 5, TH_4, …)`),
  not from `PRK_3e2m`. Consistent with RFC 9528's rule that `PRK_3e2m = PRK_2e` when the
  Responder authenticates by signature, but worth noting when writing the code.
- **In §3.4, `MAC_2`'s context changes.** It is
  `EDHOC_KDF(PRK_4e3m, 2, C_R, ID_CRED_R, TH_4, EAD_4, mac_length_2)` — keyed by
  `PRK_4e3m` and bound to `TH_4`/`EAD_4`, where RFC 9528's `MAC_2` is keyed by `PRK_3e2m`
  and bound to `TH_2`/`EAD_2`. It authenticates the Responder retroactively at message_4.

### 2.4 Transcript hashes — a deviation from RFC 9528

Every variant computes:

```
TH_3 = H(TH_2, PLAINTEXT_2, ID_CRED_R)
TH_4 = H(TH_3, PLAINTEXT_3, ID_CRED_I)
```

RFC 9528 §5.4.1 / §5.5.1 use **`CRED_R`** and **`CRED_I`** — the full credentials, not the
identifiers. Binding only `ID_CRED` means the transcript no longer commits to the
credential's actual key material, which is precisely the binding that RFC 9528 relies on to
prevent an identity-misbinding attack when `ID_CRED` is a `kid`. This looks like an error
rather than a deliberate change; it is the single most important thing to raise with the
authors (see gap G4).

Concretely, lakers already does it the RFC way and would have to be _broken_ to follow the
draft: `compute_th_3` takes the credential bytes (`Some(cred_r.bytes.as_slice())`) and
`compute_th_4` takes them through `Th4Input` (`lib/src/edhoc.rs:615`, `:649`; call sites in
`sig.rs:65`, `:139`, `:268` and the `stat.rs` equivalents). That is a useful thing to be able
to tell the authors — the deviation is not a matter of taste, it contradicts working code.

### 2.5 Signature payloads

RFC 9528 signs a COSE `Sig_structure` (`Signature1`) whose payload is `MAC_2`/`MAC_3`, with
`ID_CRED` in the protected header and `<< TH, CRED, ?EAD >>` as external_aad. The draft
does none of this. It uses ad-hoc tuples, and is not self-consistent about them:

| Location             | Signed input                                                           |
| -------------------- | ---------------------------------------------------------------------- |
| §3.2 SIGNATURE_2     | `(PLAINTEXT_2, sign_length)` — signs the plaintext, no MAC             |
| §3.2 SIGNATURE_3     | `(ID_CRED_I, TH_3, EAD_3, MAC_3, sign_length)` — RFC-style, over a MAC |
| §3.3 SIGNATURE_2     | `(C_R, ID_CRED_R, TH_2, EAD_2, MAC_2, sign_length)` — RFC-style        |
| §3.4/3.5 SIGNATURE_3 | `(PLAINTEXT_3, sign_length)` — signs the plaintext, no MAC             |

So within one document, signatures sometimes cover a MAC (RFC 9528's construction) and
sometimes cover a plaintext directly. No COSE structure is specified anywhere, and no
`external_aad`. The draft acknowledges this is provisional: _"the element signed by the
Responder, for security considerations during the security analysis, could be subject to
slight changes. However, it serves here to illustrate the principle proposed here."_

As with G4, lakers has already committed to the RFC 9528 answer here. `encode_sig_structure`
(`lib/src/edhoc.rs:807`) builds the COSE `Signature1` over `ID_CRED`, `TH`, `CRED` and `EAD`
with a hash-length `MAC` (`BytesMacSig` = `MAC_LENGTH_SIG` = 32 B) as payload, and both
`sig.rs` halves sign exactly that. So the prototype gets RFC-conformant signature inputs for
free, and every draft variant that signs a plaintext instead is a deliberate divergence the
prototype would have to add code to reproduce — another argument for reporting G5 before
implementing it.

### 2.6 Message sizes

ML-KEM-512: ek 800 B, ct 768 B, ss 32 B. ML-DSA-44: pk 1312 B, sig 2420 B.

The two RFC 9528 columns are **measured**, not estimated: `test_mixed_methods_are_per_role`
(`lib/src/lib.rs:1265`) drives all four classical methods end to end on suite 2 with
`CredentialTransfer::ByReference` and no EAD, and asserts the message_2/message_3 lengths.

| Message   | RFC 9528 m3 (stat-stat) | RFC 9528 m0 (sig-sig) | §3.5 (both KEM & sign) | §2 IKR           |
| --------- | ----------------------- | --------------------- | ---------------------- | ---------------- |
| message_1 | ~37 B                   | ~37 B                 | ~806 B                 | ~1577 B          |
| message_2 | **45 B** (measured)     | **102 B** (measured)  | ~3220 B                | ~815 B           |
| message_3 | **19 B** (measured)     | **77 B** (measured)   | ~3210 B                | ~2440 B          |
| message_4 | ~11 B (optional)        | ~11 B (optional)      | ~790 B (mandatory)     | ~11 B (optional) |
| **total** | **~112 B**              | **~227 B**            | **~8.0 KB**            | **~4.8 KB**      |

Roughly a **70× increase** over stat-stat, or **35×** over sig-sig — the latter is the fairer
comparison for §3.2–3.5, since it is ECDSA-vs-ML-DSA rather than static-DH-vs-signature. Now
that methods 0–2 work (§4), that column is a real baseline the prototype can be diffed
against rather than a paper estimate.

A `CRED` transferred by value grows from ~107 B to ~2.2 KB (ML-DSA-44 pk 1312 B + ML-KEM-512
ek 800 B for the KEM & sign variants, where a peer needs _two_ long-term public keys under one
`ID_CRED`).

For reference, this is well past a single 6LoWPAN/802.15.4 frame (127 B) and past the
typical CoAP block size; every message would need blockwise transfer or fragmentation. That
observation is itself worth feeding back to the WG — it is the central practical objection
to PQ EDHOC on constrained links, and lakers is a good place to quantify it.

---

## 3. Spec gaps found

These are the concrete items to raise with the authors. Each one currently blocks writing
code, which makes them exactly the feedback a prototype effort is supposed to produce.

| #   | Gap                                                                                                                                                                                                                                                                 | Severity                      |
| --- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ----------------------------- |
| G1  | **No METHOD code points.** "This document has no IANA actions." Five variants, zero assigned method values.                                                                                                                                                         | blocker                       |
| G2  | **No cipher suites.** Deferred to `draft-spm-lake-pqsuites-01`, whose suites are still `TBD1`/`TBD2`.                                                                                                                                                               | blocker                       |
| G3  | **No CBOR encodings and no CDDL.** Nothing says how `kem.pk_eph`, `kem.ct_eph`, `kem.ct_R`, `kem.ct_I` are wrapped, whether message_3/4 become CBOR sequences, or how a two-key credential is represented in a CCS. Zero hex bytes in 2744 lines — no test vectors. | blocker                       |
| G4  | **`TH_3`/`TH_4` bind `ID_CRED_x` instead of `CRED_x`**, contradicting RFC 9528 §5.4.1/§5.5.1 and weakening credential binding (§2.4 above).                                                                                                                         | likely bug, security-relevant |
| G5  | ~~**Signature inputs are inconsistent** between variants~~ — **superseded.** The variation is _forced_ by KEM interactivity, not a defect; what is missing is the explanation and a COSE `Sig_structure`. See [`pq_edhoc_section3.md`](pq_edhoc_section3.md) §3.    | needs text, not a fix         |
| G6  | **§3.5 contradicts itself on `PRK_out`.** §3.5.2.4 says `PRK_out = EDHOC_KDF(PRK_3e2m, 7, TH_4, hash_length)`; the schedule summary in §3.5.3 says `PRK_4e3m`. (Corrected: the conflicting formula is in §3.5.2.4, not §3.5.2.5.)                                   | contradiction                 |
| G7  | **Figures contradict prose on PLAINTEXT_2 field order.** §3.3's figure shows `(…, EAD_2, SIGNATURE_2)`, its prose says `PLAINTEXT_2 = (C_R, ID_CRED_R, SIGNATURE_2, EAD_2)`. RFC 9528 order is `(C_R, ID_CRED_R, Signature_or_MAC_2, ?EAD_2)`, matching the prose.  | contradiction                 |
| G8  | **§3.2 puts `TH_2` inside `PLAINTEXT_2`** (`PLAINTEXT_2 = (C_R, ID_CRED_R, TH_2, EAD_2)`). `TH_2` is already derivable by both peers; this adds 32 encrypted bytes for no evident purpose.                                                                          | probable editorial slip       |
| G9  | **No statement on how a peer advertises two long-term keys** (KEM + signature) under a single `ID_CRED` in §3.2–3.5, nor how `CRED` is formed.                                                                                                                      | blocker for §3.2–3.5          |
| G10 | **No error handling / EDHOC error message treatment** for KEM decapsulation failure (ML-KEM decapsulation is implicit-rejection: it _always_ returns a shared secret, so failure surfaces later as a MAC/AEAD failure — worth specifying explicitly).               | needs text                    |
| G11 | **No downgrade-protection text for SUITES_I** covering the mixed classical/PQ case; §4.3 asserts the property but the PQ suites are not in the existing negotiation table.                                                                                          | needs text                    |

**G4 and G5 have working-code evidence behind them.** Now that lakers implements the
signature methods, `compute_th_3`/`compute_th_4` bind `CRED` (not `ID_CRED`) and
`encode_sig_structure` builds a proper COSE `Signature1` over a MAC — see §2.4 and §2.5. Both
gaps can therefore be reported as "this contradicts a working RFC 9528 implementation", which
is stronger than "this looks wrong", and neither report needs any PQ code to be written first.

**Correction on G5 (2026-08-17).** The claim above that the draft "is not self-consistent"
about signature inputs is wrong, and §2.5's framing goes with it. The signed payload varies
because the _available key material_ varies: a Responder authenticating by KEM cannot key
`MAC_2` with `PRK_3e2m` at message_2, because `ss_R` only exists once the Initiator has
encapsulated and sent `kem.ct_R` in message_3. Every entry in §2.5's table follows from that.
The full argument, and a construction that keeps RFC 9528's COSE framing under the constraint,
are in [`pq_edhoc_section3.md`](pq_edhoc_section3.md) — which supersedes this section for
anything §3-related.

---

## 4. What lakers already has

_Verified against branch `sigstat-statsig` at `b919bb3`; `cargo test -p lakers --features
lakers-crypto/rustcrypto` passes 73/73, including end-to-end handshakes for all five methods._

The existing state machine factoring is genuinely well-shaped for this work — arguably it is
the single biggest asset going in, and it has got _better_ since the first draft of this
document, because the signature-method work forced the per-role composition to become real
rather than aspirational.

### 4.1 The per-authentication-mode split, and what it now looks like

`lib/src/edhoc/` is split by _authentication mode_, not by method: `sig.rs`, `stat.rs` and
`psk.rs`. `sig.rs` and `stat.rs` each expose the same six protocol-step functions suffixed
`_sig` / `_stat` (`r_prepare_message_2_*`, `r_parse_message_3_*`, `r_verify_message_3_*`,
`i_parse_message_2_*`, `i_verify_message_2_*`, `i_prepare_message_3_*`). Methods 0–3 fall out
of _composing_ the two modules per role: SigSig = sig+sig, SigStat = sig+stat, StatSig =
stat+sig, StatStat = stat+stat. Four methods from two files.

That much was already true. What is new, and what matters for PQ, is the machinery that makes
the composition work:

- **Uniform intermediate structs.** The per-mode functions no longer build state structs
  themselves; they return small mode-agnostic records defined at the top of
  `lib/src/edhoc.rs:20-66` — `PreparedMessage2`, `DecodedMessage2`, `VerifiedPeerMessage2`,
  `ParsedMessage3`, `VerifiedMessage3`, `PreparedMessage3`. `edhoc.rs` owns everything shared
  (ciphertext_2 XOR, message encoding, `PRK_out`/`PRK_exporter` derivation) and the modules
  own only the authentication. **A `kem.rs` would implement against these same six return
  types**, which is a far more concrete contract than "follow the pattern".
- **`*MethodSpecifics` enums carry the per-role choice through the state.**
  `WaitM3MethodSpecifics`, `ProcessingM2MethodSpecifics`, `ProcessedM2MethodSpecifics` and
  `ProcessingM3MethodSpecifics` (`shared/src/lib.rs:525-615`) each have `Signature` /
  `StaticDh` / `Psk` variants. These are the actual extension points: PQ adds `Kem` (and, for
  §3.2–3.5, a combined `KemSig`) variants to those four enums, and the dispatch sites in
  `edhoc.rs` pick them up.
- **Dispatch is genuinely per-role, on two independent axes.** `i_verify_message_2`
  (`lib/src/edhoc.rs:419-472`) is the clearest example: it was split so that the
  _responder_-authentication half dispatches on `state.method_specifics` (what arrived in
  message*2) while the \_initiator*-authentication half dispatches on the caller-supplied
  `InitiatorIdentity` (what I will do in message_3), and `PRK_4e3m` is derived in the second
  half. The two axes are resolved one after the other, not as a single per-method match.
  `test_mixed_methods_are_per_role` (`lib/src/lib.rs:1265`) pins this behaviourally: it
  asserts message_2 grows exactly when the responder signs and message_3 exactly when the
  initiator signs.
- **Identity is a typed, checked input.** `ResponderIdentity` and `InitiatorIdentity`
  (`lib/src/lib.rs:111-122`) have `Signature { .. }` / `StaticDh { .. }` / `Psk` variants;
  `PrepareMessage2Details` (`shared/src/lib.rs:540`) is the responder-side equivalent passed
  into `r_prepare_message_2`; and `check_initiator_identity` (`lib/src/lib.rs:126`) rejects an
  identity whose auth mode disagrees with the method announced in message_1. `EDHOCError`
  gained `MissingIdentity` and `IdentityAlreadySet` for this.

**This is exactly the right shape for PQ.** The draft introduces a third authentication mode —
KEM — so the extension is a third sibling module, `kem.rs`, with the same six functions
suffixed `_kem`, plus `Kem` variants in the four `*MethodSpecifics` enums and in the two
identity enums. The composition then covers the draft's variants directly: §2 IKR = sig (I) +
kem (R); §3.2 = sig (I) + kem&sig (R); §3.3 = kem&sig (I) + sig (R); §3.4/3.5 = kem&sig on
both sides. The "KEM & sign" combination is `kem.rs` and `sig.rs` composed within one role
rather than a fourth module — and the `i_verify_message_2` split shows that composing two
modes within one message is already something the code does.

### 4.2 Other assets

- **The whole EDHOC skeleton is preserved by the draft**: the `PRK_2e → PRK_3e2m →
PRK_4e3m` ladder, the `TH_2/3/4` chain, KEYSTREAM*2 XOR for message_2, AEAD for
  message_3, `PRK_out` and the exporter. No new \_shapes*, only new IKM sources and sizes.
- **`hkdf_extract(&BytesP256ElemLen)` happens to fit.** ML-KEM's shared secret is 32 bytes,
  the same as a P-256 element, so this trait method survives unchanged.
- **message_4 plumbing exists** (`r_prepare_message_4`, `i_process_message_4`,
  `*_complete_without_message_4`).
- **Signature machinery exists and works** from the signature-method work: `SignatureOrMac`,
  `encode_sig_structure`, const-generic `compute_mac_2::<N>` / `compute_mac_3::<N>`, and
  const-generic plaintext decoders `decode_plaintext_2_sized::<N>` /
  `decode_plaintext_3_sized::<N>` (`shared/src/lib.rs:1191`, `:1257`) instantiated at
  `SIGNATURE_LENGTH` for sig and `MAC_LENGTH_2`/`MAC_LENGTH_3` for stat. **The length is
  already a type parameter**, so ML-DSA mostly needs new constants plus a wider
  `BytesSignature`, not new decode paths.

### 4.3 Correction: the `Crypto` trait has no default-`Err` precedent

An earlier version of this document claimed the trait had "an established precedent for adding
methods with default `Err` bodies so PSA and CryptoCell310 keep compiling". **That is not what
the ECDSA work did.** `p256_ecdsa_sign` and `p256_ecdsa_verify` (`shared/src/crypto.rs:87`,
`:93`) are _required_ methods with no default body, and all three backends implement them for
real — `lakers-crypto-rustcrypto:198`, `lakers-crypto-psa:448`,
`lakers-crypto-cryptocell310-sys:312` — with shared conformance helpers
(`test_ecdsa_roundtrip`, `test_ecdsa_is_deterministic`, `test_ecdsa_rejects_bad_signature`,
`shared/src/crypto.rs:262-296`) that each backend's test suite calls.

The precedent is therefore **required method + three implementations + shared test helpers**,
which is a materially larger commitment than the plan assumed. For PQ this means Phase 1's KEM
methods must either introduce default `Err` bodies as a _new_ convention (defensible: neither
PSA's nor CryptoCell310's underlying libraries offer ML-KEM or ML-DSA at all) or ship stub
implementations in all three backends. Introducing default bodies is the right call for the
prototype, but it should be a stated deviation rather than an assumed one — and it is worth
raising with upstream, since a trait with mixed required and optional methods is a design
choice for the whole project, not just for PQ.

## 5. What lakers is missing

### 5.1 Crypto primitives

- No KEM in the `Crypto` trait at all: needs `kem_keygen`, `kem_encapsulate`,
  `kem_decapsulate`.
- No ML-DSA: needs `mldsa_sign` / `mldsa_verify`. `SIGNATURE_LENGTH = 64` is hardcoded to an
  ES256 shape (`shared/src/lib.rs:67`), and `BytesSignature = [u8; SIGNATURE_LENGTH]`
  (`:176`). The trait's ECDSA methods are typed on `BytesSignature` directly, so a wider
  signature type is an API-visible change across all three backends.
- **No hash agility.** `draft-spm-lake-pqsuites` selects SHAKE256, but the trait hardcodes
  SHA-256 — `sha256_digest`, `sha256_start`, and a `HashInProcess` bound of
  `OutputSizeUser<OutputSize = U32>`. Note `MAC_LENGTH_SIG = SHA256_DIGEST_LEN` and
  `BytesMacSig` are also tied to it.
- Backends: RustCrypto has `ml-kem` and `ml-dsa` crates (both pre-1.0, RustCrypto-audited
  ML-KEM as of 2024). PSA and CryptoCell310 have nothing usable.

### 5.2 Buffers — the hard part

`MAX_MESSAGE_SIZE_LEN` defaults to **192** and tops out at **1024** even with the
`max_message_size_len_1024` feature (`shared/src/lib.rs:36-51`). PQ messages need ~3.3 KB.
Same story for `MAX_BUFFER_LEN` (320 default, 1024 max, `:90-100`), which `edhoc_kdf` expands
into and which must hold a ~2.5 KB `KEYSTREAM_2`. `MAX_KDF_CONTEXT_LEN` (256/1024, `:74-86`)
and `MAX_EAD_LEN` (`:132`) are tiered the same way, and `MAX_INFO_LEN` is derived from them.
The `large_buffers` feature (`shared/Cargo.toml`, re-exported by `lib/Cargo.toml`) is the
umbrella that turns every tier up to 1024 at once — a PQ tier means adding a `_4096` step to
each ladder and a new umbrella, not one constant.

`EdhocBuffer<N>` is a by-value `[u8; N]` (`shared/src/buffer.rs:60-62`) and state structs
are copied around; the type's own doc comment already flags "excessive stack usage". At
4 KB buffers with several live simultaneously this is tens of KB of stack.

There is also a verification cost to growing these, which the earlier version of this document
missed: hax cannot express `EdhocBuffer<N>`'s `len <= N` invariant as a type refinement
(blocked on hax issue #899), so **every caller of `as_slice()` carries a manually propagated
`#[hax_lib::requires(...)]` annotation**. See `hax_bugs.md`. New buffers and new call sites in
PQ code inherit that obligation.

### 5.3 A family of one-byte CBOR length bugs, two fixed and two not

`encode_message_2` (`lib/src/edhoc.rs:583-594`) hardcodes `CBOR_BYTE_STRING` (0x58, one-byte
length) and computes the length as `P256_ELEM_LEN as u8 + ciphertext_2.len() as u8`. That
`as u8` **wraps silently** above 255 bytes and emits a corrupt message rather than failing.
Every PQ message_2 trips it.

`encrypt_message_3` (`lib/src/edhoc.rs:910-930`) has the same defect — `bytestring_length as _`
into a one-byte header, with an in-place FIXME saying so — plus an `assert!` on
`MAX_MESSAGE_SIZE_LEN` that **panics** rather than returning `EncodingError`. Every PQ
message_3 trips both.

This is now a recognised family rather than an isolated wart. Two siblings were found and
fixed on this branch, and are written up in the repo:

| Sibling                                                 | Location               | Status                                  |
| ------------------------------------------------------- | ---------------------- | --------------------------------------- |
| `encode_info` truncates context length ≥ 256 B          | `shared/src/lib.rs`    | **fixed** — see `encode_info_bug.md`    |
| `EADItem::new_full` head byte + `CBORDecoder::as_usize` | `shared/src/lib.rs`    | **fixed** — see `ead_long_value_bug.md` |
| `encode_message_2` bstr header                          | `lib/src/edhoc.rs:583` | open                                    |
| `encrypt_message_3` bstr header + `assert!`             | `lib/src/edhoc.rs:910` | open                                    |

The fix pattern is established: `encode_bstr_header` (`lib/src/edhoc.rs:850`) already handles
the 23 / one-byte / two-byte cases and returns `EncodingError` past `u16::MAX`, and
`CBOR_BYTE_STRING_2BYTE_LEN` exists in `shared`. The two open cases should reuse it. Both are
real bugs today, reachable via `large_buffers`; PQ makes them unavoidable.

### 5.4 Credentials

- `CredentialKey` (`shared/src/cred.rs:11`) is `#[repr(C)]` with `Symmetric(BytesKeyAES128)`
  and `EC2Compact(BytesKeyEC2)`, and is mirrored in `lakers-c`; PQ needs new variants for KEM
  and ML-DSA keys. The PSK work adding `Symmetric` is the precedent, and both `sig.rs` and
  `stat.rs` already return `UnsupportedMethod` on a non-`EC2Compact` key rather than panicking
  (with FIXMEs noting the error is inaccurate), so the match arms fail safe.
- §3.2–3.5 need **two** long-term public keys under one `ID_CRED`, which the current
  one-key `CredentialKey` cannot express at all (and which the draft does not specify — G9).
- `CredentialTransfer::ByValue` with a 1312-byte pk is out of reach of the current buffers.

### 5.5 State machine

- **`prk_out` timing.** `i_prepare_message_3` (`lib/src/edhoc.rs:474-509`) and
  `r_verify_message_3` (`:292-336`) both derive `PRK_out` _and_ `PRK_exporter` from
  `PRK_4e3m` at message_3 and return `prk_out` as an extra tuple element; `WaitM4` and
  `ProcessedM3` then carry both forward. For §3.3/3.4/3.5 that is impossible — `PRK_4e3m`
  needs `ss_I`, which arrives in message_4. This is an API-visible change, not an internal
  one, and it also reaches the typestate wrappers (`EdhocInitiatorWaitM4`,
  `EdhocResponderProcessedM3`) and both binding crates.
- **message_4 gains a cleartext prefix** (`kem.ct_I`); today it is AEAD-only.
- **Responder authentication completes at message_4** in §3.4 (deferred `MAC_2`), so the
  "Completed" state must distinguish "authenticated" from "key established".
- **§2 IKR needs the Initiator to hold R's credential before message_1**, a new
  precondition with no current equivalent.

### 5.6 Suite negotiation

`EDHOC_SUITES` is a fixed 9-entry list with no PQ entries and `EDHOC_SUPPORTED_SUITES = [0x2]`
(`shared/src/lib.rs:165-166`); the `EDHOCSuite` enum (`:405`) has exactly one variant,
`CipherSuite2 = 2`, with a comment inviting more; and `prepare_suites_i`
(`shared/src/crypto.rs:10-23`) still carries its "for now, we only support a single suite"
TODO. Nothing here changed with the signature methods — all four classical methods share
suite 2 — so PQ is still the first thing that will force real negotiation.

### 5.7 Formal verification — wider scope than assumed

An earlier version of this document said "the hax/F\* job covers `shared/`". **It covers
`lib/` too.** `.github/workflows/build-and-test.yml` runs two extractions:

```
cargo-hax -C -p lakers --no-default-features --features='lakers-crypto/rustcrypto' --release \;
          into -i '-lakers::generate_connection_identifier_cbor -lakers::generate_connection_identifier' fstar
cargo-hax -C -p lakers-shared \; into -i '-lakers_shared::ffi::**' fstar
```

then fails the job if any generated `.fst` contains "something is not implemented yet", and
separately typechecks only `Lakers_shared.Buffer.fst` under F\*. The job pins hax to commit
`87ba96831ecfeb7dbb54efcf97036fbc5f25bc71` and F\* to `v2025.10.06`, and rewrites `hax-lib` in
the root `Cargo.toml` from the crates.io dependency to the (unpinned) cryspen git one via
`sed`.

The consequence for the plan: **a new `lib/src/edhoc/kem.rs` lands inside the extraction scope
by default**, so "keep PQ code out of `shared/`'s verified paths" is not a sufficient
mitigation. The options are to exclude the PQ module explicitly with `-i '-lakers::kem::**'`,
to feature-gate it out of the extraction build, or to accept extraction and the
not-implemented-yet gate. This needs deciding before Phase 3, not after — it is cheap up front
and expensive once the module exists.

hax has also been productively run against `shared/` already and found real bugs (`i8()`
two-byte negative decoding, several latent panics, an `i32::MIN` overflow in EAD label
parsing) plus documented limitations; see `hax_bugs.md`.

---

## 6. Crypto library selection

Every variant in the draft needs **both** a KEM and a signature, so the two are chosen
together rather than separately.

### 6.1 Candidates

| Crate                                                                 | Latest            | Type               | `no_std`                               | `alloc`-free                                              | Formally verified                  | Signature companion        |
| --------------------------------------------------------------------- | ----------------- | ------------------ | -------------------------------------- | --------------------------------------------------------- | ---------------------------------- | -------------------------- |
| [`libcrux-ml-kem`](https://crates.io/crates/libcrux-ml-kem) (Cryspen) | 0.0.10 (Jul 2026) | pure Rust          | yes (`default-no-std`)                 | unverified — spike item                                   | **yes — hax + F\***                | `libcrux-ml-dsa` 0.0.10    |
| [`ml-kem`](https://crates.io/crates/ml-kem) (RustCrypto)              | 0.3.2 (May 2026)  | pure Rust          | yes                                    | **`alloc` is a default feature**; disableable, unverified | no                                 | `ml-dsa` 0.1.1 (MSRV 1.85) |
| [`pqcrypto-mlkem`](https://lib.rs/crates/pqcrypto-mlkem) (rustpq)     | —                 | PQClean C bindings | tagged no-std, but needs `libc` + `cc` | no                                                        | no                                 | yes, same family           |
| [`aws-lc-rs`](https://crates.io/crates/aws-lc-rs)                     | —                 | AWS-LC C bindings  | **no** (std + CMake)                   | no                                                        | FIPS-validated, not proof-verified | yes                        |
| `oqs` / liboqs-rust                                                   | —                 | liboqs C bindings  | **no**                                 | no                                                        | no                                 | yes                        |
| [`kyberlib`](https://github.com/sebastienrousseau/kyberlib)           | —                 | pure Rust          | yes                                    | unverified                                                | no (ACVP test vectors only)        | **none**                   |

Note that lakers declares `categories = ["no-std::no-alloc"]` — the bar is _no-alloc_, not
merely `no_std`, which is stricter than most of these crates document.

The bottom three are ruled out immediately: two are C-binding stacks that cannot serve a
bare-metal `thumbv7em-none-eabihf` target without a cross C toolchain (and liboqs upstream
still advises against production use), and `kyberlib` has no ML-DSA companion at all, which
is disqualifying when every draft variant needs a signature too.

### 6.2 Decision: `libcrux-ml-kem` + `libcrux-ml-dsa`

The deciding factor is in the dependency list: **`libcrux-ml-kem` depends on
`hax-lib ^0.3.7`** — the same crate already in the lakers workspace (`hax-lib = "0.3.1"`) —
and lakers CI already installs hax and F\* via `hacspec/hax-actions@main`
(`.github/workflows/build-and-test.yml:97-107`). libcrux and hax are both Cryspen. This is
the existing ecosystem, not a new one.

Rationale:

1. **It protects what makes lakers distinctive.** The project's differentiator is that parts
   of it are formally verified. Placing an _unverified_ lattice implementation at the core
   of a verified handshake would hollow that out. libcrux's README: _"The portable and AVX2
   code for field arithmetic, NTT polynomial arithmetic, serialization, and the generic code
   for high-level algorithms is formally verified using hax and F\*."_
2. **One vendor for both primitives, released in lockstep** — `libcrux-ml-kem` and
   `libcrux-ml-dsa` are both 0.0.10, same release date. RustCrypto's equivalents live in two
   repositories on independent version tracks (`RustCrypto/KEMs`, `RustCrypto/signatures`).
3. **`no_std` is supported** via `default-no-std`, so the eventual embedded path is not
   foreclosed by a prototype-stage decision.
4. **Cryspen is active in the same IETF space**, which has some value given the goal is
   feeding results back to LAKE.

### 6.3 Spike results (2026-08-13, branch `sigstat-statsig`)

A throwaway spike added `libcrux-ml-kem = { version = "0.0.10", default-features = false,
features = ["mlkem512"] }` to `lakers-crypto-rustcrypto` and was reverted afterwards.
**Every open question resolved favourably.**

| Question                                              | Result                                                                                                                                                                                                         |
| ----------------------------------------------------- | -------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| Does `hax-lib` resolve to one version?                | **Yes** — single `hax-lib v0.3.7`, shared by `lakers-shared` and the whole libcrux tree. lakers' `^0.3.1` and libcrux's `^0.3.7` unify cleanly.                                                                |
| Does it build on the pinned toolchain?                | **Yes** — `rustc 1.89.0-nightly (dcecb9917 2025-05-09)` compiles libcrux-ml-kem 0.0.10 (a July 2026 release) without complaint.                                                                                |
| Does the CI `sed` hax-lib rewrite break it?           | **Compiles fine, but see below.**                                                                                                                                                                              |
| Does it work `no_std` / bare-metal?                   | **Yes** — `cargo build -p lakers-crypto-rustcrypto --target thumbv7em-none-eabihf` succeeds and emits a `libcrux_ml_kem` rlib for Cortex-M4F. This is the strongest available evidence for the `no_std` claim. |
| Dependency footprint with `default-features = false`? | Only libcrux's own sub-crates (`-intrinsics`, `-platform`, `-secrets`, `-sha3`, `-traits`) plus `hax-lib`. No `tls_codec`.                                                                                     |
| Are the ML-KEM-512 sizes as assumed in §2.6?          | **Confirmed by execution**: `ek=800 ct=768 ss=32`, encapsulate/decapsulate round-trip agrees.                                                                                                                  |

Two caveats found:

1. **The CI rewrite does produce two `hax-lib` copies** — one v0.3.7 from crates.io (libcrux's
   transitive dependency) and one from `git+https://github.com/cryspen/hax` (lakers', after
   the `sed`). Both compile and coexist; `cargo build` and `cargo check` pass. This is benign
   for normal builds because hax-lib's annotations erase to nothing, and the hax job never
   extracts libcrux itself. **It has not been verified against an actual `cargo-hax`
   extraction run**, which is the one place a duplicate could still bite. Worth confirming
   before Phase 3.

   Note the git dependency in `Cargo.toml:56` carries **no `rev`**, so it floats to hax
   `main`; the version actually used in CI is pinned separately by the action's
   `hax_reference` (currently `87ba96831ecfeb7dbb54efcf97036fbc5f25bc71`). Those two can drift
   apart. And per §5.7 the extraction covers `-p lakers` as well, so a PQ module in `lib/`
   raises the stakes on this caveat rather than sidestepping it.

2. **`libcrux-traits` pulls `rand v0.10.2` / `rand_core v0.10.1`**, giving the workspace two
   `rand_core` majors (lakers already uses 0.6.4). It compiled for bare metal regardless, so
   this is untidy rather than blocking.

**Conclusion: the §6.2 decision stands, and open question 5 is answered.** The primary risk
that could have invalidated it did not materialise.

### 6.4 Risks

- **0.0.x with rapid churn** — 0.0.7 (Feb 2026), 0.0.8 (Mar), 0.0.9 (May), 0.0.10 (Jul).
  Expect breaking API changes. Pin exactly (`=0.0.10`), as libcrux does for its own internal
  dependencies.
- ~~**hax-lib version tension.**~~ **Resolved by the spike** (§6.3): resolves to a single
  `hax-lib v0.3.7` normally, and to two coexisting-but-compiling copies under the CI git
  rewrite. Residual: not yet validated against a real `cargo-hax` extraction run.
- **Verification coverage is partial** — portable and AVX2 arithmetic, not Neon, and not
  every layer.
- **Stack usage is unmeasured.** ML-KEM is stack-hungry; on an embedded target this may
  dominate. The spike confirmed it _compiles_ for Cortex-M4F but ran nothing on-target.
- **`alloc`-freedom is still not proven.** The bare-metal build produces an rlib, and the
  `alloc` crate is present in the thumb sysroot, so a successful compile demonstrates
  `no_std` but not no-alloc. Linking an actual bare-metal binary without a global allocator
  is the real test — do that before relying on it for the embedded path.
- **Toolchain pin is branch-dependent.** This branch (`sigstat-statsig`) carries
  `nightly-2025-05-10`, but the embedded-cal work moves `rust-toolchain` to stable 1.96.1.
  libcrux's portable path builds on stable; its `simd128`/`simd256` features may not. Not a
  concern for the prototype (portable only, host-side), but worth knowing before any
  performance work.
- **`alloc` status unverified** for both libcrux and RustCrypto — resolve before committing.

**Fallback:** `ml-kem` 0.3.2 + `ml-dsa` 0.1.1 if the hax-lib integration proves intractable.
They are more mature by version number and download count (4.4M vs 2.3M), and match the
existing `p256`/`sha2`/`aes`/`ccm`/`hkdf` RustCrypto dependencies in
`lakers-crypto-rustcrypto`.

**This decision is cheap to reverse.** It sits behind the `Crypto` trait seam (Phase 1
below), so swapping backends later is a contained change — which is itself an argument
against over-deliberating it now.

---

## 7. Prototype constraints

Because the goal is draft co-evolution rather than shipping, the following are deliberate
non-goals. Stating them up front is what makes the work feasible.

| Dimension           | Production would need           | Prototype does                                                                                             |
| ------------------- | ------------------------------- | ---------------------------------------------------------------------------------------------------------- |
| Targets             | `no_std`, no-alloc, embedded    | **host-only, `std` + `alloc` allowed**                                                                     |
| Buffers             | fixed-size const-generic arrays | `heapless::Vec` with large caps, or `Vec` behind a feature                                                 |
| Backends            | PSA, CryptoCell310, RustCrypto  | **RustCrypto only** (+ libcrux for PQ, §6); others get default `Err` bodies — a _new_ convention, see §4.3 |
| Bindings            | `lakers-c`, `lakers-python`     | **untouched** — but see the caveat below                                                                   |
| Formal verification | hax/F\* extraction              | **out of scope**, but must be _actively_ excluded — the job extracts `-p lakers`, see §5.7                 |
| Wire stability      | IANA code points                | **private-use / locally-chosen values, clearly marked TBD in code**                                        |
| Interop             | conformance to test vectors     | **self-consistency + our own generated vectors**                                                           |

Everything above is feature-gated so the default build, the embedded examples and the
existing hax job are unaffected. The prototype is additive.

**Caveat on the bindings row.** The claim that they "already have `_ => Err(UnsupportedMethod)`
arms" no longer holds. The signature-method work left `todo!()` — i.e. a panic — on the
`Signature` variants at six sites: `lakers-c/src/lib.rs:232`, `:371`,
`lakers-c/src/initiator.rs:185`, `lakers-python/src/initiator.rs:123`,
`lakers-python/src/responder.rs:55`, and a further TODO at `responder.rs:185`. Adding `Kem`
variants to the `*MethodSpecifics` enums will make those matches non-exhaustive and force the
bindings to be touched — which is the good outcome, because it is a compile error rather than
a silent gap. But "untouched" now means "will need new arms added, ideally `Err`, not
`todo!()`", and the existing `todo!()`s are worth converting while there.

---

## 8. Proposed plan

Ordered so that the early steps are independently valuable to lakers even if the draft
stalls or changes direction.

### Phase 0 — prerequisites that stand on their own

1. **Fix the two open bstr-header bugs** (§5.3): `encode_message_2` and `encrypt_message_3`.
   Reuse `encode_bstr_header`; make oversize an `EncodingError` rather than a silent wrap, and
   turn `encrypt_message_3`'s `assert!` into a returned error. These are real bugs today,
   independent of PQ, and two siblings in the same family are already fixed on this branch —
   so this is finishing a sweep rather than starting one.
2. **Add a `max_message_size_len_4096` tier** (and matching `max_buffer_len`,
   `max_kdf_content_len`, `max_ead_len`, plus an umbrella feature alongside `large_buffers`)
   plus a feature-gated allocating buffer backend. Address the by-value/stack story at least
   well enough that host tests do not blow the stack. Check what this does to the hax
   `requires` annotations on `EdhocBuffer` (§5.2) before going wide.

### Phase 1 — algorithm agility in the `Crypto` trait

3. **Generalize the hash**: replace the hardcoded SHA-256 methods and the `U32` output
   bound with an associated-type hash, so SHAKE256 becomes expressible.
4. **Add a KEM abstraction** (`kem_keygen` / `kem_encapsulate` / `kem_decapsulate`) with
   associated size constants, plus `mldsa_sign` / `mldsa_verify`. Default `Err` bodies —
   noting per §4.3 that this _introduces_ the convention rather than following one, and should
   be flagged as such in review. Implement in the RustCrypto backend over `libcrux-ml-kem` /
   `libcrux-ml-dsa` (see §6). The dependency spike is **done** (§6.3) — resolution, toolchain
   and bare-metal builds all pass, so this can proceed directly. Add conformance helpers in
   `shared/src/crypto.rs` next to `test_ecdsa_*`, since that is the pattern the ECDSA work set.
5. **Make `SIGNATURE_LENGTH` suite-derived** rather than a global `64` (`shared/src/lib.rs:67`).
   A known wart while suite 2 was the only suite; PQ forces the issue, since ML-DSA-44
   signatures are 2420 bytes. The plaintext decoders and MAC helpers are already const-generic
   over the length (§4.2), so the work is concentrated in `BytesSignature`, the `Crypto` trait
   signatures and the three backends — not in the state machine.

### Phase 2 — credentials and suites

6. **Add `CredentialKey` variants** for KEM and ML-DSA keys, plus a two-key credential
   form for §3.2–3.5. **This requires inventing an encoding — write it up and send it to
   the authors as proposed text for G9.**
7. **Add provisional PQ suite entries** behind a feature, clearly marked as locally-chosen
   pending G2.

### Phase 3 — first method

8. **Add `lib/src/edhoc/kem.rs`** as a third sibling to `sig.rs` / `stat.rs`, exposing the
   same six protocol-step functions suffixed `_kem` and returning the same six intermediate
   structs (see §4.1). This is the core of the work, and it deliberately follows the existing
   per-authentication-mode factoring rather than introducing a per-variant module. In the same
   step, add `Kem` variants to the four `*MethodSpecifics` enums and to `ResponderIdentity` /
   `InitiatorIdentity` / `PrepareMessage2Details`, and extend `check_initiator_identity`. Decide
   the hax exclusion (§5.7) before writing the module, not after.
9. **Implement §3.5 first** (both KEM & sign, v2). Rationale: it exercises the full
   three-stage `PRK` ladder, both new cleartext elements (`kem.ct_R`, `kem.ct_I`), the
   mandatory message*4 and the `prk_out`-timing change — i.e. it is the \_maximal* variant,
   so everything else becomes a subset. §2 IKR is the easiest but exercises the least.
   Because §3.5 is "KEM & sign" on both sides, it also proves out the `kem.rs` + `sig.rs`
   composition, which is the part of the design most likely to need rework.
10. **Extend the state machine** for deferred `prk_out` and the message_4 cleartext prefix.
11. **Write down the CBOR encodings we chose** as we go, and emit test vectors from the
    working implementation. **This is the primary deliverable to the WG** — it directly
    fills G3.

### Phase 4 — feedback

12. **Send the G1–G11 list to the authors** (Papon & Onete). G4 and G6 in particular should
    go early — they do not need any implementation to be worth reporting, and G4 is
    security-relevant.
13. **Publish the size and stack measurements** from §2.6 against real code, as input to
    the LAKE discussion on PQ feasibility on constrained links.
14. **Implement a second variant** (§3.4, to exercise deferred `MAC_2` authentication) once
    the first is stable.

---

## 9. Related drafts

The papon draft builds on, and should be read alongside:

- [`draft-pocero-authkem-edhoc-02`](https://datatracker.ietf.org/doc/html/draft-pocero-authkem-edhoc-02)
  — KEM-based authentication for EDHOC. The base this extends.
- [`draft-pocero-authkem-ikr-edhoc-02`](https://datatracker.ietf.org/doc/html/draft-pocero-authkem-ikr-edhoc-02)
  — the IKR scenario that §2 extends.
- [`draft-pocero-lake-authkemsig-edhoc-01`](https://datatracker.ietf.org/doc/draft-pocero-lake-authkemsig-edhoc/)
  — KEM/signature combined methods; overlaps §3 substantially and appears to be further
  along the WG process.
- [`draft-spm-lake-pqsuites-01`](https://datatracker.ietf.org/doc/draft-spm-lake-pqsuites/)
  (Selander & Mattsson) — the PQ cipher suites, a hard prerequisite for any of this.

**Worth deciding early:** the pocero drafts cover much of the same ground and are closer to
the LAKE working group process. If the aim is maximum influence on what ends up
standardized, it may be more effective to prototype against
`draft-pocero-lake-authkemsig-edhoc` and treat the papon draft as the source of the
message-count optimizations. Alternatively, prototype the shared substrate (Phases 0–2,
which are identical for all of them) and defer the choice of method to Phase 3.

---

## Open questions

1. Prototype against papon or pocero (see §8)? The Phase 0–2 work is common to both, so
   this decision can be deferred.
2. Is contact with the authors already established, or should the G1–G11 report go via the
   LAKE mailing list?
3. Do we want the allocating buffer backend to become a permanent lakers feature, or a
   prototype-only shim? It affects how much care Phase 0 step 2 deserves.
4. ML-KEM-512/ML-DSA-44 (the pqsuites choice, NIST level 1/2) only, or also parameterize
   for level 3 to measure the ceiling?
5. ~~Does the libcrux dependency survive the CI hax-lib rewrite?~~ **Answered** — yes, see
   §6.3. Remaining sub-question: does a real `cargo-hax` extraction run tolerate the two
   coexisting `hax-lib` copies? This got sharper now that §5.7 establishes the job also
   extracts `-p lakers`.
6. **How should PQ code relate to the hax job** — explicit `-i` exclusion, feature gate, or
   accept extraction? See §5.7. Needs answering before Phase 3 step 8.
7. The pre-existing open issues that `sigsig.md` used to track are **partly resolved**:
   - _Error modelling / `UnsupportedMethod` overloading_ — improved but not finished.
     `EDHOCError` gained `MissingIdentity` and `IdentityAlreadySet`, and there are now
     in-place `FIXME`s at ~10 sites (`lib/src/lib.rs:134`, `:193`, `lib/src/edhoc.rs:445`,
     `:462`, and three each in `sig.rs` / `stat.rs`) asking for a distinct
     `MethodIdentityMismatch` and noting that a credential-key/method mismatch is a lack of
     agreement between peers rather than an error. PQ adds more such arms, so this is worth
     fixing before, not after.
   - _Discarded y-coordinate in `CredentialKey::EC2Compact`_ — unchanged; still visible as the
     `// discard sign byte` truncation in the CryptoCell310 backend.
   - _Error modelling for a bad signing key_ — `p256_ecdsa_sign` returns
     `Result<_, EDHOCError>`, so the shape exists; whether the error is meaningful is
     backend-dependent.
