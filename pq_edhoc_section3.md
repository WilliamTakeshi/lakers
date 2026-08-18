# draft-papon-lake-pq-edhoc §3 — divergences, contradictions, and proposed text

**Target:** `draft-papon-lake-pq-edhoc-00`, §3 ("KEM & Signature combinations"), Clément Papon
& Cristina Onete, 1 March 2026.
<https://www.ietf.org/archive/id/draft-papon-lake-pq-edhoc-00.txt>

**Purpose.** This document is the specification-side deliverable of the lakers PQ-EDHOC
prototype. It records, per §3 variant, exactly what the draft says; identifies where the draft
is contradictory, under-specified, or in conflict with RFC 9528; and states the resolution the
lakers prototype implements together with the reasoning. Every claim about the draft below was
read out of the -00 text; every claim about RFC 9528 behaviour is backed by working code in
this repository, cited by file and line.

It is meant to be usable as feedback to the authors and to the LAKE WG. See
[`pq_edhoc.md`](pq_edhoc.md) for the wider implementation assessment and
[`learning_kem_edhoc.md`](learning_kem_edhoc.md) for the background reasoning.

---

## 1. The four variants at a glance

All four replace ephemeral ECDH with an ephemeral KEM. The Initiator sends `kem.pk_eph` in
message_1, the Responder encapsulates to it and returns `kem.ct_eph` in message_2, and

```
TH_2   = H(kem.ct_eph, H(message_1))
PRK_2e = EDHOC_Extract(TH_2, ss_eph)
```

They differ only in how each role authenticates its _static_ identity:

| §   | I authenticates with | R authenticates with | message_4     | Extra cleartext elements           |
| --- | -------------------- | -------------------- | ------------- | ---------------------------------- |
| 3.2 | signature            | KEM + signature      | optional      | `kem.ct_R` in message_3            |
| 3.3 | KEM + signature      | signature            | **mandatory** | `kem.ct_I` in message_4            |
| 3.4 | KEM + signature      | **KEM only**         | **mandatory** | `kem.ct_R` in m3, `kem.ct_I` in m4 |
| 3.5 | KEM + signature      | KEM + signature      | **mandatory** | `kem.ct_R` in m3, `kem.ct_I` in m4 |

Note that §3.4 is titled "Initiator and Responder KEM and sign — version 1", but its Responder
does **not** sign; it authenticates by KEM alone, retroactively, via a `MAC_2` carried in
message_4. The title is misleading. See D11.

---

## 2. Per-variant reference

Reproduced from the draft, normalised only in notation. `DS.Sign`/`DS.Verify` are the draft's
signature algorithm; `KEM.Encapsulation`/`KEM.Decapsulation` its KEM.

### 2.1 §3.2 — Initiator signs, Responder KEM & signs

```
I                                                                R
 |            METHOD, SUITES_I, kem.pk_eph, C_I, EAD_1            |  message_1
 |kem.ct_eph, Enc(KEYSTREAM_2, C_R, ID_CRED_R, EAD_2, SIGNATURE_2)|  message_2
 |          kem.ct_R, AEAD(ID_CRED_I, SIGNATURE_3, EAD_3)         |  message_3
 |                           AEAD(EAD_4)                          |  message_4 (optional)
```

```
TH_2         = H(kem.ct_eph, H(message_1))
PRK_2e       = EDHOC_Extract(TH_2, ss_eph)
KEYSTREAM_2  = EDHOC_KDF(PRK_2e, 0, TH_2, plaintext_length)
PLAINTEXT_2  = (C_R, ID_CRED_R, TH_2, EAD_2)
SIGNATURE_2  = DS.Sign(sign.sk_R, (PLAINTEXT_2, sign_length))
PLAINTEXT_2A = (PLAINTEXT_2, SIGNATURE_2)
CIPHERTEXT_2 = PLAINTEXT_2A XOR KEYSTREAM_2
SALT_3e2m    = EDHOC_KDF(PRK_2e, 1, TH_2, hash_length)
PRK_3e2m     = EDHOC_Extract(SALT_3e2m, ss_R)          -- I encapsulates to kem.pk_R
TH_3         = H(TH_2, PLAINTEXT_2A, ID_CRED_R)
K_3          = EDHOC_KDF(PRK_3e2m, 3, TH_3, key_length)
IV_3         = EDHOC_KDF(PRK_3e2m, 4, TH_3, iv_length)
MAC_3        = EDHOC_KDF(PRK_3e2m, 6, ID_CRED_I, TH_3, EAD_3, mac_length_3)
SIGNATURE_3  = DS.Sign(sign.sk_I, (ID_CRED_I, TH_3, EAD_3, MAC_3, sign_length))
PLAINTEXT_3  = (ID_CRED_I, SIGNATURE_3, EAD_3)
TH_4         = H(TH_3, PLAINTEXT_3, ID_CRED_I)
PRK_out      = EDHOC_KDF(PRK_3e2m, 7, TH_4, hash_length)
```

There is no `PRK_4e3m`: the Initiator authenticates by signature, so no `ss_I` exists.
**`K_4` and `IV_4` are never defined for this variant** — see D9.

### 2.2 §3.3 — Initiator KEM & signs, Responder signs

```
I                                                                R
 |            METHOD, SUITES_I, kem.pk_eph, C_I, EAD_1            |  message_1
 |kem.ct_eph, Enc(KEYSTREAM_2, C_R, ID_CRED_R, EAD_2, SIGNATURE_2)|  message_2
 |               AEAD(ID_CRED_I, EAD_3, SIGNATURE_3)              |  message_3
 |                      kem.ct_I, AEAD(EAD_4)                     |  message_4 (mandatory)
```

```
PRK_2e       = EDHOC_Extract(TH_2, ss_eph)
KEYSTREAM_2  = EDHOC_KDF(PRK_2e, 0, TH_2, plaintext_length)
MAC_2        = EDHOC_KDF(PRK_2e, 2, context_2, mac_length_2)
                 with context_2 = (C_R, ID_CRED_R, TH_2, EAD_2)
SIGNATURE_2  = DS.Sign(sign.sk_R, (C_R, ID_CRED_R, TH_2, EAD_2, MAC_2, sign_length))
PLAINTEXT_2  = (C_R, ID_CRED_R, SIGNATURE_2, EAD_2)
CIPHERTEXT_2 = PLAINTEXT_2 XOR KEYSTREAM_2
TH_3         = H(TH_2, PLAINTEXT_2, ID_CRED_R)
K_3          = EDHOC_KDF(PRK_2e, 3, TH_3, key_length)   -- PRK_3e2m = PRK_2e, R only signs
IV_3         = EDHOC_KDF(PRK_2e, 4, TH_3, iv_length)
SIGNATURE_3  = DS.Sign(sign.sk_I, (PLAINTEXT_3, sign_length))
PLAINTEXT_3A = (PLAINTEXT_3, SIGNATURE_3)
TH_4         = H(TH_3, PLAINTEXT_3A, ID_CRED_I)
SALT_4e3m    = EDHOC_KDF(PRK_2e, 5, TH_4, hash_length)
PRK_4e3m     = EDHOC_Extract(SALT_4e3m, ss_I)           -- R encapsulates to kem.pk_I
K_4          = EDHOC_KDF(PRK_4e3m, 8, TH_4, key_length)
IV_4         = EDHOC_KDF(PRK_4e3m, 9, TH_4, iv_length)
PRK_out      = EDHOC_KDF(PRK_4e3m, 7, TH_4, hash_length)
```

`PLAINTEXT_3` itself is never defined; only `PLAINTEXT_3A` is, and only in terms of it. From
the figure it is presumably `(ID_CRED_I, EAD_3)`. See D10.

### 2.3 §3.4 — both KEM & sign, version 1 (Responder is KEM-only)

```
I                                                              R
 |           METHOD, SUITES_I, kem.pk_eph, C_I, EAD_1           |  message_1
 |      kem.ct_eph, Enc(KEYSTREAM_2, C_R, ID_CRED_R, EAD_2)     |  message_2
 |         kem.ct_R, AEAD(ID_CRED_I, EAD_3, SIGNATURE_3)        |  message_3
 |                 kem.ct_I, AEAD(EAD_4, MAC_2)                 |  message_4 (mandatory)
```

```
PRK_2e       = EDHOC_Extract(TH_2, ss_eph)
KEYSTREAM_2  = EDHOC_KDF(PRK_2e, 0, TH_2, plaintext_length)
PLAINTEXT_2  = (C_R, ID_CRED_R, TH_2, EAD_2)            -- no SIGNATURE_2, no MAC_2
CIPHERTEXT_2 = PLAINTEXT_2 XOR KEYSTREAM_2
SALT_3e2m    = EDHOC_KDF(PRK_2e, 1, TH_2, hash_length)
PRK_3e2m     = EDHOC_Extract(SALT_3e2m, ss_R)
TH_3         = H(TH_2, PLAINTEXT_2, ID_CRED_R)
K_3          = EDHOC_KDF(PRK_3e2m, 3, TH_3, key_length)
IV_3         = EDHOC_KDF(PRK_3e2m, 4, TH_3, iv_length)
SIGNATURE_3  = DS.Sign(sign.sk_I, (PLAINTEXT_3, sign_length))
PLAINTEXT_3A = (PLAINTEXT_3, SIGNATURE_3)
TH_4         = H(TH_3, PLAINTEXT_3A, ID_CRED_I)
SALT_4e3m    = EDHOC_KDF(PRK_3e2m, 5, TH_4, hash_length)
PRK_4e3m     = EDHOC_Extract(SALT_4e3m, ss_I)
K_4          = EDHOC_KDF(PRK_4e3m, 8, TH_4, key_length)
IV_4         = EDHOC_KDF(PRK_4e3m, 9, TH_4, iv_length)
MAC_2        = EDHOC_KDF(PRK_4e3m, 2, context_2, mac_length_2)
                 with context_2 = (C_R, ID_CRED_R, TH_4, EAD_4)
PRK_out      = EDHOC_KDF(PRK_4e3m, 7, TH_4, hash_length)
```

The Responder is authenticated only when the Initiator verifies `MAC_2`, i.e. **after
message_4**. This is the sharpest deviation from RFC 9528's security timeline in the whole
document, and §3.4 does not discuss it. See D11.

### 2.4 §3.5 — both KEM & sign, version 2

```
I                                                                R
 |            METHOD, SUITES_I, kem.pk_eph, C_I, EAD_1            |  message_1
 |kem.ct_eph, Enc(KEYSTREAM_2, C_R, ID_CRED_R, EAD_2, SIGNATURE_2)|  message_2
 |          kem.ct_R, AEAD(ID_CRED_I, EAD_3, SIGNATURE_3)         |  message_3
 |                      kem.ct_I, AEAD(EAD_4)                     |  message_4 (mandatory)
```

```
PRK_2e       = EDHOC_Extract(TH_2, ss_eph)
KEYSTREAM_2  = EDHOC_KDF(PRK_2e, 0, TH_2, plaintext_length)
PLAINTEXT_2  = (C_R, ID_CRED_R, TH_2, EAD_2)
SIGNATURE_2  = DS.Sign(sign.sk_R, (PLAINTEXT_2, sign_length))
PLAINTEXT_2A = (PLAINTEXT_2, SIGNATURE_2)
CIPHERTEXT_2 = PLAINTEXT_2A XOR KEYSTREAM_2
SALT_3e2m    = EDHOC_KDF(PRK_2e, 1, TH_2, hash_length)
PRK_3e2m     = EDHOC_Extract(SALT_3e2m, ss_R)
TH_3         = H(TH_2, PLAINTEXT_2A, ID_CRED_R)
K_3          = EDHOC_KDF(PRK_3e2m, 3, TH_3, key_length)
IV_3         = EDHOC_KDF(PRK_3e2m, 4, TH_3, iv_length)
PLAINTEXT_3  = (ID_CRED_I, TH_3, EAD_3)
SIGNATURE_3  = DS.Sign(sign.sk_I, (PLAINTEXT_3, sign_length))
PLAINTEXT_3A = (PLAINTEXT_3, SIGNATURE_3)
TH_4         = H(TH_3, PLAINTEXT_3A, ID_CRED_I)
SALT_4e3m    = EDHOC_KDF(PRK_3e2m, 5, TH_4, hash_length)
PRK_4e3m     = EDHOC_Extract(SALT_4e3m, ss_I)
K_4          = EDHOC_KDF(PRK_4e3m, 8, TH_4, key_length)
IV_4          = EDHOC_KDF(PRK_4e3m, 9, TH_4, iv_length)
PRK_out      = EDHOC_KDF(PRK_4e3m, 7, TH_4, hash_length)   -- but see D1
```

---

## 3. The central finding: the varying signature inputs are forced, not arbitrary

Across §3 the payload signed by each role changes shape:

| Location             | Signed input                                        | Over a MAC? |
| -------------------- | --------------------------------------------------- | ----------- |
| §3.2 `SIGNATURE_2`   | `(PLAINTEXT_2, sign_length)`                        | no          |
| §3.3 `SIGNATURE_2`   | `(C_R, ID_CRED_R, TH_2, EAD_2, MAC_2, sign_length)` | **yes**     |
| §3.5 `SIGNATURE_2`   | `(PLAINTEXT_2, sign_length)`                        | no          |
| §3.2 `SIGNATURE_3`   | `(ID_CRED_I, TH_3, EAD_3, MAC_3, sign_length)`      | **yes**     |
| §3.3/3.4/3.5 `SIG_3` | `(PLAINTEXT_3, sign_length)`                        | no          |

A previous revision of this repository's analysis
([`pq_edhoc.md`](pq_edhoc.md) gap G5) recorded this as "likely a bug — signature inputs are
inconsistent between variants". **That characterisation is wrong, and this document supersedes
it.** The variation is a direct consequence of KEM interactivity:

> In RFC 9528, `PRK_3e2m = EDHOC_Extract(SALT_3e2m, G_RX)`, and the Responder can compute
> `G_RX` **alone**, at message_2, from its own static private key and the Initiator's ephemeral
> `G_X`. Diffie–Hellman is non-interactive.
>
> A KEM is not. `ss_R` comes into existence only when the **Initiator** runs
> `KEM.Encapsulation(kem.pk_R)` and transmits `kem.ct_R` — which, because the Initiator only
> learns `ID_CRED_R` from message_2, cannot happen before **message_3**.
>
> Therefore a Responder that authenticates by KEM **cannot key any MAC with `PRK_3e2m` at
> message_2**. It has only `PRK_2e`.

That single fact explains the whole table:

- **§3.2 and §3.5** (R = KEM + signature): `PRK_3e2m` is unavailable at message_2, so there is
  no MAC to sign, and the draft signs `PLAINTEXT_2` directly.
- **§3.3** (R = signature only): `PRK_3e2m = PRK_2e` by RFC 9528's own rule, so a MAC _is_
  available at message_2 — and §3.3 duly defines `MAC_2` and signs it. The one variant that
  can follow RFC 9528's construction does.
- **§3.4** (R = KEM only): no signature at all, and `MAC_2` is deferred to message_4 where
  `PRK_4e3m` finally exists.

The mirror-image argument applies one flight later. When the **Initiator** authenticates by KEM
(§3.3, §3.4, §3.5), `ss_I` requires the Responder to encapsulate to `kem.pk_I`, which it can
only do after learning `ID_CRED_I` from message_3. So `PRK_4e3m` does not exist at message_3,
`MAC_3` cannot be keyed by it, and those three variants sign `PLAINTEXT_3` instead. In §3.2 the
Initiator signs, so `PRK_4e3m = PRK_3e2m` and the RFC-shaped `MAC_3` is available — which is
exactly what §3.2 uses.

**The draft is self-consistent on this point and should say so.** What it is missing is the
one-paragraph explanation, and a construction that preserves RFC 9528's COSE framing under the
constraint. §4 below proposes both.

---

## 4. Proposed resolution: keep RFC 9528's construction, vary only the key

The lakers prototype implements the following rule, offered as proposed text.

> **Signature construction.** In all variants, `SIGNATURE_2` and `SIGNATURE_3` are computed
> over a COSE `Sig_structure` of type `Signature1`, as in RFC 9528 §5.3.2:
>
> ```
> [ "Signature1", << ID_CRED_x >>, << TH_x, CRED_x, ? EAD_x >>, MAC_x ]
> ```
>
> **MAC keying.** Each MAC is keyed by the most-derived PRK available to the signer at the
> point in the flow where it signs:
>
> | MAC     | Peer authenticates by | Keyed with                |
> | ------- | --------------------- | ------------------------- |
> | `MAC_2` | signature only        | `PRK_3e2m` (= `PRK_2e`)   |
> | `MAC_2` | KEM, or KEM+signature | **`PRK_2e`**              |
> | `MAC_3` | signature only        | `PRK_4e3m` (= `PRK_3e2m`) |
> | `MAC_3` | KEM, or KEM+signature | **`PRK_3e2m`**            |
>
> **Transcript hashes.** `TH_3 = H(TH_2, PLAINTEXT_2, CRED_R)` and
> `TH_4 = H(TH_3, PLAINTEXT_3, CRED_I)` — binding the full credential, as RFC 9528 §5.4.1 and
> §5.5.1 require, not `ID_CRED_x` (see D2).

This keeps every security-relevant property RFC 9528 relies on — credential binding in the
transcript, `ID_CRED` in the protected header, `EAD` in the external AAD, a fixed-width payload
— while respecting the availability constraint that forces the draft's variation. It also
collapses the five distinct signed-input shapes in §3 into one.

**Implementation evidence that this is the cheaper option.** In lakers, adopting this rule lets
the prototype reuse, unchanged: `encode_sig_structure` (`lib/src/edhoc.rs:807`),
`encode_kdf_context` (`:1060`), the const-generic `compute_mac_2::<N>` (`:1106`) and
`compute_mac_3::<N>` (`:1086`), `compute_th_3` (`:615`), `compute_th_4` with `Th4Input::Stat`
(`:649`), `encode_plaintext_2` (`:1122`), `encode_plaintext_3` (`:712`), and the const-generic
decoders `decode_plaintext_2_sized::<N>` / `decode_plaintext_3_sized::<N>`
(`shared/src/lib.rs:1191`, `:1257`). Every draft-literal variant would instead need a bespoke
encoder that bypasses all of them.

---

## 5. Divergences and defects

Severity: **B** = blocks implementation · **S** = security-relevant · **C** = internal
contradiction · **E** = editorial/under-specified.

### D1 — §3.5 contradicts itself on `PRK_out` · **C**

§3.5.2.4 states `PRK_out = EDHOC_KDF(PRK_3e2m, 7, TH_4, hash_length)`. The key-derivation
summary in §3.5.3 states `PRK_out = EDHOC_KDF(PRK_4e3m, 7, TH_4, hash_length)`. §3.5.2.5 only
says the Initiator "can finally compute `PRK_out` as the Responder did", which resolves nothing.

_(Note: an earlier revision of `pq_edhoc.md` located this in §3.5.2.5; the actual conflicting
formula is in §3.5.2.4.)_

**Proposed:** `PRK_4e3m`. Deriving `PRK_out` from `PRK_3e2m` would discard `ss_I` entirely,
which would make the Initiator's KEM authentication contribute nothing to the output key and
defeat the purpose of the variant. §3.5.3 is right; §3.5.2.4 is the typo.

### D2 — `TH_3`/`TH_4` bind `ID_CRED_x` instead of `CRED_x` · **S**

Every variant computes `TH_3 = H(TH_2, PLAINTEXT_2(A), ID_CRED_R)` and
`TH_4 = H(TH_3, PLAINTEXT_3(A), ID_CRED_I)`. RFC 9528 §5.4.1 and §5.5.1 bind **`CRED_R`** and
**`CRED_I`** — the full credentials.

When `ID_CRED_x` is a `kid`, it is a short opaque reference that does not commit to any key
material. Binding only the reference removes precisely the guarantee RFC 9528 relies on to
prevent identity misbinding: two credentials sharing a `kid` under different trust anchors
produce the same transcript.

**Evidence from working code.** lakers already does this the RFC way and would have to be
_broken_ to follow the draft: `compute_th_3` takes the credential bytes
(`Some(cred_r.bytes.as_slice())`, `lib/src/edhoc.rs:615`) and `compute_th_4` takes them via its
`cred_i: &[u8]` parameter (`:649`); call sites are in `lib/src/edhoc/sig.rs` and
`lib/src/edhoc/stat.rs`. This is not a matter of taste — it contradicts a working RFC 9528
implementation.

**Proposed:** use `CRED_R` / `CRED_I`, matching RFC 9528. If the intent was to reduce message
size, note that `TH_x` inputs are hashed, not transmitted, so there is no wire saving.

### D3 — figure and prose disagree on `PLAINTEXT_2` field order in §3.3 · **C**

The §3.3 figure shows `Enc(KEYSTREAM_2, C_R, ID_CRED_R, EAD_2, SIGNATURE_2)`; the §3.3.2.2
prose defines `PLAINTEXT_2 = (C_R, ID_CRED_R, SIGNATURE_2, EAD_2)`.

**Proposed:** the prose. RFC 9528's `PLAINTEXT_2` is
`(C_R, ID_CRED_R, Signature_or_MAC_2, ? EAD_2)`, which matches it. The figures in §3.2 and §3.5
have the same `EAD_2, SIGNATURE_2` ordering and should be corrected for consistency.

### D4 — `TH_2` is carried inside `PLAINTEXT_2` · **E**

§3.2, §3.4 and §3.5 all define `PLAINTEXT_2 = (C_R, ID_CRED_R, TH_2, EAD_2)`. `TH_2` is
computable by both peers from `kem.ct_eph` and `H(message_1)`, both of which the Initiator
already has. Transmitting it costs 32–34 encrypted bytes per handshake for no stated purpose,
and RFC 9528 does not do it.

If the intent is to bind `TH_2` into the signature, note that under the §4 construction `TH_2`
is already in the `Sig_structure`'s external AAD, so the field is redundant there too.

**Proposed:** remove `TH_2` from `PLAINTEXT_2` in all three variants.

### D5 — no METHOD code points · **B**

§3 defines four variants; the document states "This document has no IANA actions." No method
value is assigned to any of them, so two implementations cannot interoperate and message_1
cannot be encoded.

**Proposed:** request four code points from the EDHOC Method Type registry. The lakers
prototype uses locally-chosen values 40–43 (§3.2, §3.3, §3.4, §3.5 respectively), marked TBD in
the source.

Note for anyone doing the same: unlike the cipher suite registry, the **EDHOC Method Type
registry has no Private Use range at all**. It allocates −65536..−25 and 24..65535 to
Specification Required, and −24..23 to Standards Action with Expert Review. So there is no
correct value for an unregistered experiment to occupy; 40–43 are unassigned values in the
Specification Required range a real registration would come from. (lakers' own experimental
PSK method, at 4, sits in the Standards Action range — worth knowing before it is used
anywhere it might meet another implementation.)

Naming the four variants after their _per-role_ modes rather than numbering them turns out to
matter for more than tidiness. §3's four variants are exactly four points in the cross product
of {sign, KEM, KEM+sign} per role, so a method is a pair of independent choices, not a
monolithic protocol identity. That is the same shape RFC 9528's own methods have — `SigStat`
is "I signs, R static-DH" — and it is what allows one implementation module to cover all four.

### D6 — no cipher suites · **B**

Deferred to `draft-spm-lake-pqsuites`, whose PQ suites are still `TBD1`/`TBD2`. Without a suite
there is no algorithm binding, no size for `kem.pk_eph`/`kem.ct_eph`, and no way to parse any
message.

**Proposed:** the draft should at minimum name the intended parameter sets inline
(ML-KEM-512 + ML-DSA-44 at NIST level 1/2, per pqsuites' apparent direction) so sizes are
derivable while the registration is pending.

The lakers prototype squats on **60**, currently unassigned, for
`ML-KEM-512 + ML-DSA-44 + AES-CCM-16-128-128 + SHA-256`. Two notes on that choice, since the
registry ranges are easy to get wrong:

- The IANA EDHOC Cipher Suites registry allocates **-65536..-25** Specification Required,
  **-24..-21** Private Use, **-20..23** Standards Action with Expert Review, and
  **24..65535** Specification Required. So the Private Use range is only four values, all
  negative, and 60 is in the range a real registration for this would come from.
- A negative code point would be the standards-correct choice for an unregistered
  experiment, but suite values are handled as `u8` end to end in lakers — `parse_suites_i`,
  `encode_message_1`, `EdhocBuffer<MAX_SUITES_LEN>` — so it would mean re-typing the whole
  suite path. Deliberately out of scope for the prototype.

Unrelated to PQ but found while implementing this: lakers encoded a single `SUITES_I` value
of exactly 24 as a bare `0x18`, which is the CBOR "one length byte follows" header rather than
the value 24, so the decoder consumed the next byte as the suite. Suites 24 and 25 are both
assigned, so this was reachable by any implementation supporting either. Fixed, with a
round-trip test across the 23/24/25 boundary.

### D7 — no CBOR encodings, no CDDL, no test vectors · **B**

Nothing states how `kem.pk_eph`, `kem.ct_eph`, `kem.ct_R` and `kem.ct_I` are wrapped, whether
message_3 and message_4 become CBOR sequences, or how a two-key credential is represented in a
CCS. The document contains no hex bytes at all.

**Proposed encodings** (implemented by the lakers prototype; offered as a starting point):

| Message   | Encoding                                                                                                                                                         |
| --------- | ---------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| message_1 | `METHOD, SUITES_I, bstr(kem.pk_eph), C_I, ? EAD_1` — unchanged shape, `G_X` becomes an 800-byte bstr                                                             |
| message_2 | `bstr(kem.ct_eph \|\| CIPHERTEXT_2)` — one bstr, mirroring RFC 9528's `bstr(G_Y \|\| CIPHERTEXT_2)`; lengths are suite-fixed so the concatenation is unambiguous |
| message_3 | `bstr(kem.ct_R), bstr(CIPHERTEXT_3)` — a two-element CBOR sequence, matching the comma in the draft's own figures                                                |
| message_4 | `bstr(kem.ct_I), bstr(CIPHERTEXT_4)` — same shape                                                                                                                |

A defensible alternative for message_3/message_4 is a single concatenated bstr, matching
message_2's shape; the WG should pick one. Note that a 768-byte ciphertext requires a two-byte
CBOR length header, which is the kind of detail that only surfaces once someone encodes it —
lakers had two latent one-byte-header bugs that PQ sizes make unavoidable
(`lib/src/edhoc.rs:583`, `:902`).

Test vectors generated from the working prototype will be published alongside this document as
`test_vectors_pq.md`.

### D8 — no statement on how a peer advertises two long-term keys · **B**

§3.2–3.5 require roles that authenticate with "KEM & signature" to hold _both_ a static KEM
keypair and a static signature keypair (§3.5.4 says so explicitly). Nothing states how both
public keys live under a single `ID_CRED`, how `CRED` is formed, or how a verifier knows which
is which.

**Proposed**, and implemented in the lakers prototype. Keep the CCS shape of RFC 9528 §3.5.2
exactly — one `cnf` claim, holding one COSE_Key — and put both public keys in that one
COSE_Key, using the `AKP` key type from `draft-ietf-cose-post-quantum-signatures` with one
added label:

```cddl
CRED_x = {
  ? 2 => tstr,                 ; sub, ignored
    8 => { 1 => PQ_COSE_Key }  ; cnf
}

PQ_COSE_Key = {
    1  => 7,                   ; kty: AKP
  ? 2  => bstr,                ; kid
  ? -1 => bstr .size 1312,     ; AKP "pub": the ML-DSA-44 verification key
  ? -2 => bstr .size 800       ; local extension: the ML-KEM-512 encapsulation key
}
```

At least one of `-1` / `-2` MUST be present; which are present is exactly what tells a verifier
whether the peer signs, uses a KEM, or both, so no separate mode signal is needed. Because the
labels differ per key type, `kty` MUST precede them — which deterministic CBOR ordering already
guarantees, since `1` sorts before `-1`.

**This is deliberately the smallest possible divergence, not the most elegant option.** It is
_not_ AKP-conformant: AKP carries one algorithm's key per COSE_Key, with `alg` naming the
algorithm and `-1` the public key. Two alternatives were considered and rejected for this
prototype:

| Alternative                               | Why not                                                                                                                                         |
| ----------------------------------------- | ----------------------------------------------------------------------------------------------------------------------------------------------- |
| `cnf` holds an array of two AKP COSE_Keys | RFC 8747 defines the `cnf` member `1` as a COSE_Key, not an array of them. Changing that is a larger break than adding one key label.           |
| A second CWT claim carrying the KEM key   | Cleanest and fully AKP-conformant, but needs a CWT claim number, and the private-use range is negative — more machinery than a prototype needs. |

The second row is probably the right long-term answer and the WG should consider it; the
prototype's choice is what a parser could support with one extra match arm.

Two further points the WG will need to settle, which this encoding sidesteps rather than
solves: COSE has no registered `alg` for ML-KEM at all, so the KEM key here is identified by
its label and size rather than by an algorithm identifier; and neither key carries an `alg`,
so the parameter set is pinned by the cipher suite alone.

Note the size consequence: a `CRED` transferred by value grows from ~107 B to ~2.2 KB
(ML-DSA-44 public key 1312 B + ML-KEM-512 encapsulation key 800 B). That alone puts
`CredentialTransfer::ByValue` out of reach for constrained links.

### D9 — §3.2 never defines `K_4`/`IV_4` · **E**

§3.2's message_4 is `AEAD(EAD_4)`, but §3.2 defines no `K_4` or `IV_4`, and has no `PRK_4e3m`
to derive them from. Every other variant defines both.

**Proposed:** state that in §3.2, `PRK_4e3m = PRK_3e2m` (following RFC 9528's rule for a
signature-authenticating Initiator) and that `K_4`/`IV_4` are derived from it with labels 8 and
9 as usual. This is what the lakers prototype does.

### D10 — `PLAINTEXT_3` is undefined in §3.3 and §3.4 · **E**

Both variants define `PLAINTEXT_3A = (PLAINTEXT_3, SIGNATURE_3)` and sign `PLAINTEXT_3`, but
neither ever defines `PLAINTEXT_3` itself. From the figures it appears to be
`(ID_CRED_I, EAD_3)`; §3.5 by contrast defines it explicitly as `(ID_CRED_I, TH_3, EAD_3)`. The
three variants may or may not be intended to agree.

**Proposed:** define it once, consistently, in all variants.

### D11 — §3.4's Responder is not authenticated until message_4 · **S**

In §3.4 the Responder produces no `SIGNATURE_2` and no `MAC_2` at message_2; `MAC_2` is keyed
by `PRK_4e3m` and travels inside message_4. The Initiator therefore reveals `ID_CRED_I`,
signs a transcript, and completes a full encapsulation to a credential it has not yet
authenticated.

This may well be an acceptable trade — it buys the smallest message_2 in the set, and the
Initiator's own key material is not exposed — but the draft does not analyse it, and §4's
security claims do not distinguish §3.4 from the others. The variant's title ("Initiator and
Responder KEM and sign") also actively misleads, since its Responder does not sign.

**Proposed:** rename the variant, and add explicit text stating that Responder authentication
completes at message_4 and what an Initiator may and may not do before then.

### D12 — no error handling for KEM decapsulation · **E**

ML-KEM uses implicit rejection: `Decaps` on a malformed or attacker-chosen ciphertext returns a
_pseudorandom shared secret_, never an error. A failure therefore never surfaces at the KEM
layer — it surfaces one or more messages later as a MAC or AEAD verification failure, possibly
in a different flight than the one carrying the bad ciphertext.

The draft says nothing about this, and RFC 9528's error handling assumes failures are locally
detectable where they occur.

**Proposed:** state explicitly that implementations MUST NOT expect a decapsulation error, and
specify which EDHOC error message is sent when the resulting MAC/AEAD check fails, for each of
`kem.ct_eph`, `kem.ct_R` and `kem.ct_I`.

### D13 — no downgrade-protection text for mixed classical/PQ `SUITES_I` · **E**

§4 asserts downgrade protection but the PQ suites are not in the existing negotiation table,
and the document does not discuss a `SUITES_I` containing both classical and PQ suites — which
is the deployment case that matters during transition.

### D14 — undefined `kemp.` prefix used for `kem.` in nine places · **E**

§1.2.1 defines exactly one KEM namespace: `KEM.KeyGen` yields `(kem.sk, kem.pk)`,
`KEM.Encapsulation` yields `(ss, kem.ct)`. The prefix `kemp.` is never defined anywhere in the
document, but appears nine times, always naming an object that the `kem.` prefix names
elsewhere:

| Spelling      | Occurrences | `kem.` twin  | Occurrences |
| ------------- | ----------- | ------------ | ----------- |
| `kemp.ct_eph` | 5           | `kem.ct_eph` | 27          |
| `kemp.pk_R`   | 3           | `kem.pk_R`   | 10          |
| `kemp.pk_eph` | 1           | `kem.pk_eph` | 20          |

Locations, by section: §2.2.1.3 (`kemp.ct_eph`, `kemp.pk_R`), §2.2.3.1 (`kemp.pk_eph`),
§3.2.2.3 (`kemp.ct_eph`, `kemp.pk_R`), §3.3.2.3, §3.4.2.3, §3.5.2.3 (`kemp.ct_eph` in each,
plus `kemp.pk_R` in §3.5.2.3).

That these are typographical rather than a second namespace is settled by §2.2.3.1, where both
spellings denote the same value inside one sentence:

> On reception of the ephemeral KEM public key **kemp.pk_eph**, the Responder generates a pair
> (ss_eph, kem.ct_eph) with the KEM.Encapsulation algorithm (with input **kem.pk_eph**).

The five `kemp.ct_eph` hits are one paragraph — "On reception of the second message, the
Initiator, using kemp.ct_eph, can compute the ephemeral shared-secret ss_eph…" — reproduced
verbatim in §2.2.1.3 and once per §3 variant, so a single original typo propagated with the
boilerplate.

The signature namespace has no equivalent problem: `sign.{sk,pk}_{I,R}` and `DS.{KeyGen,Sign,Verify}`
are used consistently throughout.

**Proposed:** global replace `kemp.` → `kem.`. Worth fixing despite being cosmetic — a reader
implementing from the text has no way to know whether `kemp.pk_R` is the same key as `kem.pk_R`
or a distinct one belonging to some unstated second parameter set, and §3's variants do give
each role two long-term keys (see D8), which makes the ambiguity a plausible one to fall into.

### D15 — §3 test vectors cannot be byte-reproducible · **E**

RFC 9529's test vectors are reproducible: fix the two ephemeral private keys and the two static
private keys, and every subsequent byte of the exchange follows, because ECDSA-with-SHA-256 as
RFC 9528 uses it is deterministic per RFC 6979. A verifier regenerates the vectors and compares.

ML-DSA is randomised (hedged) by default: FIPS 204 signs with a fresh 32-byte _rnd_ unless the
deterministic variant is selected. So in §3, fixing every key and both ephemeral KEM pairs still
does not fix `SIGNATURE_2` or `SIGNATURE_3` — and therefore does not fix `CIPHERTEXT_2`, `TH_3`,
`PLAINTEXT_3`, `TH_4`, `PRK_out`, or anything exported from it. Only `message_1`, `H(message_1)`,
`TH_2` and `PRK_2e` are reproducible from the inputs.

This is not a defect in the draft's construction, but it changes what a test-vector appendix can
promise, and D7 asks for one without saying which. It matters for interop testing: an
implementer cannot diff their output against a reference trace, only verify it.

Observed directly: `test_vectors_pq.md` in this repository is generated from a live exchange and
is labelled a _sample trace_ rather than a test vector for exactly this reason.

**Proposed:** state which mode is expected. Either (a) mandate deterministic ML-DSA signing for
test-vector generation only, so an appendix can be regenerated and diffed, keeping hedged signing
for deployment; or (b) keep hedged signing throughout and specify that the appendix is a
verifiable trace, listing which values an implementation can compare directly (`message_1`,
`H(message_1)`, `TH_2`, `PRK_2e`) and which it can only check by verifying signatures and
recomputing the schedule.

### D16 — every variant exceeds 6LoWPAN's fragmentation limit · **B**

RFC 4944's fragment header carries `datagram_size` in an **11-bit** field, so the largest
datagram 6LoWPAN can reassemble is **2047 octets**. Measured from the working implementation
(§8), every one of the four variants produces at least one message above that:

| §   | Messages over 2047 bytes               |
| --- | -------------------------------------- |
| 3.2 | `message_2` (3196), `message_3` (3214) |
| 3.3 | `message_2` (3196), `message_3` (2443) |
| 3.4 | `message_3` (3214)                     |
| 3.5 | `message_2` (3196), `message_3` (3214) |

This is not a tuning problem. An ML-DSA-44 signature is 2420 bytes on its own, so any message
carrying one is over the limit before anything else is added, and no parameter choice inside
ML-DSA-44 changes that. The draft's target deployments are exactly the constrained networks
where 6LoWPAN is used, and RFC 9528 §A.2 already specifies EDHOC over CoAP, so the resolution
is available — but it has to be _stated_, because "use 6LoWPAN fragmentation" is the obvious
thing an implementer would reach for and it does not work.

**Proposed:** an Applicability/Transport section noting that §3's messages exceed RFC 4944's
2047-octet reassembly limit, and that a transport with its own segmentation — CoAP block-wise
transfer (RFC 7959) as in RFC 9528 §A.2 — is therefore required rather than optional. Worth
pairing with the fragment counts in §8: at a typical 76-byte usable payload, §3.5 costs 108
link-layer fragments against SigSig's 5, and 6LoWPAN reassembly is all-or-nothing, so the
probability of completing a handshake degrades sharply with frame loss.

---

## 6. What the lakers prototype implements

Summary of every deliberate deviation from the -00 text. Each is a consequence of §4 or of a
resolution proposed above.

| Item                      | Draft -00                        | lakers prototype                            | Reason                                                                                                                           |
| ------------------------- | -------------------------------- | ------------------------------------------- | -------------------------------------------------------------------------------------------------------------------------------- |
| `SIGNATURE_2`/`_3` input  | ad-hoc tuple, varies per variant | COSE `Sig_structure` over a MAC             | §4 / D-central                                                                                                                   |
| `MAC_2` key               | varies                           | `PRK_2e` when R uses KEM, else `PRK_3e2m`   | §4                                                                                                                               |
| `MAC_3` key               | varies                           | `PRK_3e2m` when I uses KEM, else `PRK_4e3m` | §4                                                                                                                               |
| `TH_3`/`TH_4` third input | `ID_CRED_x`                      | `CRED_x`                                    | D2                                                                                                                               |
| `TH_2` in `PLAINTEXT_2`   | present in §3.2/3.4/3.5          | removed                                     | D4                                                                                                                               |
| §3.5 `PRK_out`            | contradictory                    | from `PRK_4e3m`                             | D1                                                                                                                               |
| §3.2 `K_4`/`IV_4`         | undefined                        | from `PRK_4e3m` = `PRK_3e2m`, labels 8/9    | D9                                                                                                                               |
| METHOD code points        | none                             | 40–43, marked TBD                           | D5                                                                                                                               |
| Cipher suite              | none                             | 60, locally chosen, marked TBD              | D6                                                                                                                               |
| Hash                      | SHAKE256 (via pqsuites)          | **SHA-256**                                 | prototype scope; both are 32-byte outputs so the key schedule and all sizes are unaffected. A deliberate, documented divergence. |
| CBOR encodings            | none                             | as in D7                                    | D7                                                                                                                               |
| Two-key credential        | none                             | one AKP COSE_Key, `-1` sig / `-2` KEM       | D8                                                                                                                               |
| Test vectors              | none                             | a _sample trace_, not reproducible          | D15                                                                                                                              |

---

## 7. Measurements

All figures below are **measured from the working implementation**, not estimated:
`test_pq_wire_sizes`, `test_pq_handshake_kemsig_sig`, `test_pq_handshake_kemsig_kem` and
`test_pq_handshake_kemsig_kemsig` in `lib/src/lib.rs` assert them, so they cannot drift
silently. Configuration: ML-KEM-512 (ephemeral and static), ML-DSA-44, SHA-256,
AES-CCM-16-128-128, credentials **by reference**, no EAD in any message. The classical
baselines come from `test_mixed_methods_are_per_role` in the same file, at cipher suite 2.

### 7.1 Bytes on the wire

| Method     | message_1 | message_2 | message_3 | message_4 | total | vs. method 0 |
| ---------- | --------: | --------: | --------: | --------: | ----: | -----------: |
| 0 SigSig   |        37 |       102 |        77 |         9 |   225 |         1.0x |
| 3 StatStat |        37 |        45 |        19 |         9 |   110 |         0.5x |
| 40 §3.2    |       808 |      3196 |      3214 |         9 |  7227 |        32.1x |
| 41 §3.3    |       808 |      3196 |      2443 |       788 |  7235 |        32.2x |
| 42 §3.4    |       808 |       773 |      3214 |       798 |  5593 |        24.9x |
| 43 §3.5    |       808 |      3196 |      3214 |       788 |  8006 |        35.6x |

Reading the table:

- **message_1 is the same in all four** and is entirely the 800-byte `kem.pk_eph`: METHOD(2) +
  SUITES_I(2) + bstr header(3) + 800 + C_I(1).
- **message_2 follows the Responder's mode.** 3196 bytes whenever R signs — bstr header(3) +
  `kem.ct_eph`(768) + a CIPHERTEXT_2 dominated by the 2420-byte `SIGNATURE_2`. §3.4's R does
  not sign, and its message_2 collapses to 773: the same 771 bytes of framing and ephemeral
  ciphertext plus two bytes of `C_R` and `ID_CRED_R`. It is the only message in all of §3 that
  stays under a kilobyte.
- **message_3 follows the Responder's mode too**, because that is what decides whether
  `kem.ct_R` is present: 3214 with the prefix, 2443 without. The 771-byte difference is
  `kem.ct_R` and its bstr header exactly.
- **message_4 follows the Initiator's mode.** 9 bytes when it only signs (§3.2, unchanged from
  RFC 9528), 788 when `kem.ct_I` rides along, 798 for §3.4 where the deferred `MAC_2` adds ten
  more — eight of MAC, one of bstr header, and one because CIPHERTEXT_4 crosses 23 bytes and
  its own header widens.

The cheapest variant is **§3.4 at 24.9x**, and it is cheapest precisely because its Responder
never signs — which is also what makes it the one variant whose Responder is unauthenticated
until the last message (D11). That trade is worth stating explicitly in the draft.

### 7.2 Link-layer fragmentation

Model: IEEE 802.15.4 with 81 bytes of L2 payload after MAC header and FCS (short addresses,
link-layer security on), RFC 4944 6LoWPAN fragmentation with a 4-byte FRAG1 header and 5-byte
FRAGN headers — so 77 bytes of EDHOC message in the first fragment and 76 in each subsequent
one.

| Method     |  m1 |  m2 |  m3 |  m4 | fragments per handshake |
| ---------- | --: | --: | --: | --: | ----------------------: |
| 0 SigSig   |   1 |   2 |   1 |   1 |                       5 |
| 3 StatStat |   1 |   1 |   1 |   1 |                       4 |
| 40 §3.2    |  11 |  43 |  43 |   1 |                      98 |
| 41 §3.3    |  11 |  43 |  33 |  11 |                      98 |
| 42 §3.4    |  11 |  11 |  43 |  11 |                      76 |
| 43 §3.5    |  11 |  43 |  43 |  11 |                     108 |

6LoWPAN reassembly is all-or-nothing: losing any one fragment discards the whole datagram. A
handshake that takes 108 fragments instead of 5 does not merely cost 20x the airtime, it fails
at a frame-loss rate 20x lower.

**And it cannot be done at all over RFC 4944.** Its `datagram_size` field is 11 bits, capping
reassembly at 2047 octets, and every variant has at least one message above that — see D16.
The counts above are therefore what a transport with its own segmentation would cost, not what
6LoWPAN can deliver.

---

## 8. What implementing the draft turned up in lakers

Ten defects in code that predates this work, none of them post-quantum. They are listed
because they are evidence for the WG that implementing §3 exercises paths a classical EDHOC
implementation does not: five of the ten were found only because a post-quantum message is
large, or because a second cipher suite and a method code point above 23 had to work.

Every one was confirmed by restoring the old code and watching a new test fail, never by
inspection alone.

| #   | Defect                                                                                                                                                                                                                               | Surfaced by                         |
| --- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ | ----------------------------------- |
| 1   | `encode_message_2` computed the bstr length with `as u8`: panics in debug and **silently emits a corrupt message in release** for any CIPHERTEXT_2 over 255 bytes                                                                    | PQ message_2 is 3196 bytes          |
| 2   | `encrypt_message_3`/`_4` wrote a one-byte length header via a _cast_, truncating silently in both profiles                                                                                                                           | same                                |
| 3   | `decrypt_message_3`/`_4` indexed `message[0]`/`[1]` unchecked — **an empty message_3 panics, reachable from a peer** on the sig and stat paths (the existing empty-message test covered only PSK)                                    | reviewing the same functions        |
| 4   | A valid but too-short bstr reached `aes_ccm_decrypt`, which computes `ciphertext.len() - Tag::LEN` unguarded and underflows                                                                                                          | same                                |
| 5   | `r_process_message_1` validated SUITES_I against the hardcoded `EDHOC_SUPPORTED_SUITES[0]`, ignoring `crypto.supported_suites()` — any backend offering a second suite had its own selection rejected                                | adding a PQ cipher suite            |
| 6   | `encode_message_1` emitted `SUITES_I == 24` as a bare `0x18`, which is CBOR's "one length byte follows"; the decoder then ate `G_X`'s bstr header as the suite. **Suites 24 and 25 are both assigned**                               | same                                |
| 7   | `encode_message_1` emitted METHOD >= 24 as a raw byte: method 40 becomes `0x28`, which reads back as the **negative integer -9**                                                                                                     | PQ method code points are 40-43     |
| 8   | Backend crypto conformance tests never ran in CI at all — not the new ML-KEM/ML-DSA ones, nor the pre-existing ECDSA ones                                                                                                            | adding trait methods                |
| 9   | `ProcessingM2C::copy_into_c` and `ProcessedM2C::copy_into_c` in the C bindings `todo!()`d on the signature arm — **a Rust panic unwinding across the FFI boundary**, reachable by a C caller that passes method 0 to `initiator_new` | converting the bindings' `todo!()`s |
| 10  | `EdhocInitiatorWaitM4::completed_without_message_4` returned `EdhocResponderDone`. Both wrap the same `Completed`, so it compiled and no test noticed                                                                                | the message_4 rework                |

Items 1, 2, 3 and 4 are wire-format handling; 3 is remotely triggerable. Items 5, 6 and 7 are
all the same shape — a CBOR integer or a suite identifier that only ever gets exercised once a
value above 23 exists, which classical EDHOC never produces.

Two further observations for implementers, not defects:

- **State size.** The typestate chain moves protocol states by value, and a `pq` build's
  states are dominated by fixed-size buffers: `ProcessingM3` reached 37 kB before tuning, and
  driving two handshakes in one stack frame overflowed the stack of a test thread. §3 is not
  merely a bandwidth problem for constrained devices; it is a RAM problem, and an
  implementation that sizes buffers by the largest message will not fit the targets the draft
  is aimed at.
- **Randomised signing.** ML-DSA's hedged signing makes byte-reproducible test vectors
  impossible without mandating the deterministic variant — see D15.

---

## 9. Open questions for the authors

1. **D1:** confirm `PRK_4e3m` is intended for §3.5's `PRK_out`.
2. **D2:** was the `ID_CRED_x` binding in `TH_3`/`TH_4` deliberate? If so, what replaces the
   credential binding RFC 9528 gets from `CRED_x`?
3. **§4:** is the "keep the COSE `Sig_structure`, vary only the MAC key" construction acceptable
   as a replacement for the five ad-hoc signed inputs, or is there a security-analysis reason
   the raw-plaintext signature was preferred?
4. **D11:** is deferred Responder authentication in §3.4 an intended trade-off, and should the
   variant be renamed?
5. **D8:** is there existing work on two-key credentials this should align with, or should the
   prototype's encoding be taken as a starting point?
6. Given the substantial overlap with `draft-pocero-lake-authkemsig-edhoc`, which document
   should carry the KEM+signature combinations?
7. **D15:** should a test-vector appendix mandate deterministic ML-DSA signing so it can be
   regenerated and diffed, or be specified as a verifiable-but-not-reproducible trace?
8. **D16:** given that every variant exceeds RFC 4944's 2047-octet reassembly limit, should the
   draft require a transport with its own segmentation, and say so in an Applicability section?
9. **§7:** §3.4 is both the cheapest variant (24.9x rather than 35.6x) and the only one whose
   Responder is unauthenticated until message_4. Is that trade deliberate, and should the draft
   present it as the reason to choose §3.4?
