# draft-papon-lake-pq-edhoc-00 — clarity and coherence audit

**Target:** `draft-papon-lake-pq-edhoc-00`, Clément Papon & Cristina Onete, 1 March 2026.
<https://www.ietf.org/archive/id/draft-papon-lake-pq-edhoc-00.txt>

**Scope.** This is a _reading-level_ audit: every place the text impedes understanding or
implementation, regardless of whether the underlying design is sound. It is deliberately
separate from [`pq_edhoc_section3.md`](pq_edhoc_section3.md), which audits §3 for
_implementability_ and proposes replacement mechanisms. The two overlap but ask different
questions:

| Document               | Question it answers                                                      |
| ---------------------- | ------------------------------------------------------------------------ |
| `pq_edhoc_section3.md` | What does §3 fail to specify, and what should it say instead?            |
| this document          | Where does the prose mislead, contradict itself, or fail to be readable? |

Findings here are labelled **CA-n**. Where one restates or corrects a **D-n** from the other
document, it says so.

**Method.** Sections quoted below were retrieved verbatim from the -00 text. Everything
asserted about the draft is a direct quotation or an observation about quoted text. Two areas
could **not** be retrieved and are therefore out of scope: the body of §4 Security
Considerations (§4.1–4.5 truncated on retrieval) and the figures, which were read earlier in
prose form only. Findings that would depend on those are marked as unverified rather than
asserted.

---

## 0. Corrections to `pq_edhoc_section3.md`

Re-reading the -00 text against that document found two divergences that do not exist. Both
would have gone to the authors as false accusations of omission.

| Entry   | What it claims                                | What the text says                                                                                           | Action                                                                                                  |
| ------- | --------------------------------------------- | ------------------------------------------------------------------------------------------------------------ | ------------------------------------------------------------------------------------------------------- |
| **D9**  | "§3.2 never defines `K_4`/`IV_4`"             | §3.2.2.5: "`K_4 = EDHOC_KDF(PRK_3e2m, 8, TH_4, key_length); IV_4 = EDHOC_KDF(PRK_3e2m, 9, TH_4, iv_length)`" | **Withdraw.** Both are defined. The lakers implementation independently arrived at the same derivation. |
| **D10** | "`PLAINTEXT_3` is undefined in §3.3 and §3.4" | §3.3.2.3, §3.4.2.3 and §3.5.2.3 each state "`PLAINTEXT_3 = (ID_CRED_I, TH_3, EAD_3)`"                        | **Withdraw.** Defined in all three.                                                                     |

A third entry needs narrowing rather than withdrawal — see **CA-6**.

`pq_edhoc_section3.md` also states that "every claim about the draft below was read out of the
-00 text." That was not true of D9 and D10. The claim should be softened or the document
re-checked entry by entry before it is sent anywhere.

---

## 1. Structural — why the document is hard to read at all

### CA-1 — §3.2 through §3.5 are near-duplicate narratives

§3.2.2.1 and §3.3.2.1 are word-for-word identical. §3.4.2.2 and §3.5.2.2 are word-for-word
identical. §3.4.2.5 and §3.5.2.5 differ by one sentence. Across the four variants roughly 85%
of the prose is shared.

The _only_ content in §3.2–3.5 is the deltas between the variants, and the presentation makes
those deltas invisible: a reader must diff four long sections by hand to learn what
distinguishes them. This is also the mechanism that produces several contradictions below.
§3.4.2.4 and §3.5.2.4 are identical paragraphs whose sole divergence is `PRK_out`'s first
argument (CA-8) — precisely the error copy-paste prose generates, and precisely the error
copy-paste prose conceals.

**Proposed:** one base protocol description, then a per-variant delta table (what each role
authenticates with, which `kem.ct` rides on which message, where `PRK_out` becomes derivable,
whether message_4 is mandatory). This would shorten §3 substantially and make the four
variants comparable, which is the reason for offering four in the first place.

---

## 2. Terms that change meaning between sibling sections

### CA-2 — `PLAINTEXT_2` and `PLAINTEXT_3` are each redefined without notice

| Term           | §3.2                              | §3.3                                   | §3.4                            | §3.5                            |
| -------------- | --------------------------------- | -------------------------------------- | ------------------------------- | ------------------------------- |
| `PLAINTEXT_2`  | `(C_R, ID_CRED_R, TH_2, EAD_2)`   | `(C_R, ID_CRED_R, SIGNATURE_2, EAD_2)` | `(C_R, ID_CRED_R, TH_2, EAD_2)` | `(C_R, ID_CRED_R, TH_2, EAD_2)` |
| `PLAINTEXT_2A` | `(PLAINTEXT_2, SIGNATURE_2)`      | _(not used)_                           | _(not used)_                    | `(PLAINTEXT_2, SIGNATURE_2)`    |
| `PLAINTEXT_3`  | `(ID_CRED_I, SIGNATURE_3, EAD_3)` | `(ID_CRED_I, TH_3, EAD_3)`             | `(ID_CRED_I, TH_3, EAD_3)`      | `(ID_CRED_I, TH_3, EAD_3)`      |
| `PLAINTEXT_3A` | _(not used)_                      | `(PLAINTEXT_3, SIGNATURE_3)`           | `(PLAINTEXT_3, SIGNATURE_3)`    | `(PLAINTEXT_3, SIGNATURE_3)`    |

Two different conventions for "the thing that is encrypted" sit in adjacent sections. In §3.2
the signature is _inside_ `PLAINTEXT_3`; in §3.3–3.5 it is in `PLAINTEXT_3A`. `PLAINTEXT_2` in
§3.3 contains `SIGNATURE_2` and omits `TH_2`; everywhere else it contains `TH_2` and omits the
signature.

The consequence lands in the transcript hash. §3.2.2.6 computes
`TH_4 = H(TH_3, PLAINTEXT_3, ID_CRED_I)` while §3.3.2.4 computes
`TH_4 = H(TH_3, PLAINTEXT_3A, ID_CRED_I)` — the same transcript position over the same bytes,
under two different names. A reader who carries §3.2's definition forward computes the wrong
`TH_4` _and_ the wrong `PLAINTEXT_2`, and nothing warns them.

**Proposed:** pick one convention and apply it in all four variants. Either always use the
`_A` suffix for "authenticator appended", or never introduce it and list the fields explicitly
per variant.

---

## 3. Internal contradictions in operative text

### CA-3 — message_3's field order contradicts itself, and §3.2's order is unimplementable

- §3.2.2.3: "The third message is then composed of: `CIPHERTEXT_3`; `kem.ct_R`."
- §3.4.2.3: "The third message is then composed of: `kem.ct_R`; `CIPHERTEXT_3`."
- §3.5.2.3: "The third message is then composed of: `kem.ct_R`; `CIPHERTEXT_3`."

The same message, in opposite orders, in sibling sections. §3.2's figure shows
`kem.ct_R, AEAD(...)`, so §3.2's prose also contradicts §3.2's own figure.

This is not cosmetic. The Responder must read `kem.ct_R` and decapsulate it to derive
`PRK_3e2m` **before** it can decrypt `CIPHERTEXT_3`. The order §3.2 states is the one that
cannot be parsed without buffering the whole message and working backwards from a length that
is not given.

**Proposed:** `kem.ct_R` first, everywhere, and say why — the receiver needs it to derive the
key that decrypts what follows.

_(Distinct from D3, which concerns `PLAINTEXT_2`'s internal field order in §3.3.)_

### CA-4 — §3.5 derives `PRK_4e3m`, uses it, then excludes it from the session key

§3.5.2.4, one paragraph, verbatim: `PRK_4e3m = EDHOC_Extract(SALT_4e3m, ss_I)`, then
`K_4`/`IV_4` from `PRK_4e3m`, then
`PRK_out = EDHOC_KDF(PRK_3e2m, 7, TH_4, hash_length)`.

The Initiator's KEM contribution is derived, used to protect message_4, and then dropped from
the output key. §3.5.3 says `PRK_4e3m`. §3.4.2.4 — an otherwise identical paragraph — says
`PRK_4e3m`.

_(This is D1, now confirmed in the operative prose rather than only the summary table. The
locations are §3.5.2.4 and §3.5.3.)_

### CA-5 — "Optionally" in the heading, "mandatory" in the sentence

§3.2.2.5 is titled "Optionally formatting, sending and receiving message_4" and opens: "If the
Responder decides of a fourth **mandatory** message". The reader cannot tell whether §3.2's
message_4 is optional, or mandatory once elected, or something else.

### CA-6 — three of four variants drop `MAC_3` entirely, and it is not forced

- §3.2.2.3: `MAC_3 = EDHOC_KDF(PRK_3e2m, 6, ID_CRED_I, TH_3, EAD_3, mac_length_3)`, and
  `SIGNATURE_3 = DS.Sign(sign.sk_I, (ID_CRED_I, TH_3, EAD_3, MAC_3, sign_length))`.
- §3.3.2.3, §3.4.2.3, §3.5.2.3: `SIGNATURE_3 = DS.Sign(sign.sk_I, (PLAINTEXT_3, sign_length))`.
  **No `MAC_3` appears anywhere in these variants.**

RFC 9528 signs a `MAC_3` so that the Initiator's signature is bound to the derived keys, not
only to the transcript. `PLAINTEXT_3 = (ID_CRED_I, TH_3, EAD_3)` contains no secret-derived
material, so in §3.3–3.5 `SIGNATURE_3` attests to the transcript alone.

**This correction matters for `pq_edhoc_section3.md`.** That document's central finding argues
the draft's varying signature inputs are _forced_ by the KEM's non-interactivity. That holds
for `MAC_2` — a Responder authenticating by KEM genuinely has no derived key at message_2. It
does **not** hold for `MAC_3` in §3.3 and §3.5, where the Initiator does hold `PRK_3e2m` at
message_3 and could key a `MAC_3` with it. Omitting it there is a free choice the draft never
explains, and the "everything is forced" framing must be narrowed to `MAC_2`.

**Proposed:** either restore `MAC_3` in §3.3–3.5 keyed by the most-derived PRK available, or
state explicitly that the binding to derived keys is intentionally dropped and why it is safe.

### CA-7 — `SALT_4e3m` silently changes base from RFC 9528

RFC 9528: `SALT_4e3m = EDHOC-KDF(PRK_3e2m, 5, TH_3, hash_length)`.
Draft, §3.3.2.4 / §3.4.2.4 / §3.5.2.4: over **`TH_4`**, not `TH_3`.

The change is never flagged. It is defensible — `ss_I` only arrives at message_4, so binding
the fuller transcript is reasonable — but a reader working from RFC 9528 will not notice, and
the two choices are not interoperable.

_(Noted against ourselves: the lakers prototype followed RFC 9528 and used `TH_3`. It is
self-consistent across both roles, so lakers interoperates with itself but would not
interoperate with a draft-faithful implementation. This belongs in
`pq_edhoc_section3.md` §6.)_

### CA-8 — "the Initiator is properly authenticated to the Initiator"

In §3.2.2.4 and again in §3.3.2.4. In subsections whose entire subject is which party proves
what to which other party, a reversed role name is a comprehension hazard rather than a
typographical one — the sentence reads as coherent and is wrong.

### CA-9 — "as in the original EDHOC protocol", attached to a formula that is not

§3.2.2.3 gives `MAC_3 = EDHOC_KDF(PRK_3e2m, 6, …)` and appends "as in the original EDHOC
protocol". RFC 9528 keys `MAC_3` with `PRK_4e3m`. The reassurance contradicts the formula
beside it, and a reader who trusts the prose over the formula will implement RFC 9528's
version and fail to interoperate.

---

## 4. Operations that cannot be performed from the text

### CA-10 — `EDHOC_KDF` is never defined and is called with three different arities

| Call site | Arguments                                                               |
| --------- | ----------------------------------------------------------------------- |
| §3.2.2.2  | `EDHOC_KDF(PRK_2e, 0, TH_2, plaintext_length)` — 4                      |
| §3.2.2.3  | `EDHOC_KDF(PRK_3e2m, 6, ID_CRED_I, TH_3, EAD_3, mac_length_3)` — 6      |
| §3.4.2.4  | `EDHOC_KDF(PRK_4e3m, 2, C_R, ID_CRED_R, TH_4, EAD_4, mac_length_2)` — 7 |

RFC 9528's is invariably `EDHOC-KDF(PRK, label, context, length)`. The draft is evidently
flattening a `context` tuple into the argument list, but never says so, never defines
`EDHOC_KDF`, and never states how the tuple is serialised — CBOR sequence, CBOR array, or
plain concatenation. The draft is also inconsistent with itself: §3.3 has been read as using a
named `context_2 = (…)` form alongside the flattened one.

Three implementers will produce three different MAC values from the same inputs and none will
interoperate. This is the single most consequential under-specification in §3 after the
missing code points.

**Proposed:** define `EDHOC_KDF` once, in §1.2, with RFC 9528's four-argument signature, and
write every call as `EDHOC_KDF(PRK, label, context_x, length)` with `context_x` defined
separately and its CBOR encoding given.

### CA-11 — `DS.Sign`'s definition contradicts every call site

§1.2.2 defines it as taking "a signing secret key `sign.sk` and a message `m`". Every use in
§3 passes a pair whose second element is a length:

> `SIGNATURE_2 = DS.Sign(sign.sk_R, (PLAINTEXT_2, sign_length))`
> `DS.Verify(sign.pk_R, (PLAINTEXT_2, sign_length), SIGNATURE_2)`

`sign_length` is an output-size parameter of the signature scheme, not message content. Is it
part of the signed message or not? The two readings produce different signatures. The same
applies to `DS.Verify`.

**Proposed:** if `sign_length` is a parameter, write `DS.Sign(sign.sk_R, PLAINTEXT_2)` and
state the signature length in the cipher-suite definition. If it is signed data, say so in
§1.2.2 and give its encoding.

### CA-12 — the central design decision of §3 is described by an unnamed placeholder

§3.1, verbatim:

> To do this, the Responder signs **an element** (which should not be chosen randomly for
> security reasons and which must allow the Initiator to identify the session) and sends it
> directly (encrypted) in the second message.

The element is never named in §3.1. The security requirement carries no normative keyword and
no rationale — "should not be chosen randomly for security reasons" states a constraint and
withholds the reason for it. §3.1 is where a reader decides whether the whole approach is
sound, and on its own terms it cannot be evaluated.

### CA-13 — the promised size analysis never appears

§3.1: "we will provide a bytes analysis for this message later", and a second, near-identical
promise elsewhere in the document. **No byte or message-size analysis appears anywhere in the
document.**

This matters more than a missing appendix. §3.1's own argument is that the approach trades
computation for message count, and it concedes "the delicate point remains the size of the
second message". The missing analysis is the missing justification for the entire section.

_(Measured from the lakers implementation, §3.2's message_2 is 3196 bytes with credentials by
reference and no EAD. See `pq_edhoc_section3.md` §7.)_

### CA-14 — IANA Considerations is an empty heading

With no method code points and no cipher suite registrations, no two implementations can
negotiate any variant in §3. _(D5, D6, D7.)_

---

## 5. Language that changes meaning

### CA-15 — "We decline this procedure when…"

§3.1. This is French _décliner_ — "to produce variants of". An English reader parses "decline"
as "refuse", which inverts the sentence: the draft is saying it _applies_ the procedure to the
remaining two cases, not that it declines to. It is the sentence that introduces §3.3–3.5.

### CA-16 — §3.1's remaining prose problems

| Quotation                                                                                     | Problem                                                                                                                                                                                                                                                         |
| --------------------------------------------------------------------------------------------- | --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| "The rest of the protocol remains 'unchanged'."                                               | Scare quotes concede the statement is inaccurate without saying what changed.                                                                                                                                                                                   |
| "The costs of calculations are compensated."                                                  | The central claim of the section, unquantified, with no comparison figures anywhere.                                                                                                                                                                            |
| "Things get complicated when trying to apply these modifications to the other three methods." | The pivot the whole of §3 rests on, hand-waved. _Why_ the other methods are hard — a KEM is not non-interactive, so a role authenticating by KEM has no derived key at the point RFC 9528 expects one — is the interesting content and is never stated plainly. |
| "even if this still needs to be proved"                                                       | An admission that the post-quantum security of the substitution is unproven, delivered as a mid-sentence parenthetical rather than in Security Considerations.                                                                                                  |
| "the number of mandatory messages … decreases from 5 to 4"                                    | §3.1 closes on a 5→4 comparison while the headline claim for §3.2 is three messages. Two baselines in one section.                                                                                                                                              |

### CA-17 — anthropomorphic and inconsistent role pronouns

"he", "his", "himself" throughout for both roles, mixed with "it" in the same sentence:
"The Responder selects **its** Connection Identifier as specified in [RFC9528]. **He** then
computes…". RFC style is "it" for a protocol role. Pervasive; low impact individually, but it
compounds CA-8's role confusion.

### CA-18 — two competing identifier schemes for the same five protocols

§4 opens: "we number the protocols from 1 to 5 according to their order of appearance in the
document (if necessary)". The rest of the document refers to them by section number. "If
necessary" leaves it unclear whether the numbering is ever in force. A reader of §4 cannot map
a claim onto a variant with confidence.

_(§4.1–4.5 could not be retrieved and are not audited here.)_

---

## 6. Summary, in the order the authors should address them

| #                | Finding                                                         | Why it comes first                             |
| ---------------- | --------------------------------------------------------------- | ---------------------------------------------- |
| CA-10            | `EDHOC_KDF` undefined, three arities                            | Silently produces non-interoperable MACs       |
| CA-11            | `DS.Sign` definition contradicts all call sites                 | Silently produces non-interoperable signatures |
| CA-3             | message_3 field order self-contradictory; §3.2's is unparseable | Blocks implementation of §3.2                  |
| CA-2             | `PLAINTEXT_2`/`PLAINTEXT_3` redefined between sections          | Wrong `TH_4`, wrong `PLAINTEXT_2`              |
| CA-4             | §3.5 excludes `PRK_4e3m` from `PRK_out`                         | Wrong session key; contradicts §3.5.3          |
| CA-6             | `MAC_3` absent from three variants, unexplained                 | Drops RFC 9528's key binding                   |
| CA-7             | `SALT_4e3m` over `TH_4`, change unflagged                       | Silent divergence from RFC 9528                |
| CA-1             | Four near-duplicate narratives                                  | Root cause of CA-2, CA-3, CA-4                 |
| CA-13            | Promised size analysis absent                                   | Removes the justification for §3               |
| CA-12            | "an element" never named                                        | §3.1 not evaluable on its own terms            |
| CA-14            | IANA section empty                                              | Nothing can be negotiated                      |
| CA-5, CA-8, CA-9 | optional/mandatory; role reversal; false "as in the original"   | Each reads as coherent and is wrong            |
| CA-15–CA-18      | Language and consistency                                        | Cumulative drag on comprehension               |

---

## 7. What this audit did not cover

- **§4.1–4.5 Security Considerations.** Could not be retrieved in full; only the opening
  paragraph was available. The blanket claim that "At the end of each handshake, both
  endpoints: securely compute the session key `PRK_out`; securely authenticate their partner"
  sits uneasily with §3.4, whose Responder is unauthenticated until message_4, and with §3.2,
  whose message_4 is optional — but the subsections may qualify it. Worth a dedicated pass.
- **Figures.** Read earlier in prose form only. CA-3 relies on a figure reading that should be
  re-checked against the rendered document before the finding is sent.
- **§2**, the PQ-EDHOC-IKR proposal. Out of scope; this audit covers §1.2 and §3.
- **Typography and spelling.** Out of scope by request, except where a wording choice changes
  meaning (CA-8, CA-15).
