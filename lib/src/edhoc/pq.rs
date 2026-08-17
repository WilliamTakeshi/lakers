//! Post-quantum authentication, per draft-papon-lake-pq-edhoc §3.
//!
//! A fourth sibling to [`sig`](super::sig), [`stat`](super::stat) and [`psk`](super::psk),
//! exposing the same protocol-step functions and returning the same intermediate structs.
//!
//! Unlike those three, one module covers all four §3 variants. The draft's variants are
//! exactly the four useful points in the cross product of
//! [`PqAuthMode`]`{ Sign, Kem, KemSign }` per role, so each function takes the mode of the
//! role it is acting for rather than there being a module per variant.
//!
//! # Which PRK keys the MAC
//!
//! The draft signs different things in different variants — `PLAINTEXT_2` raw in §3.2/§3.5, a
//! `MAC_2` in §3.3 — and that is forced rather than arbitrary. A Responder authenticating by
//! KEM cannot key `MAC_2` with `PRK_3e2m` at message_2, because `ss_R` does not exist until
//! the Initiator encapsulates and sends `kem.ct_R` in message_3.
//!
//! This implementation keeps RFC 9528's COSE `Sig_structure` over a hash-length MAC in every
//! variant, and varies only *which* PRK keys that MAC: the most-derived one actually available
//! to the signer at that point. For message_2 that is `PRK_2e` when the Responder uses a KEM
//! and `PRK_3e2m` otherwise. See `pq_edhoc_section3.md` §4.

use super::{
    compute_mac_2, compute_mac_3, compute_salt_3e2m, compute_th_3, compute_th_4,
    decrypt_message_3_pq, encode_plaintext_2, encode_plaintext_3, encode_sig_structure,
    encrypt_message_3_pq, strip_kem_ct_r, BufferMessage3, BytesHashLen, BytesMacSig, ConnId,
    Credential, CredentialKey, CredentialTransfer, Crypto as CryptoTrait, DecodedMessage2,
    EDHOCError, EadItems, ParsedMessage2Details, ParsedMessage3, PreparedMessage2,
    PreparedMessage3, ProcessedM2, ProcessedM2MethodSpecifics, ProcessingM2,
    ProcessingM2MethodSpecifics, ProcessingM3, ProcessingM3MethodSpecifics, Th4Input,
    VerifiedMessage3, VerifiedPeerMessage2, WaitM3, WaitM3MethodSpecifics,
};
use lakers_shared::{
    decode_plaintext_2_pqsig, decode_plaintext_3_pqsig, BytesKemDecapsKey, BytesKemEncapsKey,
    BytesPqSignKey, BytesPqVerifyKey, PqAuthMode,
};

/// A peer's public key material, split out of its credential according to its mode.
///
/// A mode/credential disagreement is caught here rather than deeper in: a peer that is
/// supposed to sign but whose credential carries no ML-DSA key cannot authenticate at all.
/// Both roles use this -- nothing about it is role-specific.
fn credential_keys(
    cred: &Credential,
    mode: PqAuthMode,
) -> Result<(Option<BytesKemEncapsKey>, Option<BytesPqVerifyKey>), EDHOCError> {
    let (kem, dsa) = match cred.key {
        CredentialKey::MlKem(kem) => (Some(kem), None),
        CredentialKey::MlDsa(dsa) => (None, Some(dsa)),
        CredentialKey::MlKemMlDsa { kem, dsa } => (Some(kem), Some(dsa)),
        // FIXME: not an error so much as a lack of agreement between peers.
        _ => return Err(EDHOCError::UnsupportedMethod),
    };

    if (mode.uses_kem() && kem.is_none()) || (mode.signs() && dsa.is_none()) {
        return Err(EDHOCError::UnsupportedMethod);
    }

    Ok((kem, dsa))
}

/// Build the Responder's message_2 plaintext.
///
/// `prk_2e` is both the keying material for `MAC_2` and what the Responder carries forward:
/// when it authenticates by KEM it has nothing more derived yet.
#[allow(clippy::too_many_arguments)]
pub(crate) fn r_prepare_message_2_pq(
    crypto: &mut impl CryptoTrait,
    cred_r: Credential,
    dsa_sk: Option<&BytesPqSignKey>,
    kem_dk: Option<&BytesKemDecapsKey>,
    c_r: ConnId,
    cred_transfer: CredentialTransfer,
    ead_2: &EadItems,
    th_2: &BytesHashLen,
    prk_2e: &BytesHashLen,
    i_mode: PqAuthMode,
    r_mode: PqAuthMode,
) -> Result<PreparedMessage2, EDHOCError> {
    let (_kem_pk, _dsa_pk) = credential_keys(&cred_r, r_mode)?;

    let id_cred_r = match cred_transfer {
        CredentialTransfer::ByValue => cred_r.by_value()?,
        CredentialTransfer::ByReference => cred_r.by_kid()?,
    };

    let signature_2 = if r_mode.signs() {
        let dsa_sk = dsa_sk.ok_or(EDHOCError::MissingIdentity)?;

        let mac_2: BytesMacSig = compute_mac_2(
            crypto,
            prk_2e,
            c_r,
            id_cred_r.as_full_value(),
            cred_r.bytes.as_slice(),
            th_2,
            ead_2,
        );

        let sig_structure = encode_sig_structure(
            id_cred_r.as_full_value(),
            th_2,
            cred_r.bytes.as_slice(),
            ead_2,
            &mac_2,
        )?;

        Some(crypto.mldsa_sign(dsa_sk, sig_structure.as_slice())?)
    } else {
        // §3.4: the Responder authenticates by KEM alone, and its MAC_2 is deferred to
        // message_4 where PRK_4e3m finally exists.
        None
    };

    let plaintext_2 = match &signature_2 {
        Some(signature_2) => encode_plaintext_2(
            c_r,
            Some((id_cred_r.as_encoded_value(), &(*signature_2).into())),
            ead_2,
        )?,
        None => encode_plaintext_2(c_r, None, ead_2)?,
    };

    let th_3 = compute_th_3(crypto, th_2, &plaintext_2, Some(cred_r.bytes.as_slice()));

    Ok(PreparedMessage2 {
        plaintext_2,
        // Not PRK_3e2m: when the Responder uses a KEM that does not exist yet. The Pq
        // method-specifics below carry PRK_2e explicitly for message_3 to derive from.
        prk_3e2m: *prk_2e,
        th_3,
        method_specifics: WaitM3MethodSpecifics::Pq {
            i_mode,
            r_mode,
            prk_2e: *prk_2e,
            th_2: *th_2,
            kem_dk: kem_dk.copied(),
        },
    })
}

/// Decrypt and decode message_3, deriving `PRK_3e2m` from its `kem.ct_R` prefix first.
///
/// This is the Responder's half of the step the Initiator took in
/// [`i_verify_message_2_pq`]: it is only now, one message later, that `ss_R` reaches the role
/// whose static key defines it.
///
/// Note what ML-KEM's implicit rejection means here: `kem_decapsulate` never reports failure,
/// it returns an unpredictable shared secret for a bad ciphertext. A tampered `kem.ct_R` is
/// therefore caught by the AEAD tag on CIPHERTEXT_3, not by decapsulation, and surfaces as
/// [`EDHOCError::MacVerificationFailed`].
pub(crate) fn r_parse_message_3_pq(
    state: &WaitM3,
    crypto: &mut impl CryptoTrait,
    message_3: &BufferMessage3,
) -> Result<ParsedMessage3, EDHOCError> {
    let WaitM3MethodSpecifics::Pq {
        i_mode,
        r_mode,
        prk_2e,
        th_2,
        kem_dk,
    } = &state.method_specifics
    else {
        // FIXME: not an error so much as a lack of agreement between peers.
        return Err(EDHOCError::UnsupportedMethod);
    };

    let (prk_3e2m, ciphertext_part) = if r_mode.uses_kem() {
        let kem_dk = kem_dk.as_ref().ok_or(EDHOCError::MissingIdentity)?;
        let (kem_ct_r, rest) = strip_kem_ct_r(message_3)?;
        let ss_r = crypto.kem_decapsulate(kem_dk, &kem_ct_r)?;
        let salt_3e2m = compute_salt_3e2m(crypto, prk_2e, th_2);
        (crypto.hkdf_extract(&salt_3e2m, &ss_r), rest)
    } else {
        // §3.3: the Responder only signs, so the ladder passed through at message_2 and
        // message_3 has RFC 9528's shape.
        (*prk_2e, message_3.clone())
    };

    let plaintext_3 = decrypt_message_3_pq(crypto, &prk_3e2m, &state.th_3, &ciphertext_part)?;

    // Every §3 variant has the Initiator sign message_3, whether or not it also uses a KEM.
    let (id_cred_i, signature_3, ead_3) = decode_plaintext_3_pqsig(&plaintext_3)?;

    Ok(ParsedMessage3 {
        method_specifics: ProcessingM3MethodSpecifics::Pq {
            i_mode: *i_mode,
            signature_3,
            id_cred_i: id_cred_i.clone(),
        },
        id_cred: id_cred_i,
        plaintext_3,
        ead_3,
        prk_3e2m: Some(prk_3e2m),
    })
}

pub(crate) fn i_parse_message_2_pq(
    plaintext_2: &super::BufferPlaintext2,
    r_mode: PqAuthMode,
) -> Result<DecodedMessage2, EDHOCError> {
    if r_mode.signs() {
        let (c_r, id_cred_r, signature_2, ead_2) = decode_plaintext_2_pqsig(plaintext_2)?;
        Ok(DecodedMessage2 {
            method_specifics: ProcessingM2MethodSpecifics::Pq {
                r_mode,
                signature_2: Some(signature_2),
                id_cred_r: id_cred_r.clone(),
            },
            c_r,
            parsed_details: ParsedMessage2Details::Pq { id_cred_r },
            ead_2,
        })
    } else {
        // §3.4: PLAINTEXT_2 carries no authenticator at all, but still an ID_CRED_R -- the
        // Initiator needs it to know which key to encapsulate to.
        let (c_r, id_cred_r, _mac, ead_2) = lakers_shared::decode_plaintext_2(plaintext_2)?;
        Ok(DecodedMessage2 {
            method_specifics: ProcessingM2MethodSpecifics::Pq {
                r_mode,
                signature_2: None,
                id_cred_r: id_cred_r.clone(),
            },
            c_r,
            parsed_details: ParsedMessage2Details::Pq { id_cred_r },
            ead_2,
        })
    }
}

/// Verify the Responder and take the Initiator's half of the static KEM step.
///
/// The encapsulation happens here rather than at message_3 because this is the first moment
/// the Initiator knows `ID_CRED_R`, and therefore the Responder's static KEM key. The
/// resulting ciphertext has to be carried forward and sent in message_3.
pub(crate) fn i_verify_message_2_pq(
    state: &ProcessingM2,
    crypto: &mut impl CryptoTrait,
    valid_cred_r: Credential,
) -> Result<VerifiedPeerMessage2, EDHOCError> {
    let (r_mode, signature_2, id_cred_r) = match &state.method_specifics {
        ProcessingM2MethodSpecifics::Pq {
            r_mode,
            signature_2,
            id_cred_r,
        } => (*r_mode, signature_2, id_cred_r),
        // FIXME: the error is not accurate. It is a lack of agreement between peers.
        _ => return Err(EDHOCError::UnsupportedMethod),
    };

    let (kem_pk, dsa_pk) = credential_keys(&valid_cred_r, r_mode)?;

    if r_mode.signs() {
        let dsa_pk = dsa_pk.ok_or(EDHOCError::UnsupportedMethod)?;
        let signature_2 = signature_2.as_ref().ok_or(EDHOCError::ParsingError)?;

        // Keyed by PRK_2e, not PRK_3e2m: see the module comment.
        let mac_2: BytesMacSig = compute_mac_2(
            crypto,
            &state.prk_2e,
            state.c_r,
            id_cred_r.as_full_value(),
            valid_cred_r.bytes.as_slice(),
            &state.th_2,
            &state.ead_2,
        );

        let sig_structure = encode_sig_structure(
            id_cred_r.as_full_value(),
            &state.th_2,
            valid_cred_r.bytes.as_slice(),
            &state.ead_2,
            &mac_2,
        )?;

        if !crypto
            .mldsa_verify(&dsa_pk, sig_structure.as_slice(), signature_2)
            .unwrap_or(false)
        {
            return Err(EDHOCError::MacVerificationFailed);
        }
    }

    let (prk_3e2m, kem_ct_r) = if r_mode.uses_kem() {
        let kem_pk = kem_pk.ok_or(EDHOCError::UnsupportedMethod)?;
        let (ss_r, ct_r) = crypto.kem_encapsulate(&kem_pk)?;
        let salt_3e2m = compute_salt_3e2m(crypto, &state.prk_2e, &state.th_2);
        (crypto.hkdf_extract(&salt_3e2m, &ss_r), Some(ct_r))
    } else {
        // The Responder only signs, so the ladder passes through, as in RFC 9528.
        (state.prk_2e, None)
    };

    let th_3 = compute_th_3(
        crypto,
        &state.th_2,
        &state.plaintext_2,
        Some(valid_cred_r.bytes.as_slice()),
    );

    Ok(VerifiedPeerMessage2 {
        prk_3e2m,
        th_3,
        kem_ct_r,
    })
}

/// Sign `MAC_3` with ML-DSA and send it, with `kem.ct_R` in front when the Responder
/// authenticates by KEM.
///
/// The MAC is keyed by `state.prk_4e3m`, which the caller has already resolved per the
/// normalization rule: `PRK_3e2m` when the Initiator only signs (§3.2, where the ladder passes
/// through exactly as in RFC 9528's signature methods), and — once §3.3–3.5 land — `PRK_3e2m`
/// again when it also uses a KEM, because `ss_I` is still a message away.
pub(crate) fn i_prepare_message_3_pq(
    state: &ProcessedM2,
    crypto: &mut impl CryptoTrait,
    cred_i: Credential,
    cred_transfer: CredentialTransfer,
    ead_3: &EadItems,
) -> Result<PreparedMessage3, EDHOCError> {
    let ProcessedM2MethodSpecifics::Pq {
        i_mode,
        kem_ct_r,
        dsa_sk,
    } = &state.method_specifics
    else {
        // FIXME: not an error so much as a lack of agreement between peers.
        return Err(EDHOCError::UnsupportedMethod);
    };

    // An Initiator that also authenticates by KEM cannot finish its ladder here; `PRK_4e3m`
    // waits on message_4's kem.ct_I. Rejected until the deferred-PRK_out work lands.
    if i_mode.uses_kem() {
        return Err(EDHOCError::UnsupportedMethod);
    }
    let dsa_sk = dsa_sk.as_ref().ok_or(EDHOCError::MissingIdentity)?;

    let id_cred_i = match cred_transfer {
        CredentialTransfer::ByValue => cred_i.by_value()?,
        CredentialTransfer::ByReference => cred_i.by_kid()?,
    };

    let mac_3: BytesMacSig = compute_mac_3(
        crypto,
        &state.prk_4e3m,
        &state.th_3,
        id_cred_i.as_full_value(),
        cred_i.bytes.as_slice(),
        ead_3,
    );

    let sig_structure = encode_sig_structure(
        id_cred_i.as_full_value(),
        &state.th_3,
        cred_i.bytes.as_slice(),
        ead_3,
        &mac_3,
    )?;

    let signature_3 = crypto.mldsa_sign(dsa_sk, sig_structure.as_slice())?;

    let plaintext_3 = encode_plaintext_3(
        Some((id_cred_i.as_encoded_value(), &signature_3.into())),
        ead_3,
    )?;

    let message_3 = encrypt_message_3_pq(
        crypto,
        &state.prk_3e2m,
        &state.th_3,
        &plaintext_3,
        kem_ct_r.as_ref(),
    )?;

    let th_4 = compute_th_4(
        crypto,
        &state.th_3,
        cred_i.bytes.as_slice(),
        Th4Input::Stat {
            plaintext_3: &plaintext_3,
        },
    );

    Ok(PreparedMessage3 { message_3, th_4 })
}

/// Verify `SIGNATURE_3` and close the transcript.
///
/// `TH_4` is `H(TH_3, PLAINTEXT_3, CRED_I)`, reused verbatim from the classical signature
/// path: `CRED_I` rather than `ID_CRED_I`, which is divergence D2 in `pq_edhoc_section3.md`.
pub(crate) fn r_verify_message_3_pq(
    state: &ProcessingM3,
    crypto: &mut impl CryptoTrait,
    valid_cred_i: Credential,
) -> Result<VerifiedMessage3, EDHOCError> {
    let ProcessingM3MethodSpecifics::Pq {
        i_mode,
        signature_3,
        id_cred_i,
    } = &state.method_specifics
    else {
        // FIXME: not an error so much as a lack of agreement between peers.
        return Err(EDHOCError::UnsupportedMethod);
    };

    // Mirrors the Initiator's refusal above: with a KEM in play `PRK_4e3m` is not derivable
    // until message_4 has delivered kem.ct_I.
    if i_mode.uses_kem() {
        return Err(EDHOCError::UnsupportedMethod);
    }
    let prk_4e3m = state.prk_3e2m;

    let (_kem_pk, dsa_pk) = credential_keys(&valid_cred_i, *i_mode)?;
    let dsa_pk = dsa_pk.ok_or(EDHOCError::UnsupportedMethod)?;

    let mac_3: BytesMacSig = compute_mac_3(
        crypto,
        &prk_4e3m,
        &state.th_3,
        id_cred_i.as_full_value(),
        valid_cred_i.bytes.as_slice(),
        &state.ead_3,
    );

    let sig_structure = encode_sig_structure(
        id_cred_i.as_full_value(),
        &state.th_3,
        valid_cred_i.bytes.as_slice(),
        &state.ead_3,
        &mac_3,
    )?;

    if !crypto
        .mldsa_verify(&dsa_pk, sig_structure.as_slice(), signature_3)
        .unwrap_or(false)
    {
        return Err(EDHOCError::MacVerificationFailed);
    }

    let th_4 = compute_th_4(
        crypto,
        &state.th_3,
        valid_cred_i.bytes.as_slice(),
        Th4Input::Stat {
            plaintext_3: &state.plaintext_3,
        },
    );

    Ok(VerifiedMessage3 { prk_4e3m, th_4 })
}
