use super::{
    compute_mac_2, compute_mac_3, compute_prk_3e2m, compute_prk_4e3m, compute_salt_3e2m,
    compute_salt_4e3m, compute_th_3, compute_th_4, decode_plaintext_2, decode_plaintext_2_sized,
    decode_plaintext_3, decode_plaintext_3_sized, decrypt_message_3, encode_plaintext_2,
    encode_plaintext_3, encode_sig_structure, encrypt_message_3, BufferMessage3,
    BufferPlaintext2, BytesHashLen, BytesMac2, BytesMac3, BytesMacSig, ConnId, Credential,
    CredentialKey, CredentialTransfer, DecodedMessage2, EDHOCError, EDHOCMethod, EadItems,
    InitiatorIdentity, ParsedMessage2Details, ParsedMessage3, PrepareMessage2Details,
    PreparedMessage2, PreparedMessage3, ProcessedM2, ProcessedM2MethodSpecifics, ProcessingM1,
    ProcessingM2, ProcessingM2MethodSpecifics, ProcessingM3, ProcessingM3MethodSpecifics,
    SignatureOrMac, Th4Input, VerifiedMessage2, VerifiedMessage3, WaitM3, WaitM3MethodSpecifics,
    SIGNATURE_LENGTH,
};
use lakers_shared::Crypto as CryptoTrait;

pub(crate) fn r_prepare_message_2_peer_auth(
    state: &ProcessingM1,
    crypto: &mut impl CryptoTrait,
    cred_r: Credential,
    method_details: PrepareMessage2Details<'_>,
    c_r: ConnId,
    ead_2: &EadItems,
    th_2: &BytesHashLen,
    prk_2e: &BytesHashLen,
) -> Result<PreparedMessage2, EDHOCError> {
    let cred_transfer = match method_details {
        PrepareMessage2Details::SigSig { cred_transfer, .. }
        | PrepareMessage2Details::StatStat { cred_transfer, .. } => cred_transfer,
        // FIXME: the error is not accurate. It is a lack of agreement between peers.
        PrepareMessage2Details::Psk => return Err(EDHOCError::UnsupportedMethod),
    };

    let id_cred_r = match cred_transfer {
        CredentialTransfer::ByValue => cred_r.by_value()?,
        CredentialTransfer::ByReference => cred_r.by_kid()?,
    };

    let (prk_3e2m, sig_or_mac_2, method_specifics) = match method_details {
        PrepareMessage2Details::StatStat { r, .. } => {
            // compute prk_3e2m
            let salt_3e2m = compute_salt_3e2m(crypto, prk_2e, th_2);
            let prk_3e2m = compute_prk_3e2m(crypto, &salt_3e2m, r, &state.g_x);

            // compute MAC_2
            let mac_2: BytesMac2 = compute_mac_2(
                crypto,
                &prk_3e2m,
                c_r,
                id_cred_r.as_full_value(),
                cred_r.bytes.as_slice(),
                th_2,
                ead_2,
            );

            (
                prk_3e2m,
                SignatureOrMac::new(mac_2),
                WaitM3MethodSpecifics::StatStat {},
            )
        }
        PrepareMessage2Details::SigSig { sk_r, .. } => {
            // no static ECDH: PRK_3e2m is PRK_2e directly
            let prk_3e2m = *prk_2e;

            // compute MAC_2 (hash-length, to be signed rather than sent directly)
            let mac_2: BytesMacSig = compute_mac_2(
                crypto,
                &prk_3e2m,
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
            let signature_2 = crypto.p256_ecdsa_sign(sk_r, sig_structure.as_slice())?;

            (
                prk_3e2m,
                SignatureOrMac::new(signature_2),
                WaitM3MethodSpecifics::SigSig {},
            )
        }
        // FIXME: the error is not accurate. It is a lack of agreement between peers.
        PrepareMessage2Details::Psk => return Err(EDHOCError::UnsupportedMethod),
    };

    // compute ciphertext_2
    let plaintext_2 = encode_plaintext_2(
        c_r,
        Some((id_cred_r.as_encoded_value(), &sig_or_mac_2)),
        ead_2,
    )?;
    // step is actually from processing of message_3
    // but we do it here to avoid storing plaintext_2 in State
    let th_3 = compute_th_3(crypto, th_2, &plaintext_2, Some(cred_r.bytes.as_slice()));

    Ok(PreparedMessage2 {
        plaintext_2,
        prk_3e2m,
        th_3,
        method_specifics,
    })
}

pub(crate) fn r_parse_message_3_peer_auth(
    state: &WaitM3,
    crypto: &mut impl CryptoTrait,
    message_3: &BufferMessage3,
) -> Result<ParsedMessage3, EDHOCError> {
    let plaintext_3 = decrypt_message_3(crypto, &state.prk_3e2m, &state.th_3, message_3, None)?;

    match &state.method_specifics {
        WaitM3MethodSpecifics::StatStat {} => {
            let (id_cred_i, mac_3, ead_3) = decode_plaintext_3(&plaintext_3)?;
            Ok(ParsedMessage3 {
                method_specifics: ProcessingM3MethodSpecifics::StatStat {
                    mac_3,
                    id_cred_i: id_cred_i.clone(), // needed for compute_mac_3
                },
                id_cred: id_cred_i,
                plaintext_3, // NOTE: this is needed for th_4, which needs valid_cred_i, which is only available at the 'verify' step
                ead_3,
            })
        }
        WaitM3MethodSpecifics::SigSig {} => {
            let (id_cred_i, signature_3, ead_3) =
                decode_plaintext_3_sized::<SIGNATURE_LENGTH>(&plaintext_3)?;
            Ok(ParsedMessage3 {
                method_specifics: ProcessingM3MethodSpecifics::SigSig {
                    signature_3,
                    id_cred_i: id_cred_i.clone(),
                },
                id_cred: id_cred_i,
                plaintext_3,
                ead_3,
            })
        }
        // FIXME: the error is not accurate. It is a lack of agreement between peers.
        WaitM3MethodSpecifics::Psk { .. } => Err(EDHOCError::UnsupportedMethod),
    }
}

pub(crate) fn r_verify_message_3_peer_auth(
    state: &ProcessingM3,
    crypto: &mut impl CryptoTrait,
    valid_cred_i: Credential,
) -> Result<VerifiedMessage3, EDHOCError> {
    let public_key = match valid_cred_i.key {
        CredentialKey::EC2Compact(public_key) => public_key,
        // FIXME: the error is not accurate. It is a lack of agreement between peers.
        _ => return Err(EDHOCError::UnsupportedMethod),
    };

    match &state.method_specifics {
        ProcessingM3MethodSpecifics::StatStat { mac_3, id_cred_i } => {
            let salt_4e3m = compute_salt_4e3m(crypto, &state.prk_3e2m, &state.th_3);
            let prk_4e3m = compute_prk_4e3m(crypto, &salt_4e3m, &state.y, &public_key);

            // compute mac_3
            let expected_mac_3: BytesMac3 = compute_mac_3(
                crypto,
                &prk_4e3m,
                &state.th_3,
                id_cred_i.as_full_value(),
                valid_cred_i.bytes.as_slice(),
                &state.ead_3,
            );

            // verify mac_3
            if *mac_3 == expected_mac_3 {
                let th_4 = compute_th_4(
                    crypto,
                    &state.th_3,
                    valid_cred_i.bytes.as_slice(),
                    Th4Input::Stat {
                        plaintext_3: &state.plaintext_3,
                    },
                );

                Ok(VerifiedMessage3 { prk_4e3m, th_4 })
            } else {
                Err(EDHOCError::MacVerificationFailed)
            }
        }
        ProcessingM3MethodSpecifics::SigSig {
            signature_3,
            id_cred_i,
        } => {
            // no static ECDH: PRK_4e3m is PRK_3e2m directly, salt_4e3m is unused
            let prk_4e3m = state.prk_3e2m;

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

            let verified = crypto
                .p256_ecdsa_verify(&public_key, sig_structure.as_slice(), signature_3)
                .unwrap_or(false);

            if verified {
                let th_4 = compute_th_4(
                    crypto,
                    &state.th_3,
                    valid_cred_i.bytes.as_slice(),
                    Th4Input::Stat {
                        plaintext_3: &state.plaintext_3,
                    },
                );

                Ok(VerifiedMessage3 { prk_4e3m, th_4 })
            } else {
                Err(EDHOCError::MacVerificationFailed)
            }
        }
        // FIXME: the error is not accurate. It is a lack of agreement between peers.
        ProcessingM3MethodSpecifics::Psk { .. } => Err(EDHOCError::UnsupportedMethod),
    }
}

pub(crate) fn i_parse_message_2_peer_auth(
    method: EDHOCMethod,
    plaintext_2: &BufferPlaintext2,
) -> Result<DecodedMessage2, EDHOCError> {
    match method {
        EDHOCMethod::StatStat => {
            let (c_r, id_cred_r, mac_2, ead_2) = decode_plaintext_2(plaintext_2)?;
            Ok(DecodedMessage2 {
                method_specifics: ProcessingM2MethodSpecifics::StatStat {
                    mac_2,
                    id_cred_r: id_cred_r.clone(),
                },
                c_r,
                parsed_details: ParsedMessage2Details::StatStat { id_cred_r },
                ead_2,
            })
        }
        EDHOCMethod::SigSig => {
            let (c_r, id_cred_r, signature_2, ead_2) =
                decode_plaintext_2_sized::<SIGNATURE_LENGTH>(plaintext_2)?;
            Ok(DecodedMessage2 {
                method_specifics: ProcessingM2MethodSpecifics::SigSig {
                    signature_2,
                    id_cred_r: id_cred_r.clone(),
                },
                c_r,
                parsed_details: ParsedMessage2Details::SigSig { id_cred_r },
                ead_2,
            })
        }
        // FIXME: the error is not accurate. It is a lack of agreement between peers.
        _ => Err(EDHOCError::UnsupportedMethod),
    }
}

pub(crate) fn i_verify_message_2_peer_auth(
    state: &ProcessingM2,
    crypto: &mut impl CryptoTrait,
    valid_cred_r: Credential,
    identity: InitiatorIdentity,
) -> Result<VerifiedMessage2, EDHOCError> {
    let public_key = match valid_cred_r.key {
        CredentialKey::EC2Compact(public_key) => public_key,
        // FIXME: the error is not accurate. It is a lack of agreement between peers.
        _ => return Err(EDHOCError::UnsupportedMethod),
    };

    match (&state.method_specifics, identity) {
        (
            ProcessingM2MethodSpecifics::StatStat { id_cred_r, mac_2 },
            InitiatorIdentity::StatStat { i },
        ) => {
            // verify mac_2
            let salt_3e2m = compute_salt_3e2m(crypto, &state.prk_2e, &state.th_2);
            let prk_3e2m = compute_prk_3e2m(crypto, &salt_3e2m, &state.x, &public_key);

            let expected_mac_2: BytesMac2 = compute_mac_2(
                crypto,
                &prk_3e2m,
                state.c_r,
                id_cred_r.as_full_value(),
                valid_cred_r.bytes.as_slice(),
                &state.th_2,
                &state.ead_2,
            );

            if *mac_2 == expected_mac_2 {
                // step is actually from processing of message_3
                // but we do it here to avoid storing plaintext_2 in State
                let th_3 = compute_th_3(
                    crypto,
                    &state.th_2,
                    &state.plaintext_2,
                    Some(valid_cred_r.bytes.as_slice()),
                );
                let salt_4e3m = compute_salt_4e3m(crypto, &prk_3e2m, &th_3);
                let prk_4e3m = compute_prk_4e3m(crypto, &salt_4e3m, &i, &state.g_y);

                Ok(VerifiedMessage2 {
                    method_specifics: ProcessedM2MethodSpecifics::StatStat {},
                    prk_3e2m,
                    prk_4e3m,
                    th_3,
                })
            } else {
                Err(EDHOCError::MacVerificationFailed)
            }
        }
        (
            ProcessingM2MethodSpecifics::SigSig {
                id_cred_r,
                signature_2,
            },
            InitiatorIdentity::SigSig { sk_i },
        ) => {
            // no static ECDH: PRK_3e2m is PRK_2e directly
            let prk_3e2m = state.prk_2e;

            let mac_2: BytesMacSig = compute_mac_2(
                crypto,
                &prk_3e2m,
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

            let verified = crypto
                .p256_ecdsa_verify(&public_key, sig_structure.as_slice(), signature_2)
                .unwrap_or(false);

            if verified {
                let th_3 = compute_th_3(
                    crypto,
                    &state.th_2,
                    &state.plaintext_2,
                    Some(valid_cred_r.bytes.as_slice()),
                );
                // no static ECDH: PRK_4e3m is PRK_3e2m directly
                let prk_4e3m = prk_3e2m;

                Ok(VerifiedMessage2 {
                    // the initiator's signing key is needed again when producing Signature_or_MAC_3
                    method_specifics: ProcessedM2MethodSpecifics::SigSig { sk_i },
                    prk_3e2m,
                    prk_4e3m,
                    th_3,
                })
            } else {
                Err(EDHOCError::MacVerificationFailed)
            }
        }
        // FIXME: it is not an error, but more a lack of agreement between peers.
        _ => Err(EDHOCError::MissingIdentity),
    }
}

pub(crate) fn i_prepare_message_3_peer_auth(
    state: &ProcessedM2,
    crypto: &mut impl CryptoTrait,
    cred_i: Credential,
    cred_transfer: CredentialTransfer,
    ead_3: &EadItems,
) -> Result<PreparedMessage3, EDHOCError> {
    let id_cred_i = match cred_transfer {
        CredentialTransfer::ByValue => cred_i.by_value()?,
        CredentialTransfer::ByReference => cred_i.by_kid()?,
    };

    let sig_or_mac_3 = match &state.method_specifics {
        ProcessedM2MethodSpecifics::StatStat {} => {
            let mac_3: BytesMac3 = compute_mac_3(
                crypto,
                &state.prk_4e3m,
                &state.th_3,
                id_cred_i.as_full_value(),
                cred_i.bytes.as_slice(),
                ead_3,
            );
            SignatureOrMac::new(mac_3)
        }
        ProcessedM2MethodSpecifics::SigSig { sk_i } => {
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
            let signature_3 = crypto.p256_ecdsa_sign(sk_i, sig_structure.as_slice())?;
            SignatureOrMac::new(signature_3)
        }
        // FIXME: the error is not accurate. It is a lack of agreement between peers.
        ProcessedM2MethodSpecifics::Psk { .. } => return Err(EDHOCError::UnsupportedMethod),
    };

    let plaintext_3 = encode_plaintext_3(Some((id_cred_i.as_encoded_value(), &sig_or_mac_3)), ead_3)?;
    let message_3 = encrypt_message_3(crypto, &state.prk_3e2m, &state.th_3, &plaintext_3, None)?;

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
