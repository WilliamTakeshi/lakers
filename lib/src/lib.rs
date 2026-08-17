//! Implementation of [EDHOC] (Ephemeral Diffie-Hellman Over COSE, RFC9528), a lightweight authenticated key
//! exchange for the Internet of Things.
//!
//! The crate provides a high-level interface through the [EdhocInitiator] and the [EdhocResponder]
//! structs. Both these wrap the lower level [State] struct that is mainly used through internal
//! functions in the `edhoc` module. This separation is relevant because the lower level tools are
//! subject of ongoing formal verification, whereas the high-level interfaces aim for good
//! usability.
//!
//! Both [EdhocInitiator] and [EdhocResponder] are used in a type stated way. Following the EDHOC
//! protocol, they generate (or process) messages, progressively provide more information about
//! their peer, and on eventually devolve into an [EdhocInitiatorDone] and [EdhocResponderDone],
//! respectively, through which the EDHOC key material can be obtained.
//!
//! [EDHOC]: https://datatracker.ietf.org/doc/html/rfc9528
#![cfg_attr(not(test), no_std)]

use defmt_or_log::trace;
pub use {lakers_shared::Crypto as CryptoTrait, lakers_shared::*};

mod edhoc;
pub use edhoc::*;

/// Starting point for performing EDHOC in the role of the Initiator.
#[derive(Debug)]
pub struct EdhocInitiator<Crypto: CryptoTrait> {
    state: InitiatorStart,        // opaque state
    i: Option<InitiatorIdentity>, // static authentication identity of I when required by method
    cred_i: Option<Credential>,
    crypto: Crypto,
}

#[derive(Debug)]
pub struct EdhocInitiatorWaitM2<Crypto: CryptoTrait> {
    state: WaitM2, // opaque state
    i: Option<InitiatorIdentity>,
    cred_i: Option<Credential>,
    crypto: Crypto,
}

#[derive(Debug)]
pub struct EdhocInitiatorProcessingM2<Crypto: CryptoTrait> {
    state: ProcessingM2, // opaque state
    method: EDHOCMethod,
    i: Option<InitiatorIdentity>,
    cred_i: Option<Credential>,
    crypto: Crypto,
}

#[derive(Debug)]
pub struct EdhocInitiatorProcessedM2<Crypto: CryptoTrait> {
    state: ProcessedM2, // opaque state
    cred_i: Option<Credential>,
    crypto: Crypto,
}

#[derive(Debug)]
pub struct EdhocInitiatorWaitM4<Crypto: CryptoTrait> {
    state: WaitM4, // opaque state
    crypto: Crypto,
}

#[derive(Debug)]
pub struct EdhocInitiatorDone<Crypto: CryptoTrait> {
    state: Completed,
    crypto: Crypto,
}

/// Starting point for performing EDHOC in the role of the Responder.
#[derive(Debug)]
pub struct EdhocResponder<Crypto: CryptoTrait> {
    state: ResponderStart, // opaque state
    r: ResponderIdentity,  // private authentication key of R when required by method
    cred_r: Credential,    // R's full credential
    crypto: Crypto,
}

#[derive(Debug)]
pub struct EdhocResponderProcessedM1<Crypto: CryptoTrait> {
    state: ProcessingM1,  // opaque state
    r: ResponderIdentity, // private authentication key of R when required by method
    cred_r: Credential,   // R's full credential
    crypto: Crypto,
}

#[derive(Debug)]
pub struct EdhocResponderWaitM3<Crypto: CryptoTrait> {
    state: WaitM3, // opaque state
    crypto: Crypto,
}

#[derive(Debug)]
pub struct EdhocResponderProcessingM3<Crypto: CryptoTrait> {
    state: ProcessingM3, // opaque state
    crypto: Crypto,
}

#[derive(Debug)]
pub struct EdhocResponderProcessedM3<Crypto: CryptoTrait> {
    state: ProcessedM3, // opaque state
    crypto: Crypto,
}

#[derive(Debug)]
pub struct EdhocResponderDone<Crypto: CryptoTrait> {
    state: Completed,
    crypto: Crypto,
}

/// The post-quantum private keys of one role.
///
/// Which keys are present *is* the [`PqAuthMode`], exactly as it is for the public side in
/// [`CredentialKey`]: there is no separate mode field to disagree with the key material, so a
/// "signs but holds no signing key" identity cannot be constructed.
///
/// Note the size: an ML-KEM-512 decapsulation key is 1632 bytes and an ML-DSA-44 signing key
/// 2560, so the `KemSign` case is a ~4.2 kB value that the typestate chain moves around.
/// Acceptable for a host-side prototype, not for the embedded targets.
#[cfg(feature = "pq")]
#[derive(Debug)]
pub enum PqIdentity {
    Kem {
        kem_dk: BytesKemDecapsKey,
    },
    Sign {
        dsa_sk: BytesPqSignKey,
    },
    KemSign {
        kem_dk: BytesKemDecapsKey,
        dsa_sk: BytesPqSignKey,
    },
}

#[cfg(feature = "pq")]
impl PqIdentity {
    pub fn mode(&self) -> PqAuthMode {
        match self {
            PqIdentity::Kem { .. } => PqAuthMode::Kem,
            PqIdentity::Sign { .. } => PqAuthMode::Sign,
            PqIdentity::KemSign { .. } => PqAuthMode::KemSign,
        }
    }

    pub fn kem_dk(&self) -> Option<&BytesKemDecapsKey> {
        match self {
            PqIdentity::Kem { kem_dk } | PqIdentity::KemSign { kem_dk, .. } => Some(kem_dk),
            PqIdentity::Sign { .. } => None,
        }
    }

    pub fn dsa_sk(&self) -> Option<&BytesPqSignKey> {
        match self {
            PqIdentity::Sign { dsa_sk } | PqIdentity::KemSign { dsa_sk, .. } => Some(dsa_sk),
            PqIdentity::Kem { .. } => None,
        }
    }
}

#[derive(Debug)]
pub enum ResponderIdentity {
    Signature {
        r: BytesP256ElemLen,
    },
    StaticDh {
        r: BytesP256ElemLen,
    },
    Psk,
    #[cfg(feature = "pq")]
    Pq(PqIdentity),
}

#[derive(Debug)]
pub enum InitiatorIdentity {
    Signature {
        i: BytesP256ElemLen,
    },
    StaticDh {
        i: BytesP256ElemLen,
    },
    Psk,
    #[cfg(feature = "pq")]
    Pq(PqIdentity),
}

#[cfg(feature = "pq")]
impl InitiatorIdentity {
    fn pq_mode(&self) -> Option<PqAuthMode> {
        match self {
            InitiatorIdentity::Pq(identity) => Some(identity.mode()),
            _ => None,
        }
    }
}

/// Rejects an identity whose authentication method disagrees with the EDHOC method
/// announced in message_1.
fn check_initiator_identity(
    method: EDHOCMethod,
    identity: &InitiatorIdentity,
) -> Result<(), EDHOCError> {
    // A post-quantum method fixes each role's mode, so the check is that the identity supplies
    // exactly the key material that mode needs. Handled before the classical table so that a
    // PQ method paired with a classical identity, or the reverse, falls through to the error.
    #[cfg(feature = "pq")]
    if let Some((initiator_mode, _)) = method.pq_modes() {
        return match identity.pq_mode() {
            Some(mode) if mode == initiator_mode => Ok(()),
            _ => Err(EDHOCError::MissingIdentity),
        };
    }

    match (method, identity) {
        (EDHOCMethod::SigSig | EDHOCMethod::SigStat, InitiatorIdentity::Signature { .. })
        | (EDHOCMethod::StatSig | EDHOCMethod::StatStat, InitiatorIdentity::StaticDh { .. })
        | (EDHOCMethod::PSK, InitiatorIdentity::Psk) => Ok(()),
        // FIXME: Distinguish `MissingIdentity` from `MethodIdentityMismatch` here;
        _ => Err(EDHOCError::MissingIdentity),
    }
}

/// The responder-side counterpart of [`check_initiator_identity`]: rejects an identity whose
/// authentication method disagrees with the method announced in message_1, and on success
/// produces the per-method details `r_prepare_message_2` needs.
///
/// This was inline in `prepare_message_2`; it is a function so the two role checks sit side by
/// side and can be tested without driving a handshake.
fn check_responder_identity<'a>(
    method: EDHOCMethod,
    identity: &'a ResponderIdentity,
    cred_transfer: CredentialTransfer,
) -> Result<PrepareMessage2Details<'a>, EDHOCError> {
    #[cfg(feature = "pq")]
    if let Some((_, responder_mode)) = method.pq_modes() {
        return match identity {
            ResponderIdentity::Pq(pq) if pq.mode() == responder_mode => {
                Ok(PrepareMessage2Details::Pq {
                    mode: responder_mode,
                    kem_dk: pq.kem_dk(),
                    dsa_sk: pq.dsa_sk(),
                    cred_transfer,
                })
            }
            _ => Err(EDHOCError::MissingIdentity),
        };
    }

    match (method, identity) {
        (EDHOCMethod::SigStat | EDHOCMethod::StatStat, ResponderIdentity::StaticDh { r }) => {
            Ok(PrepareMessage2Details::StaticDh { r, cred_transfer })
        }
        (EDHOCMethod::SigSig | EDHOCMethod::StatSig, ResponderIdentity::Signature { r }) => {
            Ok(PrepareMessage2Details::Signature { r, cred_transfer })
        }
        (EDHOCMethod::PSK, ResponderIdentity::Psk) => Ok(PrepareMessage2Details::Psk {}),
        // FIXME: Distinguish `MissingIdentity` from `MethodIdentityMismatch` here;
        _ => Err(EDHOCError::MissingIdentity), // or UnsupportedMethod
    }
}

impl<Crypto: CryptoTrait> EdhocResponder<Crypto> {
    pub fn new(mut crypto: Crypto, identity: ResponderIdentity, cred_r: Credential) -> Self {
        trace!("Initializing EdhocResponder");
        let (y, g_y) = crypto.p256_generate_key_pair();

        EdhocResponder {
            state: ResponderStart { y, g_y },
            r: identity,
            cred_r,
            crypto,
        }
    }

    pub fn process_message_1(
        mut self,
        message_1: &BufferMessage1,
    ) -> Result<(EdhocResponderProcessedM1<Crypto>, ConnId, EadItems), EDHOCError> {
        trace!("Enter process_message_1");
        let (state, c_i, ead_1) = r_process_message_1(&self.state, &mut self.crypto, message_1)?;

        Ok((
            EdhocResponderProcessedM1 {
                state,
                r: self.r,
                cred_r: self.cred_r,
                crypto: self.crypto,
            },
            c_i,
            ead_1,
        ))
    }
}

impl<Crypto: CryptoTrait> EdhocResponderProcessedM1<Crypto> {
    pub fn prepare_message_2(
        mut self,
        cred_transfer: CredentialTransfer,
        c_r: Option<ConnId>,
        ead_2: &EadItems,
    ) -> Result<(EdhocResponderWaitM3<Crypto>, BufferMessage2), EDHOCError> {
        trace!("Enter prepare_message_2");
        let c_r = match c_r {
            Some(c_r) => c_r,
            None => generate_connection_identifier_cbor(&mut self.crypto),
        };

        let method_details = check_responder_identity(self.state.method, &self.r, cred_transfer)?;

        match r_prepare_message_2(
            &self.state,
            &mut self.crypto,
            self.cred_r,
            method_details,
            c_r,
            ead_2,
        ) {
            Ok((state, message_2)) => Ok((
                EdhocResponderWaitM3 {
                    state,
                    crypto: self.crypto,
                },
                message_2,
            )),
            Err(error) => Err(error),
        }
    }
}

impl<'a, Crypto: CryptoTrait> EdhocResponderWaitM3<Crypto> {
    pub fn parse_message_3(
        mut self,
        message_3: &'a BufferMessage3,
    ) -> Result<(EdhocResponderProcessingM3<Crypto>, IdCred, EadItems), EDHOCError> {
        trace!("Enter parse_message_3");
        match r_parse_message_3(&mut self.state, &mut self.crypto, message_3) {
            Ok((state, id_cred_i, ead_3)) => Ok((
                EdhocResponderProcessingM3 {
                    state,
                    crypto: self.crypto,
                },
                id_cred_i,
                ead_3,
            )),
            Err(error) => Err(error),
        }
    }

    // Example of application of lookup
    // let cred_table = [cred_i_1.clone(), cred_i_2.clone()];
    // let (responder, id_cred_i, ead_3) =
    // responder_wait_m3.parse_message_3_with_credential_lookup(&message_3, |id| {
    // credential_lookup_or_fetch(&cred_table, id.clone())
    // })?;

    pub fn parse_message_3_with_credential_lookup<F>(
        mut self,
        message_3: &'a BufferMessage3,
        resolve_cred_i: F, // we pass a function to look up for the credential: credential_lookup_or_fetch
    ) -> Result<(EdhocResponderProcessingM3<Crypto>, IdCred, EadItems), EDHOCError>
    where
        F: Fn(&IdCred) -> Result<Credential, EDHOCError>,
    {
        trace!("Enter parse_message_3_with_credential_lookup");
        match r_parse_message_3_with_cred_resolver(
            &mut self.state,
            &mut self.crypto,
            message_3,
            resolve_cred_i,
        ) {
            Ok((state, id_cred_i, ead_3)) => Ok((
                EdhocResponderProcessingM3 {
                    state,
                    crypto: self.crypto,
                },
                id_cred_i,
                ead_3,
            )),
            Err(error) => Err(error),
        }
    }
}

impl<'a, Crypto: CryptoTrait> EdhocResponderProcessingM3<Crypto> {
    pub fn verify_message_3(
        mut self,
        cred_i: Credential,
    ) -> Result<(EdhocResponderProcessedM3<Crypto>, [u8; SHA256_DIGEST_LEN]), EDHOCError> {
        trace!("Enter verify_message_3");
        match r_verify_message_3(&mut self.state, &mut self.crypto, cred_i) {
            Ok((state, prk_out)) => Ok((
                EdhocResponderProcessedM3 {
                    state,
                    crypto: self.crypto,
                },
                prk_out,
            )),
            Err(error) => Err(error),
        }
    }
}

impl<Crypto: CryptoTrait> EdhocResponderProcessedM3<Crypto> {
    pub fn prepare_message_4(
        mut self,
        ead_4: &EadItems,
    ) -> Result<(EdhocResponderDone<Crypto>, BufferMessage4), EDHOCError> {
        trace!("Enter prepare_message_4");
        match r_prepare_message_4(&self.state, &mut self.crypto, ead_4) {
            Ok((state, message_4)) => Ok((
                EdhocResponderDone {
                    state,
                    crypto: self.crypto,
                },
                message_4,
            )),
            Err(error) => Err(error),
        }
    }

    pub fn completed_without_message_4(self) -> Result<EdhocResponderDone<Crypto>, EDHOCError> {
        trace!("Enter completed");
        match r_complete_without_message_4(&self.state) {
            Ok(state) => Ok(EdhocResponderDone {
                state,
                crypto: self.crypto,
            }),
            Err(error) => Err(error),
        }
    }
}

impl<Crypto: CryptoTrait> EdhocResponderDone<Crypto> {
    pub fn edhoc_exporter(&mut self, label: u8, context: &[u8], result: &mut [u8]) {
        edhoc_exporter(&self.state, &mut self.crypto, label, context, result);
    }

    pub fn edhoc_key_update(&mut self, context: &[u8]) -> [u8; SHA256_DIGEST_LEN] {
        edhoc_key_update(&mut self.state, &mut self.crypto, context)
    }
}

impl<'a, Crypto: CryptoTrait> EdhocInitiator<Crypto> {
    pub fn new(mut crypto: Crypto, method: EDHOCMethod, selected_suite: EDHOCSuite) -> Self {
        trace!("Initializing EdhocInitiator");
        let suites_i = prepare_suites_i(&crypto.supported_suites(), selected_suite.into()).unwrap();

        // A post-quantum method needs an ephemeral KEM key pair instead of a DH one. The
        // method is known here, unlike on the responder side where it only arrives in
        // message_1, so the right pair can be generated up front.
        #[cfg(feature = "pq")]
        let state = if method.pq_modes().is_some() {
            let (sk, pk) = crypto
                .kem_generate_key_pair()
                .expect("the backend advertised a post-quantum suite");
            InitiatorStart::new_pq(suites_i, method, KemEphemeral { sk, pk })
        } else {
            let (x, g_x) = crypto.p256_generate_key_pair();
            InitiatorStart::new_dh(suites_i, method, x, g_x)
        };
        #[cfg(not(feature = "pq"))]
        let state = {
            let (x, g_x) = crypto.p256_generate_key_pair();
            InitiatorStart::new_dh(suites_i, method, x, g_x)
        };

        EdhocInitiator {
            state,
            i: None,
            cred_i: None,
            crypto,
        }
    }

    pub fn set_identity(
        &mut self,
        identity: InitiatorIdentity,
        cred_i: Credential,
    ) -> Result<(), EDHOCError> {
        if self.i.is_some() || self.cred_i.is_some() {
            return Err(EDHOCError::IdentityAlreadySet);
        }
        check_initiator_identity(self.state.method, &identity)?;
        self.i = Some(identity);
        self.cred_i = Some(cred_i);
        Ok(())
    }

    pub fn prepare_message_1(
        mut self,
        c_i: Option<ConnId>,
        ead_1: &EadItems,
    ) -> Result<(EdhocInitiatorWaitM2<Crypto>, BufferMessage1), EDHOCError> {
        trace!("Enter prepare_message_1");
        let c_i = match c_i {
            Some(c_i) => c_i,
            None => generate_connection_identifier_cbor(&mut self.crypto),
        };

        match i_prepare_message_1(&self.state, &mut self.crypto, c_i, ead_1) {
            Ok((state, message_1)) => Ok((
                EdhocInitiatorWaitM2 {
                    state,
                    i: self.i,
                    cred_i: self.cred_i,
                    crypto: self.crypto,
                },
                message_1,
            )),
            Err(error) => Err(error),
        }
    }

    pub fn compute_ephemeral_secret(&mut self, g_a: &BytesP256ElemLen) -> BytesP256ElemLen {
        self.crypto.p256_ecdh(&self.state.x, g_a)
    }

    pub fn selected_cipher_suite(&self) -> u8 {
        self.state.suites_i[self.state.suites_i.len() - 1]
    }
}

impl<'a, Crypto: CryptoTrait> EdhocInitiatorWaitM2<Crypto> {
    pub fn parse_message_2(
        mut self,
        message_2: &'a BufferMessage2,
    ) -> Result<(EdhocInitiatorProcessingM2<Crypto>, ConnId, EadItems), EDHOCError> {
        trace!("Enter parse_message_2");
        match i_parse_message_2(&self.state, &mut self.crypto, message_2) {
            Ok((state, c_r, _details, ead_2)) => Ok((
                EdhocInitiatorProcessingM2 {
                    state,
                    method: self.state.method,
                    i: self.i,
                    cred_i: self.cred_i,
                    crypto: self.crypto,
                },
                c_r,
                ead_2,
            )),
            Err(error) => Err(error),
        }
    }
}

impl<'a, Crypto: CryptoTrait> EdhocInitiatorProcessingM2<Crypto> {
    pub fn set_identity(
        &mut self,
        identity: InitiatorIdentity,
        cred_i: Credential,
    ) -> Result<(), EDHOCError> {
        if self.i.is_some() || self.cred_i.is_some() {
            return Err(EDHOCError::IdentityAlreadySet);
        }
        check_initiator_identity(self.method, &identity)?;
        self.i = Some(identity);
        self.cred_i = Some(cred_i);
        Ok(())
    }

    pub fn verify_message_2(
        mut self,
        cred_expected: Option<Credential>,
    ) -> Result<EdhocInitiatorProcessedM2<Crypto>, EDHOCError> {
        trace!("Enter verify_message_2");
        let i = self.i.ok_or(EDHOCError::MissingIdentity)?;
        let valid_cred_r = match &self.state.method_specifics {
            ProcessingM2MethodSpecifics::Signature { id_cred_r, .. }
            | ProcessingM2MethodSpecifics::StaticDh { id_cred_r, .. } => {
                credential_check_or_fetch(cred_expected, id_cred_r.clone())?
            }
            ProcessingM2MethodSpecifics::Psk {} => {
                cred_expected.ok_or(EDHOCError::MissingIdentity)?
            }
        };
        match i_verify_message_2(&self.state, &mut self.crypto, valid_cred_r, i) {
            Ok(state) => Ok(EdhocInitiatorProcessedM2 {
                state,
                cred_i: self.cred_i,
                crypto: self.crypto,
            }),
            Err(error) => Err(error),
        }
    }
}

impl<'a, Crypto: CryptoTrait> EdhocInitiatorProcessedM2<Crypto> {
    pub fn prepare_message_3(
        mut self,
        cred_transfer: CredentialTransfer,
        ead_3: &EadItems,
    ) -> Result<
        (
            EdhocInitiatorWaitM4<Crypto>,
            BufferMessage3,
            [u8; SHA256_DIGEST_LEN],
        ),
        EDHOCError,
    > {
        trace!("Enter prepare_message_3");
        let Some(cred_i) = self.cred_i else {
            return Err(EDHOCError::MissingIdentity);
        };
        match i_prepare_message_3(
            &mut self.state,
            &mut self.crypto,
            cred_i,
            cred_transfer,
            ead_3,
        ) {
            Ok((state, message_3, prk_out)) => Ok((
                EdhocInitiatorWaitM4 {
                    state,
                    crypto: self.crypto,
                },
                message_3,
                prk_out,
            )),
            Err(error) => Err(error),
        }
    }
}

impl<'a, Crypto: CryptoTrait> EdhocInitiatorWaitM4<Crypto> {
    pub fn process_message_4(
        mut self,
        message_4: &'a BufferMessage4,
    ) -> Result<(EdhocInitiatorDone<Crypto>, EadItems), EDHOCError> {
        trace!("Enter parse_message_4");
        match i_process_message_4(&mut self.state, &mut self.crypto, message_4) {
            Ok((state, ead_4)) => Ok((
                EdhocInitiatorDone {
                    state: state,
                    crypto: self.crypto,
                },
                ead_4,
            )),
            Err(error) => Err(error),
        }
    }

    pub fn completed_without_message_4(self) -> Result<EdhocResponderDone<Crypto>, EDHOCError> {
        trace!("Enter completed");
        match i_complete_without_message_4(&self.state) {
            Ok(state) => Ok(EdhocResponderDone {
                state,
                crypto: self.crypto,
            }),
            Err(error) => Err(error),
        }
    }
}

impl<Crypto: CryptoTrait> EdhocInitiatorDone<Crypto> {
    pub fn edhoc_exporter(&mut self, label: u8, context: &[u8], result: &mut [u8]) {
        edhoc_exporter(&self.state, &mut self.crypto, label, context, result);
    }

    pub fn edhoc_key_update(&mut self, context: &[u8]) -> [u8; SHA256_DIGEST_LEN] {
        edhoc_key_update(&mut self.state, &mut self.crypto, context)
    }
}

pub fn generate_connection_identifier_cbor<Crypto: CryptoTrait>(crypto: &mut Crypto) -> ConnId {
    let c_i = generate_connection_identifier(crypto);
    #[allow(deprecated)]
    ConnId::from_int_raw(if c_i >= 0 && c_i <= 23 {
        c_i as u8 // verbatim encoding of single byte integer
    } else if c_i < 0 && c_i >= -24 {
        // negative single byte integer encoding
        CBOR_NEG_INT_1BYTE_START - 1 + c_i.unsigned_abs()
    } else {
        0
    })
}

/// generates an identifier that can be serialized as a single CBOR integer, i.e. -24 <= x <= 23
pub fn generate_connection_identifier<Crypto: CryptoTrait>(crypto: &mut Crypto) -> i8 {
    let mut conn_id = crypto.get_random_byte() as i8;
    while conn_id < -24 || conn_id > 23 {
        conn_id = crypto.get_random_byte() as i8;
    }
    conn_id
}

// Implements auth credential checking according to draft-tiloca-lake-implem-cons
pub fn credential_check_or_fetch(
    cred_expected: Option<Credential>,
    id_cred_received: IdCred,
) -> Result<Credential, EDHOCError> {
    trace!("Enter credential_check_or_fetch");
    // Processing of auth credentials according to draft-tiloca-lake-implem-cons
    // Comments tagged with a number refer to steps in Section 4.3.1. of draft-tiloca-lake-implem-cons
    if let Some(cred_expected) = cred_expected {
        // 1. Does ID_CRED_X point to a stored authentication credential? YES
        // IMPL: compare cred_i_expected with id_cred
        //   IMPL: assume cred_i_expected is well formed
        let credentials_match = if id_cred_received.reference_only() {
            id_cred_received.as_full_value() == cred_expected.by_kid()?.as_full_value()
        } else {
            id_cred_received.as_full_value() == cred_expected.by_value()?.as_full_value()
        };

        // 2. Is this authentication credential still valid?
        // IMPL,TODO: check cred_r_expected is still valid

        // Continue by considering CRED_X as the authentication credential of the other peer.
        // IMPL: ready to proceed, including process ead_2

        if credentials_match {
            Ok(cred_expected)
        } else {
            Err(EDHOCError::UnexpectedCredential)
        }
    } else {
        // 1. Does ID_CRED_X point to a stored authentication credential? NO
        // IMPL: cred_i_expected provided by application is None
        //       id_cred must be a full credential
        // 3. Is the trust model Pre-knowledge-only? NO (hardcoded to NO for now)
        // 4. Is the trust model Pre-knowledge + TOFU? YES (hardcoded to YES for now)
        // 6. Validate CRED_X. Generally a CCS has to be validated only syntactically and semantically, unlike a certificate or a CWT.
        //    Is the validation successful?
        // 5. Is the authentication credential authorized for use in the context of this EDHOC session?
        // IMPL,TODO: we just skip this step for now
        // 7. Store CRED_X as valid and trusted.
        //   Pair it with consistent credential identifiers, for each supported type of credential identifier.

        if let Some(cred) = id_cred_received.get_ccs() {
            Ok(cred)
        } else {
            Err(EDHOCError::ParsingError)
        }
    }

    // 8. Is this authentication credential good to use in the context of this EDHOC session?
    // IMPL,TODO: we just skip this step for now
}

/// Resolve an authentication credential from a local table of trusted credentials.
///
/// This is useful when receiving ID_CRED by reference (for example `kid`): each candidate
/// credential is converted to the matching ID_CRED form and compared against `id_cred_received`.
/// If no entry matches and `id_cred_received` carries a full CCS by value, that CCS is returned.
pub fn credential_lookup_or_fetch(
    credentials: &[Credential],
    id_cred_received: IdCred,
) -> Result<Credential, EDHOCError> {
    for cred in credentials {
        let candidate = if id_cred_received.reference_only() {
            cred.by_kid()
        } else {
            cred.by_value()
        };

        if let Ok(candidate) = candidate {
            if candidate.as_full_value() == id_cred_received.as_full_value() {
                return Ok(cred.clone());
            }
        }
    }

    if let Some(cred) = id_cred_received.get_ccs() {
        Ok(cred)
    } else {
        Err(EDHOCError::MissingIdentity)
    }
}

#[cfg(test)]
mod test_vectors_common {
    use hexlit::hex;
    use lakers_shared::*;

    pub const CRED_I: &[u8] = &hex!("A2027734322D35302D33312D46462D45462D33372D33322D333908A101A5010202412B2001215820AC75E9ECE3E50BFC8ED60399889522405C47BF16DF96660A41298CB4307F7EB62258206E5DE611388A4B8A8211334AC7D37ECB52A387D257E6DB3C2A93DF21FF3AFFC8");
    pub const I: &[u8] = &hex!("fb13adeb6518cee5f88417660841142e830a81fe334380a953406a1305e8706b");
    pub const R: &[u8] = &hex!("72cc4761dbd4c78f758931aa589d348d1ef874a7e303ede2f140dcf3e6aa4aac");
    pub const _G_I_Y_COORD: &[u8] =
        &hex!("6e5de611388a4b8a8211334ac7d37ecb52a387d257e6db3c2a93df21ff3affc8"); // not used
    pub const CRED_R: &[u8] = &hex!("A2026008A101A5010202410A2001215820BBC34960526EA4D32E940CAD2A234148DDC21791A12AFBCBAC93622046DD44F02258204519E257236B2A0CE2023F0931F1F386CA7AFDA64FCDE0108C224C51EABF6072");

    pub const MESSAGE_1_TV_FIRST_TIME: BufferMessage1 = BufferMessage1::new_from_array(&hex!(
        "03065820741a13d7ba048fbb615e94386aa3b61bea5b3d8f65f32620b749bee8d278efa90e"
    ));
    pub const MESSAGE_1_TV: BufferMessage1 = BufferMessage1::new_from_array(&hex!(
        "0382060258208af6f430ebe18d34184017a9a11bf511c8dff8f834730b96c1b7c8dbca2fc3b637"
    ));
}

#[cfg(test)]
mod test {
    use super::*;
    use hexlit::hex;
    use lakers_crypto::default_crypto;
    use test_vectors_common::*;
    #[cfg(feature = "test-ead-none")]
    const CRED_I_PSK: &[u8] =
        &hex!("A20269696E69746961746F7208A101A30104024110205050930FF462A77A3540CF546325DEA214");
    const CRED_R_PSK: &[u8] =
        &hex!("A20269726573706F6E64657208A101A30104024110205050930FF462A77A3540CF546325DEA214");

    #[test]
    fn test_new_initiator() {
        let _initiator = EdhocInitiator::new(
            default_crypto(),
            EDHOCMethod::StatStat,
            EDHOCSuite::CipherSuite2,
        );
    }

    #[test]
    fn test_new_responder() {
        let _responder = EdhocResponder::new(
            default_crypto(),
            ResponderIdentity::StaticDh {
                r: R.try_into().expect("Wrong length of responder private key"),
            },
            Credential::parse_ccs(CRED_R.try_into().unwrap()).unwrap(),
        );
    }

    #[test]
    fn test_prepare_message_1() {
        let initiator = EdhocInitiator::new(
            default_crypto(),
            EDHOCMethod::StatStat,
            EDHOCSuite::CipherSuite2,
        );

        let c_i = generate_connection_identifier_cbor(&mut default_crypto());
        let result = initiator.prepare_message_1(Some(c_i), &EadItems::new());
        assert!(result.is_ok());
    }

    #[test]
    fn test_process_message_1() {
        let responder = EdhocResponder::new(
            default_crypto(),
            ResponderIdentity::StaticDh {
                r: R.try_into().expect("Wrong length of responder private key"),
            },
            Credential::parse_ccs(CRED_R.try_into().unwrap()).unwrap(),
        );

        // process message_1 first time, when unsupported suite is selected
        let error = responder.process_message_1(&MESSAGE_1_TV_FIRST_TIME);
        assert!(error.is_err());
        assert_eq!(error.unwrap_err(), EDHOCError::UnsupportedCipherSuite);

        // We need to create a new responder -- no message is supposed to be processed twice by a
        // responder or initiator
        let responder = EdhocResponder::new(
            default_crypto(),
            ResponderIdentity::StaticDh {
                r: R.try_into().expect("Wrong length of responder private key"),
            },
            Credential::parse_ccs(CRED_R.try_into().unwrap()).unwrap(),
        );

        // process message_1 second time
        let error = responder.process_message_1(&MESSAGE_1_TV);
        assert!(error.is_ok());
    }

    #[test]
    fn test_generate_connection_identifier() {
        let conn_id = generate_connection_identifier(&mut default_crypto());
        assert!(conn_id >= -24 && conn_id <= 23);
    }

    #[cfg(feature = "test-ead-none")]
    #[test]
    fn test_handshake() {
        let cred_i = Credential::parse_ccs(CRED_I.try_into().unwrap()).unwrap();
        let cred_r = Credential::parse_ccs(CRED_R.try_into().unwrap()).unwrap();

        let initiator = EdhocInitiator::new(
            default_crypto(),
            EDHOCMethod::StatStat,
            EDHOCSuite::CipherSuite2,
        );

        let responder = EdhocResponder::new(
            default_crypto(),
            ResponderIdentity::StaticDh {
                r: R.try_into().expect("Wrong length of responder private key"),
            },
            cred_r.clone(),
        ); // has to select an identity before learning who is I

        // ---- begin initiator handling
        // if needed: prepare ead_1
        let (initiator, message_1) = initiator.prepare_message_1(None, &EadItems::new()).unwrap();
        // ---- end initiator handling

        // ---- begin responder handling
        let (responder, _c_i, _ead_1) = responder.process_message_1(&message_1).unwrap();
        // if ead_1: process ead_1
        // if needed: prepare ead_2
        let (responder, message_2) = responder
            .prepare_message_2(CredentialTransfer::ByReference, None, &EadItems::new())
            .unwrap();
        // ---- end responder handling

        // ---- being initiator handling
        let (mut initiator, _c_r, _ead_2) = initiator.parse_message_2(&message_2).unwrap();
        initiator
            .set_identity(
                InitiatorIdentity::StaticDh {
                    i: I.try_into().expect("Wrong length of initiator private key"),
                },
                cred_i.clone(),
            )
            .unwrap(); // exposing own identity only after validating cred_r
        let initiator = initiator.verify_message_2(Some(cred_r)).unwrap();

        // if needed: prepare ead_3
        let (initiator, message_3, i_prk_out) = initiator
            .prepare_message_3(CredentialTransfer::ByReference, &EadItems::new())
            .unwrap();
        // ---- end initiator handling

        // ---- begin responder handling
        let (responder, id_cred_i, _ead_3) = responder.parse_message_3(&message_3).unwrap();
        let valid_cred_i = credential_check_or_fetch(Some(cred_i), id_cred_i).unwrap();
        let (responder, r_prk_out) = responder.verify_message_3(valid_cred_i).unwrap();

        // Send message_4
        let (mut responder, message_4) = responder.prepare_message_4(&EadItems::new()).unwrap();
        // ---- end responder handling

        let (mut initiator, _ead_4) = initiator.process_message_4(&message_4).unwrap();
        // ---- end initiator handling

        // check that prk_out is equal at initiator and responder side
        assert_eq!(i_prk_out, r_prk_out);

        // derive OSCORE secret and salt at both sides and compare
        let mut i_oscore_secret = [0; 16];
        initiator.edhoc_exporter(0u8, &[], &mut i_oscore_secret); // label is 0
        let mut i_oscore_salt = [0; 8];
        initiator.edhoc_exporter(1u8, &[], &mut i_oscore_salt); // label is 1

        let mut r_oscore_secret = [0; 16];
        responder.edhoc_exporter(0u8, &[], &mut r_oscore_secret); // label is 0
        let mut r_oscore_salt = [0; 8];
        responder.edhoc_exporter(1u8, &[], &mut r_oscore_salt); // label is 1

        assert_eq!(i_oscore_secret, r_oscore_secret);
        assert_eq!(i_oscore_salt, r_oscore_salt);

        // test key update with context from draft-ietf-lake-traces
        let context = &[
            0xa0, 0x11, 0x58, 0xfd, 0xb8, 0x20, 0x89, 0x0c, 0xd6, 0xbe, 0x16, 0x96, 0x02, 0xb8,
            0xbc, 0xea,
        ];
        let i_prk_out_new = initiator.edhoc_key_update(context);
        let r_prk_out_new = responder.edhoc_key_update(context);

        assert_eq!(i_prk_out_new, r_prk_out_new);
    }

    #[cfg(feature = "test-ead-none")]
    #[test]
    fn test_handshake_psk() {
        let cred_i = Credential::parse_ccs_symmetric(CRED_I_PSK.try_into().unwrap()).unwrap();
        let cred_r = Credential::parse_ccs_symmetric(CRED_R_PSK.try_into().unwrap()).unwrap();

        let initiator =
            EdhocInitiator::new(default_crypto(), EDHOCMethod::PSK, EDHOCSuite::CipherSuite2);

        let responder =
            EdhocResponder::new(default_crypto(), ResponderIdentity::Psk, cred_r.clone());

        let (initiator, message_1) = initiator.prepare_message_1(None, &EadItems::new()).unwrap();

        let (responder, _c_i, _ead_1) = responder.process_message_1(&message_1).unwrap();
        let (responder, message_2) = responder
            .prepare_message_2(CredentialTransfer::ByReference, None, &EadItems::new())
            .unwrap();

        let (mut initiator, _c_r, _ead_2) = initiator.parse_message_2(&message_2).unwrap();
        initiator
            .set_identity(InitiatorIdentity::Psk, cred_i.clone())
            .unwrap();
        let initiator = initiator.verify_message_2(Some(cred_r)).unwrap();

        let (initiator, message_3, i_prk_out) = initiator
            .prepare_message_3(CredentialTransfer::ByReference, &EadItems::new())
            .unwrap();

        let (responder, id_cred_i, _ead_3) = responder
            .parse_message_3_with_credential_lookup(&message_3, |id| {
                credential_check_or_fetch(Some(cred_i.clone()), id.clone())
            })
            .unwrap();
        assert!(id_cred_i.reference_only());
        let (responder, r_prk_out) = responder.verify_message_3(cred_i.clone()).unwrap();

        let (mut responder, message_4) = responder.prepare_message_4(&EadItems::new()).unwrap();
        let (mut initiator, _ead_4) = initiator.process_message_4(&message_4).unwrap();

        assert_eq!(i_prk_out, r_prk_out);

        let mut i_oscore_secret = [0; 16];
        initiator.edhoc_exporter(0u8, &[], &mut i_oscore_secret);
        let mut i_oscore_salt = [0; 8];
        initiator.edhoc_exporter(1u8, &[], &mut i_oscore_salt);

        let mut r_oscore_secret = [0; 16];
        responder.edhoc_exporter(0u8, &[], &mut r_oscore_secret);
        let mut r_oscore_salt = [0; 8];
        responder.edhoc_exporter(1u8, &[], &mut r_oscore_salt);

        assert_eq!(i_oscore_secret, r_oscore_secret);
        assert_eq!(i_oscore_salt, r_oscore_salt);
    }

    #[cfg(feature = "test-ead-none")]
    #[test]
    fn test_handshake_sigsig() {
        let cred_i = Credential::parse_ccs(CRED_I.try_into().unwrap()).unwrap();
        let cred_r = Credential::parse_ccs(CRED_R.try_into().unwrap()).unwrap();

        let initiator = EdhocInitiator::new(
            default_crypto(),
            EDHOCMethod::SigSig,
            EDHOCSuite::CipherSuite2,
        );

        let responder = EdhocResponder::new(
            default_crypto(),
            ResponderIdentity::Signature {
                r: R.try_into().expect("Wrong length of responder private key"),
            },
            cred_r.clone(),
        ); // has to select an identity before learning who is I

        let (initiator, message_1) = initiator.prepare_message_1(None, &EadItems::new()).unwrap();

        let (responder, _c_i, _ead_1) = responder.process_message_1(&message_1).unwrap();
        let (responder, message_2) = responder
            .prepare_message_2(CredentialTransfer::ByReference, None, &EadItems::new())
            .unwrap();

        let (mut initiator, _c_r, _ead_2) = initiator.parse_message_2(&message_2).unwrap();
        initiator
            .set_identity(
                InitiatorIdentity::Signature {
                    i: I.try_into().expect("Wrong length of initiator private key"),
                },
                cred_i.clone(),
            )
            .unwrap(); // exposing own identity only after validating cred_r
        let initiator = initiator.verify_message_2(Some(cred_r)).unwrap();

        let (initiator, message_3, i_prk_out) = initiator
            .prepare_message_3(CredentialTransfer::ByReference, &EadItems::new())
            .unwrap();

        let (responder, id_cred_i, _ead_3) = responder.parse_message_3(&message_3).unwrap();
        let valid_cred_i = credential_check_or_fetch(Some(cred_i), id_cred_i).unwrap();
        let (responder, r_prk_out) = responder.verify_message_3(valid_cred_i).unwrap();

        let (mut responder, message_4) = responder.prepare_message_4(&EadItems::new()).unwrap();
        let (mut initiator, _ead_4) = initiator.process_message_4(&message_4).unwrap();

        // check that prk_out is equal at initiator and responder side
        assert_eq!(i_prk_out, r_prk_out);

        // derive OSCORE secret and salt at both sides and compare
        let mut i_oscore_secret = [0; 16];
        initiator.edhoc_exporter(0u8, &[], &mut i_oscore_secret);
        let mut i_oscore_salt = [0; 8];
        initiator.edhoc_exporter(1u8, &[], &mut i_oscore_salt);

        let mut r_oscore_secret = [0; 16];
        responder.edhoc_exporter(0u8, &[], &mut r_oscore_secret);
        let mut r_oscore_salt = [0; 8];
        responder.edhoc_exporter(1u8, &[], &mut r_oscore_salt);

        assert_eq!(i_oscore_secret, r_oscore_secret);
        assert_eq!(i_oscore_salt, r_oscore_salt);
    }

    #[cfg(feature = "test-ead-none")]
    #[test]
    fn test_handshake_sigsig_rejects_tampered_signature_2() {
        let cred_r = Credential::parse_ccs(CRED_R.try_into().unwrap()).unwrap();

        let initiator = EdhocInitiator::new(
            default_crypto(),
            EDHOCMethod::SigSig,
            EDHOCSuite::CipherSuite2,
        );

        let responder = EdhocResponder::new(
            default_crypto(),
            ResponderIdentity::Signature {
                r: R.try_into().expect("Wrong length of responder private key"),
            },
            cred_r.clone(),
        );

        let (initiator, message_1) = initiator.prepare_message_1(None, &EadItems::new()).unwrap();
        let (responder, _c_i, _ead_1) = responder.process_message_1(&message_1).unwrap();
        let (_responder, message_2) = responder
            .prepare_message_2(CredentialTransfer::ByReference, None, &EadItems::new())
            .unwrap();

        // flip the last byte of ciphertext_2, landing inside signature_2 (the field
        // immediately preceding EAD_2, which is absent here)
        let last = message_2.len() - 1;
        let mut bytes = message_2.as_slice().to_vec();
        bytes[last] ^= 0xff;
        let message_2 = BufferMessage2::new_from_slice(&bytes).unwrap();

        let (mut initiator, _c_r, _ead_2) = initiator.parse_message_2(&message_2).unwrap();
        initiator
            .set_identity(
                InitiatorIdentity::Signature {
                    i: I.try_into().expect("Wrong length of initiator private key"),
                },
                Credential::parse_ccs(CRED_I.try_into().unwrap()).unwrap(),
            )
            .unwrap();
        let error = initiator.verify_message_2(Some(cred_r)).unwrap_err();
        assert_eq!(error, EDHOCError::MacVerificationFailed);
    }

    #[cfg(feature = "test-ead-none")]
    #[test]
    fn test_handshake_sigstat() {
        let cred_i = Credential::parse_ccs(CRED_I.try_into().unwrap()).unwrap();
        let cred_r = Credential::parse_ccs(CRED_R.try_into().unwrap()).unwrap();

        let initiator = EdhocInitiator::new(
            default_crypto(),
            EDHOCMethod::SigStat,
            EDHOCSuite::CipherSuite2,
        );

        // the responder authenticates with a static DH key, the initiator with a signature
        let responder = EdhocResponder::new(
            default_crypto(),
            ResponderIdentity::StaticDh {
                r: R.try_into().expect("Wrong length of responder private key"),
            },
            cred_r.clone(),
        );

        let (initiator, message_1) = initiator.prepare_message_1(None, &EadItems::new()).unwrap();

        let (responder, _c_i, _ead_1) = responder.process_message_1(&message_1).unwrap();
        let (responder, message_2) = responder
            .prepare_message_2(CredentialTransfer::ByReference, None, &EadItems::new())
            .unwrap();

        let (mut initiator, _c_r, _ead_2) = initiator.parse_message_2(&message_2).unwrap();
        initiator
            .set_identity(
                InitiatorIdentity::Signature {
                    i: I.try_into().expect("Wrong length of initiator private key"),
                },
                cred_i.clone(),
            )
            .unwrap();
        let initiator = initiator.verify_message_2(Some(cred_r)).unwrap();

        let (initiator, message_3, i_prk_out) = initiator
            .prepare_message_3(CredentialTransfer::ByReference, &EadItems::new())
            .unwrap();

        let (responder, id_cred_i, _ead_3) = responder.parse_message_3(&message_3).unwrap();
        let valid_cred_i = credential_check_or_fetch(Some(cred_i), id_cred_i).unwrap();
        let (responder, r_prk_out) = responder.verify_message_3(valid_cred_i).unwrap();

        let (mut responder, message_4) = responder.prepare_message_4(&EadItems::new()).unwrap();
        let (mut initiator, _ead_4) = initiator.process_message_4(&message_4).unwrap();

        // check that prk_out is equal at initiator and responder side
        assert_eq!(i_prk_out, r_prk_out);

        // derive OSCORE secret and salt at both sides and compare
        let mut i_oscore_secret = [0; 16];
        initiator.edhoc_exporter(0u8, &[], &mut i_oscore_secret);
        let mut i_oscore_salt = [0; 8];
        initiator.edhoc_exporter(1u8, &[], &mut i_oscore_salt);

        let mut r_oscore_secret = [0; 16];
        responder.edhoc_exporter(0u8, &[], &mut r_oscore_secret);
        let mut r_oscore_salt = [0; 8];
        responder.edhoc_exporter(1u8, &[], &mut r_oscore_salt);

        assert_eq!(i_oscore_secret, r_oscore_secret);
        assert_eq!(i_oscore_salt, r_oscore_salt);
    }

    #[cfg(feature = "test-ead-none")]
    #[test]
    fn test_handshake_statsig() {
        let cred_i = Credential::parse_ccs(CRED_I.try_into().unwrap()).unwrap();
        let cred_r = Credential::parse_ccs(CRED_R.try_into().unwrap()).unwrap();

        let initiator = EdhocInitiator::new(
            default_crypto(),
            EDHOCMethod::StatSig,
            EDHOCSuite::CipherSuite2,
        );

        // the responder authenticates with a signature, the initiator with a static DH key
        let responder = EdhocResponder::new(
            default_crypto(),
            ResponderIdentity::Signature {
                r: R.try_into().expect("Wrong length of responder private key"),
            },
            cred_r.clone(),
        );

        let (initiator, message_1) = initiator.prepare_message_1(None, &EadItems::new()).unwrap();

        let (responder, _c_i, _ead_1) = responder.process_message_1(&message_1).unwrap();
        let (responder, message_2) = responder
            .prepare_message_2(CredentialTransfer::ByReference, None, &EadItems::new())
            .unwrap();

        let (mut initiator, _c_r, _ead_2) = initiator.parse_message_2(&message_2).unwrap();
        initiator
            .set_identity(
                InitiatorIdentity::StaticDh {
                    i: I.try_into().expect("Wrong length of initiator private key"),
                },
                cred_i.clone(),
            )
            .unwrap();
        let initiator = initiator.verify_message_2(Some(cred_r)).unwrap();

        let (initiator, message_3, i_prk_out) = initiator
            .prepare_message_3(CredentialTransfer::ByReference, &EadItems::new())
            .unwrap();

        let (responder, id_cred_i, _ead_3) = responder.parse_message_3(&message_3).unwrap();
        let valid_cred_i = credential_check_or_fetch(Some(cred_i), id_cred_i).unwrap();
        let (responder, r_prk_out) = responder.verify_message_3(valid_cred_i).unwrap();

        let (mut responder, message_4) = responder.prepare_message_4(&EadItems::new()).unwrap();
        let (mut initiator, _ead_4) = initiator.process_message_4(&message_4).unwrap();

        // check that prk_out is equal at initiator and responder side
        assert_eq!(i_prk_out, r_prk_out);

        // derive OSCORE secret and salt at both sides and compare
        let mut i_oscore_secret = [0; 16];
        initiator.edhoc_exporter(0u8, &[], &mut i_oscore_secret);
        let mut i_oscore_salt = [0; 8];
        initiator.edhoc_exporter(1u8, &[], &mut i_oscore_salt);

        let mut r_oscore_secret = [0; 16];
        responder.edhoc_exporter(0u8, &[], &mut r_oscore_secret);
        let mut r_oscore_salt = [0; 8];
        responder.edhoc_exporter(1u8, &[], &mut r_oscore_salt);

        assert_eq!(i_oscore_secret, r_oscore_secret);
        assert_eq!(i_oscore_salt, r_oscore_salt);
    }

    #[cfg(feature = "test-ead-none")]
    #[test]
    fn test_handshake_statsig_rejects_tampered_signature_2() {
        let cred_r = Credential::parse_ccs(CRED_R.try_into().unwrap()).unwrap();

        let initiator = EdhocInitiator::new(
            default_crypto(),
            EDHOCMethod::StatSig,
            EDHOCSuite::CipherSuite2,
        );

        let responder = EdhocResponder::new(
            default_crypto(),
            ResponderIdentity::Signature {
                r: R.try_into().expect("Wrong length of responder private key"),
            },
            cred_r.clone(),
        );

        let (initiator, message_1) = initiator.prepare_message_1(None, &EadItems::new()).unwrap();
        let (responder, _c_i, _ead_1) = responder.process_message_1(&message_1).unwrap();
        let (_responder, message_2) = responder
            .prepare_message_2(CredentialTransfer::ByReference, None, &EadItems::new())
            .unwrap();

        // flip the last byte of ciphertext_2, landing inside signature_2 (the field
        // immediately preceding EAD_2, which is absent here)
        let last = message_2.len() - 1;
        let mut bytes = message_2.as_slice().to_vec();
        bytes[last] ^= 0xff;
        let message_2 = BufferMessage2::new_from_slice(&bytes).unwrap();

        let (mut initiator, _c_r, _ead_2) = initiator.parse_message_2(&message_2).unwrap();
        initiator
            .set_identity(
                InitiatorIdentity::StaticDh {
                    i: I.try_into().expect("Wrong length of initiator private key"),
                },
                Credential::parse_ccs(CRED_I.try_into().unwrap()).unwrap(),
            )
            .unwrap();
        let error = initiator.verify_message_2(Some(cred_r)).unwrap_err();
        assert_eq!(error, EDHOCError::MacVerificationFailed);
    }

    #[cfg(feature = "test-ead-none")]
    #[test]
    fn test_sigstat_rejects_mismatched_initiator_identity() {
        let cred_i = Credential::parse_ccs(CRED_I.try_into().unwrap()).unwrap();
        let cred_r = Credential::parse_ccs(CRED_R.try_into().unwrap()).unwrap();
        let i: BytesP256ElemLen = I.try_into().expect("Wrong length of initiator private key");

        // method 1 authenticates the initiator with a signature, so a static DH identity
        // is rejected before message_1 is even prepared
        let mut initiator = EdhocInitiator::new(
            default_crypto(),
            EDHOCMethod::SigStat,
            EDHOCSuite::CipherSuite2,
        );
        let error = initiator
            .set_identity(InitiatorIdentity::StaticDh { i }, cred_i.clone())
            .unwrap_err();
        assert_eq!(error, EDHOCError::MissingIdentity);

        // and equally when the identity is only revealed after message_2 was validated
        let initiator = EdhocInitiator::new(
            default_crypto(),
            EDHOCMethod::SigStat,
            EDHOCSuite::CipherSuite2,
        );
        let responder = EdhocResponder::new(
            default_crypto(),
            ResponderIdentity::StaticDh {
                r: R.try_into().expect("Wrong length of responder private key"),
            },
            cred_r.clone(),
        );

        let (initiator, message_1) = initiator.prepare_message_1(None, &EadItems::new()).unwrap();
        let (responder, _c_i, _ead_1) = responder.process_message_1(&message_1).unwrap();
        let (_responder, message_2) = responder
            .prepare_message_2(CredentialTransfer::ByReference, None, &EadItems::new())
            .unwrap();

        let (mut initiator, _c_r, _ead_2) = initiator.parse_message_2(&message_2).unwrap();
        let error = initiator
            .set_identity(InitiatorIdentity::StaticDh { i }, cred_i)
            .unwrap_err();
        assert_eq!(error, EDHOCError::MissingIdentity);
    }

    /// Runs a handshake up to message_3 and reports the METHOD byte of message_1 along with
    /// the sizes of message_2 and message_3.
    #[cfg(feature = "test-ead-none")]
    fn handshake_wire_sizes(
        method: EDHOCMethod,
        r_identity: ResponderIdentity,
        i_identity: InitiatorIdentity,
    ) -> (u8, usize, usize) {
        let cred_i = Credential::parse_ccs(CRED_I.try_into().unwrap()).unwrap();
        let cred_r = Credential::parse_ccs(CRED_R.try_into().unwrap()).unwrap();

        let initiator = EdhocInitiator::new(default_crypto(), method, EDHOCSuite::CipherSuite2);
        let responder = EdhocResponder::new(default_crypto(), r_identity, cred_r.clone());

        let (initiator, message_1) = initiator.prepare_message_1(None, &EadItems::new()).unwrap();
        let method_byte = message_1.as_slice()[0];

        let (responder, _c_i, _ead_1) = responder.process_message_1(&message_1).unwrap();
        let (_responder, message_2) = responder
            .prepare_message_2(CredentialTransfer::ByReference, None, &EadItems::new())
            .unwrap();

        let (mut initiator, _c_r, _ead_2) = initiator.parse_message_2(&message_2).unwrap();
        initiator.set_identity(i_identity, cred_i).unwrap();
        let initiator = initiator.verify_message_2(Some(cred_r)).unwrap();
        let (_initiator, message_3, _prk_out) = initiator
            .prepare_message_3(CredentialTransfer::ByReference, &EadItems::new())
            .unwrap();

        (method_byte, message_2.len(), message_3.len())
    }

    #[cfg(feature = "test-ead-none")]
    #[test]
    fn test_mixed_methods_are_per_role() {
        let i: BytesP256ElemLen = I.try_into().expect("Wrong length of initiator private key");
        let r: BytesP256ElemLen = R.try_into().expect("Wrong length of responder private key");

        let (method0, method0_msg2, method0_msg3) = handshake_wire_sizes(
            EDHOCMethod::SigSig,
            ResponderIdentity::Signature { r },
            InitiatorIdentity::Signature { i },
        );
        let (method1, method1_msg2, method1_msg3) = handshake_wire_sizes(
            EDHOCMethod::SigStat,
            ResponderIdentity::StaticDh { r },
            InitiatorIdentity::Signature { i },
        );
        let (method2, method2_msg2, method2_msg3) = handshake_wire_sizes(
            EDHOCMethod::StatSig,
            ResponderIdentity::Signature { r },
            InitiatorIdentity::StaticDh { i },
        );
        let (method3, method3_msg2, method3_msg3) = handshake_wire_sizes(
            EDHOCMethod::StatStat,
            ResponderIdentity::StaticDh { r },
            InitiatorIdentity::StaticDh { i },
        );

        assert_eq!(
            [method0, method1, method2, method3],
            [0, 1, 2, 3],
            "wrong method in message_1"
        );

        // message_2 carries a signature exactly when the responder signs
        assert_eq!(method0_msg2, method2_msg2);
        assert_eq!(method1_msg2, method3_msg2);
        assert!(method0_msg2 > method1_msg2);

        // message_3 carries a signature exactly when the initiator signs
        assert_eq!(method0_msg3, method1_msg3);
        assert_eq!(method2_msg3, method3_msg3);
        assert!(method0_msg3 > method2_msg3);

        assert_eq!(method0_msg2, 102); // Signature
        assert_eq!(method0_msg3, 77); // Signature
        assert_eq!(method3_msg2, 45); // StaticDH
        assert_eq!(method3_msg3, 19); // StaticDH
    }

    #[test]
    fn test_parse_message_3_empty_returns_error() {
        let cred_r = Credential::parse_ccs_symmetric(CRED_R_PSK.try_into().unwrap()).unwrap();

        let initiator =
            EdhocInitiator::new(default_crypto(), EDHOCMethod::PSK, EDHOCSuite::CipherSuite2);
        let responder =
            EdhocResponder::new(default_crypto(), ResponderIdentity::Psk, cred_r.clone());

        let (_initiator, message_1) = initiator.prepare_message_1(None, &EadItems::new()).unwrap();
        let (responder, _c_i, _ead_1) = responder.process_message_1(&message_1).unwrap();
        let (responder, _message_2) = responder
            .prepare_message_2(CredentialTransfer::ByReference, None, &EadItems::new())
            .unwrap();

        let empty_message_3 = BufferMessage3::new();
        let err = responder.parse_message_3(&empty_message_3).unwrap_err();
        assert_eq!(err, EDHOCError::ParsingError);
    }

    /// Both roles' method/identity agreement checks must accept exactly the mode the method
    /// names for that role, and reject every other pairing -- including a PQ method with a
    /// classical identity and the reverse.
    #[cfg(feature = "pq")]
    #[test]
    fn test_pq_identity_must_match_the_method() {
        use lakers_shared::PqAuthMode;

        fn identity(mode: PqAuthMode) -> PqIdentity {
            match mode {
                PqAuthMode::Kem => PqIdentity::Kem {
                    kem_dk: [0u8; ML_KEM_DECAPS_KEY_LEN],
                },
                PqAuthMode::Sign => PqIdentity::Sign {
                    dsa_sk: [0u8; ML_DSA_SIGN_KEY_LEN],
                },
                PqAuthMode::KemSign => PqIdentity::KemSign {
                    kem_dk: [0u8; ML_KEM_DECAPS_KEY_LEN],
                    dsa_sk: [0u8; ML_DSA_SIGN_KEY_LEN],
                },
            }
        }

        let methods = [
            EDHOCMethod::PqSigKemsig,
            EDHOCMethod::PqKemsigSig,
            EDHOCMethod::PqKemsigKem,
            EDHOCMethod::PqKemsigKemsig,
        ];
        let modes = [PqAuthMode::Sign, PqAuthMode::Kem, PqAuthMode::KemSign];

        for method in methods {
            let (want_i, want_r) = method.pq_modes().unwrap();
            for mode in modes {
                let i_ok = check_initiator_identity(method, &InitiatorIdentity::Pq(identity(mode)))
                    .is_ok();
                assert_eq!(i_ok, mode == want_i, "initiator {method:?} / {mode:?}");

                let r_ok = check_responder_identity(
                    method,
                    &ResponderIdentity::Pq(identity(mode)),
                    CredentialTransfer::ByReference,
                )
                .is_ok();
                assert_eq!(r_ok, mode == want_r, "responder {method:?} / {mode:?}");
            }

            // A PQ method with a classical identity.
            assert!(check_initiator_identity(method, &InitiatorIdentity::Psk).is_err());
            assert!(check_responder_identity(
                method,
                &ResponderIdentity::Psk,
                CredentialTransfer::ByReference
            )
            .is_err());
        }

        // A classical method with a PQ identity.
        for method in [EDHOCMethod::SigSig, EDHOCMethod::StatStat, EDHOCMethod::PSK] {
            assert!(check_initiator_identity(
                method,
                &InitiatorIdentity::Pq(identity(PqAuthMode::KemSign))
            )
            .is_err());
            assert!(check_responder_identity(
                method,
                &ResponderIdentity::Pq(identity(PqAuthMode::KemSign)),
                CredentialTransfer::ByReference
            )
            .is_err());
        }
    }

    /// Which keys a `PqIdentity` holds is its mode; there is no separate field to disagree.
    #[cfg(feature = "pq")]
    #[test]
    fn test_pq_identity_mode_follows_its_keys() {
        use lakers_shared::PqAuthMode;

        let kem = PqIdentity::Kem {
            kem_dk: [1u8; ML_KEM_DECAPS_KEY_LEN],
        };
        assert_eq!(kem.mode(), PqAuthMode::Kem);
        assert!(kem.kem_dk().is_some() && kem.dsa_sk().is_none());

        let sign = PqIdentity::Sign {
            dsa_sk: [2u8; ML_DSA_SIGN_KEY_LEN],
        };
        assert_eq!(sign.mode(), PqAuthMode::Sign);
        assert!(sign.kem_dk().is_none() && sign.dsa_sk().is_some());

        let both = PqIdentity::KemSign {
            kem_dk: [3u8; ML_KEM_DECAPS_KEY_LEN],
            dsa_sk: [4u8; ML_DSA_SIGN_KEY_LEN],
        };
        assert_eq!(both.mode(), PqAuthMode::KemSign);
        assert!(both.kem_dk().is_some() && both.dsa_sk().is_some());
    }

    /// The public API up to the point the ephemeral KEM reaches: the Initiator generates an
    /// ML-KEM ephemeral pair instead of a DH one and sends `kem.pk_eph`, and the Responder
    /// encapsulates to it while processing message_1.
    ///
    /// `prepare_message_2` still fails, because the per-mode authentication module does not
    /// exist yet; asserted here so that the boundary is explicit rather than accidental.
    #[cfg(feature = "pq")]
    #[cfg(feature = "test-ead-none")]
    #[test]
    fn test_pq_ephemeral_reaches_the_responder() {
        use lakers_shared::{EDHOCSuite, ML_KEM_ENCAPS_KEY_LEN};

        let cred_r = Credential::parse_ccs(CRED_R.try_into().unwrap()).unwrap();

        let initiator = EdhocInitiator::new(
            default_crypto(),
            EDHOCMethod::PqSigKemsig,
            EDHOCSuite::PqCipherSuite,
        );
        let (_initiator, message_1) = initiator.prepare_message_1(None, &EadItems::new()).unwrap();

        // METHOD 40 needs the one-byte-uint form, then SUITES_I 60, then an 800-byte bstr.
        assert_eq!(
            &message_1.as_slice()[..6],
            &[0x18, 40, 0x18, 60, 0x59, 0x03]
        );
        assert_eq!(
            message_1.as_slice()[6],
            (ML_KEM_ENCAPS_KEY_LEN & 0xff) as u8
        );

        let responder = EdhocResponder::new(
            default_crypto(),
            ResponderIdentity::Pq(PqIdentity::KemSign {
                kem_dk: [0u8; ML_KEM_DECAPS_KEY_LEN],
                dsa_sk: [0u8; ML_DSA_SIGN_KEY_LEN],
            }),
            cred_r,
        );
        let (responder, _c_i, _ead_1) = responder
            .process_message_1(&message_1)
            .expect("the responder encapsulates to kem.pk_eph here");

        assert_eq!(
            responder
                .prepare_message_2(CredentialTransfer::ByReference, None, &EadItems::new())
                .map(|_| ())
                .unwrap_err(),
            EDHOCError::UnsupportedMethod,
            "authentication is not wired up yet"
        );
    }

    /// The rustcrypto backend advertises the provisional post-quantum suite once `pq` is on,
    /// and a responder must accept a message_1 selecting it. Before the responder consulted
    /// `crypto.supported_suites()` it compared against the single hardcoded
    /// `EDHOC_SUPPORTED_SUITES[0]`, so any suite but 2 was rejected regardless of the backend.
    #[cfg(feature = "pq")]
    #[cfg(feature = "test-ead-none")]
    #[test]
    fn test_pq_suite_is_negotiable() {
        use lakers_shared::EDHOCSuite;

        let cred_r = Credential::parse_ccs(CRED_R.try_into().unwrap()).unwrap();

        let initiator = EdhocInitiator::new(
            default_crypto(),
            EDHOCMethod::StatStat,
            EDHOCSuite::PqCipherSuite,
        );
        assert_eq!(
            initiator.selected_cipher_suite(),
            EDHOCSuite::PqCipherSuite as u8
        );

        let (_initiator, message_1) = initiator.prepare_message_1(None, &EadItems::new()).unwrap();

        // SUITES_I is a single suite above 23, so it takes the two-byte encoding.
        assert_eq!(&message_1.as_slice()[1..3], &[0x18, 60]);

        let responder = EdhocResponder::new(
            default_crypto(),
            ResponderIdentity::StaticDh {
                r: R.try_into().expect("Wrong length of responder private key"),
            },
            cred_r,
        );
        responder
            .process_message_1(&message_1)
            .expect("the backend advertises this suite, so it must be accepted");
    }

    /// The PSK path above rejected an empty message_3 already; the sig and stat paths reach
    /// `decrypt_message_3` instead and used to panic there on the unchecked header read.
    #[cfg(feature = "test-ead-none")]
    #[test]
    fn test_parse_message_3_empty_returns_error_stat() {
        let cred_r = Credential::parse_ccs(CRED_R.try_into().unwrap()).unwrap();

        let initiator = EdhocInitiator::new(
            default_crypto(),
            EDHOCMethod::StatStat,
            EDHOCSuite::CipherSuite2,
        );
        let responder = EdhocResponder::new(
            default_crypto(),
            ResponderIdentity::StaticDh {
                r: R.try_into().expect("Wrong length of responder private key"),
            },
            cred_r,
        );

        let (_initiator, message_1) = initiator.prepare_message_1(None, &EadItems::new()).unwrap();
        let (responder, _c_i, _ead_1) = responder.process_message_1(&message_1).unwrap();
        let (responder, _message_2) = responder
            .prepare_message_2(CredentialTransfer::ByReference, None, &EadItems::new())
            .unwrap();

        let empty_message_3 = BufferMessage3::new();
        let err = responder.parse_message_3(&empty_message_3).unwrap_err();
        assert_eq!(err, EDHOCError::ParsingError);
    }
}

#[cfg(feature = "test-ead-authz")]
#[cfg(test)]
mod test_authz {
    use super::*;
    use hexlit::hex;
    use lakers_crypto::default_crypto;
    use lakers_ead_authz::*;
    use test_vectors_common::*;

    // U
    const ID_U_TV: &[u8] = &hex!("a104412b");

    // V -- nothing to do, will reuse CRED_R from above to act as CRED_V

    // W
    pub const W_TV: &[u8] =
        &hex!("4E5E15AB35008C15B89E91F9F329164D4AACD53D9923672CE0019F9ACD98573F");
    const G_W_TV: &[u8] = &hex!("FFA4F102134029B3B156890B88C9D9619501196574174DCB68A07DB0588E4D41");
    const LOC_W_TV: &[u8] = &hex!("636F61703A2F2F656E726F6C6C6D656E742E736572766572");

    // TODO: have a setup_test function that prepares the common objects for the ead tests
    #[test]
    fn test_handshake_authz() {
        let cred_i = Credential::parse_ccs(CRED_I.try_into().unwrap()).unwrap();
        let cred_r = Credential::parse_ccs(CRED_R.try_into().unwrap()).unwrap();

        let mock_fetch_cred_i = |id_cred_i: IdCred| -> Result<Credential, EDHOCError> {
            if id_cred_i.as_full_value() == cred_i.by_kid()?.as_full_value() {
                Ok(cred_i.clone())
            } else {
                Err(EDHOCError::UnexpectedCredential)
            }
        };

        // ==== initialize edhoc ====
        let mut initiator = EdhocInitiator::new(
            default_crypto(),
            EDHOCMethod::StatStat,
            EDHOCSuite::CipherSuite2,
        );
        let responder = EdhocResponder::new(
            default_crypto(),
            ResponderIdentity::StaticDh {
                r: R.try_into().expect("Wrong length of responder private key"),
            },
            cred_r.clone(),
        );

        // ==== initialize ead-authz ====
        let device = ZeroTouchDevice::new(
            ID_U_TV.try_into().unwrap(),
            G_W_TV.try_into().unwrap(),
            LOC_W_TV.try_into().unwrap(),
        );
        let authenticator = ZeroTouchAuthenticator::default();

        let single_byte_kid = cred_i.kid.as_ref().unwrap()[0]; // FIXME: add longer kid support in ACL
        let acl = EdhocMessageBuffer::new_from_array(&[single_byte_kid]);
        let server = ZeroTouchServer::new(
            W_TV.try_into().unwrap(),
            CRED_R.try_into().unwrap(),
            Some(acl),
        );

        // ==== begin edhoc with ead-authz ====

        let (mut device, ead_item) = device.prepare_ead_1(
            &mut default_crypto(),
            initiator.compute_ephemeral_secret(&device.g_w),
            initiator.selected_cipher_suite(),
        );
        let mut ead_1 = EadItems::new();
        ead_1.try_push(ead_item).unwrap();
        let (initiator, message_1) = initiator.prepare_message_1(None, &ead_1).unwrap();
        device.set_h_message_1(initiator.state.h_message_1.clone());

        let (responder, _c_i, ead_1) = responder.process_message_1(&message_1).unwrap();
        let ead_2 = if let Some(ead_item) = ead_1.iter().next() {
            let (authenticator, _loc_w, voucher_request) =
                authenticator.process_ead_1(&ead_item, &message_1).unwrap();

            // the line below mocks a request to the server: let voucher_response = auth_client.post(loc_w, voucher_request)?
            let voucher_response = server
                .handle_voucher_request(&mut default_crypto(), &voucher_request)
                .unwrap();

            let res = authenticator.prepare_ead_2(&voucher_response);
            assert!(res.is_ok());
            let mut eads_2 = EadItems::new();
            eads_2
                .try_push(authenticator.prepare_ead_2(&voucher_response).unwrap())
                .unwrap();

            eads_2
        } else {
            EadItems::new()
        };
        let (responder, message_2) = responder
            .prepare_message_2(CredentialTransfer::ByValue, None, &ead_2)
            .unwrap();

        let (mut initiator, _c_r, ead_2) = initiator.parse_message_2(&message_2).unwrap();
        let result =
            device.process_ead_2(&mut default_crypto(), ead_2.iter().next().unwrap(), CRED_R);
        assert!(result.is_ok());
        initiator
            .set_identity(
                InitiatorIdentity::StaticDh {
                    i: I.try_into().expect("Wrong length of initiator private key"),
                },
                cred_i.clone(),
            )
            .unwrap();
        let initiator = initiator.verify_message_2(None).unwrap();

        let (initiator, message_3, i_prk_out) = initiator
            .prepare_message_3(CredentialTransfer::ByReference, &EadItems::new())
            .unwrap();
        let _initiator = initiator.completed_without_message_4();
        let (responder, id_cred_i, _ead_3) = responder.parse_message_3(&message_3).unwrap();
        let valid_cred_i = if id_cred_i.reference_only() {
            mock_fetch_cred_i(id_cred_i).unwrap()
        } else {
            id_cred_i.get_ccs().unwrap()
        };
        let (responder, r_prk_out) = responder.verify_message_3(valid_cred_i).unwrap();

        let mut _responder = responder.completed_without_message_4();
        // check that prk_out is equal at initiator and responder side
        assert_eq!(i_prk_out, r_prk_out);
    }
}
