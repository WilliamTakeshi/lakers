//! EDHOC error type and the CBOR-format constants needed to recognize/produce certain errors.
//!
//! This module is deliberately kept dependency-free (it does not even depend on the rest of this
//! crate's top-level module): both `cred` and the `cbor_decoder` submodule need `EDHOCError`, and
//! the top-level module needs `Credential`/`IdCred` (from `cred`) and `CBORDecoder` (from
//! `cbor_decoder`). If `EDHOCError` lived in the top-level module instead, that would form a
//! dependency cycle between modules, which hax's F* extraction cannot represent as separate
//! modules (so it falls back to bundling them all into one).

pub(crate) const CBOR_MAJOR_UNSIGNED: u8 = 0 << 5;
pub(crate) const CBOR_MAJOR_NEGATIVE: u8 = 1 << 5;
pub(crate) const CBOR_MAJOR_TAG: u8 = 6 << 5;
pub(crate) const CBOR_MAJOR_FLOATSIMPLE: u8 = 7 << 5;
pub const CBOR_MAJOR_TEXT_STRING: u8 = 0x60u8;
pub const CBOR_MAJOR_BYTE_STRING: u8 = 0x40u8;
pub const CBOR_MAJOR_BYTE_STRING_MAX: u8 = 0x57u8;
pub const CBOR_MAJOR_ARRAY: u8 = 0x80u8;
pub const CBOR_MAJOR_ARRAY_MAX: u8 = 0x97u8;
pub const CBOR_MAJOR_MAP: u8 = 0xA0;

pub const CBOR_NEG_INT_1BYTE_START: u8 = 0x20u8;
pub const CBOR_NEG_INT_1BYTE_END: u8 = 0x37u8;
pub const CBOR_UINT_1BYTE_START: u8 = 0x0u8;
pub const CBOR_UINT_1BYTE_END: u8 = 0x17u8;

pub const KCCS_LABEL: u8 = 14;
#[deprecated(note = "Typo for KCCS_LABEL")]
pub const KCSS_LABEL: u8 = KCCS_LABEL;
pub const KID_LABEL: u8 = 4;

#[derive(PartialEq, Debug)]
#[non_exhaustive]
pub enum EDHOCError {
    /// In an exchange, a credential was set as "expected", but the credential configured by the
    /// peer did not match what was presented. This is more an application internal than an EDHOC
    /// error: When the application sets the expected credential, that process should be informed
    /// by the known details.
    UnexpectedCredential,
    MissingIdentity,
    IdentityAlreadySet,
    MacVerificationFailed,
    UnsupportedMethod,
    UnsupportedCipherSuite,
    ParsingError,
    EncodingError,
    CredentialTooLongError,
    EadLabelTooLongError,
    EadTooLongError,
    /// An EAD was received that was either not known (and critical), or not understood, or
    /// otherwise erroneous.
    EADUnprocessable,
    /// The credential or EADs could be processed (possibly by a third party), but the decision
    /// based on that was to not to continue the EDHOC session.
    ///
    /// See also
    /// <https://datatracker.ietf.org/doc/html/draft-ietf-lake-authz#name-edhoc-error-access-denied>
    AccessDenied,
}

impl EDHOCError {
    /// The ERR_CODE corresponding to the error
    ///
    /// Errors that refer to internal limitations (such as EadTooLongError) are treated the same
    /// way as parsing errors, and return an unspecified error: Those are equivalent to limitations
    /// of the parser, and a constrained system can not be expected to differentiate between "the
    /// standard allows this but my number space is too small" and "this violates the standard".
    ///
    /// If an EDHOCError is returned through EDHOC, it will use this in its EDHOC error message.
    ///
    /// Note that this on its own is insufficient to create an error message: Additional ERR_INFO
    /// is needed, which may or may not be available with the EDHOCError alone.
    ///
    /// TODO: Evolve the EDHOCError type such that all information needed is available.
    pub fn err_code(&self) -> ErrCode {
        use EDHOCError::*;
        match self {
            UnexpectedCredential => ErrCode::UNSPECIFIED,
            MissingIdentity => ErrCode::UNSPECIFIED,
            IdentityAlreadySet => ErrCode::UNSPECIFIED,
            MacVerificationFailed => ErrCode::UNSPECIFIED,
            UnsupportedMethod => ErrCode::UNSPECIFIED,
            UnsupportedCipherSuite => ErrCode::WRONG_SELECTED_CIPHER_SUITE,
            ParsingError => ErrCode::UNSPECIFIED,
            EncodingError => ErrCode::UNSPECIFIED,
            CredentialTooLongError => ErrCode::UNSPECIFIED,
            EadLabelTooLongError => ErrCode::UNSPECIFIED,
            EadTooLongError => ErrCode::UNSPECIFIED,
            EADUnprocessable => ErrCode::UNSPECIFIED,
            AccessDenied => ErrCode::ACCESS_DENIED,
        }
    }
}

/// Representation of an EDHOC ERR_CODE
#[repr(C)]
pub struct ErrCode(pub i16);

impl ErrCode {
    pub const UNSPECIFIED: Self = ErrCode(1);
    pub const WRONG_SELECTED_CIPHER_SUITE: Self = ErrCode(2);
    pub const UNKNOWN_CREDENTIAL: Self = ErrCode(3);
    // Code requested in https://datatracker.ietf.org/doc/html/draft-ietf-lake-authz
    pub const ACCESS_DENIED: Self = ErrCode(3333);
}
