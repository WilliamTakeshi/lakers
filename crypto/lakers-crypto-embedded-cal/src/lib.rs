//! EDHOC crypto backend backed by the [`embedded-cal`](embedded_cal) Cryptographic Abstraction
//! Layer.
//!
//! [`Crypto`] is generic over any [`embedded_cal::Cal`] instance. This lets lakers use
//! hardware-accelerated crypto on microcontrollers that ship an embedded-cal backend (e.g.
//! nRF54L15, STM32WBA55), while falling back to a software `Cal` elsewhere. "Use hardware if
//! available" is expressed by *which concrete `Cal` the caller constructs*, not by cfg flags here.
#![cfg_attr(not(test), no_std)]

/// A [`lakers_shared::Crypto`] implementation that forwards to an embedded-cal [`Cal`] instance.
///
/// Construct it with [`Crypto::new`], passing a fully-wired `Cal` (for hardware backends, typically
/// an `embedded_cal_software_demo::Extender` wrapping the hardware `Cal`, so that SHA-256, HMAC and
/// therefore HKDF are available on top of the hardware's raw primitives).
pub struct Crypto<C> {
    cal: C,
}

impl<C> Crypto<C> {
    /// Wraps an embedded-cal [`Cal`](embedded_cal::Cal) instance as a lakers crypto backend.
    pub const fn new(cal: C) -> Self {
        Self { cal }
    }
}

// Hand-written so we do not require `C: Debug`; most `Cal` types do not implement it, but the
// `lakers_shared::Crypto` trait requires the backend to be `Debug`.
impl<C> core::fmt::Debug for Crypto<C> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> Result<(), core::fmt::Error> {
        f.debug_struct("lakers_crypto_embedded_cal::Crypto")
            .field("cal", &core::any::type_name::<C>())
            .finish()
    }
}

use embedded_cal::accessor::{
    AeadAlgorithmOf, DhAlgorithmOf, DhSecretKeyOf, HashAlgorithmOf, HmacAlgorithmOf,
};
use embedded_cal::{
    AeadAlgorithm, AeadProvider, Cal, DhAlgorithm, DhProvider, HashAlgorithm, HashProvider,
    HkdfProvider, HmacAlgorithm,
};
use lakers_shared::{
    BytesCcmIvLen, BytesCcmKeyLen, BytesHashLen, BytesP256ElemLen, CcmTagLen,
    Crypto as CryptoTrait, EDHOCError, EDHOCSuite, EdhocBuffer, MAX_SUITES_LEN,
};

impl<C: Cal + rand_core::TryCryptoRng> CryptoTrait for Crypto<C> {
    fn supported_suites(&self) -> EdhocBuffer<MAX_SUITES_LEN> {
        EdhocBuffer::<MAX_SUITES_LEN>::new_from_slice(&[EDHOCSuite::CipherSuite2 as u8])
            .expect("the slice is of a length that always fits")
    }

    fn sha256_digest(&mut self, message: &[u8]) -> BytesHashLen {
        // SHA-256 is IANA Named-Information hash id 1; every EDHOC-capable `Cal` provides it.
        let alg = HashAlgorithmOf::<C>::from_ni_id(1).expect("cal must support sha-256");
        let digest = self.cal.hash().hash(alg, message);
        digest
            .as_ref()
            .try_into()
            .expect("sha-256 output is exactly 32 bytes")
    }

    // The `digest::Digest` interface requires an owned, `Default`-constructible hasher, which cannot
    // hold a `&mut` into the `Cal`'s hash provider. We therefore use a self-contained software
    // hasher for the streaming interface (the same compromise the psa backend makes); the one-shot
    // `sha256_digest` above still routes through the `Cal` and thus any hardware acceleration.
    type HashInProcess<'a>
        = sha2::Sha256
    where
        Self: 'a;

    #[inline]
    fn sha256_start<'a>(&'a mut self) -> Self::HashInProcess<'a> {
        use digest::Digest;
        sha2::Sha256::new()
    }

    fn hkdf_expand(&mut self, prk: &BytesHashLen, info: &[u8], result: &mut [u8]) {
        // HKDF is provided by embedded-cal as a blanket impl over the HMAC provider (RFC 5869);
        // HMAC-SHA-256 is COSE algorithm 5.
        let alg = HmacAlgorithmOf::<C>::from_cose_number(5).expect("cal must support hmac-sha-256");
        self.cal
            .hmac()
            .hkdf_expand(alg, prk, info, result)
            .expect("output length fits within 255 * hashlen");
    }

    fn hkdf_extract(&mut self, salt: &BytesHashLen, ikm: &BytesP256ElemLen) -> BytesHashLen {
        let alg = HmacAlgorithmOf::<C>::from_cose_number(5).expect("cal must support hmac-sha-256");
        let prk = self
            .cal
            .hmac()
            .hkdf_extract(alg, Some(salt), ikm)
            .expect("hkdf-extract over a present salt is infallible");
        prk.as_ref()
            .try_into()
            .expect("hmac-sha-256 output is exactly 32 bytes")
    }

    fn aes_ccm_encrypt<const N: usize, Tag: CcmTagLen>(
        &mut self,
        key: &BytesCcmKeyLen,
        iv: &BytesCcmIvLen,
        ad: &[u8],
        plaintext: &[u8],
    ) -> EdhocBuffer<N> {
        let alg = aes_ccm_algorithm::<C, Tag>();
        let mut outbuffer =
            EdhocBuffer::<N>::new_from_slice(plaintext).expect("plaintext fits the output buffer");
        let aead = self.cal.aead();
        let key = aead.load_from_keydata(alg, key);
        // The tag is returned detached; lakers expects `ciphertext || tag` in one buffer.
        #[allow(
            deprecated,
            reason = "EdhocBuffer has no non-deprecated mutable-slice accessor (hax constraint)"
        )]
        let tag = aead.encrypt_in_place(&key, iv, &mut outbuffer.content[..plaintext.len()], ad);
        outbuffer
            .extend_from_slice(tag.as_ref())
            .expect("tag fits the output buffer");
        outbuffer
    }

    fn aes_ccm_decrypt<const N: usize, Tag: CcmTagLen>(
        &mut self,
        key: &BytesCcmKeyLen,
        iv: &BytesCcmIvLen,
        ad: &[u8],
        ciphertext: &[u8],
    ) -> Result<EdhocBuffer<N>, EDHOCError> {
        let alg = aes_ccm_algorithm::<C, Tag>();
        let plaintext_len = ciphertext.len() - Tag::LEN;
        let mut buffer = EdhocBuffer::<N>::new_from_slice(&ciphertext[..plaintext_len])
            .expect("ciphertext-without-tag fits the output buffer");
        let tag = &ciphertext[plaintext_len..];
        let aead = self.cal.aead();
        let key = aead.load_from_keydata(alg, key);
        #[allow(
            deprecated,
            reason = "EdhocBuffer has no non-deprecated mutable-slice accessor (hax constraint)"
        )]
        aead.decrypt_in_place(&key, iv, &mut buffer.content[..plaintext_len], tag, ad)
            .map_err(|_| EDHOCError::MacVerificationFailed)?;
        Ok(buffer)
    }

    fn p256_ecdh(
        &mut self,
        private_key: &BytesP256ElemLen,
        public_key: &BytesP256ElemLen,
    ) -> BytesP256ElemLen {
        // COSE elliptic curve 1 is P-256. Public keys cross the embedded-cal boundary in the
        // compact 32-byte x-only representation, which is exactly lakers' representation.
        let alg = DhAlgorithmOf::<C>::from_cose_ecdh(1).expect("cal must support ecdh p-256");
        let dh = self.cal.dh();
        let secret: DhSecretKeyOf<C> = dh
            .import_secretkey_bytes(alg.clone(), private_key)
            .expect("private key is a valid p-256 scalar")
            .into();
        let public = dh
            .import_publickey_bytes(alg, public_key)
            .expect("public key is a valid compact p-256 point");
        let shared = dh
            .shared_secret(&secret, &public)
            .expect("both keys are for p-256");
        let secret_bytes = dh
            .raw_secret_bytes(&shared)
            .as_ref()
            .try_into()
            .expect("p-256 shared secret is exactly 32 bytes");
        secret_bytes
    }

    fn get_random_byte(&mut self) -> u8 {
        let mut byte = [0u8; 1];
        self.cal
            .try_fill_bytes(&mut byte)
            .expect("cal random number generation must not fail");
        byte[0]
    }

    fn p256_generate_key_pair(&mut self) -> (BytesP256ElemLen, BytesP256ElemLen) {
        let alg = DhAlgorithmOf::<C>::from_cose_ecdh(1).expect("cal must support ecdh p-256");
        let dh = self.cal.dh();
        let visible_secret = dh.generate_visible(alg);
        let private_key = dh
            .export_secretkey_bytes(&visible_secret)
            .as_ref()
            .try_into()
            .expect("p-256 scalar is exactly 32 bytes");
        // The public key is exported in compact x-only form (32 bytes), matching lakers.
        let secret: DhSecretKeyOf<C> = visible_secret.into();
        let public = dh.public_key(&secret);
        let public_key = dh
            .export_publickey_bytes(&public)
            .as_ref()
            .try_into()
            .expect("compact p-256 public key is exactly 32 bytes");
        (private_key, public_key)
    }
}

/// Selects the embedded-cal AEAD algorithm for the requested CCM tag length.
///
/// Only an 8-byte tag (AES-CCM-16-64-128, COSE algorithm 10) is supported by any embedded-cal
/// backend; this is the only tag length EDHOC cipher suite 2 uses. A 16-byte tag panics.
fn aes_ccm_algorithm<C: Cal, Tag: CcmTagLen>() -> AeadAlgorithmOf<C> {
    let cose_number = match Tag::LEN {
        8 => 10,
        other => panic!("aes-ccm with a {other}-byte tag is not supported by embedded-cal"),
    };
    AeadAlgorithmOf::<C>::from_cose_number(cose_number).expect("cal must support aes-ccm-16-64-128")
}

#[cfg(test)]
mod tests {
    use super::*;
    use embedded_cal::accessor::{AeadProviderOf, DhProviderOf, HashProviderOf};
    use embedded_cal::{HmacAlgorithm, HmacProvider};
    use embedded_cal_rustcrypto::RustcryptoCal;
    use hmac::Mac;
    use lakers_shared::{test_helper, CcmTagLen8};

    /// A host-only composite [`Cal`]: `RustcryptoCal` provides hash / AEAD / DH / RNG in software
    /// but no longer provides HMAC, so we add software HMAC-SHA-256 here. That makes HKDF available
    /// (blanket impl over `HmacProvider`) and gives us a complete host-runnable `Cal` to exercise
    /// the adapter against.
    #[derive(Default)]
    struct TestCal(RustcryptoCal);

    impl Cal for TestCal {
        type DhProvider = DhProviderOf<RustcryptoCal>;
        type AeadProvider = AeadProviderOf<RustcryptoCal>;
        type HashProvider = HashProviderOf<RustcryptoCal>;
        type HmacProvider = Self;

        fn dh(&mut self) -> &mut Self::DhProvider {
            self.0.dh()
        }
        fn aead(&mut self) -> &mut Self::AeadProvider {
            self.0.aead()
        }
        fn hash(&mut self) -> &mut Self::HashProvider {
            // `RustcryptoCal` implements both `Cal` and `HashProvider` (which also has a `hash`
            // method), so the accessor must be named explicitly.
            Cal::hash(&mut self.0)
        }
        fn hmac(&mut self) -> &mut Self::HmacProvider {
            self
        }
    }

    impl rand_core::TryRng for TestCal {
        type Error = <RustcryptoCal as rand_core::TryRng>::Error;
        fn try_next_u32(&mut self) -> Result<u32, Self::Error> {
            self.0.try_next_u32()
        }
        fn try_next_u64(&mut self) -> Result<u64, Self::Error> {
            self.0.try_next_u64()
        }
        fn try_fill_bytes(&mut self, dst: &mut [u8]) -> Result<(), Self::Error> {
            self.0.try_fill_bytes(dst)
        }
    }
    impl rand_core::TryCryptoRng for TestCal {}

    // --- software HMAC-SHA-256 for TestCal ---

    #[derive(Clone, PartialEq, Eq, Debug)]
    enum TestHmacAlgorithm {
        HmacSha256,
    }

    impl HmacAlgorithm for TestHmacAlgorithm {
        const MAX_LEN: usize = 32;
        type MaxLenBuf = [u8; 32];
        fn len(&self) -> usize {
            32
        }
        fn from_cose_number(number: impl Into<i128>) -> Option<Self> {
            match number.into() {
                5 => Some(Self::HmacSha256),
                _ => None,
            }
        }
    }

    type HmacSha256 = hmac::Hmac<sha2::Sha256>;

    struct TestHmacOutput([u8; 32]);
    impl AsRef<[u8]> for TestHmacOutput {
        fn as_ref(&self) -> &[u8] {
            &self.0
        }
    }

    impl HmacProvider for TestCal {
        type Algorithm = TestHmacAlgorithm;
        type Key = HmacSha256;
        type State = HmacSha256;
        type Output = TestHmacOutput;

        fn load_from_keydata(&mut self, _algorithm: Self::Algorithm, key: &[u8]) -> Self::Key {
            HmacSha256::new_from_slice(key).expect("hmac accepts a key of any length")
        }
        fn init(&mut self, key: Self::Key) -> Self::State {
            key
        }
        fn update(&mut self, state: &mut Self::State, data: &[u8]) {
            Mac::update(state, data);
        }
        fn finalize(&mut self, state: Self::State) -> Self::Output {
            let mut out = [0u8; 32];
            out.copy_from_slice(&state.finalize().into_bytes());
            TestHmacOutput(out)
        }
    }

    fn crypto() -> Crypto<TestCal> {
        Crypto::new(TestCal::default())
    }

    // Compile-time guard that the adapter actually implements the lakers Crypto trait.
    #[allow(dead_code)]
    fn assert_implements_crypto<T: CryptoTrait>() {}
    #[allow(dead_code)]
    fn test_implements_crypto() {
        assert_implements_crypto::<Crypto<TestCal>>()
    }

    #[test]
    fn sha256_matches_vectors() {
        let mut c = crypto();
        test_helper::test_sha256_digest(&mut c);
        for (input, expected) in testvectors::SHA256HASHES {
            assert_eq!(c.sha256_digest(input), *expected);
        }
    }

    #[test]
    fn hkdf_expand_matches_vectors() {
        let mut c = crypto();
        for (_salt, _ikm, info, expected_prk, expected_okm) in testvectors::HKDF_SHA256 {
            let expected_okm: &[u8] = expected_okm;
            let mut buf = [0u8; 82];
            let okm = &mut buf[..expected_okm.len()];
            c.hkdf_expand(expected_prk, info, okm);
            assert_eq!(&*okm, expected_okm);
        }
    }

    /// Exercises the extract path and the HMAC that the adapter's HKDF forwards to, using
    /// embedded-cal's own RFC 5869 / RFC 4231 known-answer tests.
    #[test]
    fn hkdf_and_hmac_via_embedded_cal_vectors() {
        let mut cal = TestCal::default();
        testvectors::test_hkdf_sha256(&mut cal);
        testvectors::test_hmac_sha256(&mut cal);
    }

    #[test]
    fn aes_ccm_tag8_roundtrip() {
        let mut c = crypto();
        test_helper::test_aes_ccm_tag_8(&mut c);
        test_helper::test_aes_ccm_roundtrip::<_, CcmTagLen8>(&mut c);
    }

    /// P-256 ECDH known-answer test, RFC 5903 Section 8.1 (copied from
    /// `embedded-cal/testvectors/src/dh.rs`). lakers exchanges the compact x-only public key.
    #[test]
    fn p256_ecdh_rfc5903() {
        use hexlit::hex;
        let alice_private =
            hex!("C88F01F510D9AC3F70A292DAA2316DE544E9AAB8AFE84049C62A9C57862D1433");
        let alice_public = hex!("DAD0B65394221CF9B051E1FECA5787D098DFE637FC90B9EF945D0C3772581180");
        let bob_private = hex!("C6EF9C5D78AE012A011164ACB397CE2088685D8F06BF9BE0B283AB46476BEE53");
        let bob_public = hex!("D12DFB5289C8D4F81208B70270398C342296970A0BCCB74C736FC7554494BF63");
        let shared = hex!("D6840F6B42F6EDAFD13116E0E12565202FEF8E9ECE7DCE03812464D04B9442DE");

        let mut c = crypto();
        assert_eq!(c.p256_ecdh(&alice_private, &bob_public), shared);
        assert_eq!(c.p256_ecdh(&bob_private, &alice_public), shared);
    }

    #[test]
    fn p256_generate_key_pair_selftest() {
        let mut c = crypto();
        let (private_a, public_a) = c.p256_generate_key_pair();
        let (private_b, public_b) = c.p256_generate_key_pair();
        assert_ne!(private_a, private_b, "two generated keys should differ");
        // Both parties derive the same shared secret.
        assert_eq!(
            c.p256_ecdh(&private_a, &public_b),
            c.p256_ecdh(&private_b, &public_a),
        );
    }
}
