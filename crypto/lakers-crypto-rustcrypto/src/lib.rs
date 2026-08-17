#![no_std]

use lakers_shared::{
    BytesCcmIvLen, BytesCcmKeyLen, BytesElemLenPSK, BytesHashLen, BytesP256ElemLen,
    Crypto as CryptoTrait, EDHOCError, EDHOCSuite, EdhocBuffer, MAX_SUITES_LEN,
};
#[cfg(feature = "pq")]
use lakers_shared::{
    BytesKemCiphertext, BytesKemDecapsKey, BytesKemEncapsKey, BytesKemSharedSecret, BytesPqSignKey,
    BytesPqSignature, BytesPqVerifyKey, ML_DSA_SIGN_KEY_LEN, ML_DSA_VERIFY_KEY_LEN,
    PQ_SIGNATURE_LENGTH,
};
use lakers_shared::{BytesSignature, CcmTagLen};

use ccm::AeadInPlace;
use ccm::KeyInit;
use p256::ecdsa::signature::{Signer, Verifier};
use p256::elliptic_curve::point::AffineCoordinates;
use p256::elliptic_curve::point::DecompressPoint;
use p256::elliptic_curve::subtle::Choice;
use sha2::Digest;

type AesCcm16_64_128 = ccm::Ccm<aes::Aes128, ccm::consts::U8, ccm::consts::U13>;
type AesCcm16_128_128 = ccm::Ccm<aes::Aes128, ccm::consts::U16, ccm::consts::U13>;

/// A type representing cryptographic operations through various RustCrypto crates (eg. [aes],
/// [ccm], [p256]).
///
/// Its size depends on the implementation of Rng passed in at creation.
pub struct Crypto<Rng: rand_core::RngCore + rand_core::CryptoRng> {
    rng: Rng,
}

impl<Rng: rand_core::RngCore + rand_core::CryptoRng> Crypto<Rng> {
    pub const fn new(rng: Rng) -> Self {
        Self { rng }
    }
}

impl<Rng: rand_core::RngCore + rand_core::CryptoRng> core::fmt::Debug for Crypto<Rng> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> Result<(), core::fmt::Error> {
        f.debug_struct("lakers_crypto_rustcrypto::Crypto")
            .field("rng", &core::any::type_name::<Rng>())
            .finish()
    }
}

impl<Rng: rand_core::RngCore + rand_core::CryptoRng> CryptoTrait for Crypto<Rng> {
    fn supported_suites(&self) -> EdhocBuffer<MAX_SUITES_LEN> {
        EdhocBuffer::<MAX_SUITES_LEN>::new_from_slice(&[EDHOCSuite::CipherSuite2 as u8])
            .expect("This should never fail, as the slice is of the correct length")
    }

    fn sha256_digest(&mut self, message: &[u8]) -> BytesHashLen {
        let mut hasher = sha2::Sha256::new();
        hasher.update(message);
        hasher.finalize().into()
    }

    type HashInProcess<'a>
        = sha2::Sha256
    where
        Self: 'a;

    #[inline]
    fn sha256_start<'a>(&'a mut self) -> Self::HashInProcess<'a> {
        sha2::Sha256::new()
    }

    fn hkdf_expand(&mut self, prk: &BytesHashLen, info: &[u8], result: &mut [u8]) {
        let hkdf =
            hkdf::Hkdf::<sha2::Sha256>::from_prk(prk).expect("Static size was checked at extract");
        hkdf.expand(info, result)
            .expect("Static lengths match the algorithm");
    }

    fn hkdf_extract(&mut self, salt: &BytesHashLen, ikm: &BytesP256ElemLen) -> BytesHashLen {
        // While it'd be nice to just pass around an Hkdf, the extract output is not a type generic
        // of this trait (yet?).
        let mut extracted = hkdf::HkdfExtract::<sha2::Sha256>::new(Some(salt));
        extracted.input_ikm(ikm);
        extracted.finalize().0.into()
    }

    fn hkdf_extract_psk(&mut self, salt: &BytesHashLen, ikm: &BytesElemLenPSK) -> BytesHashLen {
        // While it'd be nice to just pass around an Hkdf, the extract output is not a type generic
        // of this trait (yet?).
        let mut extracted = hkdf::HkdfExtract::<sha2::Sha256>::new(Some(salt));
        extracted.input_ikm(ikm);
        extracted.finalize().0.into()
    }

    fn aes_ccm_encrypt<const N: usize, Tag: CcmTagLen>(
        &mut self,
        key: &BytesCcmKeyLen,
        iv: &BytesCcmIvLen,
        ad: &[u8],
        plaintext: &[u8],
    ) -> EdhocBuffer<N> {
        let mut outbuffer = EdhocBuffer::new_from_slice(plaintext).unwrap();
        #[allow(
            deprecated,
            reason = "hax won't allow creating a .as_mut_slice() method"
        )]
        match Tag::LEN {
            8 => {
                let enc = AesCcm16_64_128::new(key.into())
                    .encrypt_in_place_detached(
                        iv.into(),
                        ad,
                        &mut outbuffer.content[..plaintext.len()],
                    )
                    .expect("Preconfigured sizes should not allow encryption to fail");

                outbuffer.extend_from_slice(&enc).unwrap()
            }

            16 => {
                let enc = AesCcm16_128_128::new(key.into())
                    .encrypt_in_place_detached(
                        iv.into(),
                        ad,
                        &mut outbuffer.content[..plaintext.len()],
                    )
                    .expect("Preconfigured sizes should not allow encryption to fail");

                outbuffer.extend_from_slice(&enc).unwrap()
            }

            _ => unreachable!(), // CcmTagLen bound guarantees this
        };
        outbuffer
    }

    fn aes_ccm_decrypt<const N: usize, Tag: CcmTagLen>(
        &mut self,
        key: &BytesCcmKeyLen,
        iv: &BytesCcmIvLen,
        ad: &[u8],
        ciphertext: &[u8],
    ) -> Result<EdhocBuffer<N>, EDHOCError> {
        let plaintext_len = ciphertext.len() - Tag::LEN;
        let mut buffer = EdhocBuffer::new_from_slice(&ciphertext[..plaintext_len]).unwrap();
        let tag = &ciphertext[plaintext_len..];
        #[allow(
            deprecated,
            reason = "hax won't allow creating a .as_mut_slice() method"
        )]
        match Tag::LEN {
            8 => AesCcm16_64_128::new(key.into())
                .decrypt_in_place_detached(
                    iv.into(),
                    ad,
                    &mut buffer.content[..plaintext_len],
                    tag.into(),
                )
                .map_err(|_| EDHOCError::MacVerificationFailed)?,
            16 => AesCcm16_128_128::new(key.into())
                .decrypt_in_place_detached(
                    iv.into(),
                    ad,
                    &mut buffer.content[..plaintext_len],
                    tag.into(),
                )
                .map_err(|_| EDHOCError::MacVerificationFailed)?,
            _ => unreachable!(), // CcmTagLen bound guarantees this
        };
        Ok(buffer)
    }

    fn p256_ecdh(
        &mut self,
        private_key: &BytesP256ElemLen,
        public_key: &BytesP256ElemLen,
    ) -> BytesP256ElemLen {
        let secret = p256::SecretKey::from_bytes(private_key.as_slice().into())
            .expect("Invalid secret key generated");
        let public = p256::AffinePoint::decompress(
            public_key.into(),
            1.into(), /* Y coordinate choice does not matter for ECDH operation */
        )
        // While this can actually panic so far, the proper fix is in
        // https://github.com/lake-rs/lakers/issues/93 which will justify this to be a
        // panic (because after that, public key validity will be an invariant of the public key
        // type)
        .expect("Public key is not a good point");

        (*p256::ecdh::diffie_hellman(secret.to_nonzero_scalar(), public).raw_secret_bytes()).into()
    }

    fn get_random_byte(&mut self) -> u8 {
        self.rng.next_u32() as _
    }

    fn p256_generate_key_pair(&mut self) -> (BytesP256ElemLen, BytesP256ElemLen) {
        let secret = p256::SecretKey::random(&mut self.rng);

        let public_key = secret.public_key().as_affine().x();
        let private_key = secret.to_bytes();

        (private_key.into(), public_key.into())
    }

    fn p256_ecdsa_sign(
        &mut self,
        private_key: &BytesP256ElemLen,
        message: &[u8],
    ) -> Result<BytesSignature, EDHOCError> {
        let signing_key = p256::ecdsa::SigningKey::from_bytes(private_key.into())
            .map_err(|_| EDHOCError::MissingIdentity)?;

        let signature: p256::ecdsa::Signature = signing_key.sign(message);

        Ok(signature.to_bytes().into())
    }

    fn p256_ecdsa_verify(
        &mut self,
        public_key_x: &BytesP256ElemLen,
        message: &[u8],
        signature: &BytesSignature,
    ) -> Result<bool, EDHOCError> {
        let Ok(signature) = p256::ecdsa::Signature::from_slice(signature) else {
            return Ok(false);
        };

        // the compact representation of the credential omits the y coordinate, so both points
        // with this x are tried; both belong to the same key holder (private keys d and n-d)
        for y_is_odd in [0u8, 1u8] {
            let point = p256::AffinePoint::decompress(public_key_x.into(), Choice::from(y_is_odd));
            if bool::from(point.is_none()) {
                continue;
            }
            let point = point.unwrap();

            let Ok(verifying_key) = p256::ecdsa::VerifyingKey::from_affine(point) else {
                continue;
            };

            if verifying_key.verify(message, &signature).is_ok() {
                return Ok(true);
            }
        }

        Ok(false)
    }

    #[cfg(feature = "pq")]
    fn kem_generate_key_pair(
        &mut self,
    ) -> Result<(BytesKemDecapsKey, BytesKemEncapsKey), EDHOCError> {
        let mut seed = [0u8; libcrux_ml_kem::KEY_GENERATION_SEED_SIZE];
        self.rng.fill_bytes(&mut seed);

        let key_pair = libcrux_ml_kem::mlkem512::portable::generate_key_pair(seed);

        Ok((*key_pair.sk(), *key_pair.pk()))
    }

    #[cfg(feature = "pq")]
    fn kem_encapsulate(
        &mut self,
        encaps_key: &BytesKemEncapsKey,
    ) -> Result<(BytesKemSharedSecret, BytesKemCiphertext), EDHOCError> {
        let mut randomness = [0u8; libcrux_ml_kem::ENCAPS_SEED_SIZE];
        self.rng.fill_bytes(&mut randomness);

        let encaps_key = libcrux_ml_kem::mlkem512::MlKem512PublicKey::from(*encaps_key);
        let (ciphertext, shared_secret) =
            libcrux_ml_kem::mlkem512::portable::encapsulate(&encaps_key, randomness);

        Ok((shared_secret, *ciphertext.as_slice()))
    }

    #[cfg(feature = "pq")]
    fn kem_decapsulate(
        &mut self,
        decaps_key: &BytesKemDecapsKey,
        ciphertext: &BytesKemCiphertext,
    ) -> Result<BytesKemSharedSecret, EDHOCError> {
        let decaps_key = libcrux_ml_kem::mlkem512::MlKem512PrivateKey::from(*decaps_key);
        let ciphertext = libcrux_ml_kem::mlkem512::MlKem512Ciphertext::from(*ciphertext);

        // Infallible by construction: ML-KEM uses implicit rejection, so a bad ciphertext
        // returns a pseudorandom secret rather than an error. The Result is for backends that
        // cannot perform the operation at all.
        Ok(libcrux_ml_kem::mlkem512::portable::decapsulate(
            &decaps_key,
            &ciphertext,
        ))
    }

    #[cfg(feature = "pq")]
    fn mldsa_generate_key_pair(
        &mut self,
    ) -> Result<(BytesPqSignKey, BytesPqVerifyKey), EDHOCError> {
        let mut seed = [0u8; libcrux_ml_dsa::KEY_GENERATION_RANDOMNESS_SIZE];
        self.rng.fill_bytes(&mut seed);

        let key_pair = libcrux_ml_dsa::ml_dsa_44::portable::generate_key_pair(seed);

        Ok((
            *key_pair.signing_key.as_ref(),
            *key_pair.verification_key.as_ref(),
        ))
    }

    #[cfg(feature = "pq")]
    fn mldsa_sign(
        &mut self,
        signing_key: &BytesPqSignKey,
        message: &[u8],
    ) -> Result<BytesPqSignature, EDHOCError> {
        let mut randomness = [0u8; libcrux_ml_dsa::SIGNING_RANDOMNESS_SIZE];
        self.rng.fill_bytes(&mut randomness);

        let signing_key = libcrux_ml_dsa::ml_dsa_44::MLDSA44SigningKey::new(*signing_key);

        // Empty context: EDHOC does its own domain separation through the COSE Sig_structure.
        libcrux_ml_dsa::ml_dsa_44::portable::sign(&signing_key, message, &[], randomness)
            .map(|signature| *signature.as_ref())
            .map_err(|_| EDHOCError::UnsupportedCipherSuite)
    }

    #[cfg(feature = "pq")]
    fn mldsa_verify(
        &mut self,
        verify_key: &BytesPqVerifyKey,
        message: &[u8],
        signature: &BytesPqSignature,
    ) -> Result<bool, EDHOCError> {
        let verify_key = libcrux_ml_dsa::ml_dsa_44::MLDSA44VerificationKey::new(*verify_key);
        let signature = libcrux_ml_dsa::ml_dsa_44::MLDSA44Signature::new(*signature);

        Ok(
            libcrux_ml_dsa::ml_dsa_44::portable::verify(&verify_key, message, &[], &signature)
                .is_ok(),
        )
    }
}

/// The sizes in lakers-shared are written out as literals, because they come from the cipher
/// suite rather than from whichever backend happens to be compiled in. Check them against the
/// implementation so the two cannot drift apart silently.
#[cfg(feature = "pq")]
const _: () = {
    use lakers_shared::{
        ML_KEM_CIPHERTEXT_LEN, ML_KEM_DECAPS_KEY_LEN, ML_KEM_ENCAPS_KEY_LEN,
        ML_KEM_SHARED_SECRET_LEN,
    };

    assert!(ML_KEM_SHARED_SECRET_LEN == libcrux_ml_kem::SHARED_SECRET_SIZE);
    assert!(ML_KEM_ENCAPS_KEY_LEN == libcrux_ml_kem::mlkem512::MlKem512PublicKey::len());
    assert!(ML_KEM_DECAPS_KEY_LEN == libcrux_ml_kem::mlkem512::MlKem512PrivateKey::len());
    assert!(ML_KEM_CIPHERTEXT_LEN == libcrux_ml_kem::mlkem512::MlKem512Ciphertext::len());

    assert!(ML_DSA_SIGN_KEY_LEN == libcrux_ml_dsa::ml_dsa_44::MLDSA44SigningKey::len());
    assert!(ML_DSA_VERIFY_KEY_LEN == libcrux_ml_dsa::ml_dsa_44::MLDSA44VerificationKey::len());
    assert!(PQ_SIGNATURE_LENGTH == libcrux_ml_dsa::ml_dsa_44::MLDSA44Signature::len());
};

#[cfg(test)]
mod tests {
    use lakers_shared::test_helper::{
        test_aes_ccm_roundtrip, test_aes_ccm_tag_16, test_aes_ccm_tag_8,
        test_ecdsa_is_deterministic, test_ecdsa_rejects_bad_signature, test_ecdsa_roundtrip,
    };
    use lakers_shared::{CcmTagLen16, CcmTagLen8};

    use super::*;

    #[cfg(feature = "pq")]
    #[test]
    fn test_rustcrypto_mlkem() {
        use lakers_shared::test_helper::{test_mlkem_implicit_rejection, test_mlkem_roundtrip};

        let mut crypto = Crypto::new(rand_core::OsRng);
        test_mlkem_roundtrip::<Crypto<rand_core::OsRng>>(&mut crypto);
        test_mlkem_implicit_rejection::<Crypto<rand_core::OsRng>>(&mut crypto);
    }

    #[cfg(feature = "pq")]
    #[test]
    fn test_rustcrypto_mldsa() {
        use lakers_shared::test_helper::{
            test_mldsa_is_randomised, test_mldsa_rejects_bad_signature, test_mldsa_roundtrip,
        };

        let mut crypto = Crypto::new(rand_core::OsRng);
        test_mldsa_roundtrip::<Crypto<rand_core::OsRng>>(&mut crypto);
        test_mldsa_is_randomised::<Crypto<rand_core::OsRng>>(&mut crypto);
        test_mldsa_rejects_bad_signature::<Crypto<rand_core::OsRng>>(&mut crypto);
    }

    #[test]
    fn test_rustcrypto_aes_ccm() {
        let mut crypto = Crypto::new(rand_core::OsRng);
        test_aes_ccm_roundtrip::<Crypto<rand_core::OsRng>, CcmTagLen8>(&mut crypto);
        test_aes_ccm_roundtrip::<Crypto<rand_core::OsRng>, CcmTagLen16>(&mut crypto);

        test_aes_ccm_tag_8::<Crypto<rand_core::OsRng>>(&mut crypto);
        test_aes_ccm_tag_16::<Crypto<rand_core::OsRng>>(&mut crypto);
    }

    #[test]
    fn test_rustcrypto_ecdsa() {
        let mut crypto = Crypto::new(rand_core::OsRng);
        test_ecdsa_roundtrip::<Crypto<rand_core::OsRng>>(&mut crypto);
        test_ecdsa_rejects_bad_signature::<Crypto<rand_core::OsRng>>(&mut crypto);
        test_ecdsa_is_deterministic::<Crypto<rand_core::OsRng>>(&mut crypto);
    }
}
