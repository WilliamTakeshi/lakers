#![no_std]
#![no_main]

//! On-board tests of the lakers crypto backend on the STM32WBA55 (HASH, AES, PKA, RNG).
//!
//! Run with `cargo test --release` from this directory.

use {defmt_rtt as _, panic_probe as _};

fn import(
    crypto: &mut lakers_crypto::Crypto,
    sk: &lakers::BytesP256ElemLen,
) -> <lakers_crypto::Crypto as lakers::CryptoTrait>::SigningKey {
    crypto.import_signing_key(sk).expect("valid p-256 scalar")
}

#[defmt_test::tests]
mod tests {
    use super::import;
    use lakers::test_helper::{test_ecdsa_rejects_bad_signature, test_ecdsa_roundtrip};

    #[init]
    fn init() -> lakers_crypto::Crypto {
        lakers_stm32wba55::hardware_crypto()
    }

    #[test]
    fn test_ecdsa_sign_verify(crypto: &mut lakers_crypto::Crypto) {
        test_ecdsa_roundtrip(crypto, import);
    }

    #[test]
    fn test_ecdsa_rejects_invalid(crypto: &mut lakers_crypto::Crypto) {
        test_ecdsa_rejects_bad_signature(crypto, import);
    }
}
