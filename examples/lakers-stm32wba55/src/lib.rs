#![no_std]

//! Shared support code for running lakers on the STM32WBA55.

/// Builds the hardware `Crypto`: the STM32WBA55 `Cal` (hardware HASH / AES / PKA / RNG) wrapped in
/// the software `Extender` that adds the high-level SHA-256 / HMAC / HKDF / ECDSA layer.
pub fn hardware_crypto() -> lakers_crypto::Crypto {
    let cal = embedded_cal_software_demo::Extender::<lakers_crypto::Stm32wba55ExtConfig>::new(
        embedded_cal_stm32wba55::Stm32wba55Cal::new(
            stm32_metapac::HASH,
            stm32_metapac::RCC,
            stm32_metapac::RNG,
            stm32_metapac::AES,
            stm32_metapac::PKA,
        ),
    );
    lakers_crypto::Crypto::new(cal)
}
