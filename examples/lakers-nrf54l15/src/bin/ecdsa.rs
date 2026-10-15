#![no_std]
#![no_main]

//! ECDSA P-256 sign/verify self-test on the nRF54L15's CRACEN.

use defmt::info;
use lakers_nrf54l15::hardware_crypto;
use lakers_shared::test_helper::{test_ecdsa_rejects_bad_signature, test_ecdsa_roundtrip};
use {defmt_rtt as _, panic_probe as _};

// Add a test P-256 sign/verify since we still don't have the method0 implemented
// TODO: remove this test when we have a method0 working and tested
#[cortex_m_rt::entry]
fn main() -> ! {
    let mut crypto = hardware_crypto();

    info!("ecdsa roundtrip");
    test_ecdsa_roundtrip(&mut crypto, |sk| *sk);
    info!("ecdsa roundtrip ok");

    info!("ecdsa rejects bad signature");
    test_ecdsa_rejects_bad_signature(&mut crypto, |sk| *sk);
    info!("ecdsa rejects bad signature ok");

    info!("all ecdsa tests passed");
    loop {
        cortex_m::asm::wfi();
    }
}
