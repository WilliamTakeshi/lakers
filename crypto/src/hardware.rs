use core::mem::ManuallyDrop;

use embedded_cal::Cal;

pub struct KeepPowered<C>(ManuallyDrop<C>);

impl<C> KeepPowered<C> {
    pub const fn new(cal: C) -> Self {
        Self(ManuallyDrop::new(cal))
    }
}

impl<C: Cal> Cal for KeepPowered<C> {
    type DhProvider = C::DhProvider;
    type AeadProvider = C::AeadProvider;
    type HashProvider = C::HashProvider;
    type HmacProvider = C::HmacProvider;
    type SignProvider = C::SignProvider;

    fn dh(&mut self) -> &mut Self::DhProvider {
        self.0.dh()
    }

    fn aead(&mut self) -> &mut Self::AeadProvider {
        self.0.aead()
    }

    fn hash(&mut self) -> &mut Self::HashProvider {
        self.0.hash()
    }

    fn hmac(&mut self) -> &mut Self::HmacProvider {
        self.0.hmac()
    }

    fn sign(&mut self) -> &mut Self::SignProvider {
        self.0.sign()
    }
}

impl<C: rand_core::TryRng> rand_core::TryRng for KeepPowered<C> {
    type Error = C::Error;

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

impl<C: rand_core::TryCryptoRng> rand_core::TryCryptoRng for KeepPowered<C> {}
