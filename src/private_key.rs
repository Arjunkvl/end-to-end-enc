use curve25519_dalek::scalar;
use rand::RngCore;
use x25519_dalek::StaticSecret;

pub struct PrivateKey {}

impl PrivateKey {
    pub fn new() -> StaticSecret {
        let mut bytes = [0u8; 32];
        rand::thread_rng().fill_bytes(&mut bytes);
        bytes = scalar::clamp_integer(bytes);
        StaticSecret::from(bytes)
    }
}
