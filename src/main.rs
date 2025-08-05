use ed25519_dalek::{Signer, SigningKey};
use rand_core::OsRng;
use x25519_dalek::{PublicKey, StaticSecret};

mod curve_to_ed;
fn main() {
    let alice_secret = StaticSecret::random_from_rng(&mut OsRng);
    let alice_public = PublicKey::from(&alice_secret);
    let prekey = StaticSecret::random_from_rng(&mut OsRng);
    let prekey_pub = PublicKey::from(&prekey);
}
