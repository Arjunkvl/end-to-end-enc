mod curve_to_ed;
mod private_key;

use curve_to_ed::generate_signature;
use private_key::PrivateKey;
use rand_core::OsRng;
use x25519_dalek::{PublicKey, StaticSecret};

use crate::curve_to_ed::verify_hash;

fn main() {
    let key = PrivateKey::new();
    let key_pub = PublicKey::from(&key);
    let spk = StaticSecret::random_from_rng(&mut OsRng);
    let msg = PublicKey::from(&spk);
    let p = msg.as_bytes();
    let sig = generate_signature(&key, &[&p[..]]);
    verify_hash(key_pub.as_bytes(), &[&p[..]], &sig);
    println!("{:?}", hex::encode(sig));
}
