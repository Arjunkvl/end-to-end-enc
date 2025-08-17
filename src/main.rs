mod curve_to_ed;
mod encryption_aead;
mod key_agree;
mod private_key;

use curve_to_ed::{generate_signature, verify_hash};
use key_agree::calc_send_root_key;
use private_key::PrivateKey;
use rand_core::OsRng;
use x25519_dalek::{PublicKey, StaticSecret};

use crate::key_agree::calc_recv_root_key;

fn main() {
    //alice keys
    let alice_idk = PrivateKey::new();
    let alice_idk_pub = PublicKey::from(&alice_idk);
    let alice_eph = StaticSecret::random_from_rng(&mut OsRng);
    let alice_eph_pub = PublicKey::from(&alice_eph);

    //bobs keys...
    let bob_idk = PrivateKey::new();
    let bob_idk_pub = PublicKey::from(&bob_idk);
    let bob_spk = PrivateKey::new();
    let bob_spk_pub = PublicKey::from(&bob_spk);
    let bob_spk_sig = generate_signature(&bob_idk, &[bob_spk_pub.as_bytes()]);

    if verify_hash(
        bob_idk_pub.as_bytes(),
        &[bob_spk_pub.as_bytes()],
        &bob_spk_sig,
    ) {
        let key = calc_send_root_key(alice_idk, bob_idk_pub, alice_eph, bob_spk_pub);
        println!("{:?}", hex::encode(key));
    }

    let key = calc_recv_root_key(bob_idk, alice_idk_pub, alice_eph_pub, bob_spk);
    println!("{:?}", hex::encode(key));
}
