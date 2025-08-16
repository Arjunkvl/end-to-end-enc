mod curve_to_ed;
mod private_key;

use curve_to_ed::{generate_signature, verify_hash};
use hkdf::Hkdf;
use private_key::PrivateKey;
use rand_core::OsRng;
use sha2::Sha256;
use x25519_dalek::{PublicKey, ReusableSecret};

fn main() {
    //alice keys
    let alice_idk = PrivateKey::new();
    let alice_idk_pub = PublicKey::from(&alice_idk);
    let alice_eph = ReusableSecret::random_from_rng(&mut OsRng);
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
        //alice calculations
        let dh1 = alice_idk.diffie_hellman(&bob_spk_pub);
        let dh2 = alice_eph.diffie_hellman(&bob_idk_pub);
        let dh3 = alice_eph.diffie_hellman(&bob_spk_pub);

        let mut ikm = [0u8; 96];
        ikm[..32].copy_from_slice(&dh1.to_bytes()[..]);
        ikm[32..64].copy_from_slice(&dh2.to_bytes()[..]);
        ikm[64..96].copy_from_slice(&dh3.to_bytes()[..]);

        let hk = Hkdf::<Sha256>::new(None, &ikm);
        let mut root_key = [0u8; 32];
        hk.expand(&[], &mut root_key).expect("somthig is not right");
        println!("{:?}", hex::encode(root_key));
    }

    //bobs calculations;
    let dh1 = bob_spk.diffie_hellman(&alice_idk_pub);
    let dh2 = bob_idk.diffie_hellman(&alice_eph_pub);
    let dh3 = bob_spk.diffie_hellman(&alice_eph_pub);

    let mut ikm = [0u8; 96];
    ikm[..32].copy_from_slice(&dh1.to_bytes()[..]);
    ikm[32..64].copy_from_slice(&dh2.to_bytes()[..]);
    ikm[64..96].copy_from_slice(&dh3.to_bytes()[..]);

    let hk = Hkdf::<Sha256>::new(None, &ikm);
    let mut root_key = [0u8; 32];
    hk.expand(&[], &mut root_key).expect("somthig is not right");
    println!("{:?}", hex::encode(root_key));
}
