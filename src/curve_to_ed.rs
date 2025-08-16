use curve25519_dalek::scalar::Scalar;
use curve25519_dalek::{EdwardsPoint, MontgomeryPoint, constants::ED25519_BASEPOINT_TABLE};
use rand::RngCore;
use sha2::{Digest, Sha512};
use subtle::ConstantTimeEq;
use x25519_dalek::StaticSecret;

pub fn generate_signature(key: &StaticSecret, message: &[&[u8]]) -> [u8; 64] {
    let mut random_bytes = [0u8; 64];
    rand::thread_rng().fill_bytes(&mut random_bytes);
    let key_bytes = key.to_bytes();
    let a = Scalar::from_bytes_mod_order(key_bytes);
    let ed_public_key_point = &a * ED25519_BASEPOINT_TABLE;
    let ed_public_key = ed_public_key_point.compress();
    let sign_bit = ed_public_key.as_bytes()[31] & 0b1000_0000_u8;

    //first hash;
    let mut hash1 = Sha512::new();
    let hash_prefix = [
        0xFEu8, 0xFFu8, 0xFFu8, 0xFFu8, 0xFFu8, 0xFFu8, 0xFFu8, 0xFFu8, 0xFFu8, 0xFFu8, 0xFFu8,
        0xFFu8, 0xFFu8, 0xFFu8, 0xFFu8, 0xFFu8, 0xFFu8, 0xFFu8, 0xFFu8, 0xFFu8, 0xFFu8, 0xFFu8,
        0xFFu8, 0xFFu8, 0xFFu8, 0xFFu8, 0xFFu8, 0xFFu8, 0xFFu8, 0xFFu8, 0xFFu8, 0xFFu8,
    ];
    hash1.update(&hash_prefix[..]);
    hash1.update(&key_bytes[..]);
    for message_bit in message {
        hash1.update(message_bit);
    }
    hash1.update(&random_bytes[..]);
    let r = Scalar::from_hash(hash1);
    let cap_r = (&r * ED25519_BASEPOINT_TABLE).compress();

    let mut hash = Sha512::new();
    hash.update(cap_r.as_bytes());
    hash.update(ed_public_key.as_bytes());
    for message_bit in message {
        hash.update(message_bit);
    }
    let h = Scalar::from_hash(hash);
    let s = (h * a) + r;

    let mut result = [0u8; 64];
    result[..32].copy_from_slice(cap_r.as_bytes());
    result[32..].copy_from_slice(s.as_bytes());
    result[63] &= 0b0111_1111_u8;
    result[63] |= sign_bit;
    result
}

pub fn verify_hash(public_key: &[u8; 32], message: &[&[u8]], signature: &[u8; 64]) -> bool {
    let mont_point = MontgomeryPoint(*public_key);
    let ed_public_key_point = match mont_point.to_edwards((signature[63] & 0b1000_0000_u8) >> 7) {
        Some(x) => x,
        None => return false,
    };
    let cap_a = ed_public_key_point.compress();
    let mut cap_r = [0u8; 32];
    cap_r.copy_from_slice(&signature[..32]);
    let mut s = [0u8; 32];
    s.copy_from_slice(&signature[32..]);
    s[31] &= 0b0111_1111_u8;
    if (s[31] & 0b1110_0000_u8) != 0 {
        return false;
    }
    let minus_cap_a = -ed_public_key_point;

    let mut hash = Sha512::new();
    hash.update(&cap_r[..]);
    hash.update(cap_a.as_bytes());
    for message_piece in message {
        hash.update(message_piece);
    }
    let h = Scalar::from_hash(hash);

    let cap_r_check_point = EdwardsPoint::vartime_double_scalar_mul_basepoint(
        &h,
        &minus_cap_a,
        &Scalar::from_bytes_mod_order(s),
    );
    let cap_r_check = cap_r_check_point.compress();

    bool::from(cap_r_check.as_bytes().ct_eq(&cap_r))
}
