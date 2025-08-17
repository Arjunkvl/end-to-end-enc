use hkdf::Hkdf;
use sha2::Sha256;
use x25519_dalek::{PublicKey, StaticSecret};

pub fn calc_send_root_key(
    idk_self: StaticSecret,
    idk_opp: PublicKey,
    eph_self: StaticSecret,
    spk_opp: PublicKey,
) -> [u8; 32] {
    let dh1 = idk_self.diffie_hellman(&spk_opp);
    let dh2 = eph_self.diffie_hellman(&idk_opp);
    let dh3 = eph_self.diffie_hellman(&spk_opp);

    let mut ikm = [0u8; 96];
    ikm[..32].copy_from_slice(&dh1.to_bytes()[..]);
    ikm[32..64].copy_from_slice(&dh2.to_bytes()[..]);
    ikm[64..96].copy_from_slice(&dh3.to_bytes()[..]);

    let hk = Hkdf::<Sha256>::new(None, &ikm);
    let mut root_key = [0u8; 32];
    hk.expand(&[], &mut root_key).expect("somthig is not right");
    root_key
}

pub fn calc_recv_root_key(
    idk_self: StaticSecret,
    idk_opp: PublicKey,
    ehp_opp: PublicKey,
    spk_self: StaticSecret,
) -> [u8; 32] {
    //bobs calculations;
    let dh1 = spk_self.diffie_hellman(&idk_opp);
    let dh2 = idk_self.diffie_hellman(&ehp_opp);
    let dh3 = spk_self.diffie_hellman(&ehp_opp);

    let mut ikm = [0u8; 96];
    ikm[..32].copy_from_slice(&dh1.to_bytes()[..]);
    ikm[32..64].copy_from_slice(&dh2.to_bytes()[..]);
    ikm[64..96].copy_from_slice(&dh3.to_bytes()[..]);

    let hk = Hkdf::<Sha256>::new(None, &ikm);
    let mut root_key = [0u8; 32];
    hk.expand(&[], &mut root_key).expect("somthig is not right");
    root_key
}
