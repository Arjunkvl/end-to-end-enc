use aes_gcm::{Aes256Gcm, Key, KeyInit, Nonce, aead::Aead};
use hkdf::Hkdf;
use sha2::Sha256;

pub fn encrypt(key: [u8; 32], payload: &[u8]) -> Vec<u8> {
    let hk = Hkdf::<Sha256>::new(None, &key);
    let mut salt = [0u8; 12];
    hk.expand(&[], &mut salt).expect("error happen");
    let nonce = Nonce::from_slice(&salt[..]);
    let key = Key::<Aes256Gcm>::from_slice(&key);
    let cipher = Aes256Gcm::new(key);
    cipher.encrypt(&nonce, payload.as_ref()).unwrap()
}

pub fn decrypt(key: [u8; 32], data: &[u8]) -> Vec<u8> {
    let hk = Hkdf::<Sha256>::new(None, &key);
    let mut salt = [0u8; 12];
    hk.expand(&[], &mut salt).expect("error happen");
    let nonce = Nonce::from_slice(&salt[..]);
    let key = Key::<Aes256Gcm>::from_slice(&key);
    let cipher = Aes256Gcm::new(key);
    cipher.decrypt(&nonce, data.as_ref()).unwrap()
}
