use curve25519_dalek::constants::ED25519_BASEPOINT_POINT;
use curve25519_dalek::edwards::CompressedEdwardsY;
use curve25519_dalek::scalar::Scalar;
use x25519_dalek::StaticSecret;

struct EdKeyPair {
    public: [u8; 32],
    private: Scalar,
}

fn generate_key_pair(k: StaticSecret) -> EdKeyPair {
    let _k = Scalar::from_bytes_mod_order(k.to_bytes());
    let _e = (_k * ED25519_BASEPOINT_POINT).compress().to_bytes();
    let sign_bit = (_e[31] >> 7) & 1;
    let mut _a = _e;
    _a[31] &= 0x7f;
    let _a = CompressedEdwardsY(_a).to_bytes();
    let _p = if sign_bit == 1 { -_k } else { _k };
    EdKeyPair {
        public: _a,
        private: _p,
    }
}
