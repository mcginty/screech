extern crate sodiumoxide;

use byteorder::{ByteOrder, LittleEndian};

use super::CryptoResolver;
use crate::{
    Error,
    params::{CipherChoice, DHChoice, HashChoice},
    types::{Cipher, Dh, Hash, Random},
};

use sodiumoxide::crypto::{
    aead::chacha20poly1305_ietf as sodium_chacha20poly1305, hash::sha256 as sodium_sha256,
    scalarmult::curve25519 as sodium_curve25519,
};

/// A resolver that uses [libsodium](https://github.com/jedisct1/libsodium)
/// via [sodiumoxide](https://crates.io/crates/sodiumoxide).
#[derive(Default)]
pub struct SodiumResolver;

impl CryptoResolver for SodiumResolver {
    fn resolve_rng(&self) -> Option<Box<dyn Random>> {
        Some(Box::new(SodiumRng::default()))
    }

    fn resolve_dh(&self, choice: &DHChoice) -> Option<Box<dyn Dh>> {
        match *choice {
            DHChoice::Curve25519 => Some(Box::new(SodiumDh25519::default())),
            _ => None,
        }
    }

    fn resolve_hash(&self, choice: &HashChoice) -> Option<Box<dyn Hash>> {
        match *choice {
            HashChoice::SHA256 => Some(Box::new(SodiumSha256::default())),
            _ => None,
        }
    }

    fn resolve_cipher(&self, choice: &CipherChoice) -> Option<Box<dyn Cipher>> {
        match *choice {
            CipherChoice::ChaChaPoly => Some(Box::new(SodiumChaChaPoly::default())),
            _ => None,
        }
    }
}

// Elliptic curve 25519.
pub struct SodiumDh25519 {
    privkey: sodium_curve25519::Scalar,
    pubkey:  sodium_curve25519::GroupElement,
}

impl SodiumDh25519 {
    fn convert_to_private_key(key: &mut [u8; 32]) {
        key[0] &= 248;
        key[31] &= 127;
        key[31] |= 64;
    }
}

impl Default for SodiumDh25519 {
    fn default() -> SodiumDh25519 {
        sodiumoxide::init().unwrap();

        SodiumDh25519 {
            privkey: sodium_curve25519::Scalar([0; 32]),
            pubkey:  sodium_curve25519::GroupElement([0; 32]),
        }
    }
}

impl Dh for SodiumDh25519 {
    fn name(&self) -> &'static str {
        "25519"
    }

    fn pub_len(&self) -> usize {
        32
    }

    fn priv_len(&self) -> usize {
        32
    }

    fn set(&mut self, privkey: &[u8]) {
        self.privkey = sodium_curve25519::Scalar::from_slice(privkey)
            .expect("Can't construct private key for Dh25519");
        self.pubkey = sodium_curve25519::scalarmult_base(&self.privkey);
    }

    fn generate(&mut self, rng: &mut dyn Random) {
        let mut privkey_bytes = [0; 32];
        rng.fill_bytes(&mut privkey_bytes);

        Self::convert_to_private_key(&mut privkey_bytes);

        self.privkey = sodium_curve25519::Scalar::from_slice(&privkey_bytes)
            .expect("Can't construct private key for Dh25519");
        self.pubkey = sodium_curve25519::scalarmult_base(&self.privkey);
    }

    fn pubkey(&self) -> &[u8] {
        &self.pubkey[0..32]
    }

    fn privkey(&self) -> &[u8] {
        &self.privkey[0..32]
    }

    fn dh(&self, pubkey: &[u8], out: &mut [u8]) -> Result<(), Error> {
        let pubkey = sodium_curve25519::GroupElement::from_slice(&pubkey[0..32])
            .expect("Can't construct public key for Dh25519");
        let result = sodium_curve25519::scalarmult(&self.privkey, &pubkey);

        match result {
            Ok(ref buf) => {
                copy_slices!(buf.as_ref(), out);
                Ok(())
            },
            Err(_) => Err(Error::Dh),
        }
    }
}

// Chacha20poly1305 cipher.
pub struct SodiumChaChaPoly {
    key: sodium_chacha20poly1305::Key,
}

impl Default for SodiumChaChaPoly {
    fn default() -> SodiumChaChaPoly {
        sodiumoxide::init().unwrap();

        SodiumChaChaPoly { key: sodium_chacha20poly1305::Key([0; 32]) }
    }
}

impl Cipher for SodiumChaChaPoly {
    fn name(&self) -> &'static str {
        "ChaChaPoly"
    }

    fn set(&mut self, key: &[u8]) {
        self.key = sodium_chacha20poly1305::Key::from_slice(&key[0..32])
            .expect("Can't get key for ChaChaPoly");
    }

    fn encrypt(&self, nonce: u64, authtext: &[u8], plaintext: &[u8], out: &mut [u8]) -> usize {
        let mut nonce_bytes = [0u8; 12];
        LittleEndian::write_u64(&mut nonce_bytes[4..], nonce);
        let nonce = sodium_chacha20poly1305::Nonce(nonce_bytes);

        let buf = sodium_chacha20poly1305::seal(plaintext, Some(authtext), &nonce, &self.key);

        copy_slices!(&buf, out);
        buf.len()
    }

    fn decrypt(
        &self,
        nonce: u64,
        authtext: &[u8],
        ciphertext: &[u8],
        out: &mut [u8],
    ) -> Result<usize, Error> {
        let mut nonce_bytes = [0u8; 12];
        LittleEndian::write_u64(&mut nonce_bytes[4..], nonce);
        let nonce = sodium_chacha20poly1305::Nonce(nonce_bytes);

        let result = sodium_chacha20poly1305::open(ciphertext, Some(authtext), &nonce, &self.key);

        match result {
            Ok(ref buf) => {
                copy_slices!(&buf, out);
                Ok(buf.len())
            },
            Err(_) => Err(Error::Decrypt),
        }
    }
}

// Hash Sha256.
struct SodiumSha256(sodium_sha256::State);

impl Default for SodiumSha256 {
    fn default() -> Self {
        sodiumoxide::init().unwrap();

        Self(sodium_sha256::State::default())
    }
}

impl Hash for SodiumSha256 {
    fn name(&self) -> &'static str {
        "SHA256"
    }

    fn block_len(&self) -> usize {
        64
    }

    fn hash_len(&self) -> usize {
        32
    }

    fn reset(&mut self) {
        self.0 = sodium_sha256::State::new();
    }

    fn input(&mut self, data: &[u8]) {
        self.0.update(data);
    }

    fn result(&mut self, out: &mut [u8]) {
        let digest = self.0.finalize();
        copy_slices!(digest.as_ref(), out);
    }
}

struct SodiumRng;

impl SodiumRng {
    fn default() -> Self {
        sodiumoxide::init().unwrap();
        Self
    }
}

impl rand_core::RngCore for SodiumRng {
    fn fill_bytes(&mut self, dest: &mut [u8]) {
        sodiumoxide::randombytes::randombytes_into(dest)
    }

    fn try_fill_bytes(&mut self, dest: &mut [u8]) -> Result<(), rand_core::Error> {
        Ok(self.fill_bytes(dest))
    }

    fn next_u32(&mut self) -> u32 {
        let mut buffer = [0; 4];
        self.fill_bytes(&mut buffer);
        u32::from_be_bytes(buffer)
    }

    fn next_u64(&mut self) -> u64 {
        let mut buffer = [0; 8];
        self.fill_bytes(&mut buffer);
        u64::from_be_bytes(buffer)
    }
}

impl rand_core::CryptoRng for SodiumRng {}

impl Random for SodiumRng {}

#[cfg(test)]
mod tests {
    extern crate hex;

    use self::hex::FromHex;
    use super::*;
    use rand::rngs::OsRng;

    #[test]
    fn test_curve25519() {
        // Values are cited from RFC-7748: 5.2.  Test Vectors.
        let mut keypair: SodiumDh25519 = Default::default();
        let scalar =
            Vec::<u8>::from_hex("a546e36bf0527c9d3b16154b82465edd62144c0ac1fc5a18506a2244ba449ac4")
                .unwrap();
        keypair.set(&scalar);
        let public =
            Vec::<u8>::from_hex("e6db6867583030db3594c1a424b15f7c726624ec26b3353b10a903a6d0ab1c4c")
                .unwrap();
        let mut output = [0u8; 32];
        keypair.dh(&public, &mut output).expect("Can't calculate DH");

        assert_eq!(
            output,
            Vec::<u8>::from_hex("c3da55379de9c6908e94ea4df28d084f32eccf03491c71f754b4075577a28552")
                .unwrap()
                .as_ref()
        );
    }

    #[test]
    fn test_curve25519_shared_secret() {
        let mut rng = OsRng::default();

        // Create two keypairs.
        let mut keypair_a = SodiumDh25519::default();
        keypair_a.generate(&mut rng);

        let mut keypair_b = SodiumDh25519::default();
        keypair_b.generate(&mut rng);

        // Create shared secrets with public keys of each other.
        let mut our_shared_secret = [0u8; 32];
        keypair_a.dh(keypair_b.pubkey(), &mut our_shared_secret).expect("Can't calculate DH");

        let mut remote_shared_secret = [0u8; 32];
        keypair_b.dh(keypair_a.pubkey(), &mut remote_shared_secret).expect("Can't calculate DH");

        // Results are expected to be the same.
        assert_eq!(our_shared_secret, remote_shared_secret);
    }
}
