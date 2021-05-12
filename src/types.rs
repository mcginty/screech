//! The traits for cryptographic implementations that can be used by Noise.

use crate::{constants::{CIPHERKEYLEN, MAXBLOCKLEN, MAXHASHLEN, TAGLEN}, Error};
use rand_core::{CryptoRng, RngCore};

/// CSPRNG operations
pub trait Random: CryptoRng + RngCore + Send + Sync {}

/// Diffie-Hellman operations
pub trait Dh: Send + Sync {
    /// The string that the Noise spec defines for the primitive
    fn name(&self) -> &'static str;

    /// The length in bytes of a public key for this primitive
    fn pub_len(&self) -> usize;

    /// The length in bytes of a private key for this primitive
    fn priv_len(&self) -> usize;

    /// Set the private key
    fn set(&mut self, privkey: &[u8]);

    /// Generate a new private key
    fn generate(&mut self, rng: &mut dyn Random);

    /// Get the public key
    fn pubkey(&self) -> &[u8];

    /// Get the private key
    fn privkey(&self) -> &[u8];

    /// Calculate a Diffie-Hellman exchange.
    fn dh(&self, pubkey: &[u8], out: &mut [u8]) -> Result<(), Error>;
}

/// Cipher operations
pub trait Cipher: Send + Sync {
    /// The string that the Noise spec defines for the primitive
    fn name(&self) -> &'static str;

    /// Set the key
    fn set(&mut self, key: &[u8]);

    /// Encrypt (with associated data) a given plaintext.
    fn encrypt(&self, nonce: u64, authtext: &[u8], plaintext: &[u8], out: &mut [u8]) -> usize;

    /// Decrypt (with associated data) a given ciphertext.
    fn decrypt(
        &self,
        nonce: u64,
        authtext: &[u8],
        ciphertext: &[u8],
        out: &mut [u8],
    ) -> Result<usize, Error>;

    /// Rekey according to Section 4.2 of the Noise Specification, with a default
    /// implementation guaranteed to be secure for all ciphers.
    fn rekey(&mut self) {
        let mut ciphertext = [0; CIPHERKEYLEN + TAGLEN];
        let ciphertext_len =
            self.encrypt(u64::max_value(), &[], &[0; CIPHERKEYLEN], &mut ciphertext);
        assert_eq!(ciphertext_len, ciphertext.len());
        self.set(&ciphertext[..CIPHERKEYLEN]);
    }
}

/// Hashing operations
pub trait Hash: Send + Sync {
    /// The string that the Noise spec defines for the primitive
    fn name(&self) -> &'static str;

    /// The block length for the primitive
    fn block_len(&self) -> usize;

    /// The final hash digest length for the primitive
    fn hash_len(&self) -> usize;

    /// Reset the internal state
    fn reset(&mut self);

    /// Provide input to the internal state
    fn input(&mut self, data: &[u8]);

    /// Get the resulting hash
    fn result(&mut self, out: &mut [u8]);

    /// Calculate HMAC, as specified in the Noise spec.
    ///
    /// NOTE: This method clobbers the existing internal state
    fn hmac(&mut self, key: &[u8], data: &[u8], out: &mut [u8]) {
        assert!(key.len() <= self.block_len());
        let block_len = self.block_len();
        let hash_len = self.hash_len();
        let mut ipad = [0x36u8; MAXBLOCKLEN];
        let mut opad = [0x5cu8; MAXBLOCKLEN];
        for count in 0..key.len() {
            ipad[count] ^= key[count];
            opad[count] ^= key[count];
        }
        self.reset();
        self.input(&ipad[..block_len]);
        self.input(data);
        let mut inner_output = [0u8; MAXHASHLEN];
        self.result(&mut inner_output);
        self.reset();
        self.input(&opad[..block_len]);
        self.input(&inner_output[..hash_len]);
        self.result(out);
    }

    /// Derive keys as specified in the Noise spec.
    ///
    /// NOTE: This method clobbers the existing internal state
    fn hkdf(
        &mut self,
        chaining_key: &[u8],
        input_key_material: &[u8],
        outputs: usize,
        out1: &mut [u8],
        out2: &mut [u8],
        out3: &mut [u8],
    ) {
        let hash_len = self.hash_len();
        let mut temp_key = [0u8; MAXHASHLEN];
        self.hmac(chaining_key, input_key_material, &mut temp_key);
        self.hmac(&temp_key, &[1u8], out1);
        if outputs == 1 {
            return;
        }

        let mut in2 = [0u8; MAXHASHLEN + 1];
        copy_slices!(&out1[0..hash_len], &mut in2);
        in2[hash_len] = 2;
        self.hmac(&temp_key, &in2[..=hash_len], out2);
        if outputs == 2 {
            return;
        }

        let mut in3 = [0u8; MAXHASHLEN + 1];
        copy_slices!(&out2[0..hash_len], &mut in3);
        in3[hash_len] = 3;
        self.hmac(&temp_key, &in3[..=hash_len], out3);
    }
}

/// Kem operations.
#[cfg(feature = "hfs")]
pub trait Kem: Send + Sync {
    /// The string that the Noise spec defines for the primitive.
    fn name(&self) -> &'static str;

    /// The length in bytes of a public key for this primitive.
    fn pub_len(&self) -> usize;

    /// The length in bytes the Kem cipherthext for this primitive.
    fn ciphertext_len(&self) -> usize;

    /// Shared secret length in bytes that this Kem encapsulates.
    fn shared_secret_len(&self) -> usize;

    /// Generate a new private key.
    fn generate(&mut self, rng: &mut dyn Random);

    /// Get the public key
    fn pubkey(&self) -> &[u8];

    /// Generate a shared secret and encapsulate it using this Kem.
    #[must_use]
    fn encapsulate(
        &self,
        pubkey: &[u8],
        shared_secret_out: &mut [u8],
        ciphertext_out: &mut [u8],
    ) -> Result<(usize, usize), ()>;

    /// Decapsulate a ciphertext producing a shared secret.
    #[must_use]
    fn decapsulate(&self, ciphertext: &[u8], shared_secret_out: &mut [u8]) -> Result<usize, ()>;
}
