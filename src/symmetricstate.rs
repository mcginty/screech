use crate::error::Error;
use crate::constants::{CIPHERKEYLEN, MAXHASHLEN};
use crate::types::Hash;
use crate::cipherstate::CipherState;
use alloc::boxed::Box;

#[derive(Copy, Clone)]
pub(crate) struct SymmetricStateData {
    h       : [u8; MAXHASHLEN],
    ck      : [u8; MAXHASHLEN],
    has_key : bool,
}

impl Default for SymmetricStateData {
    fn default() -> Self {
        SymmetricStateData {
            h: [0u8; MAXHASHLEN],
            ck: [0u8; MAXHASHLEN],
            has_key: false
        }
    }
}

pub(crate) struct SymmetricState {
    cipherstate : CipherState,
    hasher      : Box<dyn Hash>,
    inner       : SymmetricStateData,
}

impl SymmetricState {
    pub fn new(cipherstate: CipherState, hasher: Box<dyn Hash>) -> SymmetricState {
        SymmetricState {
            cipherstate,
            hasher,
            inner: SymmetricStateData::default(),
        }
    }

    pub fn initialize(&mut self, handshake_name: &str) {
        if handshake_name.len() <= self.hasher.hash_len() {
            copy_slices!(handshake_name.as_bytes(), self.inner.h);
        } else {
            self.hasher.reset();
            self.hasher.input(handshake_name.as_bytes());
            self.hasher.result(&mut self.inner.h);
        }
        copy_slices!(&self.inner.h, &mut self.inner.ck);
        self.inner.has_key = false;
    }

    pub fn mix_key(&mut self, data: &[u8]) {
        let hash_len = self.hasher.hash_len();
        let mut hkdf_output = ([0u8; MAXHASHLEN], [0u8; MAXHASHLEN]);
        self.hasher.hkdf(&self.inner.ck[..hash_len], data, 2, &mut hkdf_output.0, &mut hkdf_output.1, &mut []);
        copy_slices!(&hkdf_output.0, &mut self.inner.ck);
        self.cipherstate.set(&hkdf_output.1[..CIPHERKEYLEN], 0);
        self.inner.has_key = true;
    }

    pub fn mix_hash(&mut self, data: &[u8]) {
        let hash_len = self.hasher.hash_len();
        self.hasher.reset();
        self.hasher.input(&self.inner.h[..hash_len]);
        self.hasher.input(data);
        self.hasher.result(&mut self.inner.h);
    }

    pub fn mix_key_and_hash(&mut self, data: &[u8]) {
        let hash_len = self.hasher.hash_len();
        let mut hkdf_output = ([0u8; MAXHASHLEN], [0u8; MAXHASHLEN], [0u8; MAXHASHLEN]);
        self.hasher.hkdf(&self.inner.ck[..hash_len], data, 3, &mut hkdf_output.0, &mut hkdf_output.1, &mut hkdf_output.2);
        copy_slices!(&hkdf_output.0, &mut self.inner.ck);
        self.mix_hash(&hkdf_output.1[..hash_len]);
        self.cipherstate.set(&hkdf_output.2[..CIPHERKEYLEN], 0);
    }

    pub fn has_key(&self) -> bool {
        self.inner.has_key
    }

    /// Encrypt a message and mixes in the hash of the output
    pub fn encrypt_and_mix_hash(&mut self, plaintext: &[u8], out: &mut [u8]) -> Result<usize, Error> {
        let hash_len = self.hasher.hash_len();
        let output_len = if self.inner.has_key {
            self.cipherstate.encrypt_ad(&self.inner.h[..hash_len], plaintext, out)?
        } else {
            copy_slices!(plaintext, out);
            plaintext.len()
        };
        self.mix_hash(&out[..output_len]);
        Ok(output_len)
    }

    pub fn decrypt_and_mix_hash(&mut self, data: &[u8], out: &mut [u8]) -> Result<usize, ()> {
        let hash_len = self.hasher.hash_len();
        let payload_len = if self.inner.has_key {
            self.cipherstate.decrypt_ad(&self.inner.h[..hash_len], data, out)?
        } else {
            if out.len() < data.len() {
                return Err(())
            }
            copy_slices!(data, out);
            data.len()
        };
        self.mix_hash(data);
        Ok(payload_len)
    }

    pub fn split(&mut self, child1: &mut CipherState, child2: &mut CipherState) {
        let hash_len = self.hasher.hash_len();
        let mut hkdf_output = ([0u8; MAXHASHLEN], [0u8; MAXHASHLEN]);
        self.hasher.hkdf(&self.inner.ck[..hash_len], &[0u8; 0], 2,
                         &mut hkdf_output.0,
                         &mut hkdf_output.1,
                         &mut []);
        child1.set(&hkdf_output.0[..CIPHERKEYLEN], 0);
        child2.set(&hkdf_output.1[..CIPHERKEYLEN], 0);
    }

    pub(crate) fn checkpoint(&mut self) -> SymmetricStateData {
        self.inner
    }

    pub(crate) fn restore(&mut self, checkpoint: SymmetricStateData) {
        self.inner = checkpoint;
    }

    pub fn handshake_hash(&self) -> &[u8] {
        let hash_len = self.hasher.hash_len();
        &self.inner.h[..hash_len]
    }
}
