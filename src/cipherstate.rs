use crate::{
    constants::TAGLEN,
    error::{Error, InitStage, StateProblem},
    types::Cipher,
};

pub(crate) struct CipherState {
    cipher:  Box<dyn Cipher>,
    n:       u64,
    has_key: bool,
}

impl CipherState {
    pub fn new(cipher: Box<dyn Cipher>) -> Self {
        Self { cipher, n: 0, has_key: false }
    }

    pub fn name(&self) -> &'static str {
        self.cipher.name()
    }

    pub fn set(&mut self, key: &[u8], n: u64) {
        self.cipher.set(key);
        self.n = n;
        self.has_key = true;
    }

    pub fn encrypt_ad(
        &mut self,
        authtext: &[u8],
        plaintext: &[u8],
        out: &mut [u8],
    ) -> Result<usize, Error> {
        if !self.has_key {
            return Err(StateProblem::MissingKeyMaterial.into())
        }

        let len = self.cipher.encrypt(self.n, authtext, plaintext, out);
        self.n = self.n.checked_add(1).ok_or(StateProblem::Exhausted)?;

        Ok(len)
    }

    pub fn decrypt_ad(
        &mut self,
        authtext: &[u8],
        ciphertext: &[u8],
        out: &mut [u8],
    ) -> Result<usize, Error> {
        if (ciphertext.len() < TAGLEN) || out.len() < (ciphertext.len() - TAGLEN) {
            return Err(Error::Decrypt);
        }

        if !self.has_key {
            return Err(StateProblem::MissingKeyMaterial.into());
        }

        let len = self.cipher.decrypt(self.n, authtext, ciphertext, out);
        self.n = self.n.checked_add(1).ok_or(StateProblem::Exhausted)?;

        len
    }

    pub fn encrypt(&mut self, plaintext: &[u8], out: &mut [u8]) -> Result<usize, Error> {
        self.encrypt_ad(&[0u8; 0], plaintext, out)
    }

    pub fn decrypt(&mut self, ciphertext: &[u8], out: &mut [u8]) -> Result<usize, Error> {
        self.decrypt_ad(&[0u8; 0], ciphertext, out)
    }

    pub fn rekey(&mut self) {
        self.cipher.rekey();
    }

    pub fn rekey_manually(&mut self, key: &[u8]) {
        self.cipher.set(key);
    }

    pub fn nonce(&self) -> u64 {
        self.n
    }

    pub fn set_nonce(&mut self, nonce: u64) {
        self.n = nonce;
    }
}

pub(crate) struct CipherStates(pub CipherState, pub CipherState);

impl CipherStates {
    pub fn new(initiator: CipherState, responder: CipherState) -> Result<Self, Error> {
        if initiator.name() != responder.name() {
            bail!(InitStage::ValidateCipherTypes);
        }

        Ok(CipherStates(initiator, responder))
    }

    pub fn rekey_initiator(&mut self) {
        self.0.rekey()
    }

    pub fn rekey_initiator_manually(&mut self, key: &[u8]) {
        self.0.rekey_manually(key)
    }

    pub fn rekey_responder(&mut self) {
        self.1.rekey()
    }

    pub fn rekey_responder_manually(&mut self, key: &[u8]) {
        self.1.rekey_manually(key)
    }
}

pub(crate) struct StatelessCipherState {
    cipher:  Box<dyn Cipher>,
    has_key: bool,
}

impl StatelessCipherState {
    pub fn encrypt_ad(
        &self,
        nonce: u64,
        authtext: &[u8],
        plaintext: &[u8],
        out: &mut [u8],
    ) -> Result<usize, Error> {
        if !self.has_key {
            return Err(StateProblem::MissingKeyMaterial.into())
        }

        Ok(self.cipher.encrypt(nonce, authtext, plaintext, out))
    }

    pub fn decrypt_ad(
        &self,
        nonce: u64,
        authtext: &[u8],
        ciphertext: &[u8],
        out: &mut [u8],
    ) -> Result<usize, Error> {
        if (ciphertext.len() < TAGLEN) || out.len() < (ciphertext.len() - TAGLEN) {
            return Err(Error::Decrypt);
        }

        if !self.has_key {
            return Err(StateProblem::MissingKeyMaterial.into());
        }

        self.cipher.decrypt(nonce, authtext, ciphertext, out)
    }

    pub fn encrypt(&self, nonce: u64, plaintext: &[u8], out: &mut [u8]) -> Result<usize, Error> {
        self.encrypt_ad(nonce, &[], plaintext, out)
    }

    pub fn decrypt(&self, nonce: u64, ciphertext: &[u8], out: &mut [u8]) -> Result<usize, Error> {
        self.decrypt_ad(nonce, &[], ciphertext, out)
    }

    pub fn rekey(&mut self) {
        self.cipher.rekey()
    }

    pub fn rekey_manually(&mut self, key: &[u8]) {
        self.cipher.set(key);
    }
}

impl From<CipherState> for StatelessCipherState {
    fn from(other: CipherState) -> Self {
        Self { cipher: other.cipher, has_key: other.has_key }
    }
}

pub(crate) struct StatelessCipherStates(pub StatelessCipherState, pub StatelessCipherState);

impl From<CipherStates> for StatelessCipherStates {
    fn from(other: CipherStates) -> Self {
        StatelessCipherStates(other.0.into(), other.1.into())
    }
}

impl StatelessCipherStates {
    pub fn rekey_initiator(&mut self) {
        self.0.rekey()
    }

    pub fn rekey_initiator_manually(&mut self, key: &[u8]) {
        self.0.rekey_manually(key)
    }

    pub fn rekey_responder(&mut self) {
        self.1.rekey()
    }

    pub fn rekey_responder_manually(&mut self, key: &[u8]) {
        self.1.rekey_manually(key)
    }
}
