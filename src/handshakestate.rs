#[cfg(feature = "risky-raw-split")]
use crate::constants::{CIPHERKEYLEN, MAXHASHLEN};
#[cfg(feature = "hfs")]
use crate::constants::{MAXKEMCTLEN, MAXKEMPUBLEN, MAXKEMSSLEN};
#[cfg(feature = "hfs")]
use crate::types::Kem;
use crate::{
    cipherstate::{CipherState, CipherStates},
    constants::{MAXDHLEN, MAXMSGLEN, PSKLEN, TAGLEN},
    error::{Error, InitStage, StateProblem},
    params::{DhToken, HandshakeTokens, MessagePatterns, NoiseParams, Token},
    stateless_transportstate::StatelessTransportState,
    symmetricstate::SymmetricState,
    transportstate::TransportState,
    types::{Dh, Hash, Random},
    utils::Toggle,
};
use std::{
    convert::{TryFrom, TryInto},
    fmt,
};

/// A state machine encompassing the handshake phase of a Noise session.
///
/// **Note:** you are probably looking for [`Builder`](struct.Builder.html) to
/// get started.
///
/// See: [http://noiseprotocol.org/noise.html#the-handshakestate-object](http://noiseprotocol.org/noise.html#the-handshakestate-object)
pub struct HandshakeState {
    pub(crate) rng:              Box<dyn Random>,
    pub(crate) symmetricstate:   SymmetricState,
    pub(crate) cipherstates:     CipherStates,
    pub(crate) s:                Toggle<Box<dyn Dh>>,
    pub(crate) e:                Toggle<Box<dyn Dh>>,
    pub(crate) fixed_ephemeral:  bool,
    pub(crate) rs:               Toggle<[u8; MAXDHLEN]>,
    pub(crate) re:               Toggle<[u8; MAXDHLEN]>,
    pub(crate) initiator:        bool,
    pub(crate) params:           NoiseParams,
    pub(crate) psks:             [Option<[u8; PSKLEN]>; 10],
    #[cfg(feature = "hfs")]
    pub(crate) kem:              Option<Box<dyn Kem>>,
    #[cfg(feature = "hfs")]
    pub(crate) kem_re:           Option<[u8; MAXKEMPUBLEN]>,
    pub(crate) my_turn:          bool,
    pub(crate) message_patterns: MessagePatterns,
    pub(crate) pattern_position: usize,
}

impl HandshakeState {
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn new(
        rng: Box<dyn Random>,
        cipherstate: CipherState,
        hasher: Box<dyn Hash>,
        s: Toggle<Box<dyn Dh>>,
        e: Toggle<Box<dyn Dh>>,
        fixed_ephemeral: bool,
        rs: Toggle<[u8; MAXDHLEN]>,
        re: Toggle<[u8; MAXDHLEN]>,
        initiator: bool,
        params: NoiseParams,
        psks: [Option<[u8; PSKLEN]>; 10],
        prologue: &[u8],
        cipherstates: CipherStates,
    ) -> Result<HandshakeState, Error> {
        if (s.is_on() && e.is_on() && s.pub_len() != e.pub_len())
            || (s.is_on() && rs.is_on() && s.pub_len() > rs.len())
            || (s.is_on() && re.is_on() && s.pub_len() > re.len())
        {
            bail!(InitStage::ValidateKeyLengths);
        }

        let tokens = HandshakeTokens::try_from(&params.handshake)?;

        let mut symmetricstate = SymmetricState::new(cipherstate, hasher);

        symmetricstate.initialize(&params.name);
        symmetricstate.mix_hash(prologue);

        let dh_len = s.pub_len();
        if initiator {
            for token in tokens.premsg_pattern_i {
                symmetricstate.mix_hash(
                    match *token {
                        Token::S => &s,
                        Token::E => &e,
                        _ => unreachable!(),
                    }
                    .get()
                    .ok_or(StateProblem::MissingKeyMaterial)?
                    .pubkey(),
                );
            }
            for token in tokens.premsg_pattern_r {
                symmetricstate.mix_hash(
                    &match *token {
                        Token::S => &rs,
                        Token::E => &re,
                        _ => unreachable!(),
                    }
                    .get()
                    .ok_or(StateProblem::MissingKeyMaterial)?[..dh_len],
                );
            }
        } else {
            for token in tokens.premsg_pattern_i {
                symmetricstate.mix_hash(
                    &match *token {
                        Token::S => &rs,
                        Token::E => &re,
                        _ => unreachable!(),
                    }
                    .get()
                    .ok_or(StateProblem::MissingKeyMaterial)?[..dh_len],
                );
            }
            for token in tokens.premsg_pattern_r {
                symmetricstate.mix_hash(
                    match *token {
                        Token::S => &s,
                        Token::E => &e,
                        _ => unreachable!(),
                    }
                    .get()
                    .ok_or(StateProblem::MissingKeyMaterial)?
                    .pubkey(),
                );
            }
        }

        Ok(HandshakeState {
            rng,
            symmetricstate,
            cipherstates,
            s,
            e,
            fixed_ephemeral,
            rs,
            re,
            initiator,
            params,
            psks,
            #[cfg(feature = "hfs")]
            kem: None,
            #[cfg(feature = "hfs")]
            kem_re: None,
            my_turn: initiator,
            message_patterns: tokens.msg_patterns,
            pattern_position: 0,
        })
    }

    pub(crate) fn dh_len(&self) -> usize {
        self.s.pub_len()
    }

    #[cfg(feature = "hfs")]
    pub(crate) fn set_kem(&mut self, kem: Box<dyn Kem>) {
        self.kem = Some(kem);
    }

    fn dh(&self, token: &DhToken) -> Result<[u8; MAXDHLEN], Error> {
        let mut dh_out = [0u8; MAXDHLEN];
        let (dh, key) = match (token, self.is_initiator()) {
            (DhToken::Ee, _) => (&self.e, &self.re),
            (DhToken::Ss, _) => (&self.s, &self.rs),
            (DhToken::Se, true) | (DhToken::Es, false) => (&self.s, &self.re),
            (DhToken::Es, true) | (DhToken::Se, false) => (&self.e, &self.rs),
        };
        if !(dh.is_on() && key.is_on()) {
            bail!(StateProblem::MissingKeyMaterial);
        }
        dh.dh(&**key, &mut dh_out).map_err(|_| Error::Dh)?;
        Ok(dh_out)
    }

    /// This method will return `true` if the *previous* write payload was encrypted.
    ///
    /// See [Payload Security Properties](http://noiseprotocol.org/noise.html#payload-security-properties)
    /// for more information on the specific properties of your chosen handshake pattern.
    ///
    /// # Examples
    ///
    /// ```rust,ignore
    /// let mut session = Builder::new("Noise_NN_25519_AESGCM_SHA256".parse()?)
    ///     .build_initiator()?;
    ///
    /// // write message...
    ///
    /// assert!(session.was_write_payload_encrypted());
    /// ```
    pub fn was_write_payload_encrypted(&self) -> bool {
        self.symmetricstate.has_key()
    }

    /// Construct a message from `payload` (and pending handshake tokens if in handshake state),
    /// and writes it to the `message` buffer.
    ///
    /// Returns the size of the written payload.
    ///
    /// # Errors
    ///
    /// Will result in `Error::Input` if the size of the output exceeds the max message
    /// length in the Noise Protocol (65535 bytes).
    pub fn write_message(&mut self, payload: &[u8], message: &mut [u8]) -> Result<usize, Error> {
        let checkpoint = self.symmetricstate.checkpoint();
        match self._write_message(payload, message) {
            Ok(res) => {
                self.pattern_position += 1;
                self.my_turn = false;
                Ok(res)
            },
            Err(err) => {
                self.symmetricstate.restore(checkpoint);
                Err(err)
            },
        }
    }

    fn _write_message(&mut self, payload: &[u8], message: &mut [u8]) -> Result<usize, Error> {
        if !self.my_turn {
            bail!(StateProblem::NotTurnToWrite);
        } else if self.pattern_position >= self.message_patterns.len() {
            bail!(StateProblem::HandshakeAlreadyFinished);
        }

        let mut byte_index = 0;
        for token in self.message_patterns[self.pattern_position].iter() {
            match token {
                Token::E => {
                    if byte_index + self.e.pub_len() > message.len() {
                        bail!(Error::Input)
                    }

                    if !self.fixed_ephemeral {
                        self.e.generate(&mut *self.rng);
                    }
                    let pubkey = self.e.pubkey();
                    message[byte_index..byte_index + pubkey.len()].copy_from_slice(pubkey);
                    byte_index += pubkey.len();
                    self.symmetricstate.mix_hash(pubkey);
                    if self.params.handshake.is_psk() {
                        self.symmetricstate.mix_key(pubkey);
                    }
                    self.e.enable();
                },
                Token::S => {
                    if !self.s.is_on() {
                        bail!(StateProblem::MissingKeyMaterial);
                    } else if byte_index + self.s.pub_len() > message.len() {
                        bail!(Error::Input)
                    }

                    byte_index += self
                        .symmetricstate
                        .encrypt_and_mix_hash(self.s.pubkey(), &mut message[byte_index..])?;
                },
                Token::Psk(n) => match self.psks[*n as usize] {
                    Some(psk) => {
                        self.symmetricstate.mix_key_and_hash(&psk);
                    },
                    None => {
                        bail!(StateProblem::MissingPsk);
                    },
                },
                Token::Dh(t) => {
                    let dh_out = self.dh(t)?;
                    self.symmetricstate.mix_key(&dh_out[..self.dh_len()]);
                },
                #[cfg(feature = "hfs")]
                Token::E1 => {
                    let kem = self.kem.as_mut().ok_or(Error::Input)?;
                    if kem.pub_len() > message.len() {
                        bail!(Error::Input);
                    }
                    kem.generate(&mut *self.rng);
                    byte_index += self
                        .symmetricstate
                        .encrypt_and_mix_hash(&kem.pubkey(), &mut message[byte_index..])?;
                },
                #[cfg(feature = "hfs")]
                Token::Ekem1 => {
                    let kem = self.kem.as_mut().unwrap();
                    let mut kem_output_buf = [0; MAXKEMSSLEN];
                    let mut ciphertext_buf = [0; MAXKEMCTLEN];

                    if kem.ciphertext_len() > message.len() {
                        bail!(Error::Input);
                    }

                    let kem_output = &mut kem_output_buf[..kem.shared_secret_len()];
                    let ciphertext = &mut ciphertext_buf[..kem.ciphertext_len()];
                    let pubkey = &self.kem_re.as_ref().unwrap()[..kem.pub_len()];
                    if kem.encapsulate(pubkey, kem_output, ciphertext).is_err() {
                        bail!(Error::Kem);
                    }

                    byte_index += self.symmetricstate.encrypt_and_mix_hash(
                        &ciphertext[..kem.ciphertext_len()],
                        &mut message[byte_index..],
                    )?;
                    self.symmetricstate.mix_key(&kem_output[..kem.shared_secret_len()]);
                },
            }
        }

        if byte_index + payload.len() + TAGLEN > message.len() {
            bail!(Error::Input);
        }
        byte_index +=
            self.symmetricstate.encrypt_and_mix_hash(payload, &mut message[byte_index..])?;
        if byte_index > MAXMSGLEN {
            bail!(Error::Input);
        }
        if self.pattern_position == (self.message_patterns.len() - 1) {
            self.symmetricstate.split(&mut self.cipherstates.0, &mut self.cipherstates.1);
        }
        Ok(byte_index)
    }

    /// Reads a noise message from `input`
    ///
    /// Returns the size of the payload written to `payload`.
    ///
    /// # Errors
    ///
    /// Will result in `Error::Decrypt` if the contents couldn't be decrypted and/or the
    /// authentication tag didn't verify.
    ///
    /// # Panics
    ///
    /// This function will panic if there is no key, or if there is a nonce overflow.
    pub fn read_message(&mut self, message: &[u8], payload: &mut [u8]) -> Result<usize, Error> {
        let checkpoint = self.symmetricstate.checkpoint();
        match self._read_message(message, payload) {
            Ok(res) => {
                self.pattern_position += 1;
                self.my_turn = true;
                Ok(res)
            },
            Err(err) => {
                self.symmetricstate.restore(checkpoint);
                Err(err)
            },
        }
    }

    fn _read_message(&mut self, message: &[u8], payload: &mut [u8]) -> Result<usize, Error> {
        if message.len() > MAXMSGLEN {
            bail!(Error::Input);
        } else if self.my_turn {
            bail!(StateProblem::NotTurnToRead);
        } else if self.pattern_position >= self.message_patterns.len() {
            bail!(StateProblem::HandshakeAlreadyFinished);
        }
        let last = self.pattern_position == (self.message_patterns.len() - 1);

        let dh_len = self.dh_len();
        let mut ptr = message;
        for token in self.message_patterns[self.pattern_position].iter() {
            match token {
                Token::E => {
                    if ptr.len() < dh_len {
                        bail!(Error::Input);
                    }
                    self.re[..dh_len].copy_from_slice(&ptr[..dh_len]);
                    ptr = &ptr[dh_len..];
                    self.symmetricstate.mix_hash(&self.re[..dh_len]);
                    if self.params.handshake.is_psk() {
                        self.symmetricstate.mix_key(&self.re[..dh_len]);
                    }
                    self.re.enable();
                },
                Token::S => {
                    let data = if self.symmetricstate.has_key() {
                        if ptr.len() < dh_len + TAGLEN {
                            bail!(Error::Input);
                        }
                        let temp = &ptr[..dh_len + TAGLEN];
                        ptr = &ptr[dh_len + TAGLEN..];
                        temp
                    } else {
                        if ptr.len() < dh_len {
                            bail!(Error::Input);
                        }
                        let temp = &ptr[..dh_len];
                        ptr = &ptr[dh_len..];
                        temp
                    };
                    self.symmetricstate
                        .decrypt_and_mix_hash(data, &mut self.rs[..dh_len])
                        .map_err(|_| Error::Decrypt)?;
                    self.rs.enable();
                },
                Token::Psk(n) => match self.psks[*n as usize] {
                    Some(psk) => {
                        self.symmetricstate.mix_key_and_hash(&psk);
                    },
                    None => {
                        bail!(StateProblem::MissingPsk);
                    },
                },
                Token::Dh(t) => {
                    let dh_out = self.dh(t)?;
                    self.symmetricstate.mix_key(&dh_out[..self.dh_len()]);
                },
                #[cfg(feature = "hfs")]
                Token::E1 => {
                    let kem = self.kem.as_ref().ok_or(Error::Kem)?;
                    let read_len = if self.symmetricstate.has_key() {
                        kem.pub_len() + TAGLEN
                    } else {
                        kem.pub_len()
                    };
                    if ptr.len() < read_len {
                        bail!(Error::Input);
                    }
                    let mut kem_re = [0; MAXKEMPUBLEN];
                    self.symmetricstate
                        .decrypt_and_mix_hash(&ptr[..read_len], &mut kem_re[..kem.pub_len()])
                        .map_err(|_| Error::Decrypt)?;
                    self.kem_re = Some(kem_re);
                    ptr = &ptr[read_len..];
                },
                #[cfg(feature = "hfs")]
                Token::Ekem1 => {
                    let kem = self.kem.as_ref().unwrap();
                    let read_len = if self.symmetricstate.has_key() {
                        kem.ciphertext_len() + TAGLEN
                    } else {
                        kem.ciphertext_len()
                    };
                    if ptr.len() < read_len {
                        bail!(Error::Input);
                    }
                    let mut ciphertext_buf = [0; MAXKEMCTLEN];
                    let ciphertext = &mut ciphertext_buf[..kem.ciphertext_len()];
                    self.symmetricstate
                        .decrypt_and_mix_hash(&ptr[..read_len], ciphertext)
                        .map_err(|_| Error::Decrypt)?;
                    let mut kem_output_buf = [0; MAXKEMSSLEN];
                    let kem_output = &mut kem_output_buf[..kem.shared_secret_len()];
                    kem.decapsulate(ciphertext, kem_output).map_err(|_| Error::Kem)?;
                    self.symmetricstate.mix_key(&kem_output[..kem.shared_secret_len()]);
                    ptr = &ptr[read_len..];
                },
            }
        }

        self.symmetricstate.decrypt_and_mix_hash(ptr, payload).map_err(|_| Error::Decrypt)?;
        if last {
            self.symmetricstate.split(&mut self.cipherstates.0, &mut self.cipherstates.1);
        }
        let payload_len =
            if self.symmetricstate.has_key() { ptr.len() - TAGLEN } else { ptr.len() };
        Ok(payload_len)
    }

    /// Set the preshared key at the specified location. It is up to the caller
    /// to correctly set the location based on the specified handshake - Snow
    /// won't stop you from placing a PSK in an unused slot.
    ///
    /// # Errors
    ///
    /// Will result in `Error::Input` if the PSK is not the right length or the location is out of bounds.
    pub fn set_psk(&mut self, location: usize, key: &[u8]) -> Result<(), Error> {
        if key.len() != PSKLEN || self.psks.len() <= location {
            bail!(Error::Input);
        }

        let mut new_psk = [0u8; PSKLEN];
        new_psk.copy_from_slice(&key[..]);
        self.psks[location as usize] = Some(new_psk);

        Ok(())
    }

    /// Get the remote party's static public key, if available.
    ///
    /// Note: will return `None` if either the chosen Noise pattern
    /// doesn't necessitate a remote static key, *or* if the remote
    /// static key is not yet known (as can be the case in the `XX`
    /// pattern, for example).
    pub fn get_remote_static(&self) -> Option<&[u8]> {
        self.rs.get().map(|rs| &rs[..self.dh_len()])
    }

    /// Get the handshake hash.
    ///
    /// Returns a slice of length `Hasher.hash_len()` (i.e. HASHLEN for the chosen Hash function).
    pub fn get_handshake_hash(&self) -> &[u8] {
        self.symmetricstate.handshake_hash()
    }

    /// Check if this session was started with the "initiator" role.
    pub fn is_initiator(&self) -> bool {
        self.initiator
    }

    /// Check if the handshake is finished and `into_transport_mode()` can now be called.
    pub fn is_handshake_finished(&self) -> bool {
        self.pattern_position == self.message_patterns.len()
    }

    /// Check whether it is our turn to send in the handshake state machine
    pub fn is_my_turn(&self) -> bool {
        self.my_turn
    }

    /// Perform the split calculation and return the resulting keys.
    ///
    /// This returns raw key material so it should be used with care. The "risky-raw-split"
    /// feature has to be enabled to use this function.
    #[cfg(feature = "risky-raw-split")]
    pub fn dangerously_get_raw_split(&mut self) -> ([u8; CIPHERKEYLEN], [u8; CIPHERKEYLEN]) {
        let mut output = ([0u8; MAXHASHLEN], [0u8; MAXHASHLEN]);
        self.symmetricstate.split_raw(&mut output.0, &mut output.1);
        (output.0[..CIPHERKEYLEN].try_into().unwrap(), output.1[..CIPHERKEYLEN].try_into().unwrap())
    }

    /// Convert this `HandshakeState` into a `TransportState` with an internally stored nonce.
    pub fn into_transport_mode(self) -> Result<TransportState, Error> {
        Ok(self.try_into()?)
    }

    /// Convert this `HandshakeState` into a `StatelessTransportState` without an internally stored nonce.
    pub fn into_stateless_transport_mode(self) -> Result<StatelessTransportState, Error> {
        Ok(self.try_into()?)
    }
}

impl fmt::Debug for HandshakeState {
    fn fmt(&self, fmt: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt.debug_struct("HandshakeState").finish()
    }
}
