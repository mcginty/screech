use crate::{
    cipherstate::StatelessCipherStates,
    constants::{MAXDHLEN, MAXMSGLEN, TAGLEN},
    error::{Error, StateProblem},
    handshakestate::HandshakeState,
    params::HandshakePattern,
    utils::Toggle,
};
use std::{convert::TryFrom, fmt};

/// A state machine encompassing the transport phase of a Noise session, using the two
/// `CipherState`s (for sending and receiving) that were spawned from the `SymmetricState`'s
/// `Split()` method, called after a handshake has been finished.
///
/// See: http://noiseprotocol.org/noise.html#the-handshakestate-object
pub struct StatelessTransportState {
    cipherstates: StatelessCipherStates,
    pattern:      HandshakePattern,
    dh_len:       usize,
    rs:           Toggle<[u8; MAXDHLEN]>,
    initiator:    bool,
}

impl StatelessTransportState {
    pub(crate) fn new(handshake: HandshakeState) -> Result<Self, Error> {
        if !handshake.is_handshake_finished() {
            bail!(StateProblem::HandshakeNotFinished);
        }

        let dh_len = handshake.dh_len();
        let HandshakeState { cipherstates, params, rs, initiator, .. } = handshake;
        let pattern = params.handshake.pattern;

        Ok(Self { cipherstates: cipherstates.into(), pattern, dh_len, rs, initiator })
    }

    /// Get the remote party's static public key, if available.
    ///
    /// Note: will return `None` if either the chosen Noise pattern
    /// doesn't necessitate a remote static key, *or* if the remote
    /// static key is not yet known (as can be the case in the `XX`
    /// pattern, for example).
    pub fn get_remote_static(&self) -> Option<&[u8]> {
        self.rs.get().map(|rs| &rs[..self.dh_len])
    }

    /// Construct a message from `payload` (and pending handshake tokens if in handshake state),
    /// and writes it to the `output` buffer.
    ///
    /// Returns the size of the written payload.
    ///
    /// # Errors
    ///
    /// Will result in `Error::Input` if the size of the output exceeds the max message
    /// length in the Noise Protocol (65535 bytes).
    pub fn write_message(
        &self,
        nonce: u64,
        payload: &[u8],
        message: &mut [u8],
    ) -> Result<usize, Error> {
        if !self.initiator && self.pattern.is_oneway() {
            bail!(StateProblem::OneWay);
        } else if payload.len() + TAGLEN > MAXMSGLEN || payload.len() + TAGLEN > message.len() {
            bail!(Error::Input);
        }

        let cipher = if self.initiator { &self.cipherstates.0 } else { &self.cipherstates.1 };
        cipher.encrypt(nonce, payload, message)
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
    /// Will result in `StateProblem::Exhausted` if the max nonce overflows.
    pub fn read_message(
        &self,
        nonce: u64,
        payload: &[u8],
        message: &mut [u8],
    ) -> Result<usize, Error> {
        if self.initiator && self.pattern.is_oneway() {
            bail!(StateProblem::OneWay);
        }
        let cipher = if self.initiator { &self.cipherstates.1 } else { &self.cipherstates.0 };
        cipher.decrypt(nonce, payload, message)
    }

    /// Generates a new key for the egress symmetric cipher according to Section 4.2
    /// of the Noise Specification. Synchronizing timing of rekey between initiator and
    /// responder is the responsibility of the application, as described in Section 11.3
    /// of the Noise Specification.
    pub fn rekey_outgoing(&mut self) {
        if self.initiator {
            self.cipherstates.rekey_initiator()
        } else {
            self.cipherstates.rekey_responder()
        }
    }

    /// Generates a new key for the ingress symmetric cipher according to Section 4.2
    /// of the Noise Specification. Synchronizing timing of rekey between initiator and
    /// responder is the responsibility of the application, as described in Section 11.3
    /// of the Noise Specification.
    pub fn rekey_incoming(&mut self) {
        if self.initiator {
            self.cipherstates.rekey_responder()
        } else {
            self.cipherstates.rekey_initiator()
        }
    }

    /// Set a new key for the one or both of the initiator-egress and responder-egress symmetric ciphers.
    pub fn rekey_manually(&mut self, initiator: Option<&[u8]>, responder: Option<&[u8]>) {
        if let Some(key) = initiator {
            self.rekey_initiator_manually(key);
        }
        if let Some(key) = responder {
            self.rekey_responder_manually(key);
        }
    }

    /// Set a new key for the initiator-egress symmetric cipher.
    pub fn rekey_initiator_manually(&mut self, key: &[u8]) {
        self.cipherstates.rekey_initiator_manually(key)
    }

    /// Set a new key for the responder-egress symmetric cipher.
    pub fn rekey_responder_manually(&mut self, key: &[u8]) {
        self.cipherstates.rekey_responder_manually(key)
    }

    /// Check if this session was started with the "initiator" role.
    pub fn is_initiator(&self) -> bool {
        self.initiator
    }
}

impl fmt::Debug for StatelessTransportState {
    fn fmt(&self, fmt: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt.debug_struct("StatelessTransportState").finish()
    }
}

impl TryFrom<HandshakeState> for StatelessTransportState {
    type Error = Error;

    fn try_from(old: HandshakeState) -> Result<Self, Self::Error> {
        StatelessTransportState::new(old)
    }
}
