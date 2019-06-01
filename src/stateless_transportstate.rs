use crate::params::HandshakePattern;
use crate::error::{Error, StateProblem};
use crate::cipherstate::StatelessCipherStates;
use crate::constants::{MAXDHLEN, MAXMSGLEN, TAGLEN};
use crate::handshakestate::HandshakeState;
use crate::utils::Toggle;
use std::fmt;

/// A state machine encompassing the transport phase of a Noise session, using the two
/// `CipherState`s (for sending and receiving) that were spawned from the `SymmetricState`'s
/// `Split()` method, called after a handshake has been finished.
///
/// See: http://noiseprotocol.org/noise.html#the-handshakestate-object
pub struct StatelessTransportState {
    pub cipherstates: StatelessCipherStates,
    pattern: HandshakePattern,
    dh_len: usize,
    rs: Toggle<[u8; MAXDHLEN]>,
    initiator: bool,
}

impl StatelessTransportState {
    pub fn new(handshake: HandshakeState) -> Result<Self, Error> {
        if !handshake.is_finished() {
            bail!(StateProblem::HandshakeNotFinished);
        }

        let dh_len = handshake.dh_len();
        let HandshakeState {cipherstates, params, rs, initiator, ..} = handshake;
        let pattern = params.handshake.pattern;

        Ok(Self {
            cipherstates: cipherstates.into(),
            pattern,
            dh_len,
            rs,
            initiator,
        })
    }

    pub fn get_remote_static(&self) -> Option<&[u8]> {
        self.rs.get().map(|rs| &rs[..self.dh_len])
    }

    pub fn write_transport_message(&self,
                                   nonce: u64,
                                   authtext: &[u8],
                                   payload: &[u8],
                                   message: &mut [u8]) -> Result<usize, Error> {
        if !self.initiator && self.pattern.is_oneway() {
            bail!(StateProblem::OneWay);
        } else if payload.len() + TAGLEN > MAXMSGLEN || payload.len() + TAGLEN > message.len() {
            bail!(Error::Input);
        }

        let cipher = if self.initiator { &self.cipherstates.0 } else { &self.cipherstates.1 };
        Ok(cipher.encrypt_ad(nonce, authtext, payload, message)?)
    }

    pub fn read_transport_message(&self,
                                  nonce: u64,
                                  authtext: &[u8],
                                  payload: &[u8],
                                  message: &mut [u8]) -> Result<usize, Error> {
        if self.initiator && self.pattern.is_oneway() {
            bail!(StateProblem::OneWay);
        }
        let cipher = if self.initiator { &self.cipherstates.1 } else { &self.cipherstates.0 };
        cipher.decrypt_ad(nonce, authtext, payload, message).map_err(|_| Error::Decrypt)
    }

    pub fn rekey_outgoing(&mut self) {
        if self.initiator {
            self.cipherstates.rekey_initiator()
        } else {
            self.cipherstates.rekey_responder()
        }
    }

    pub fn rekey_incoming(&mut self) {
        if self.initiator {
            self.cipherstates.rekey_responder()
        } else {
            self.cipherstates.rekey_initiator()
        }
    }

    pub fn rekey_initiator_manually(&mut self, key: &[u8]) {
        self.cipherstates.rekey_initiator_manually(key)
    }

    pub fn rekey_responder_manually(&mut self, key: &[u8]) {
        self.cipherstates.rekey_responder_manually(key)
    }

    pub fn is_initiator(&self) -> bool {
        self.initiator
    }
}

impl fmt::Debug for StatelessTransportState {
    fn fmt(&self, fmt: &mut fmt::Formatter) -> fmt::Result {
        fmt.debug_struct("StatelessTransportState").finish()
    }
}
