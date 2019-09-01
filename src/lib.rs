#![no_std]
//! The `snow` crate is a straightforward, Hard To Fuck Up™ Noise Protocol implementation.
//!
//! Read the [Noise Protocol Framework Spec](http://noiseprotocol.org/noise.html) for more
//! information.
//!
//! The typical usage flow is to use [`Builder`] to construct a [`HandshakeState`], where you
//! will complete the handshake phase and convert into either a [`TransportState`] or
//! [`StatelessTransportState`].
//!
//! # Examples
//! See `examples/simple.rs` for a more complete TCP client/server example with static keys.
//!
//! ```
//! # use snow::Error;
//! #
//! # #[cfg(any(feature = "default-resolver", feature = "ring-accelerated"))]
//! # fn try_main() -> Result<(), Error> {
//! static PATTERN: &'static str = "Noise_NN_25519_ChaChaPoly_BLAKE2s";
//!
//! let mut initiator = snow::Builder::new(PATTERN.parse()?)
//!     .build_initiator()?;
//! let mut responder = snow::Builder::new(PATTERN.parse()?)
//!     .build_responder()?;
//!
//! let (mut read_buf, mut first_msg, mut second_msg) =
//!     ([0u8; 1024], [0u8; 1024], [0u8; 1024]);
//!
//! // -> e
//! let len = initiator.write_message(&[], &mut first_msg)?;
//!
//! // responder processes the first message...
//! responder.read_message(&first_msg[..len], &mut read_buf)?;
//!
//! // <- e, ee
//! let len = responder.write_message(&[], &mut second_msg)?;
//!
//! // initiator processes the response...
//! initiator.read_message(&second_msg[..len], &mut read_buf)?;
//!
//! // NN handshake complete, transition into transport mode.
//! let initiator = initiator.into_transport_mode();
//! let responder = responder.into_transport_mode();
//! #     Ok(())
//! # }
//! #
//! # #[cfg(not(any(feature = "default-resolver", feature = "ring-accelerated")))]
//! # fn try_main() -> Result<(), ()> { Ok(()) }
//! #
//! # fn main() {
//! #     try_main().unwrap();
//! # }
//! ```

#![warn(missing_docs)]

macro_rules! copy_slices {
    ($inslice:expr, $outslice:expr) => {
        $outslice[..$inslice.len()].copy_from_slice(&$inslice[..])
    };
}

macro_rules! static_slice {
    ($_type:ty: $($item:expr),*) => ({
        static STATIC_SLICE: &'static [$_type] = &[$($item),*];
        STATIC_SLICE
    });
}

macro_rules! bail {
    ($e:expr) => {
        return Err(($e).into());
    };
}
extern crate alloc;

#[cfg(feature = "std")]
#[macro_use]
extern crate std;

pub mod error;
mod utils;
mod constants;
mod cipherstate;
mod symmetricstate;
mod handshakestate;
mod builder;
mod transportstate;
mod stateless_transportstate;

pub mod params;
pub mod types;
pub mod resolvers;

pub use crate::error::Error;
pub use crate::builder::{Builder, Keypair};
pub use crate::handshakestate::HandshakeState;
pub use crate::transportstate::TransportState;
pub use crate::stateless_transportstate::StatelessTransportState;
