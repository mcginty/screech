use crate::error::{Error, PatternProblem};
use core::{convert::TryFrom, str::FromStr};
use alloc::{vec, vec::Vec};

/// A small helper macro that behaves similar to the `vec![]` standard macro,
/// except it allocates a bit extra to avoid resizing.
macro_rules! message_vec {
    ($($item:expr),*) => ({
        let token_groups: &[&[Token]] = &[$($item),*];
        let mut vec: MessagePatterns = Vec::with_capacity(10);
        for group in token_groups {
            let mut inner = Vec::with_capacity(10);
            inner.extend_from_slice(group);
            vec.push(inner);
        }
        vec
    });
}

/// This macro is specifically a helper to generate the enum of all handshake
/// patterns in a less error-prone way.
///
/// While rust macros can be really difficult to read, it felt too sketchy to hand-
/// write a growing list of str -> enum variant match statements.
macro_rules! pattern_enum {
    // NOTE: see https://danielkeep.github.io/tlborm/book/mbe-macro-rules.html and
    // https://doc.rust-lang.org/rust-by-example/macros.html for a great overview
    // of `macro_rules!`.
    ($name:ident {
        $($variant:ident),* $(,)*
    }) => {
        /// One of the patterns as defined in the
        /// [Handshake Pattern](http://noiseprotocol.org/noise.html#handshake-patterns)
        /// section.
        #[allow(missing_docs)]
        #[derive(Copy, Clone, PartialEq, Debug)]
        pub enum $name {
            $($variant),*,
        }

        impl FromStr for $name {
            type Err = Error;
            fn from_str(s: &str) -> Result<Self, Self::Err> {
                use self::$name::*;
                match s {
                    $(
                        stringify!($variant) => Ok($variant)
                    ),
                    *,
                    _    => bail!(PatternProblem::UnsupportedHandshakeType)
                }
            }
        }

        impl $name {
            /// The equivalent of the `ToString` trait, but for `&'static str`.
            pub fn as_str(self) -> &'static str {
                use self::$name::*;
                match self {
                    $(
                        $variant => stringify!($variant)
                    ),
                    *
                }
            }
        }

        #[doc(hidden)]
        pub const SUPPORTED_HANDSHAKE_PATTERNS: &'static [$name] = &[$($name::$variant),*];
    }
}

/// The tokens which describe message patterns.
///
/// See: http://noiseprotocol.org/noise.html#handshake-patterns
#[allow(missing_docs)]
#[derive(Copy, Clone, PartialEq, Debug)]
pub(crate) enum Token { E, S, Dhee, Dhes, Dhse, Dhss, Psk(u8) }

// See the documentation in the macro above.
pattern_enum! {
    HandshakePattern {
        // 7.4. One-way handshake patterns
        N, X, K,

        // 7.5. Interactive handshake patterns (fundamental)
        NN, NK, NX, XN, XK, XX, KN, KK, KX, IN, IK, IX,

        // 7.6. Interactive handshake patterns (deferred)
        NK1, NX1, X1N, X1K, XK1, X1K1, X1X, XX1, X1X1, K1N, K1K, KK1, K1K1, K1X,
        KX1, K1X1, I1N, I1K, IK1, I1K1, I1X, IX1, I1X1
    }
}

impl HandshakePattern {
    /// If the protocol is one-way only
    ///
    /// See: http://noiseprotocol.org/noise.html#one-way-patterns
    pub fn is_oneway(self) -> bool {
        match self {
            N | X | K => true,
            _ => false
        }
    }

    /// Whether this pattern requires a long-term static key.
    pub fn needs_local_static_key(self, initiator: bool) -> bool {
        if initiator {
            match self {
                N | NN | NK | NX | NK1 | NX1 => false,
                _ => true
            }
        } else {
            match self {
                NN | XN | KN | IN | X1N | K1N | I1N => false,
                _ => true
            }
        }
    }

    /// Whether this pattern demands a remote public key pre-message.
    pub fn need_known_remote_pubkey(self, initiator: bool) -> bool {
        if initiator {
            match self {
                N | K | X | NK | XK | KK | IK | NK1 | X1K | XK1 | X1K1
                  | K1K | KK1 | K1K1 | I1K | IK1 | I1K1 => true,
                _ => false
            }
        } else {
            match self {
                K | KN | KK | KX | K1N | K1K | KK1 | K1K1 | K1X | KX1
                  | K1X1 => true,
                _ => false,
            }
        }
    }
}

/// A modifier applied to the base pattern as defined in the Noise spec.
#[derive(Copy, Clone, PartialEq, Debug)]
pub enum HandshakeModifier {
    /// Insert a PSK to mix at the associated position
    Psk(u8),

    /// Modify the base pattern to its "fallback" form
    Fallback
}

impl FromStr for HandshakeModifier {
    type Err = Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        if s.starts_with("psk") {
            Ok(HandshakeModifier::Psk((&s[3..])
                .parse()
                .map_err(|_| PatternProblem::InvalidPsk)?))
        } else if s == "fallback" {
            Ok(HandshakeModifier::Fallback)
        } else {
            bail!(PatternProblem::UnsupportedModifier);
        }
    }
}

#[derive(Clone, PartialEq, Debug)]
pub struct HandshakeModifierList {
    pub list: Vec<HandshakeModifier>
}

impl FromStr for HandshakeModifierList {
    type Err = Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        if s.is_empty() {
            Ok(HandshakeModifierList{ list: vec![] })
        } else {
            let modifier_names = s.split('+');
            let mut modifiers = vec![];
            for modifier_name in modifier_names {
                modifiers.push(modifier_name.parse()?);
            }
            Ok(HandshakeModifierList{ list: modifiers })
        }
    }
}

/// The pattern/modifier combination choice (no primitives specified)
/// for a full noise protocol definition.
#[derive(Clone, PartialEq, Debug)]
pub struct HandshakeChoice {
    /// The base pattern itself
    pub pattern: HandshakePattern,

    /// The modifier(s) requested for the base pattern
    pub modifiers: HandshakeModifierList,
}

impl HandshakeChoice {
    /// Whether the handshake choice includes one or more PSK modifiers.
    pub fn is_psk(&self) -> bool {
        for modifier in &self.modifiers.list {
            if let HandshakeModifier::Psk(_) = *modifier {
                return true;
            }
        }
        false
    }

    /// Whether the handshake choice includes the fallback modifier.
    pub fn is_fallback(&self) -> bool {
        for modifier in &self.modifiers.list {
            if HandshakeModifier::Fallback == *modifier {
                return true;
            }
        }
        false
    }

    /// Parse and split a base HandshakePattern from its optional modifiers
    fn parse_pattern_and_modifier(s: &str) -> Result<(HandshakePattern, &str), Error> {
        for i in (1..=4).rev() {
            if s.len() > i-1 && s.is_char_boundary(i) {
                if let Ok(p) = (&s[..i]).parse() {
                    return Ok((p, &s[i..]));
                }
            }
        }

        bail!(PatternProblem::UnsupportedHandshakeType);
    }
}

impl FromStr for HandshakeChoice {
    type Err = Error;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let (pattern, remainder) = Self::parse_pattern_and_modifier(s)?;
        let modifiers = remainder.parse()?;

        Ok(HandshakeChoice {
            pattern,
            modifiers,
        })
    }
}

type PremessagePatterns = &'static [Token];
pub(crate) type MessagePatterns = Vec<Vec<Token>>;

/// The defined token patterns for a given handshake.
///
/// See: http://noiseprotocol.org/noise.html#handshake-patterns
#[derive(Debug)]
pub(crate) struct HandshakeTokens {
    pub premsg_pattern_i: PremessagePatterns,
    pub premsg_pattern_r: PremessagePatterns,
    pub msg_patterns: MessagePatterns,
}

use self::Token::*;
use self::HandshakePattern::*;

type Patterns = (PremessagePatterns, PremessagePatterns, MessagePatterns);

impl<'a> TryFrom<&'a HandshakeChoice> for HandshakeTokens {
    type Error = Error;

    #[allow(clippy::cognitive_complexity)]
    fn try_from(handshake: &'a HandshakeChoice) -> Result<Self, Self::Error> {
        let mut patterns: Patterns = match handshake.pattern {
            N  => (
                static_slice![Token: ],
                static_slice![Token: S],
                message_vec![&[E, Dhes]]
            ),
            K  => (
                static_slice![Token: S],
                static_slice![Token: S],
                message_vec![&[E, Dhes, Dhss]]
            ),
            X  => (
                static_slice![Token: ],
                static_slice![Token: S],
                message_vec![&[E, Dhes, S, Dhss]]
            ),
            NN => (
                static_slice![Token: ],
                static_slice![Token: ],
                message_vec![&[E], &[E, Dhee]]
            ),
            NK => (
                static_slice![Token: ],
                static_slice![Token: S],
                message_vec![&[E, Dhes], &[E, Dhee]]
            ),
            NX => (
                static_slice![Token: ],
                static_slice![Token: ],
                message_vec![&[E], &[E, Dhee, S, Dhse]]
            ),
            XN => (
                static_slice![Token: ],
                static_slice![Token: ],
                message_vec![&[E], &[E, Dhee], &[S, Dhse]]
            ),
            XK => (
                static_slice![Token: ],
                static_slice![Token: S],
                message_vec![&[E, Dhes], &[E, Dhee], &[S, Dhse]]
            ),
            XX => (
                static_slice![Token: ],
                static_slice![Token: ],
                message_vec![&[E], &[E, Dhee, S, Dhse], &[S, Dhse]],
            ),
            KN => (
                static_slice![Token: S],
                static_slice![Token: ],
                message_vec![&[E], &[E, Dhee, Dhes]],
            ),
            KK => (
                static_slice![Token: S],
                static_slice![Token: S],
                message_vec![&[E, Dhes, Dhss], &[E, Dhee, Dhes]],
            ),
            KX => (
                static_slice![Token: S],
                static_slice![Token: ],
                message_vec![&[E], &[E, Dhee, Dhes, S, Dhse]],
            ),
            IN => (
                static_slice![Token: ],
                static_slice![Token: ],
                message_vec![&[E, S], &[E, Dhee, Dhes]],
            ),
            IK => (
                static_slice![Token: ],
                static_slice![Token: S],
                message_vec![&[E, Dhes, S, Dhss], &[E, Dhee, Dhes]],
            ),
            IX => (
                static_slice![Token: ],
                static_slice![Token: ],
                message_vec![&[E, S], &[E, Dhee, Dhes, S, Dhse]],
            ),
            NK1 => (
                static_slice![Token: ],
                static_slice![Token: S],
                message_vec![&[E], &[E, Dhee, Dhse]],
            ),
            NX1 => (
                static_slice![Token: ],
                static_slice![Token: ],
                message_vec![&[E], &[E, Dhee, S], &[Dhes]]
            ),
            X1N => (
                static_slice![Token: ],
                static_slice![Token: ],
                message_vec![&[E], &[E, Dhee], &[S], &[Dhes]]
            ),
            X1K => (
                static_slice![Token: ],
                static_slice![Token: S],
                message_vec![&[E, Dhes], &[E, Dhee], &[S], &[Dhes]]
            ),
            XK1 => (
                static_slice![Token: ],
                static_slice![Token: S],
                message_vec![&[E], &[E, Dhee, Dhse], &[S, Dhse]]
            ),
            X1K1 => (
                static_slice![Token: ],
                static_slice![Token: S],
                message_vec![&[E], &[E, Dhee, Dhse], &[S], &[Dhes]]
            ),
            X1X => (
                static_slice![Token: ],
                static_slice![Token: ],
                message_vec![&[E], &[E, Dhee, S, Dhse], &[S], &[Dhes]],
            ),
            XX1 => (
                static_slice![Token: ],
                static_slice![Token: ],
                message_vec![&[E], &[E, Dhee, S], &[Dhes, S, Dhse]],
            ),
            X1X1 => (
                static_slice![Token: ],
                static_slice![Token: ],
                message_vec![&[E], &[E, Dhee, S], &[Dhes, S], &[Dhes]],
            ),
            K1N => (
                static_slice![Token: S],
                static_slice![Token: ],
                message_vec![&[E], &[E, Dhee], &[Dhse]],
            ),
            K1K => (
                static_slice![Token: S],
                static_slice![Token: S],
                message_vec![&[E, Dhes], &[E, Dhee], &[Dhse]],
            ),
            KK1 => (
                static_slice![Token: S],
                static_slice![Token: S],
                message_vec![&[E], &[E, Dhee, Dhes, Dhse]],
            ),
            K1K1 => (
                static_slice![Token: S],
                static_slice![Token: S],
                message_vec![&[E], &[E, Dhee, Dhse], &[Dhse]],
            ),
            K1X => (
                static_slice![Token: S],
                static_slice![Token: ],
                message_vec![&[E], &[E, Dhee, S, Dhse], &[Dhse]],
            ),
            KX1 => (
                static_slice![Token: S],
                static_slice![Token: ],
                message_vec![&[E], &[E, Dhee, Dhes, S], &[Dhes]],
            ),
            K1X1 => (
                static_slice![Token: S],
                static_slice![Token: ],
                message_vec![&[E], &[E, Dhee, S], &[Dhse, Dhes]],
            ),
            I1N => (
                static_slice![Token: ],
                static_slice![Token: ],
                message_vec![&[E, S], &[E, Dhee], &[Dhse]],
            ),
            I1K => (
                static_slice![Token: ],
                static_slice![Token: S],
                message_vec![&[E, Dhes, S], &[E, Dhee], &[Dhse]],
            ),
            IK1 => (
                static_slice![Token: ],
                static_slice![Token: S],
                message_vec![&[E, S], &[E, Dhee, Dhes, Dhse]],
            ),
            I1K1 => (
                static_slice![Token: ],
                static_slice![Token: S],
                message_vec![&[E, S], &[E, Dhee, Dhse], &[Dhse]],
            ),
            I1X => (
                static_slice![Token: ],
                static_slice![Token: ],
                message_vec![&[E, S], &[E, Dhee, S, Dhse], &[Dhse]],
            ),
            IX1 => (
                static_slice![Token: ],
                static_slice![Token: ],
                message_vec![&[E, S], &[E, Dhee, Dhes, S], &[Dhes]],
            ),
            I1X1 => (
                static_slice![Token: ],
                static_slice![Token: ],
                message_vec![&[E, S], &[E, Dhee, S], &[Dhse, Dhes]],
            ),
        };

        for modifier in handshake.modifiers.list.iter() {
            if let HandshakeModifier::Psk(n) = modifier {
                match n {
                    0 => { patterns.2[0].insert(0, Token::Psk(*n)); },
                    _ => {
                        let i = (*n as usize) - 1;
                        patterns.2[i].push(Token::Psk(*n));
                    }
                }
            }
        }

        Ok(HandshakeTokens {
            premsg_pattern_i: patterns.0,
            premsg_pattern_r: patterns.1,
            msg_patterns: patterns.2,
        })
    }
}
