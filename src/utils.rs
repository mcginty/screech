use std::ops::{Deref, DerefMut};

pub fn copy_memory(input: &[u8], out: &mut [u8]) -> usize {
    for count in 0..input.len() {
        out[count] = input[count];
    }
    input.len()
}

/// Toggle is similar to Option, except that even in the Off/"None" case, there is still
/// an owned allocated inner object. This is useful for holding onto pre-allocated objects
/// that can be toggled as enabled.
pub struct Toggle<T> {
    inner: T,
    on: bool,
}

impl<T> Toggle<T> {
    pub fn on(inner: T) -> Self {
        Self {
            inner: inner,
            on: true,
        }
    }

    pub fn off(inner: T) -> Self {
        Self {
            inner: inner,
            on: false,
        }
    }

    pub fn into_inner(self) -> T {
        self.inner
    }

    pub fn enable(&mut self) {
        self.on = true;
    }

    pub fn is_on(&self) -> bool {
        self.on
    }

    pub fn as_option_ref(&self) -> Option<&T> {
        if self.on {
            Some(&self.inner)
        } else {
            None
        }
    }
}

impl<T> Deref for Toggle<T> {
    type Target = T;

    fn deref(&self) -> &T {
        &self.inner
    }
}

impl<T> DerefMut for Toggle<T> {
    fn deref_mut(&mut self) -> &mut T {
        &mut self.inner
    }
}

#[cfg(not(feature = "nightly"))]
pub trait TryInto<T>: Sized {
    type Error;

    fn try_into(self) -> Result<T, Self::Error>;
}

#[cfg(not(feature = "nightly"))]
pub trait TryFrom<T>: Sized {
    type Error;

    fn try_from(value: T) -> Result<Self, Self::Error>;
}

#[cfg(not(feature = "nightly"))]
impl<T, U> TryInto<U> for T
where
    U: TryFrom<T>,
{
    type Error = U::Error;

    fn try_into(self) -> Result<U, U::Error> {
        U::try_from(self)
    }
}
