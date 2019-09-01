use core::ops::{Deref, DerefMut};

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
            inner,
            on: true
        }
    }

    pub fn off(inner: T) -> Self {
        Self {
            inner,
            on: false
        }
    }

    pub fn enable(&mut self) {
        self.on = true;
    }

    pub fn is_on(&self) -> bool {
        self.on
    }

    pub fn get(&self) -> Option<&T> {
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
