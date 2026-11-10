//! `SecretValue`: the only type a secret's content travels in.
//!
//! No `Display`, no `Clone`, no `Serialize`; `Debug` shows nothing; the bytes are
//! wiped on drop (by `redactant::Secret`, which uses `zeroize`). The wipe is
//! best effort: memory is not locked and copies made by the caller's own code
//! after `expose` are the caller's.

use redactant::Secret;
use std::fmt;

/// A secret's content. Obtain the bytes only through [`SecretValue::expose`].
pub struct SecretValue(Secret<Vec<u8>>);

impl SecretValue {
    /// Wrap bytes. The vector is moved in, so no copy stays with the caller.
    pub fn new(bytes: Vec<u8>) -> Self {
        Self(Secret::new(bytes))
    }

    /// Wrap a string's bytes (the string is moved in).
    pub fn from_string(text: String) -> Self {
        Self::new(text.into_bytes())
    }

    /// The content. The one place a value leaves this type.
    pub fn expose(&self) -> &[u8] {
        self.0.expose()
    }

    /// Length in bytes (not secret).
    pub fn len(&self) -> usize {
        self.0.expose().len()
    }

    /// True when the value has no bytes.
    pub fn is_empty(&self) -> bool {
        self.0.expose().is_empty()
    }
}

impl fmt::Debug for SecretValue {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("SecretValue(<redacted>)")
    }
}

#[cfg(test)]
mod tests {
    use super::SecretValue;
    use std::fmt::Debug;

    /// A canary that must never appear in any formatted output. Tests compare
    /// booleans, never print the value, so a failing assert cannot leak it.
    const CANARY: &str = "hunter2-canary";

    fn leaks(text: &str) -> bool {
        text.contains(CANARY)
    }

    #[test]
    fn debug_shows_nothing() {
        let v = SecretValue::from_string(CANARY.to_string());
        assert!(!leaks(&format!("{v:?}")));
        assert!(!leaks(&format!("{v:#?}")));
        assert!(!leaks(&format!("{:?}", Some(&v))));
    }

    #[test]
    fn debug_is_not_empty_so_a_reader_sees_it_is_a_secret() {
        let v = SecretValue::from_string(CANARY.to_string());
        assert!(format!("{v:?}").contains("redacted"));
    }

    #[test]
    fn expose_returns_the_exact_bytes() {
        let v = SecretValue::new(CANARY.as_bytes().to_vec());
        assert!(v.expose() == CANARY.as_bytes());
        assert_eq!(v.len(), CANARY.len());
        assert!(!v.is_empty());
    }

    #[test]
    fn empty_value_is_allowed_and_reported() {
        let v = SecretValue::new(Vec::new());
        assert!(v.is_empty());
        assert_eq!(v.len(), 0);
    }

    // Compile-time absence of Display, Clone and Serialize, by the
    // method-resolution trick: the inherent-looking probe picks `true` only
    // when the trait is implemented. Each probe is asserted false.
    macro_rules! has_trait {
        ($t:ty, $tr:path) => {{
            struct W<T>(std::marker::PhantomData<T>);
            impl<T: $tr> W<T> {
                #[allow(dead_code)]
                const HAS: bool = true;
            }
            #[allow(dead_code)]
            trait Fallback {
                const HAS: bool = false;
            }
            impl<T> Fallback for W<T> {}
            <W<$t>>::HAS
        }};
    }

    #[test]
    fn has_no_display_clone_or_serialize() {
        assert!(!has_trait!(SecretValue, std::fmt::Display));
        assert!(!has_trait!(SecretValue, Clone));
        assert!(!has_trait!(SecretValue, serde::Serialize));
        // Control: the probe does see a trait that is implemented.
        assert!(has_trait!(SecretValue, Debug));
    }
}
