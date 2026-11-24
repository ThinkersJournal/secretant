// SPDX-License-Identifier: MIT OR Apache-2.0
//! The approval subject, `NAME -> path`, built and parsed strictly. What the
//! person approves is this exact text, so it must be unambiguous and shown
//! whole: `user-request` 0.17 refuses a `SecretPlacement` subject over
//! [`MAX_SUBJECT_CHARS`] (200) and the prompt clips there, so a name over
//! [`MAX_NAME_CHARS`] or a whole subject over the cap is refused, never
//! clipped; the
//! separator ` -> ` may appear once (a path containing it could forge a second
//! subject); controls, line breaks and invisible or bidirectional formatting
//! characters are refused. The path keeps its case exactly.

use std::path::{Path, PathBuf};

/// The most characters the whole `NAME -> path` subject may have (user-request 0.17).
pub const MAX_SUBJECT_CHARS: usize = 200;
/// The most characters a secret name may have in a subject.
pub const MAX_NAME_CHARS: usize = 64;
const SEP: &str = " -> ";

/// Why a subject was refused.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SubjectError {
    /// Over the cap: refused, never clipped.
    TooLong,
    /// A control, invisible or bidi character, an empty half, or a name outside
    /// `[A-Za-z0-9_.-]`.
    Forbidden,
    /// The text could be read as more than one subject.
    Ambiguous,
}

fn bad_char(c: char) -> bool {
    c.is_control()
        || matches!(c, '\u{200b}'..='\u{200f}' | '\u{202a}'..='\u{202e}' | '\u{2060}'..='\u{2069}' | '\u{feff}')
}

fn name_ok(n: &str) -> bool {
    !n.is_empty()
        && n.chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '_' | '.' | '-'))
}

/// `NAME -> path`, or why not.
pub fn format(name: &str, path: &Path) -> Result<String, SubjectError> {
    if !name_ok(name) {
        return Err(SubjectError::Forbidden);
    }
    if name.chars().count() > MAX_NAME_CHARS {
        return Err(SubjectError::TooLong);
    }
    let p = path.to_str().ok_or(SubjectError::Forbidden)?;
    if p.is_empty() || p.chars().any(bad_char) {
        return Err(SubjectError::Forbidden);
    }
    if p.contains(SEP) {
        return Err(SubjectError::Ambiguous);
    }
    let whole = format!("{name}{SEP}{p}");
    if whole.chars().count() > MAX_SUBJECT_CHARS {
        return Err(SubjectError::TooLong);
    }
    Ok(whole)
}

/// Parse a subject back: the exact inverse of [`format()`](fn@format).
pub fn parse(text: &str) -> Result<(String, PathBuf), SubjectError> {
    let (name, path) = text.split_once(SEP).ok_or(SubjectError::Forbidden)?;
    if path.contains(SEP) {
        return Err(SubjectError::Ambiguous);
    }
    let path = PathBuf::from(path);
    let again = format(name, &path)?;
    if again == text {
        Ok((name.to_string(), path))
    } else {
        Err(SubjectError::Forbidden)
    }
}
