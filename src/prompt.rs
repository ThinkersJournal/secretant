// SPDX-License-Identifier: MIT OR Apache-2.0
//! Asking a person for a secret on the terminal, without echo.
//!
//! The prompt goes to standard error and the answer is read from the
//! terminal itself (not standard input) with echo off, so neither appears in a
//! pipe or a log. With no terminal there is no prompt and no silent fallback:
//! the caller is told to choose an explicit source.

use secretant::SecretValue;
use std::io::IsTerminal;

/// Why a secret could not be asked for. A class only.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AskError {
    /// There is no terminal to ask on.
    NoTerminal,
    /// The terminal failed.
    Failed,
    /// The two entries of a new passphrase differ.
    Mismatch,
    /// An empty passphrase.
    Empty,
}

/// Something that can ask for a secret.
pub trait Ask {
    /// Ask with `prompt`, without echo.
    fn secret(&mut self, prompt: &str) -> Result<SecretValue, AskError>;
}

/// The real terminal.
pub struct Terminal;

impl Ask for Terminal {
    fn secret(&mut self, prompt: &str) -> Result<SecretValue, AskError> {
        if !std::io::stdin().is_terminal() || !std::io::stderr().is_terminal() {
            return Err(AskError::NoTerminal);
        }
        eprint!("{prompt}");
        let answer = rpassword::read_password().map_err(|_| AskError::Failed)?;
        Ok(SecretValue::from_string(answer))
    }
}

/// The passphrase of an existing store.
pub fn passphrase(ask: &mut dyn Ask) -> Result<SecretValue, AskError> {
    ask.secret("Passphrase: ")
}

/// A new passphrase, asked twice; refused if the two differ or it is empty.
pub fn new_passphrase(ask: &mut dyn Ask) -> Result<SecretValue, AskError> {
    let first = ask.secret("New passphrase: ")?;
    let second = ask.secret("Repeat passphrase: ")?;
    if first.expose() != second.expose() {
        return Err(AskError::Mismatch);
    }
    if first.is_empty() {
        return Err(AskError::Empty);
    }
    Ok(first)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A scripted terminal that records every prompt it was shown.
    struct Mock {
        answers: Vec<&'static str>,
        shown: Vec<String>,
    }

    impl Ask for Mock {
        fn secret(&mut self, prompt: &str) -> Result<SecretValue, AskError> {
            self.shown.push(prompt.to_string());
            if self.answers.is_empty() {
                return Err(AskError::Failed);
            }
            Ok(SecretValue::from_string(self.answers.remove(0).into()))
        }
    }

    fn mock(answers: &[&'static str]) -> Mock {
        Mock {
            answers: answers.to_vec(),
            shown: Vec::new(),
        }
    }

    #[test]
    fn a_new_passphrase_is_asked_twice_and_must_match() {
        let mut m = mock(&["CANARY-pass-1c", "CANARY-pass-1c"]);
        let p = new_passphrase(&mut m).unwrap();
        assert_eq!(p.expose(), b"CANARY-pass-1c");
        assert_eq!(m.shown.len(), 2);
        // the prompts never carry an answer
        assert!(m.shown.iter().all(|s| !s.contains("CANARY")));
    }

    #[test]
    fn a_mismatch_or_empty_new_passphrase_is_refused() {
        let mut m = mock(&["a-one", "a-two"]);
        assert_eq!(new_passphrase(&mut m).err(), Some(AskError::Mismatch));
        let mut m = mock(&["", ""]);
        assert_eq!(new_passphrase(&mut m).err(), Some(AskError::Empty));
    }

    #[test]
    fn an_existing_passphrase_is_asked_once() {
        let mut m = mock(&["CANARY-pass-2d"]);
        assert_eq!(passphrase(&mut m).unwrap().expose(), b"CANARY-pass-2d");
        assert_eq!(m.shown, vec!["Passphrase: ".to_string()]);
    }

    #[test]
    fn a_failing_terminal_is_an_error_not_an_empty_passphrase() {
        let mut m = mock(&[]);
        assert_eq!(passphrase(&mut m).err(), Some(AskError::Failed));
    }
}
