// SPDX-License-Identifier: MIT OR Apache-2.0
//! The Windows Hello approver: a [`PlacementApprover`] that asks the person
//! through `user-request`'s Secret kind. Three things to know.
//!
//! - **Who is asking** comes from `with-secret`'s `identity::resolve` over the
//!   OS process table, never from an argument or a hand-built value. If the
//!   table cannot place this process (self missing, no claude ancestor) the
//!   approver answers [`Decision::Denied`] and never asks: no made-up requester.
//!   The face depends on `with-secret` only for that function; the clean home
//!   is `user-request`, which pm-ants will ask the consent lane for.
//! - **What is shown** is the subject `NAME -> path` ([`crate::subject`]),
//!   whole (the prompt clips at 200 characters and the subject cannot exceed
//!   it) and nothing else about the secret.
//! - **The grant** is the shortest the Secret kind allows that can still be
//!   answered: `OneUse` is not available to it, so it is 120 seconds with a 60
//!   second wait. The approval is used at once and not stored by the face. A
//!   `KindId::SecretPlacement` (user-request 0.17.0) will replace this.

use crate::{Decision, PlacementApprover, PlacementRequest};
use lane_state::facts::{SysinfoFacts, SystemFacts};
use std::path::PathBuf;
use user_request::channel::{Channel, HelloChannel, Outcome};
use user_request::consent::Consent;
use user_request::{Grant, KindId, Request, Requester};
use with_secret::identity;

/// How long the person has to answer.
pub const WAIT_SECS: u64 = 60;
/// The grant shown: the shortest the Secret kind allows that outlives the wait.
pub const GRANT_SECS: i64 = 120;

/// Asks through `user-request`. `C` is the consent channel (the real Hello one,
/// or a fake in tests); a fresh one is made per ask.
pub struct HelloApprover<C: Consent + 'static> {
    who: Result<Requester, String>,
    consent: Box<dyn Fn() -> C + Send + Sync>,
}

impl<C: Consent + 'static> HelloApprover<C> {
    /// With an identity already resolved (or the reason it could not be).
    pub fn with_identity(
        who: Result<Requester, String>,
        consent: Box<dyn Fn() -> C + Send + Sync>,
    ) -> Self {
        Self { who, consent }
    }

    /// Place this process in the OS process table and lane-state files.
    pub fn from_process(consent: Box<dyn Fn() -> C + Send + Sync>) -> Self {
        let who = SysinfoFacts::new(PathBuf::new())
            .process_table()
            .map_err(|e| format!("{e:?}"))
            .and_then(|table| {
                identity::resolve(
                    &table,
                    std::process::id(),
                    &identity::load_states(&lane_state::platform::state_dir()),
                )
            });
        Self { who, consent }
    }

    /// Why no requester could be placed, if so.
    #[must_use]
    pub fn identity_error(&self) -> Option<&str> {
        self.who.as_ref().err().map(String::as_str)
    }
}

impl<C: Consent + 'static> PlacementApprover for HelloApprover<C> {
    fn approve(&self, req: &PlacementRequest) -> Decision {
        let Ok(who) = &self.who else {
            return Decision::Denied;
        };
        let request = Request {
            kind: KindId::Secret,
            subject: req.subject.clone(),
            summary: "place a secret in a file".to_string(),
            requester: who.clone(),
            reason: format!("an agent in role {} asked for this placement", req.role),
            allowed_lanes: None,
        };
        let grant = Grant::For { secs: GRANT_SECS };
        let channel = HelloChannel::new((self.consent)());
        match channel.present(&request, &grant, std::time::Duration::from_secs(WAIT_SECS)) {
            Outcome::Approved(_) => Decision::Approved,
            Outcome::TimedOut => Decision::TimedOut,
            Outcome::Unavailable(_) => Decision::Unavailable,
            // Denied, Refused and anything new: no.
            _ => Decision::Denied,
        }
    }
}

/// The real Hello approver for the host binary.
#[must_use]
pub fn platform() -> HelloApprover<user_request::platform::PlatformConsent> {
    HelloApprover::from_process(Box::new(user_request::platform::platform_consent))
}
