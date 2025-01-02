//! Generic structures and traits for interactions between users, bulletins, and services.
//!
//! This module consists of structures and traits for generic interactions. The most important
//! object is the [`User`](`user::User`) object, which wraps any struct implementing
//! [`UserData`](`user::UserData`). A `User` consists of all the data associated with a user,
//! including the data itself, the nullifier and nonce, and the list of callbacks. The main
//! functions of interest are implemented on top of [`User`](`user::User`), which produce proofs of
//!
//!* Adding callbacks to the user (and performing some method)
//!* Scanning callbacks and checking if they have been called (if so, performing some
//!        method).
//!
//! This are encapsulated within the [`User::interact`](`user::User::interact`) function, which
//! allows users to make a state change while producing a proof.
//!
//! Additionally, this module has traits associated to bulletins and services. This allows for:
//!
//!* Inserting commitments to users in a bulletin.
//!* "Calling" callbacks by posting them to a callback bulletin.
//!* Sending a proof with a callback and interacting with a service.
//!

#[cfg(feature = "asynchr")]
#[cfg(any(feature = "asynchr", doc))]
#[doc(cfg(feature = "asynchr"))]
pub mod asynchr;

pub mod bulletin;

pub mod callbacks;

#[cfg(feature = "folding")]
#[cfg(any(feature = "folding", doc))]
#[doc(cfg(feature = "folding"))]
pub mod fold;

pub mod interaction;

pub mod object;

pub mod scan;

pub mod service;

/// Contains structs associated to users and results of proofs done on user objects.
///
/// Specifically,
/// this module contains the [`User`](`user::User`) object and the [`UserData`](`user::UserData`) trait, which are integral to the
/// system.
pub mod user;
