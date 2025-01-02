//! `zk-callbacks` is a generic framework for constructing anonymous reputation systems. It is an
//! implementation of the framework from [zk-Promises](https://eprint.iacr.org/2024/1260), along with some common cryptography primitives and storage systems.
//!
//! The callbacks system consists of generic traits and objects to represent user objects and
//! commitments, callbacks, and bulletins. The generic framework provides a layer by which users
//! can create proofs of method execution and callback scans, and allows arbitrary state in user
//! data. The generic framework is built off of `arkworks` and allows for any base field and proof
//! system supported by arkworks, including `bn254` and `bls12-381`.
//!
//! For additional information, take a look at the documentation and the examples.
//!
//! ## Design
//!
//! zk-callbacks relies on Rust's generic types and trait system, which permits the library to be
//! flexible with bulletins and objects. Data stored within a user object implements
//! the [`UserData`](`generic::user::UserData`) trait. Wrapping such data within a
//! [`User`](`generic::user::User`) object, one can then perform a wide range of functions (make
//! callbacks, scan callbacks, prove methods). The [`User`](`generic::user::User`) object provides
//! all bookkeeping fields within a user object. It maintains a list of callbacks, a nonce,
//! nullifier, and scanning data.
//!
//! Separately, zk-callbacks also holds a host of different bulletin and service traits to check membership,
//! store user objects and callbacks, and store interaction data. For example, a user may interact
//! with a [`ServiceProvider`](`generic::service::ServiceProvider`) by making a forum post, and
//! update their object stored on a [`UserBul`](`generic::bulletin::UserBul`). In the future, the
//! service may then call a callback by interacting with a
//! [`CallbackBulletin`](`generic::bulletin::CallbackBulletin`).
//!
//! Outside of the generic types and traits, [`impls`] contains some default and simple implementations of the
//! previous traits and those described in the paper. It contains some implementations of
//! [`UserData`](`generic::user::UserData`) for simple objects, along with some data structures for
//! the bulletins, such as a [`SigObjStore`](`impls::centralized::ds::sigstore::SigObjStore`) and
//! some more cryptography.

#![allow(incomplete_features)]
#![feature(generic_const_exprs)]
#![feature(associated_type_defaults)]
#![feature(type_alias_impl_trait)]
#![feature(doc_cfg)]
pub mod crypto;
pub mod generic;
pub mod impls;

#[doc(hidden)]
pub mod util;

pub use zk_object::{scannable_zk_object, zk_object};
