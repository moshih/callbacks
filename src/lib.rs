#![feature(associated_type_defaults)]
/// Cryptographic definitions and constructions for concrete instantiations.
pub mod crypto;
/// Generic definitions useful for construction zero knowledge callback based applications.
pub mod generic;
/// Concrete instantiations and implementations of zk-callbacks traits and objects for basic types.
pub mod impls;
/// Utility types and methods for R1CS and zero knowledge proofs.
pub mod util;
