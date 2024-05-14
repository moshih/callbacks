use ark_ff::PrimeField;
use ark_ff::ToConstraintField;
use ark_r1cs_std::prelude::AllocVar;
use ark_r1cs_std::ToConstraintFieldGadget;
use rand::CryptoRng;
use rand::RngCore;

pub trait RRSigner<S, M, R, V: RRVerifier<S, M, R>> {
    type Vk = V;
    fn sign_message(&self, message: &M) -> S;

    fn sk_to_pk(&self) -> V;

    fn gen() -> Self;

    fn rerand(&self, randomness: R) -> Self;
}

pub trait RRVerifier<S, M, R> {
    fn verify(&self, message: M, signature: S) -> bool;

    fn rerand(&self, rng: &mut (impl CryptoRng + RngCore)) -> (R, Self);
}

pub trait RRTicket<F: PrimeField, A: Clone>: Clone + Eq + std::fmt::Debug {
    type Sig;
    type Rand: std::fmt::Debug;

    type Tik: RRVerifier<Self::Sig, A, Self::Rand>
        + ToConstraintField<F>
        + Clone
        + Eq
        + std::fmt::Debug
        + Default;

    type TikVar: ToConstraintFieldGadget<F> + AllocVar<Self::Tik, F> + Clone;
}
