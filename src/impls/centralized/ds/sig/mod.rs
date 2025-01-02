use ark_ff::{PrimeField, ToConstraintField};
use ark_r1cs_std::{alloc::AllocVar, fields::fp::FpVar, prelude::Boolean};
use ark_relations::r1cs::SynthesisError;
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use rand::{CryptoRng, RngCore};

pub trait Pubkey<F: PrimeField>: Default + ToConstraintField<F> {
    type PubkeyVar: AllocVar<Self, F>;

    type Sig;
    type SigVar: AllocVar<Self::Sig, F>;

    fn verify(&self, signature: Self::Sig, msg: F) -> bool;

    fn verify_zk(
        pubkey: Self::PubkeyVar,
        signature: Self::SigVar,
        msg: FpVar<F>,
    ) -> Result<Boolean<F>, SynthesisError>;
}

pub trait Privkey<F: PrimeField> {
    type CompressedPrivKey;

    type Sig;

    type Pubkey: Pubkey<F, Sig = Self::Sig>;

    fn gen_ckey(rng: &mut (impl CryptoRng + RngCore)) -> Self::CompressedPrivKey;

    fn into_key(c: Self::CompressedPrivKey) -> Self;

    fn gen_key(rng: &mut (impl CryptoRng + RngCore)) -> Self;

    fn get_pubkey(&self) -> Self::Pubkey;

    fn sign(&self, rng: &mut (impl CryptoRng + RngCore), msg: F) -> Option<Self::Sig>;
}

pub trait Signature<F: PrimeField>: Clone {
    type SigVar: Clone + AllocVar<Self::Sig, F>;
    type Sig: Clone + Default + CanonicalSerialize + CanonicalDeserialize + std::fmt::Debug;
    type Pubkey: Pubkey<F, Sig = Self::Sig, PubkeyVar = Self::PubkeyVar, SigVar = Self::SigVar>
        + Clone
        + Default;
    type PubkeyVar: Clone + AllocVar<Self::Pubkey, F>;
    type CPrivkey: Clone;
    type Privkey: Privkey<F, CompressedPrivKey = Self::CPrivkey, Pubkey = Self::Pubkey, Sig = Self::Sig>
        + Clone;

    fn gen_ckey(rng: &mut (impl CryptoRng + RngCore)) -> Self::CPrivkey {
        Self::Privkey::gen_ckey(rng)
    }

    fn gen_key(rng: &mut (impl CryptoRng + RngCore)) -> Self::Privkey {
        Self::Privkey::gen_key(rng)
    }

    fn into_key(c: Self::CPrivkey) -> Self::Privkey {
        Self::Privkey::into_key(c)
    }

    fn get_pubkey(pk: &Self::Privkey) -> Self::Pubkey {
        pk.get_pubkey()
    }

    fn sign(pk: &Self::Privkey, rng: &mut (impl CryptoRng + RngCore), msg: F) -> Option<Self::Sig> {
        pk.sign(rng, msg)
    }

    fn verify(vk: Self::Pubkey, signature: Self::Sig, msg: F) -> bool {
        vk.verify(signature, msg)
    }

    fn verify_zk(
        pubkey: Self::PubkeyVar,
        signature: Self::SigVar,
        msg: FpVar<F>,
    ) -> Result<Boolean<F>, SynthesisError> {
        Self::Pubkey::verify_zk(pubkey, signature, msg)
    }
}

pub mod uov;
