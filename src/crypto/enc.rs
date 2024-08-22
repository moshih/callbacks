use crate::crypto::rr::{RRSigner, RRVerifier};
use ark_ff::PrimeField;
use ark_ff::ToConstraintField;
use ark_r1cs_std::prelude::AllocVar;
use ark_r1cs_std::ToConstraintFieldGadget;
use ark_relations::r1cs::SynthesisError;
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use rand::{CryptoRng, RngCore};

pub trait CPACipher<F: PrimeField> {
    type KeyVar: AllocVar<Self, F> + Clone + ToConstraintFieldGadget<F>;

    type M;

    type C;

    type MV: AllocVar<Self::M, F>;

    type CV: AllocVar<Self::C, F>;

    fn keygen(rng: &mut (impl CryptoRng + RngCore)) -> Self;

    fn encrypt(&self, message: Self::M) -> Self::C;

    fn decrypt(&self, ciphertext: Self::C) -> Self::M;

    fn encrypt_in_zk(key: Self::KeyVar, message: Self::MV) -> Result<Self::CV, SynthesisError>;

    fn decrypt_in_zk(key: Self::KeyVar, ciphertext: Self::CV) -> Result<Self::MV, SynthesisError>;
}

pub trait AECipherSigZK<F: PrimeField, Args: Clone>: Clone + std::fmt::Debug {
    type Ct: Clone;
    type EncKey: CPACipher<F, C = Self::Ct, M = Args, KeyVar = Self::EncKeyVar>
        + ToConstraintField<F>
        + CanonicalSerialize
        + CanonicalDeserialize
        + Clone
        + Eq
        + std::fmt::Debug
        + Default;
    type EncKeyVar: AllocVar<Self::EncKey, F> + ToConstraintFieldGadget<F> + Clone;

    type Sig;
    type Rand: std::fmt::Debug + Clone + CanonicalSerialize + CanonicalDeserialize;

    type SigPK: RRVerifier<Self::Sig, Self::Ct, Self::Rand>
        + ToConstraintField<F>
        + CanonicalSerialize
        + CanonicalDeserialize
        + Clone
        + Eq
        + std::fmt::Debug
        + Default;

    type SigPKV: AllocVar<Self::SigPK, F> + ToConstraintFieldGadget<F> + Clone;

    type SigSK: RRSigner<Self::Sig, Self::Ct, Self::Rand, Self::SigPK>;

    fn encrypt_and_sign(
        message: Args,
        enc_key: Self::EncKey,
        sig_sk: Self::SigSK,
    ) -> (Self::Ct, Self::Sig) {
        let enc = enc_key.encrypt(message);
        let sig = sig_sk.sign_message(&enc);

        (enc, sig)
    }
}
