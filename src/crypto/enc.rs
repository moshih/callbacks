use crate::crypto::rr::{RRSigner, RRVerifier};
use ark_ff::PrimeField;
use ark_ff::ToConstraintField;
use ark_r1cs_std::prelude::AllocVar;
use ark_r1cs_std::ToConstraintFieldGadget;
use ark_relations::r1cs::SynthesisError;
use core::borrow::Borrow;

pub trait CPACipher<F: PrimeField> {
    type KeyVar: AllocVar<Self, F> + Clone + ToConstraintFieldGadget<F>;

    type M;

    type C;

    type MV: AllocVar<Self::M, F>;

    type CV: AllocVar<Self::C, F>;

    fn encrypt(&self, message: Self::M) -> Self::C;

    fn decrypt(&self, ciphertext: Self::C) -> Self::M;

    fn encrypt_in_zk(key: Self::KeyVar, message: Self::MV) -> Result<Self::CV, SynthesisError>;

    fn decrypt_in_zk(key: Self::KeyVar, ciphertext: Self::CV) -> Result<Self::MV, SynthesisError>;
}

pub trait AECipherSigZK<F: PrimeField, A: Clone> {
    type Ct: Clone;
    type EncKey: CPACipher<F, C = Self::Ct, M = A> + ToConstraintField<F> + Borrow<F>;

    type Sig;
    type Rand;

    type SigPK: RRVerifier<Self::Sig, Self::Ct, Self::Rand>
        + ToConstraintField<F>
        + Clone
        + Eq
        + std::fmt::Debug;

    type SigPKV: ToConstraintFieldGadget<F> + AllocVar<Self::SigPK, F> + Clone;

    type SigSK: RRSigner<Self::Sig, Self::Ct, Self::Rand, Self::SigPK>;

    fn encrypt_and_sign(
        message: A,
        enc_key: Self::EncKey,
        sig_sk: Self::SigSK,
    ) -> (Self::Ct, Self::Sig) {
        let enc = enc_key.encrypt(message);
        let sig = sig_sk.sign_message(&enc);

        (enc, sig)
    }
}
