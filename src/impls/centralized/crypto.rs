use crate::crypto::enc::{AECipherSigZK, CPACipher};
use crate::crypto::rr::{RRSigner, RRVerifier};
#[cfg(feature = "folding")]
use crate::generic::fold::FoldSer;
use ark_ff::PrimeField;
use ark_r1cs_std::fields::fp::FpVar;
use ark_r1cs_std::prelude::AllocVar;
use ark_r1cs_std::prelude::AllocationMode;
use ark_relations::ns;
use ark_relations::r1cs::Namespace;
use ark_relations::r1cs::SynthesisError;
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use core::borrow::Borrow;
use rand::distributions::{Distribution, Standard};
use rand::Rng;
use rand::{CryptoRng, RngCore};

use ark_r1cs_std::convert::ToConstraintFieldGadget;
use ark_relations::r1cs::ToConstraintField;

#[derive(
    Clone, Debug, PartialEq, Eq, Default, CanonicalSerialize, CanonicalDeserialize, PartialOrd, Ord,
)]
pub struct PlainTikCrypto<F: CanonicalSerialize + CanonicalDeserialize>(pub F);

impl<F: PrimeField> ToConstraintField<F> for PlainTikCrypto<F> {
    fn to_field_elements(&self) -> Option<Vec<F>> {
        self.0.to_field_elements()
    }
}

#[derive(Clone)]
pub struct PlainTikCryptoVar<F: PrimeField>(pub FpVar<F>);

impl<F: PrimeField> ToConstraintFieldGadget<F> for PlainTikCryptoVar<F> {
    fn to_constraint_field(&self) -> Result<Vec<FpVar<F>>, SynthesisError> {
        self.0.to_constraint_field()
    }
}

impl<F: PrimeField> AllocVar<PlainTikCrypto<F>, F> for PlainTikCryptoVar<F> {
    fn new_variable<T: Borrow<PlainTikCrypto<F>>>(
        cs: impl Into<Namespace<F>>,
        f: impl FnOnce() -> Result<T, SynthesisError>,
        mode: AllocationMode,
    ) -> Result<Self, SynthesisError> {
        let ns = cs.into();
        let cs = ns.cs();
        let res = f();
        res.and_then(|rec| {
            let rec = rec.borrow();
            let tik = FpVar::new_variable(ns!(cs, "tik"), || Ok(rec.0), mode)?;
            Ok(PlainTikCryptoVar(tik))
        })
    }
}

impl<F: PrimeField, A> RRVerifier<(), A, F> for PlainTikCrypto<F>
where
    Standard: Distribution<F>,
{
    fn verify(&self, _mes: A, _sig: ()) -> bool {
        true
    }

    fn rerand(&self, rng: &mut (impl CryptoRng + RngCore)) -> (F, Self) {
        let mut out: F = rng.gen();
        while out > F::from_bigint(F::MODULUS_MINUS_ONE_DIV_TWO).unwrap() {
            out -= F::from_bigint(F::MODULUS_MINUS_ONE_DIV_TWO).unwrap();
        }
        (out, PlainTikCrypto(out))
    }
}

impl<F: PrimeField> CPACipher<F> for PlainTikCrypto<F>
where
    Standard: Distribution<F>,
{
    type M = F;
    type C = F;
    type MV = FpVar<F>;
    type CV = FpVar<F>;

    type KeyVar = PlainTikCryptoVar<F>;

    fn keygen(rng: &mut (impl CryptoRng + RngCore)) -> Self {
        let mut f: F = rng.gen();
        while f > F::from_bigint(F::MODULUS_MINUS_ONE_DIV_TWO).unwrap() {
            f -= F::from_bigint(F::MODULUS_MINUS_ONE_DIV_TWO).unwrap();
        }
        Self(f)
    }

    fn encrypt(&self, message: Self::M) -> Self::C {
        message + self.0
    }

    fn decrypt(&self, ciphertext: Self::C) -> Self::M {
        ciphertext - self.0
    }

    fn encrypt_in_zk(key: Self::KeyVar, message: Self::MV) -> Result<Self::CV, SynthesisError> {
        Ok(message + key.0)
    }

    fn decrypt_in_zk(key: Self::KeyVar, ciphertext: Self::CV) -> Result<Self::MV, SynthesisError> {
        Ok(ciphertext - key.0)
    }
}

impl<F: PrimeField, A> RRSigner<(), A, F, PlainTikCrypto<F>> for PlainTikCrypto<F>
where
    Standard: Distribution<F>,
{
    fn gen(_rng: &mut (impl CryptoRng + RngCore)) -> Self {
        PlainTikCrypto(F::zero())
    }

    fn sk_to_pk(&self) -> PlainTikCrypto<F> {
        self.clone()
    }

    fn sign_message(&self, _mes: &A) {}

    fn rerand(&self, rand: F) -> Self {
        PlainTikCrypto(rand)
    }
}

impl<F: PrimeField> AECipherSigZK<F, F> for PlainTikCrypto<F>
where
    Standard: Distribution<F>,
{
    type Sig = ();
    type SigPK = PlainTikCrypto<F>;
    type SigPKV = PlainTikCryptoVar<F>;

    type SigSK = PlainTikCrypto<F>;

    type AV = FpVar<F>;

    type Ct = F;

    type EncKey = PlainTikCrypto<F>;

    type EncKeyVar = PlainTikCryptoVar<F>;

    type Rand = F;
}

#[cfg(feature = "folding")]
impl<F: PrimeField> FoldSer<F, PlainTikCryptoVar<F>> for PlainTikCrypto<F> {
    fn repr_len() -> usize {
        1
    }

    fn to_fold_repr(&self) -> Vec<crate::generic::object::Ser<F>> {
        vec![self.0.clone()]
    }

    fn from_fold_repr(ser: &[crate::generic::object::Ser<F>]) -> Self {
        PlainTikCrypto(ser[0].clone())
    }

    fn from_fold_repr_zk(
        var: &[crate::generic::object::SerVar<F>],
    ) -> Result<PlainTikCryptoVar<F>, SynthesisError> {
        Ok(PlainTikCryptoVar(var[0].clone()))
    }

    fn to_fold_repr_zk(
        var: &PlainTikCryptoVar<F>,
    ) -> Result<Vec<crate::generic::object::SerVar<F>>, SynthesisError> {
        Ok(vec![var.0.clone()])
    }
}

#[cfg(feature = "folding")]
impl<F: PrimeField> FoldSer<F, FpVar<F>> for F {
    fn repr_len() -> usize {
        1
    }

    fn to_fold_repr(&self) -> Vec<crate::generic::object::Ser<F>> {
        vec![self.clone()]
    }

    fn from_fold_repr(ser: &[crate::generic::object::Ser<F>]) -> Self {
        ser[0].clone()
    }

    fn from_fold_repr_zk(
        var: &[crate::generic::object::SerVar<F>],
    ) -> Result<FpVar<F>, SynthesisError> {
        Ok(var[0].clone())
    }

    fn to_fold_repr_zk(
        var: &FpVar<F>,
    ) -> Result<Vec<crate::generic::object::SerVar<F>>, SynthesisError> {
        Ok(vec![var.clone()])
    }
}
