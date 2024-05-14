use crate::crypto::rr::{RRTicket, RRVerifier};
use ark_ff::PrimeField;
use ark_r1cs_std::fields::fp::FpVar;
use ark_r1cs_std::prelude::AllocVar;
use ark_r1cs_std::prelude::AllocationMode;
use ark_relations::ns;
use ark_relations::r1cs::Namespace;
use ark_relations::r1cs::SynthesisError;
use core::borrow::Borrow;
use rand::distributions::{Distribution, Standard};
use rand::Rng;
use rand::{CryptoRng, RngCore};

use ark_r1cs_std::ToConstraintFieldGadget;
use ark_relations::r1cs::ToConstraintField;

#[derive(Clone, Debug, PartialEq, Eq, Default)]
pub struct CentralTik<F>(pub F);

impl<F: PrimeField> ToConstraintField<F> for CentralTik<F> {
    fn to_field_elements(&self) -> Option<Vec<F>> {
        self.0.to_field_elements()
    }
}

#[derive(Clone)]
pub struct CentralTikVar<F: PrimeField>(pub FpVar<F>);

impl<F: PrimeField> ToConstraintFieldGadget<F> for CentralTikVar<F> {
    fn to_constraint_field(&self) -> Result<Vec<FpVar<F>>, SynthesisError> {
        self.0.to_constraint_field()
    }
}

impl<F: PrimeField> AllocVar<CentralTik<F>, F> for CentralTikVar<F> {
    fn new_variable<T: Borrow<CentralTik<F>>>(
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
            Ok(CentralTikVar(tik))
        })
    }
}

impl<F: PrimeField, A> RRVerifier<(), A, ()> for CentralTik<F>
where
    Standard: Distribution<F>,
{
    fn verify(&self, _mes: A, _sig: ()) -> bool {
        true
    }

    fn rerand(&self, rng: &mut (impl CryptoRng + RngCore)) -> ((), Self) {
        let out = rng.gen();
        ((), CentralTik(out))
    }
}

impl<F: PrimeField, A: Clone> RRTicket<F, A> for CentralTik<F>
where
    Standard: Distribution<F>,
{
    type Sig = ();
    type Rand = ();
    type Tik = CentralTik<F>;
    type TikVar = CentralTikVar<F>;
}
