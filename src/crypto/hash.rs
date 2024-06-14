use crate::generic::object::{Ser, SerVar};
use ark_ff::PrimeField;
use ark_r1cs_std::fields::fp::FpVar;
use ark_r1cs_std::prelude::AllocVar;
use ark_relations::r1cs::SynthesisError;

pub trait HasherZK<F: PrimeField> {
    type M;
    type C;
    type MV: AllocVar<Self::M, F>;
    type CV: AllocVar<Self::C, F>;

    fn hash(data: &[Self::M]) -> Self::C;

    fn hash_in_zk(data: &[Self::MV]) -> Result<Self::CV, SynthesisError>;
}

pub trait FieldHash<F: PrimeField>:
    HasherZK<F, C = F, M = Ser<F>, MV = SerVar<F>, CV = FpVar<F>> + Clone
{
}
