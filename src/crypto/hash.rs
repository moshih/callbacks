use crate::util::gen_poseidon_params;
use ark_crypto_primitives::crh::{poseidon, poseidon::CRH, CRHScheme, CRHSchemeGadget};
use ark_crypto_primitives::sponge::Absorb;
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

pub struct Poseidon<const R: usize>();

impl<F: PrimeField + Absorb, const R: usize> HasherZK<F> for Poseidon<R> {
    type M = F;
    type C = F;
    type MV = FpVar<F>;
    type CV = FpVar<F>;

    fn hash(data: &[F]) -> F {
        CRH::evaluate(&gen_poseidon_params(R, false), data).unwrap()
    }

    fn hash_in_zk(data: &[FpVar<F>]) -> Result<FpVar<F>, SynthesisError> {
        let params = gen_poseidon_params(2, false);
        let params_var = poseidon::constraints::CRHParametersVar { parameters: params };

        poseidon::constraints::CRHGadget::evaluate(&params_var, data)
    }
}
