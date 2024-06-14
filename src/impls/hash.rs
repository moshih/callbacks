use crate::crypto::hash::FieldHash;
use crate::crypto::hash::HasherZK;
use crate::util::gen_poseidon_params;
use ark_crypto_primitives::crh::{poseidon, poseidon::CRH, CRHScheme, CRHSchemeGadget};
use ark_crypto_primitives::sponge::Absorb;
use ark_ff::PrimeField;
use ark_r1cs_std::fields::fp::FpVar;
use ark_relations::r1cs::SynthesisError;
use circom_poseidon::get_poseidon_params;

#[derive(Clone)]
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

impl<F: PrimeField + Absorb, const R: usize> FieldHash<F> for Poseidon<R> {}

#[derive(Clone)]
pub struct CircPoseidon<const R: usize>();

impl<F: PrimeField + Absorb, const R: usize> HasherZK<F> for CircPoseidon<R> {
    type M = F;
    type C = F;
    type MV = FpVar<F>;
    type CV = FpVar<F>;

    fn hash(data: &[F]) -> F {
        CRH::evaluate(&get_poseidon_params(R), data).unwrap()
    }

    fn hash_in_zk(data: &[FpVar<F>]) -> Result<FpVar<F>, SynthesisError> {
        let params = get_poseidon_params(2);
        let params_var = poseidon::constraints::CRHParametersVar { parameters: params };

        poseidon::constraints::CRHGadget::evaluate(&params_var, data)
    }
}

impl<F: PrimeField + Absorb, const R: usize> FieldHash<F> for CircPoseidon<R> {}
