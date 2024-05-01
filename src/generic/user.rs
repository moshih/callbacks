use crate::generic::interaction::{ExecMethodCircuit, Interaction};
use crate::generic::object::{Com, ComVar, Nul, Ser, SerVar, ZKFields, ZKFieldsVar};
use crate::util::gen_poseidon_params;
use ark_crypto_primitives::crh::{poseidon, poseidon::CRH, CRHScheme, CRHSchemeGadget};
use ark_crypto_primitives::sponge::Absorb;
use ark_ff::PrimeField;
use ark_r1cs_std::alloc::AllocVar;
use ark_r1cs_std::alloc::AllocationMode;
use ark_relations::ns;
use ark_relations::r1cs::Namespace;
use ark_relations::r1cs::{ConstraintSynthesizer, ConstraintSystem, SynthesisError};
use ark_snark::SNARK;
use rand::{CryptoRng, RngCore};
use std::borrow::Borrow;

pub trait UserData: Clone + Eq + std::fmt::Debug {
    type F: PrimeField + Absorb;

    type UserDataVar: AllocVar<Self, Self::F> + Clone;

    fn serialize_elements(&self) -> Vec<Ser<Self::F>>;

    fn serialize_in_zk(user_var: Self::UserDataVar)
        -> Result<Vec<SerVar<Self::F>>, SynthesisError>;
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct User<U: UserData> {
    pub data: U,
    pub zk_fields: ZKFields<U::F>,
}

#[derive(Clone)]
pub struct UserVar<U: UserData> {
    pub data: U::UserDataVar,
    pub zk_fields: ZKFieldsVar<U::F>,
}

impl<U: UserData> AllocVar<User<U>, U::F> for UserVar<U> {
    fn new_variable<T: Borrow<User<U>>>(
        cs: impl Into<Namespace<U::F>>,
        f: impl FnOnce() -> Result<T, SynthesisError>,
        mode: AllocationMode,
    ) -> Result<Self, SynthesisError> {
        let ns = cs.into();
        let cs = ns.cs();
        let res = f();

        res.and_then(|rec| {
            let rec = rec.borrow();
            let data =
                U::UserDataVar::new_variable(ns!(cs, "data"), || Ok(rec.data.clone()), mode)?;
            let zk_fields = ZKFieldsVar::new_variable(
                ns!(cs, "zk_fields"),
                || Ok(rec.zk_fields.clone()),
                mode,
            )?;
            Ok(UserVar { data, zk_fields })
        })
    }
}

// UserCommitment, Old Nullifier, Bookkeeping Proof, Predicate Proof
pub type ExecRet<F, S> = (
    Com<F>,
    Nul<F>,
    <S as SNARK<F>>::Proof,
    <S as SNARK<F>>::VerifyingKey,
);

impl<U: UserData> User<U> {
    pub fn interact<A: Clone, S: SNARK<U::F, Error = SynthesisError>, const N: usize>(
        &mut self,
        rng: &mut (impl CryptoRng + RngCore),
        method: Interaction<U, A, N>,
        args: A,
    ) -> Result<ExecRet<U::F, S>, SynthesisError> {
        // Steps:
        // a) update user/self [ old user ] --> method(user) [ new user ]
        // b) update user's zk fields properly (new nul, new comrand, proper cblist, etc)
        // c) generate proof of correctness for
        //      - a) the user was properly updated via the predicate
        //      - b) the zk statements (nul == old nul, proper cblist, etc)

        // (A) update the user object
        // Create the new zk_object from the method
        let new_user = (method.meth.0)(self, args.clone());

        // (B) update the new users zk fields properly
        // Extract the zk fields from the objects to do bookkeeping

        let out_commit = new_user.commit();

        let out_nul = self.zk_fields.nul;

        let exec_method_circ: ExecMethodCircuit<U, A, N> = ExecMethodCircuit {
            priv_old_user: self.clone(),
            priv_new_user: new_user.clone(),
            pub_new_com: out_commit,
            pub_old_nul: out_nul,
            method,
            args,
        };

        let new_cs = ConstraintSystem::<U::F>::new_ref();
        exec_method_circ
            .clone()
            .generate_constraints(new_cs.clone())?;
        new_cs.is_satisfied()?;

        let (pk, vk) = S::circuit_specific_setup(exec_method_circ.clone(), rng)?;
        let proof = S::prove(&pk, exec_method_circ, rng)?;

        // Update current object
        *self = new_user;

        Ok((out_commit, out_nul, proof, vk))
    }

    pub fn commit(&self) -> Com<U::F> {
        let ser_data = self.data.serialize_elements();
        let ser_fields = self.zk_fields.serialize();
        let full_dat = [ser_data.as_slice(), ser_fields.as_slice()].concat();
        CRH::evaluate(&gen_poseidon_params(2, false), full_dat).unwrap()
    }

    pub fn commit_in_zk(user_var: UserVar<U>) -> Result<ComVar<U::F>, SynthesisError> {
        let params = gen_poseidon_params(2, false);
        let params_var = poseidon::constraints::CRHParametersVar { parameters: params };

        let ser_data = U::serialize_in_zk(user_var.data)?;
        let ser_fields = user_var.zk_fields.serialize()?;
        let full_dat = [ser_data.as_slice(), ser_fields.as_slice()].concat();

        poseidon::constraints::CRHGadget::evaluate(&params_var, &full_dat)
    }
}
