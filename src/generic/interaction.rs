use crate::generic::object::{Com, ComVar, Nul, NulVar};
use crate::generic::user::{User, UserData, UserVar};
use ark_r1cs_std::alloc::AllocVar;
use ark_r1cs_std::eq::EqGadget;
use ark_relations::{
    ns,
    r1cs::{ConstraintSynthesizer, ConstraintSystemRef, Result as ArkResult},
};

pub type Predicate<V, A> = fn(&V, &V, A) -> ArkResult<()>;
pub type Method<U, A> = fn(&U, A) -> U;

pub type CallbackList<U, A, const N: usize> = [(Method<User<U>, A>, Predicate<UserVar<U>, A>); N];

#[derive(Clone)]
pub struct Interaction<U: UserData, A, const N: usize> {
    pub meth: (Method<User<U>, A>, Predicate<UserVar<U>, A>),
    pub callbacks: CallbackList<U, A, N>,
}

#[derive(Clone)]
pub(crate) struct ExecMethodCircuit<U: UserData, A, const N: usize> {
    // Private Inputs
    pub priv_old_user: User<U>,
    pub priv_new_user: User<U>,

    // Public Inputs
    pub pub_new_com: Com<U::F>,
    pub pub_old_nul: Nul<U::F>,
    pub method: Interaction<U, A, N>,
    pub args: A,
}

impl<U: UserData, A, const N: usize> ConstraintSynthesizer<U::F> for ExecMethodCircuit<U, A, N> {
    fn generate_constraints(self, cs: ConstraintSystemRef<U::F>) -> ArkResult<()> {
        // Create private variables
        let old_user_var = UserVar::new_witness(ns!(cs, "old_user"), || Ok(self.priv_old_user))?;
        let new_user_var = UserVar::new_witness(ns!(cs, "new_user"), || Ok(self.priv_new_user))?;

        // Create public variables
        let new_com_var = ComVar::new_input(ns!(cs, "new_object"), || Ok(&self.pub_new_com))?;
        let old_nul_var = NulVar::new_input(ns!(cs, "old_nul"), || Ok(&self.pub_old_nul))?;

        // Enforce any method-specific predicates
        (self.method.meth.1)(&old_user_var, &new_user_var, self.args)?;

        let old_zk_fields = old_user_var.zk_fields;
        let new_zk_fields = new_user_var.zk_fields;

        // Enforce revealed nullifier (previous state) == the old nullifier
        old_nul_var.enforce_equal(&old_zk_fields.nul)?;

        Ok(())
    }
}
