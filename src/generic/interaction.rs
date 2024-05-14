use crate::crypto::rr::RRTicket;
use crate::generic::bulletin::PublicUserBul;
use crate::generic::callbacks::add_ticket_to_hc_zk;
use crate::generic::callbacks::create_defaults;
use crate::generic::callbacks::{CallbackCom, CallbackComVar};
use crate::generic::object::{Com, ComVar, Id, Nul, NulVar, Time};
use crate::generic::user::{User, UserData, UserVar};
use crate::util::ArrayVar;
use ark_crypto_primitives::sponge::Absorb;
use ark_ff::PrimeField;
use ark_r1cs_std::alloc::AllocVar;
use ark_r1cs_std::boolean::Boolean;
use ark_r1cs_std::eq::EqGadget;
use ark_relations::{
    ns,
    r1cs::{ConstraintSynthesizer, ConstraintSystemRef, Result as ArkResult},
};
use ark_snark::SNARK;
use core::marker::PhantomData;
use rand::distributions::{Distribution, Standard};
use rand::{CryptoRng, RngCore};

/// A predicate is a function which takes in 3 arguments:
///  - an old object
///  - a new object
///  - some auxiliary arguments
///
/// and places constraints on the values within the old and new objects. For example, say a user
/// has an `is_banned` field. Then when the user accesses the server, the predicate can enforce:
///  - `old.is_banned == false`
///  - `new.is_banned == old.is_banned`
/// or that the user was never banned and the state of `is_banned` did not change.
pub type Predicate<V, X> = fn(&V, &V, X) -> ArkResult<()>;

pub type SingularPredicate<V, C, X> = fn(&V, &C, X) -> ArkResult<()>;

/// A method is a function which takes in 2 arguments:
///  - an old object
///  - auxiliary arguments
///
/// and outputs a new object. For example, suppose we have a user with a `num_acccesses` field.
/// Every time the user accesses the server, we would like the num accesses to increment. To do
/// this, we can have a method which takes in the user `U`, and outputs a new user `U'` such that
/// `U'.num_accesses = U.num_accesses + 1`.
pub type Method<U, A> = fn(&U, A) -> U;

#[derive(Clone)]
pub struct Callback<F: PrimeField + Absorb, U: UserData<F>, A, X> {
    pub method_id: Id<F>,
    pub expirable: bool,
    pub expiration: Time<F>,
    pub method: Method<User<F, U>, A>,
    pub predicate: Predicate<UserVar<F, U>, X>,
}

/// This consists of a list of callbacks. A singular callback consists of
///  - an identifiable id
///  - a boolean indicating whether this callback can expire or not
///  - the expiry time (only valid if the expiration is set to true)
///  - a method on the user state
///  - a predicate enforcing rules on the method update
///
/// When a callback ticket is posted by the service provider, as long as it was posted before the
/// expiry, the user is forced to prove the predicate on their new state (after the method
/// executed).
///
/// Note: The IDs MUST be unique, otherwise the server cannot identify what to call.
pub type CallbackList<F, U, A, X, const N: usize> = [Callback<F, U, A, X>; N];

// TODO: Add two examples: one with callbacks, one without
/// This is a single "interaction" with a service provider. When a user interacts with the service
/// provider, a method can be called on the user's data and a proof provided of the method
/// predicate.
///
/// A ticket associated with each callback in the list is handed to the server. If the server
/// chooses to call a specific callback, the server posts it on the callback bulletin, where the
/// user then must execute the method and prove the predicate associated with that callback.
#[derive(Clone)]
pub struct Interaction<
    F: PrimeField + Absorb,
    U: UserData<F>,
    A: Clone,
    X: AllocVar<A, F>,
    const N: usize,
> {
    pub meth: (Method<User<F, U>, A>, Predicate<UserVar<F, U>, X>),
    pub callbacks: CallbackList<F, U, A, X, N>,
}

impl<
        F: PrimeField + Absorb,
        U: UserData<F> + Default,
        A: Clone + Default + std::fmt::Debug,
        X: AllocVar<A, F> + Clone,
        const N: usize,
    > Interaction<F, U, A, X, N>
where
    Standard: Distribution<F>,
{
    pub fn generate_keys<S: SNARK<F>, T: RRTicket<F, A>>(
        &self,
        rng: &mut (impl CryptoRng + RngCore),
    ) -> (S::ProvingKey, S::VerifyingKey) {
        let u = User::create(U::default(), rng);

        let cbs: [CallbackCom<F, A, T>; N] = create_defaults(rng, (*self).clone());

        let x = (*self).clone();

        let out = ExecMethodCircuit {
            priv_old_user: u.clone(),
            priv_new_user: u.clone(),
            priv_issued_callbacks: cbs.clone(),

            pub_new_com: u.commit(),
            pub_old_nul: u.zk_fields.nul,
            pub_issued_callback_coms: cbs.map(|x| x.commit()),
            pub_args: A::default(),
            associated_method: x,
        };
        S::circuit_specific_setup(out, rng).unwrap()
    }
}

#[derive(Clone)]
pub(crate) struct ExecMethodCircuit<
    F: PrimeField + Absorb,
    U: UserData<F>,
    A: Clone,
    X: AllocVar<A, F>,
    T: RRTicket<F, A>,
    const N: usize,
> {
    // Private Inputs
    pub priv_old_user: User<F, U>,
    pub priv_new_user: User<F, U>,
    pub priv_issued_callbacks: [CallbackCom<F, A, T>; N],

    // Public Inputs
    pub pub_new_com: Com<F>,
    pub pub_old_nul: Nul<F>,
    pub pub_issued_callback_coms: [Com<F>; N],
    pub pub_args: A,

    pub associated_method: Interaction<F, U, A, X, N>,
}

impl<
        F: PrimeField + Absorb,
        U: UserData<F>,
        A: Clone + std::fmt::Debug,
        X: AllocVar<A, F>,
        T: RRTicket<F, A>,
        const N: usize,
    > ConstraintSynthesizer<F> for ExecMethodCircuit<F, U, A, X, T, N>
{
    fn generate_constraints(self, cs: ConstraintSystemRef<F>) -> ArkResult<()> {
        // Create private variables
        let old_user_var = UserVar::new_witness(ns!(cs, "old_user"), || Ok(self.priv_old_user))?;
        let new_user_var = UserVar::new_witness(ns!(cs, "new_user"), || Ok(self.priv_new_user))?;
        let issued_cbs: ArrayVar<CallbackComVar<F, A, T>, N> =
            ArrayVar::new_witness(ns!(cs, "issued_cbs"), || Ok(&self.priv_issued_callbacks))?;

        // Create public variables
        let new_com_var = ComVar::new_input(ns!(cs, "new_com"), || Ok(&self.pub_new_com))?;
        let old_nul_var = NulVar::new_input(ns!(cs, "old_nul"), || Ok(&self.pub_old_nul))?;
        let args_var = X::new_input(ns!(cs, "args"), || Ok(&self.pub_args))?;

        let issued_cb_coms: ArrayVar<ComVar<F>, N> =
            ArrayVar::new_input(ns!(cs, "issued_cb_coms"), || {
                Ok(&self.pub_issued_callback_coms)
            })?;

        // Enforce Com(old_user) = old_user and old_user in bulletin

        // Enforce any method-specific predicates
        (self.associated_method.meth.1)(&old_user_var, &new_user_var, args_var)?;

        let mut old_zk_fields = old_user_var.clone().zk_fields;
        let new_zk_fields = new_user_var.clone().zk_fields;

        // Enforce revealed nullifier (previous state) == the old nullifier
        old_nul_var.enforce_equal(&old_zk_fields.nul)?;

        // Enforce we are currently not sweeping.
        old_zk_fields.is_ingest_over.enforce_equal(&Boolean::TRUE)?;

        for i in 0..N {
            // Enforce that the callback commitments are well-formed
            issued_cb_coms.0[i]
                .enforce_equal(&CallbackCom::commit_in_zk(issued_cbs.0[i].clone())?)?;

            // Append callbacks to the callback list
            add_ticket_to_hc_zk(
                &mut old_zk_fields.callback_hash,
                issued_cbs.0[i].clone().cb_entry,
            )?;
        }

        old_zk_fields.old_in_progress_callback_hash = old_zk_fields.callback_hash.clone();

        // Enforce new == the updated states
        new_zk_fields
            .callback_hash
            .enforce_equal(&old_zk_fields.callback_hash)?;

        new_zk_fields
            .old_in_progress_callback_hash
            .enforce_equal(&old_zk_fields.old_in_progress_callback_hash)?;

        new_zk_fields
            .new_in_progress_callback_hash
            .enforce_equal(&old_zk_fields.new_in_progress_callback_hash)?;

        new_zk_fields
            .is_ingest_over
            .enforce_equal(&old_zk_fields.is_ingest_over)?;

        // Enforce that Com(new_user) == new_com
        let com = User::commit_in_zk(new_user_var)?;

        new_com_var.enforce_equal(&com)?;

        Ok(())
    }
}

#[derive(Clone)]
pub(crate) struct ProvePredicateCircuit<
    F: PrimeField + Absorb,
    U: UserData<F>,
    A: Clone,
    X: AllocVar<A, F>,
> {
    // Private
    pub priv_user: User<F, U>,

    // Public
    pub pub_com: Com<F>,
    pub pub_args: A,

    pub associated_method: SingularPredicate<UserVar<F, U>, ComVar<F>, X>,
}

impl<F: PrimeField + Absorb, U: UserData<F>, A: Clone, X: AllocVar<A, F>> ConstraintSynthesizer<F>
    for ProvePredicateCircuit<F, U, A, X>
{
    fn generate_constraints(self, cs: ConstraintSystemRef<F>) -> ArkResult<()> {
        let user_var = UserVar::new_witness(ns!(cs, "user"), || Ok(self.priv_user))?;
        let com_var = ComVar::new_input(ns!(cs, "com"), || Ok(&self.pub_com))?;
        let args_var = X::new_input(ns!(cs, "args"), || Ok(&self.pub_args))?;

        (self.associated_method)(&user_var, &com_var, args_var)?;

        Ok(())
    }
}

#[derive(Clone)]
pub(crate) struct ProvePredInCircuit<
    F: PrimeField + Absorb,
    U: UserData<F>,
    A: Clone,
    X: AllocVar<A, F>,
    W,
    WVar: AllocVar<W, F>,
    B: PublicUserBul<F, U, User = U>,
> {
    // Private
    pub priv_user: User<F, U>,
    pub priv_extra_membership_data: W,

    // Public
    pub pub_args: A,

    pub associated_bul: B,
    pub associated_method: SingularPredicate<UserVar<F, U>, ComVar<F>, X>,

    pub _ph: PhantomData<WVar>,
}

impl<
        F: PrimeField + Absorb,
        U: UserData<F>,
        A: Clone,
        X: AllocVar<A, F>,
        W,
        WVar: AllocVar<W, F>,
        B: PublicUserBul<F, U, User = U>,
    > ConstraintSynthesizer<F> for ProvePredInCircuit<F, U, A, X, W, WVar, B>
{
    fn generate_constraints(self, cs: ConstraintSystemRef<F>) -> ArkResult<()> {
        let user_var = UserVar::new_witness(ns!(cs, "user"), || Ok(self.priv_user))?;
        let extra_data_for_membership =
            WVar::new_witness(
                ns!(cs, "extra_data"),
                || Ok(self.priv_extra_membership_data),
            )?;

        let args_var = X::new_input(ns!(cs, "args"), || Ok(&self.pub_args))?;

        let com = User::commit_in_zk(user_var.clone())?;

        (self.associated_method)(&user_var, &com, args_var)?;
        self.associated_bul
            .enforce_membership_of(user_var, extra_data_for_membership)?;

        Ok(())
    }
}
