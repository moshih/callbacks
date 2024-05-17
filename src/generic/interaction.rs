use crate::crypto::enc::AECipherSigZK;
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
use rand::distributions::{Distribution, Standard};
use rand::{CryptoRng, RngCore};

pub type Predicate<UserVar, ArgsVar> = fn(&UserVar, &UserVar, ArgsVar) -> ArkResult<()>;

pub type SingularPredicate<UserVar, PubUserCom, ArgsVar> =
    fn(&UserVar, &PubUserCom, ArgsVar) -> ArkResult<()>;

pub type Method<User, Args> = fn(&User, Args) -> User;

#[derive(Clone)]
pub struct Callback<F: PrimeField + Absorb, U: UserData<F>, Args, ArgsVar: AllocVar<Args, F>> {
    pub method_id: Id<F>,
    pub expirable: bool,
    pub expiration: Time<F>,
    pub method: Method<User<F, U>, Args>,
    pub predicate: Predicate<UserVar<F, U>, ArgsVar>,
}

pub type CallbackList<F, U, A, X, const N: usize> = [Callback<F, U, A, X>; N];
pub type MethProof<F, U, Args, ArgsVar> =
    (Method<User<F, U>, Args>, Predicate<UserVar<F, U>, ArgsVar>);

#[derive(Clone)]
pub struct Interaction<
    F: PrimeField + Absorb,
    U: UserData<F>,
    Args: Clone,
    ArgsVar: AllocVar<Args, F>,
    const NUMCBS: usize,
> {
    pub meth: MethProof<F, U, Args, ArgsVar>,
    pub callbacks: CallbackList<F, U, Args, ArgsVar, NUMCBS>,
}

impl<
        F: PrimeField + Absorb,
        U: UserData<F> + Default,
        Args: Clone + Default + std::fmt::Debug,
        ArgsVar: AllocVar<Args, F> + Clone,
        const NUMCBS: usize,
    > Interaction<F, U, Args, ArgsVar, NUMCBS>
where
    Standard: Distribution<F>,
{
    pub fn generate_keys<
        Snark: SNARK<F>,
        Crypto: AECipherSigZK<F, Args>,
        Bul: PublicUserBul<F, U> + Clone,
    >(
        &self,
        rng: &mut (impl CryptoRng + RngCore),
    ) -> (Snark::ProvingKey, Snark::VerifyingKey) {
        let u = User::create(U::default(), rng);

        let cbs: [CallbackCom<F, Args, Crypto>; NUMCBS] = create_defaults((*self).clone());

        let x = (*self).clone();

        let out: ExecMethodCircuit<F, U, Args, ArgsVar, Crypto, Bul, NUMCBS> = ExecMethodCircuit {
            priv_old_user: u.clone(),
            priv_new_user: u.clone(),
            priv_issued_callbacks: cbs.clone(),
            priv_bul_membership_witness: Bul::MembershipWitness::default(),

            pub_new_com: u.commit(),
            pub_old_nul: u.zk_fields.nul,
            pub_issued_callback_coms: cbs.map(|x| x.commit()),
            pub_args: Args::default(),
            associated_method: x,
            pub_bul_membership_data: Bul::MembershipPub::default(),
        };
        Snark::circuit_specific_setup(out, rng).unwrap()
    }
}

#[derive(Clone)]
pub(crate) struct ExecMethodCircuit<
    F: PrimeField + Absorb,
    U: UserData<F>,
    Args: Clone,
    ArgsVar: AllocVar<Args, F>,
    Crypto: AECipherSigZK<F, Args>,
    Bul: PublicUserBul<F, U> + Clone,
    const NUMCBS: usize,
> {
    // Private Inputs
    pub priv_old_user: User<F, U>,
    pub priv_new_user: User<F, U>,
    pub priv_issued_callbacks: [CallbackCom<F, Args, Crypto>; NUMCBS],
    pub priv_bul_membership_witness: Bul::MembershipWitness,

    // Public Inputs
    pub pub_new_com: Com<F>,
    pub pub_old_nul: Nul<F>,
    pub pub_issued_callback_coms: [Com<F>; NUMCBS],
    pub pub_args: Args,
    pub pub_bul_membership_data: Bul::MembershipPub,

    pub associated_method: Interaction<F, U, Args, ArgsVar, NUMCBS>,
}

impl<
        F: PrimeField + Absorb,
        U: UserData<F>,
        Args: Clone + std::fmt::Debug,
        ArgsVar: AllocVar<Args, F>,
        Crypto: AECipherSigZK<F, Args>,
        Bul: PublicUserBul<F, U> + Clone,
        const NUMCBS: usize,
    > ConstraintSynthesizer<F> for ExecMethodCircuit<F, U, Args, ArgsVar, Crypto, Bul, NUMCBS>
{
    fn generate_constraints(self, cs: ConstraintSystemRef<F>) -> ArkResult<()> {
        // Create private variables
        let old_user_var = UserVar::new_witness(ns!(cs, "old_user"), || Ok(self.priv_old_user))?;
        let new_user_var = UserVar::new_witness(ns!(cs, "new_user"), || Ok(self.priv_new_user))?;
        let issued_cbs: ArrayVar<CallbackComVar<F, Args, Crypto>, NUMCBS> =
            ArrayVar::new_witness(ns!(cs, "issued_cbs"), || Ok(&self.priv_issued_callbacks))?;
        let priv_bul_witness =
            Bul::MembershipWitnessVar::new_witness(ns!(cs, "priv_bul_witness"), || {
                Ok(&self.priv_bul_membership_witness)
            })?;

        // Create public variables
        let new_com_var = ComVar::new_input(ns!(cs, "new_com"), || Ok(&self.pub_new_com))?;
        let old_nul_var = NulVar::new_input(ns!(cs, "old_nul"), || Ok(&self.pub_old_nul))?;
        let args_var = ArgsVar::new_input(ns!(cs, "args"), || Ok(&self.pub_args))?;

        let issued_cb_coms: ArrayVar<ComVar<F>, NUMCBS> =
            ArrayVar::new_input(ns!(cs, "issued_cb_coms"), || {
                Ok(&self.pub_issued_callback_coms)
            })?;

        let pub_bul_data = Bul::MembershipPubVar::new_witness(ns!(cs, "pub_bul_data"), || {
            Ok(&self.pub_bul_membership_data)
        })?;

        // Enforce old_user in bulletin
        Bul::enforce_membership_of(
            User::commit_in_zk(old_user_var.clone())?,
            priv_bul_witness,
            pub_bul_data,
        )?;

        // Enforce any method-specific predicates
        (self.associated_method.meth.1)(&old_user_var, &new_user_var, args_var)?;

        let mut old_zk_fields = old_user_var.clone().zk_fields;
        let new_zk_fields = new_user_var.clone().zk_fields;

        // Enforce revealed nullifier (previous state) == the old nullifier
        old_nul_var.enforce_equal(&old_zk_fields.nul)?;

        // Enforce we are currently not sweeping.
        old_zk_fields.is_ingest_over.enforce_equal(&Boolean::TRUE)?;

        for i in 0..NUMCBS {
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

pub fn generate_keys_for_statement<
    F: PrimeField + Absorb,
    U: UserData<F> + Default,
    Args: Clone + Default,
    ArgsVar: AllocVar<Args, F>,
    Snark: SNARK<F>,
>(
    pred: SingularPredicate<UserVar<F, U>, ComVar<F>, ArgsVar>,
    rng: &mut (impl CryptoRng + RngCore),
) -> (Snark::ProvingKey, Snark::VerifyingKey)
where
    Standard: Distribution<F>,
{
    let u = User::create(U::default(), rng);
    let out = ProvePredicateCircuit {
        priv_user: u.clone(),
        pub_com: u.commit(),
        pub_args: Args::default(),
        associated_method: pred,
    };
    Snark::circuit_specific_setup(out, rng).unwrap()
}

#[derive(Clone)]
pub(crate) struct ProvePredicateCircuit<
    F: PrimeField + Absorb,
    U: UserData<F>,
    Args: Clone,
    ArgsVar: AllocVar<Args, F>,
> {
    // Private
    pub priv_user: User<F, U>,

    // Public
    pub pub_com: Com<F>,
    pub pub_args: Args,

    pub associated_method: SingularPredicate<UserVar<F, U>, ComVar<F>, ArgsVar>,
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

pub fn generate_keys_for_statement_in<
    F: PrimeField + Absorb,
    U: UserData<F> + Default,
    Args: Clone + Default,
    ArgsVar: AllocVar<Args, F>,
    Snark: SNARK<F>,
    Bul: PublicUserBul<F, U>,
>(
    pred: SingularPredicate<UserVar<F, U>, ComVar<F>, ArgsVar>,
    rng: &mut (impl CryptoRng + RngCore),
) -> (Snark::ProvingKey, Snark::VerifyingKey)
where
    Standard: Distribution<F>,
{
    let u = User::create(U::default(), rng);
    let out: ProvePredInCircuit<F, U, Args, ArgsVar, Bul> = ProvePredInCircuit {
        priv_user: u.clone(),
        priv_extra_membership_data: Bul::MembershipWitness::default(),
        pub_args: Args::default(),
        pub_extra_membership_data: Bul::MembershipPub::default(),
        associated_method: pred,
    };
    Snark::circuit_specific_setup(out, rng).unwrap()
}

#[derive(Clone)]
pub(crate) struct ProvePredInCircuit<
    F: PrimeField + Absorb,
    U: UserData<F>,
    Args: Clone,
    ArgsVar: AllocVar<Args, F>,
    Bul: PublicUserBul<F, U>,
> {
    // Private
    pub priv_user: User<F, U>,
    pub priv_extra_membership_data: Bul::MembershipWitness,

    // Public
    pub pub_args: Args,
    pub pub_extra_membership_data: Bul::MembershipPub,
    pub associated_method: SingularPredicate<UserVar<F, U>, ComVar<F>, ArgsVar>,
}

impl<
        F: PrimeField + Absorb,
        U: UserData<F>,
        Args: Clone,
        ArgsVar: AllocVar<Args, F>,
        Bul: PublicUserBul<F, U>,
    > ConstraintSynthesizer<F> for ProvePredInCircuit<F, U, Args, ArgsVar, Bul>
{
    fn generate_constraints(self, cs: ConstraintSystemRef<F>) -> ArkResult<()> {
        let user_var = UserVar::new_witness(ns!(cs, "user"), || Ok(self.priv_user))?;
        let extra_data_for_membership =
            Bul::MembershipWitnessVar::new_witness(ns!(cs, "extra_data"), || {
                Ok(self.priv_extra_membership_data)
            })?;

        let args_var = ArgsVar::new_input(ns!(cs, "args"), || Ok(&self.pub_args))?;

        let pub_data_for_membership =
            Bul::MembershipPubVar::new_input(ns!(cs, "pub_data"), || {
                Ok(self.pub_extra_membership_data)
            })?;

        let com = User::commit_in_zk(user_var.clone())?;

        (self.associated_method)(&user_var, &com, args_var)?;
        Bul::enforce_membership_of(
            User::commit_in_zk(user_var)?,
            extra_data_for_membership,
            pub_data_for_membership,
        )?;

        Ok(())
    }
}
