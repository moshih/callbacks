use crate::{
    crypto::{enc::AECipherSigZK, hash::FieldHash},
    generic::{
        bulletin::PublicUserBul,
        callbacks::{add_ticket_to_hc_zk, create_defaults, CallbackCom, CallbackComVar},
        object::{Com, ComVar, Id, Nul, NulVar, Time},
        user::{User, UserData, UserVar},
    },
    util::ArrayVar,
};
use ark_crypto_primitives::sponge::Absorb;
use ark_ff::PrimeField;
use ark_r1cs_std::{alloc::AllocVar, boolean::Boolean, eq::EqGadget};
use ark_relations::{
    ns,
    r1cs::{ConstraintSynthesizer, ConstraintSystemRef, Result as ArkResult},
};
use ark_snark::SNARK;
use core::marker::PhantomData;
use rand::{
    distributions::{Distribution, Standard},
    CryptoRng, RngCore,
};

pub type Predicate<F, UserVar, PubArgsVar, PrivArgsVar> =
    fn(&UserVar, &UserVar, PubArgsVar, PrivArgsVar) -> ArkResult<Boolean<F>>;

pub type SingularPredicate<F, UserVar, PubUserCom, PubArgsVar, PrivArgsVar> =
    fn(&UserVar, &PubUserCom, PubArgsVar, PrivArgsVar) -> ArkResult<Boolean<F>>;

pub type Method<User, PubArgs, PrivArgs> = fn(&User, PubArgs, PrivArgs) -> User;

pub type NoPrivMethod<User, Args> = fn(&User, Args) -> User;
pub type NoPrivPredicate<UserVar, ArgsVar> = fn(&UserVar, ArgsVar) -> ArkResult<UserVar>;

#[derive(Clone)]
pub struct Callback<F: PrimeField + Absorb, U: UserData<F>, Args, ArgsVar: AllocVar<Args, F>> {
    pub method_id: Id<F>,
    pub expirable: bool,
    pub expiration: Time<F>,
    pub method: NoPrivMethod<User<F, U>, Args>,
    pub predicate: NoPrivPredicate<UserVar<F, U>, ArgsVar>,
}

impl<F: PrimeField + Absorb, U: UserData<F>, Args, ArgsVar: AllocVar<Args, F>> std::fmt::Debug
    for Callback<F, U, Args, ArgsVar>
{
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "Callback: {}", self.method_id)
    }
}

pub type CallbackList<F, U, A, X, const N: usize> = [Callback<F, U, A, X>; N];
pub type MethProof<F, U, PubArgs, PubArgsVar, PrivArgs, PrivArgsVar> = (
    Method<User<F, U>, PubArgs, PrivArgs>,
    Predicate<F, UserVar<F, U>, PubArgsVar, PrivArgsVar>,
);

#[derive(Clone)]
pub struct Interaction<
    F: PrimeField + Absorb,
    U: UserData<F>,
    PubArgs: Clone,
    PubArgsVar: AllocVar<PubArgs, F>,
    PrivArgs: Clone,
    PrivArgsVar: AllocVar<PrivArgs, F>,
    CBArgs: Clone,
    CBArgsVar: AllocVar<CBArgs, F>,
    const NUMCBS: usize,
> {
    pub meth: MethProof<F, U, PubArgs, PubArgsVar, PrivArgs, PrivArgsVar>,
    pub callbacks: CallbackList<F, U, CBArgs, CBArgsVar, NUMCBS>,
}

impl<
        F: PrimeField + Absorb,
        U: UserData<F> + Default,
        PubArgs: Clone + Default + std::fmt::Debug,
        PubArgsVar: AllocVar<PubArgs, F> + Clone,
        PrivArgs: Clone + Default + std::fmt::Debug,
        PrivArgsVar: AllocVar<PrivArgs, F> + Clone,
        CBArgs: Clone + Default + std::fmt::Debug,
        CBArgsVar: AllocVar<CBArgs, F> + Clone,
        const NUMCBS: usize,
    > Interaction<F, U, PubArgs, PubArgsVar, PrivArgs, PrivArgsVar, CBArgs, CBArgsVar, NUMCBS>
where
    Standard: Distribution<F>,
{
    pub fn generate_keys<
        H: FieldHash<F>,
        Snark: SNARK<F>,
        Crypto: AECipherSigZK<F, CBArgs>,
        Bul: PublicUserBul<F, U>,
    >(
        &self,
        rng: &mut (impl CryptoRng + RngCore),
        memb_data: Option<Bul::MembershipPub>,
        aux_data: Option<PubArgs>,
        is_scan: bool,
    ) -> (Snark::ProvingKey, Snark::VerifyingKey) {
        let u = User::create(U::default(), rng);

        let cbs: [CallbackCom<F, CBArgs, Crypto>; NUMCBS] = create_defaults((*self).clone());

        let x = (*self).clone();

        let out: ExecMethodCircuit<
            F,
            H,
            U,
            PubArgs,
            PubArgsVar,
            PrivArgs,
            PrivArgsVar,
            CBArgs,
            CBArgsVar,
            Crypto,
            Bul,
            NUMCBS,
        > = ExecMethodCircuit {
            priv_old_user: u.clone(),
            priv_new_user: u.clone(),
            priv_issued_callbacks: cbs.clone(),
            priv_bul_membership_witness: Bul::MembershipWitness::default(),
            priv_args: PrivArgs::default(),

            pub_new_com: u.commit::<H>(),
            pub_old_nul: u.zk_fields.nul,
            pub_issued_callback_coms: cbs.map(|x| x.commit::<H>()),
            pub_args: aux_data.unwrap_or_default(),
            associated_method: x,
            is_scan,
            bul_memb_is_const: memb_data.is_some(),
            pub_bul_membership_data: memb_data.unwrap_or_default(),
            _phantom_hash: PhantomData,
        };
        Snark::circuit_specific_setup(out, rng).unwrap()
    }
}

pub(crate) struct ExecMethodCircuit<
    F: PrimeField + Absorb,
    H: FieldHash<F>,
    U: UserData<F>,
    PubArgs: Clone,
    PubArgsVar: AllocVar<PubArgs, F>,
    PrivArgs: Clone,
    PrivArgsVar: AllocVar<PrivArgs, F>,
    CBArgs: Clone,
    CBArgsVar: AllocVar<CBArgs, F>,
    Crypto: AECipherSigZK<F, CBArgs>,
    Bul: PublicUserBul<F, U>,
    const NUMCBS: usize,
> {
    // Private Inputs
    pub priv_old_user: User<F, U>,
    pub priv_new_user: User<F, U>,
    pub priv_issued_callbacks: [CallbackCom<F, CBArgs, Crypto>; NUMCBS],
    pub priv_bul_membership_witness: Bul::MembershipWitness,
    pub priv_args: PrivArgs,

    // Public Inputs
    pub pub_new_com: Com<F>,
    pub pub_old_nul: Nul<F>,
    pub pub_issued_callback_coms: [Com<F>; NUMCBS],
    pub pub_args: PubArgs,
    pub pub_bul_membership_data: Bul::MembershipPub,
    pub bul_memb_is_const: bool,

    pub associated_method:
        Interaction<F, U, PubArgs, PubArgsVar, PrivArgs, PrivArgsVar, CBArgs, CBArgsVar, NUMCBS>,
    pub is_scan: bool,
    pub _phantom_hash: PhantomData<H>,
}

impl<
        F: PrimeField + Absorb,
        H: FieldHash<F>,
        U: UserData<F>,
        PubArgs: Clone + std::fmt::Debug,
        PubArgsVar: AllocVar<PubArgs, F>,
        PrivArgs: Clone + std::fmt::Debug,
        PrivArgsVar: AllocVar<PrivArgs, F>,
        CBArgs: Clone + std::fmt::Debug,
        CBArgsVar: AllocVar<CBArgs, F>,
        Crypto: AECipherSigZK<F, CBArgs>,
        Bul: PublicUserBul<F, U>,
        const NUMCBS: usize,
    > ConstraintSynthesizer<F>
    for ExecMethodCircuit<
        F,
        H,
        U,
        PubArgs,
        PubArgsVar,
        PrivArgs,
        PrivArgsVar,
        CBArgs,
        CBArgsVar,
        Crypto,
        Bul,
        NUMCBS,
    >
{
    fn generate_constraints(self, cs: ConstraintSystemRef<F>) -> ArkResult<()> {
        // Create private variables
        let old_user_var = UserVar::new_witness(ns!(cs, "old_user"), || Ok(self.priv_old_user))?;
        let new_user_var = UserVar::new_witness(ns!(cs, "new_user"), || Ok(self.priv_new_user))?;
        let issued_cbs: ArrayVar<CallbackComVar<F, CBArgs, Crypto>, NUMCBS> =
            ArrayVar::new_witness(ns!(cs, "issued_cbs"), || Ok(&self.priv_issued_callbacks))?;
        let priv_bul_witness =
            Bul::MembershipWitnessVar::new_witness(ns!(cs, "priv_bul_witness"), || {
                Ok(&self.priv_bul_membership_witness)
            })?;
        let priv_args_var = PrivArgsVar::new_witness(ns!(cs, "priv_args"), || Ok(&self.priv_args))?;

        // Create public variables
        let new_com_var = ComVar::new_input(ns!(cs, "new_com"), || Ok(&self.pub_new_com))?;
        let old_nul_var = NulVar::new_input(ns!(cs, "old_nul"), || Ok(&self.pub_old_nul))?;
        let pub_args_var = PubArgsVar::new_input(ns!(cs, "pub_args"), || Ok(&self.pub_args))?;

        let issued_cb_coms: ArrayVar<ComVar<F>, NUMCBS> =
            ArrayVar::new_input(ns!(cs, "issued_cb_coms"), || {
                Ok(&self.pub_issued_callback_coms)
            })?;

        let pub_bul_data = match self.bul_memb_is_const {
            true => Bul::MembershipPubVar::new_constant(cs.clone(), &self.pub_bul_membership_data)?,
            false => Bul::MembershipPubVar::new_input(ns!(cs, "pub_bul_data"), || {
                Ok(&self.pub_bul_membership_data)
            })?,
        };

        // Enforce old_user in bulletin
        Bul::enforce_membership_of(
            User::commit_in_zk::<H>(old_user_var.clone())?,
            priv_bul_witness,
            pub_bul_data,
        )?
        .enforce_equal(&Boolean::TRUE)?;

        // Enforce any method-specific predicates
        let b = (self.associated_method.meth.1)(
            &old_user_var,
            &new_user_var,
            pub_args_var,
            priv_args_var,
        )?;

        b.enforce_equal(&Boolean::TRUE)?;

        let mut old_zk_fields = old_user_var.clone().zk_fields;
        let new_zk_fields = new_user_var.clone().zk_fields;

        // Enforce revealed nullifier (previous state) == the old nullifier
        old_nul_var.enforce_equal(&old_zk_fields.nul)?;

        // Enforce we are currently not sweeping.
        if !self.is_scan {
            old_zk_fields.is_ingest_over.enforce_equal(&Boolean::TRUE)?;
        }

        if !self.is_scan {
            for i in 0..NUMCBS {
                // Enforce that the callback commitments are well-formed
                issued_cb_coms.0[i]
                    .enforce_equal(&CallbackCom::commit_in_zk::<H>(issued_cbs.0[i].clone())?)?;

                // Append callbacks to the callback list
                add_ticket_to_hc_zk::<F, H, CBArgs, Crypto>(
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
        }

        // Enforce that Com(new_user) == new_com
        let com = User::commit_in_zk::<H>(new_user_var)?;

        new_com_var.enforce_equal(&com)?;

        Ok(())
    }
}

impl<
        F: PrimeField + Absorb,
        H: FieldHash<F>,
        U: UserData<F>,
        PubArgs: Clone,
        PubArgsVar: AllocVar<PubArgs, F> + Clone,
        PrivArgs: Clone,
        PrivArgsVar: AllocVar<PrivArgs, F> + Clone,
        CBArgs: Clone,
        CBArgsVar: AllocVar<CBArgs, F> + Clone,
        Crypto: AECipherSigZK<F, CBArgs>,
        Bul: PublicUserBul<F, U>,
        const NUMCBS: usize,
    > Clone
    for ExecMethodCircuit<
        F,
        H,
        U,
        PubArgs,
        PubArgsVar,
        PrivArgs,
        PrivArgsVar,
        CBArgs,
        CBArgsVar,
        Crypto,
        Bul,
        NUMCBS,
    >
{
    fn clone(&self) -> Self {
        Self {
            priv_old_user: self.priv_old_user.clone(),
            priv_new_user: self.priv_new_user.clone(),
            priv_issued_callbacks: self.priv_issued_callbacks.clone(),
            priv_bul_membership_witness: self.priv_bul_membership_witness.clone(),
            priv_args: self.priv_args.clone(),

            pub_new_com: self.pub_new_com,
            pub_old_nul: self.pub_old_nul,
            pub_issued_callback_coms: self.pub_issued_callback_coms,
            pub_args: self.pub_args.clone(),
            pub_bul_membership_data: self.pub_bul_membership_data.clone(),
            bul_memb_is_const: self.bul_memb_is_const,

            is_scan: self.is_scan,
            associated_method: self.associated_method.clone(),
            _phantom_hash: self._phantom_hash,
        }
    }
}

pub fn generate_keys_for_statement<
    F: PrimeField + Absorb,
    H: FieldHash<F>,
    U: UserData<F> + Default,
    PubArgs: Clone + Default,
    PubArgsVar: AllocVar<PubArgs, F>,
    PrivArgs: Clone + Default,
    PrivArgsVar: AllocVar<PrivArgs, F>,
    Snark: SNARK<F>,
>(
    rng: &mut (impl CryptoRng + RngCore),
    pred: SingularPredicate<F, UserVar<F, U>, ComVar<F>, PubArgsVar, PrivArgsVar>,
    aux_data: Option<PubArgs>,
) -> (Snark::ProvingKey, Snark::VerifyingKey)
where
    Standard: Distribution<F>,
{
    let u = User::create(U::default(), rng);
    let out = ProvePredicateCircuit {
        priv_user: u.clone(),
        pub_com: u.commit::<H>(),
        pub_args: aux_data.unwrap_or_default(),
        priv_args: PrivArgs::default(),
        associated_method: pred,
    };
    Snark::circuit_specific_setup(out, rng).unwrap()
}

#[derive(Clone)]
pub(crate) struct ProvePredicateCircuit<
    F: PrimeField + Absorb,
    U: UserData<F>,
    PubArgs: Clone,
    PubArgsVar: AllocVar<PubArgs, F>,
    PrivArgs: Clone,
    PrivArgsVar: AllocVar<PrivArgs, F>,
> {
    // Private
    pub priv_user: User<F, U>,
    pub priv_args: PrivArgs,

    // Public
    pub pub_com: Com<F>,
    pub pub_args: PubArgs,

    pub associated_method: SingularPredicate<F, UserVar<F, U>, ComVar<F>, PubArgsVar, PrivArgsVar>,
}

impl<
        F: PrimeField + Absorb,
        U: UserData<F>,
        PubArgs: Clone,
        PubArgsVar: AllocVar<PubArgs, F>,
        PrivArgs: Clone,
        PrivArgsVar: AllocVar<PrivArgs, F>,
    > ConstraintSynthesizer<F>
    for ProvePredicateCircuit<F, U, PubArgs, PubArgsVar, PrivArgs, PrivArgsVar>
{
    fn generate_constraints(self, cs: ConstraintSystemRef<F>) -> ArkResult<()> {
        let user_var = UserVar::new_witness(ns!(cs, "user"), || Ok(self.priv_user))?;
        let priv_args_var = PrivArgsVar::new_witness(ns!(cs, "priv_args"), || Ok(&self.priv_args))?;

        let com_var = ComVar::new_input(ns!(cs, "com"), || Ok(&self.pub_com))?;
        let pub_args_var = PubArgsVar::new_input(ns!(cs, "pub_args"), || Ok(&self.pub_args))?;

        let b = (self.associated_method)(&user_var, &com_var, pub_args_var, priv_args_var)?;

        b.enforce_equal(&Boolean::TRUE)?;

        Ok(())
    }
}

pub fn generate_keys_for_statement_in<
    F: PrimeField + Absorb,
    H: FieldHash<F>,
    U: UserData<F> + Default,
    PubArgs: Clone + Default,
    PubArgsVar: AllocVar<PubArgs, F>,
    PrivArgs: Clone + Default,
    PrivArgsVar: AllocVar<PrivArgs, F>,
    Snark: SNARK<F>,
    Bul: PublicUserBul<F, U>,
>(
    rng: &mut (impl CryptoRng + RngCore),
    pred: SingularPredicate<F, UserVar<F, U>, ComVar<F>, PubArgsVar, PrivArgsVar>,
    memb_data: Option<Bul::MembershipPub>,

    aux_data: Option<PubArgs>,
) -> (Snark::ProvingKey, Snark::VerifyingKey)
where
    Standard: Distribution<F>,
{
    let u = User::create(U::default(), rng);
    let out: ProvePredInCircuit<F, H, U, PubArgs, PubArgsVar, PrivArgs, PrivArgsVar, Bul> =
        ProvePredInCircuit {
            priv_user: u.clone(),
            priv_extra_membership_data: Bul::MembershipWitness::default(),
            pub_args: aux_data.unwrap_or_default(),
            priv_args: PrivArgs::default(),
            bul_memb_is_const: memb_data.is_some(),
            pub_extra_membership_data: memb_data.unwrap_or_default(),
            associated_method: pred,

            _phantom_hash: PhantomData,
        };
    Snark::circuit_specific_setup(out, rng).unwrap()
}

pub(crate) struct ProvePredInCircuit<
    F: PrimeField + Absorb,
    H: FieldHash<F>,
    U: UserData<F>,
    PubArgs: Clone,
    PubArgsVar: AllocVar<PubArgs, F>,
    PrivArgs: Clone,
    PrivArgsVar: AllocVar<PrivArgs, F>,
    Bul: PublicUserBul<F, U>,
> {
    // Private
    pub priv_user: User<F, U>,
    pub priv_extra_membership_data: Bul::MembershipWitness,
    pub priv_args: PrivArgs,

    // Public
    pub pub_args: PubArgs,
    pub pub_extra_membership_data: Bul::MembershipPub,
    pub bul_memb_is_const: bool,
    pub associated_method: SingularPredicate<F, UserVar<F, U>, ComVar<F>, PubArgsVar, PrivArgsVar>,

    pub _phantom_hash: PhantomData<H>,
}

impl<
        F: PrimeField + Absorb,
        H: FieldHash<F>,
        U: UserData<F>,
        PubArgs: Clone,
        PubArgsVar: AllocVar<PubArgs, F>,
        PrivArgs: Clone,
        PrivArgsVar: AllocVar<PrivArgs, F>,
        Bul: PublicUserBul<F, U>,
    > Clone for ProvePredInCircuit<F, H, U, PubArgs, PubArgsVar, PrivArgs, PrivArgsVar, Bul>
{
    fn clone(&self) -> Self {
        Self {
            priv_user: self.priv_user.clone(),
            priv_extra_membership_data: self.priv_extra_membership_data.clone(),
            priv_args: self.priv_args.clone(),
            pub_args: self.pub_args.clone(),
            pub_extra_membership_data: self.pub_extra_membership_data.clone(),
            bul_memb_is_const: self.bul_memb_is_const,
            associated_method: self.associated_method,
            _phantom_hash: self._phantom_hash,
        }
    }
}

impl<
        F: PrimeField + Absorb,
        H: FieldHash<F>,
        U: UserData<F>,
        PubArgs: Clone,
        PubArgsVar: AllocVar<PubArgs, F>,
        PrivArgs: Clone,
        PrivArgsVar: AllocVar<PrivArgs, F>,
        Bul: PublicUserBul<F, U>,
    > ConstraintSynthesizer<F>
    for ProvePredInCircuit<F, H, U, PubArgs, PubArgsVar, PrivArgs, PrivArgsVar, Bul>
{
    fn generate_constraints(self, cs: ConstraintSystemRef<F>) -> ArkResult<()> {
        let user_var = UserVar::new_witness(ns!(cs, "user"), || Ok(self.priv_user))?;
        let extra_data_for_membership =
            Bul::MembershipWitnessVar::new_witness(ns!(cs, "extra_data"), || {
                Ok(self.priv_extra_membership_data)
            })?;

        let priv_args_var = PrivArgsVar::new_witness(ns!(cs, "priv_args"), || Ok(&self.priv_args))?;

        let pub_args_var = PubArgsVar::new_input(ns!(cs, "pub_args"), || Ok(&self.pub_args))?;

        let pub_data_for_membership = match self.bul_memb_is_const {
            true => {
                Bul::MembershipPubVar::new_constant(cs.clone(), &self.pub_extra_membership_data)?
            }
            false => Bul::MembershipPubVar::new_input(ns!(cs, "pub_bul_data"), || {
                Ok(&self.pub_extra_membership_data)
            })?,
        };

        let com = User::commit_in_zk::<H>(user_var.clone())?;

        let b = (self.associated_method)(&user_var, &com, pub_args_var, priv_args_var)?;

        b.enforce_equal(&Boolean::TRUE)?;

        Bul::enforce_membership_of(
            User::commit_in_zk::<H>(user_var)?,
            extra_data_for_membership,
            pub_data_for_membership,
        )?
        .enforce_equal(&Boolean::TRUE)?;

        Ok(())
    }
}
