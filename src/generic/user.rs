use crate::crypto::hash::HasherZK;
use crate::crypto::hash::Poseidon;
use crate::crypto::rr::RRTicket;
use crate::generic::bulletin::PublicUserBul;
use crate::generic::callbacks::add_ticket_to_hc;
use crate::generic::callbacks::create_cbs_from_interaction;
use crate::generic::callbacks::CallbackCom;
use crate::generic::interaction::ProvePredInCircuit;
use crate::generic::interaction::ProvePredicateCircuit;
use crate::generic::interaction::{ExecMethodCircuit, Interaction, SingularPredicate};
use crate::generic::object::{Com, ComVar, Nul, Ser, SerVar, ZKFields, ZKFieldsVar};
use ark_crypto_primitives::sponge::Absorb;
use ark_ff::PrimeField;
use ark_r1cs_std::alloc::AllocVar;
use ark_r1cs_std::alloc::AllocationMode;
use ark_relations::ns;
use ark_relations::r1cs::Namespace;
use ark_relations::r1cs::{ConstraintSynthesizer, ConstraintSystem, SynthesisError};
use ark_snark::SNARK;
use core::marker::PhantomData;
use rand::distributions::Standard;
use rand::prelude::Distribution;
use rand::Rng;
use rand::{CryptoRng, RngCore};
use std::borrow::Borrow;

/// A struct implementing the UserData trait represents the data stored within a user object in an
/// arbitrary zk-callbacks system. For example, one may have some reputation associated with a
/// user, which can be represented as below.
/// ```
/// use ark_bls12_381::{Fr as F};
/// use zk_callbacks::generic::user::UserData;
/// use ark_r1cs_std::fields::fp::FpVar;
/// use ark_r1cs_std::ToConstraintFieldGadget;
/// # use ark_r1cs_std::prelude::AllocVar;
/// # use core::borrow::Borrow;
/// # use ark_relations::r1cs::Namespace;
/// # use ark_relations::r1cs::SynthesisError;
/// # use ark_r1cs_std::prelude::AllocationMode;
/// # use ark_relations::ns;
///
///
/// #[derive(Clone, PartialEq, Eq, Debug)]
/// struct UserObject {
///     pub reputation: F
/// }
///
/// #[derive(Clone)]
/// struct UserObjectVar {
///     pub reputation: FpVar<F>
/// }
///
/// # impl AllocVar<UserObject, F> for UserObjectVar {
/// #     fn new_variable<T: Borrow<UserObject>>(
/// #        cs: impl Into<Namespace<F>>,
/// #        f: impl FnOnce() -> Result<T, SynthesisError>,
/// #        mode: AllocationMode,
/// #     ) -> Result<Self, SynthesisError> {
/// #        let ns = cs.into();
/// #        let cs = ns.cs();
/// #        let res = f();
/// #        res.and_then(|rec| {
/// #            let rec = rec.borrow();
/// #            let rep = FpVar::new_variable(ns!(cs, "rep"), || Ok(rec.reputation), mode)?;
/// #            Ok( UserObjectVar {
/// #                 reputation: rep
/// #            })
/// #        })
/// #     }
/// #    }
///
/// // (Assuming UserObjectVar already implements AllocVar)
/// impl UserData for UserObject {
///
///     type F = F;
///
///     type UserDataVar = UserObjectVar;
///
///     fn serialize_elements(&self) -> Vec<F> {
///         let mut buf: Vec<F> = Vec::new();
///         buf.extend_from_slice(&self.reputation.serialize_elements());
///         buf
///     }
///
///     fn serialize_in_zk(user_var: UserObjectVar) -> Result<Vec<FpVar<F>>, SynthesisError> {
///         let mut buf: Vec<FpVar<F>> = Vec::new();
///         buf.extend_from_slice(&user_var.reputation.to_constraint_field()?);
///         Ok(buf)
///     }
///
/// }
/// ```
pub trait UserData<F: PrimeField + Absorb>: Clone + Eq + std::fmt::Debug {
    /// The zero knowledge representation of the user data.
    type UserDataVar: AllocVar<Self, F> + Clone;

    /// A method to serialize the user data into field elements. Used in user commitments.
    fn serialize_elements(&self) -> Vec<Ser<F>>;

    /// Serialize the user data in the zero knowledge representation. Used to prove statements
    /// about user data with a commitment to the data.
    fn serialize_in_zk(user_var: Self::UserDataVar) -> Result<Vec<SerVar<F>>, SynthesisError>;
}

/// This struct represents an actual user used within a zk-callbacks system. It contains extra
/// fields which include the last interacted time, the serial number, nonce, last ingestion time,
/// and more, along with the custom application based data specified by the generic `U`.
/// ```
/// use zk_callbacks::generic::user::User;
///
/// fn method_transform<'a>(old_user: &'a User<u8>, args: ()) -> User<u8> {
///     let mut out = old_user.clone();
///     out.data = out.data + 1;
///     out
/// }
/// ```
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct User<F: PrimeField + Absorb, U: UserData<F>> {
    /// The application defined data associated with the user.
    pub data: U,
    /// Fields necessary for any zero knowledge application, including the serial number and nonce.
    /// See `ZkFields` for more information.
    pub zk_fields: ZKFields<F>,
}

/// `UserVar` is the zero knowledge representation of the user. This object is passed into
/// predicates so users can prove statements about their data. Example usage can be seen below with
/// the following predicate.
/// ```
/// # use ark_r1cs_std::alloc::AllocVar;
/// # use ark_r1cs_std::eq::EqGadget;
/// # use ark_bls12_381::{Fr as F};
/// # use core::cmp::Ordering;
/// # use ark_r1cs_std::boolean::Boolean;
/// # use ark_relations::ns;
/// # use ark_r1cs_std::fields::fp::FpVar;
/// use ark_relations::r1cs::Result as ArkResult;
/// use zk_callbacks::generic::object::TimeVar;
/// use zk_callbacks::generic::user::UserVar;
///
/// fn interaction_predicate<'a>(
///     tu_old: &'a UserVar<bool>,
///     tu_new: &'a UserVar<bool>,
///     cur_time: FpVar<F>,
/// ) -> ArkResult<()> {
///
///     // Use any arkworks statements here with tu_old, tu_new, and the arguments (here cur_time).
///
///     // Enforce that the old bool is false.
///     tu_old.data.enforce_equal(&Boolean::FALSE)?;
///
///     // Enforce the new bool == old bool.
///     tu_new.data.enforce_equal(&tu_new.data)?;
///
///     Ok(())
/// }
///
#[derive(Clone)]
pub struct UserVar<F: PrimeField + Absorb, U: UserData<F>> {
    /// The zero knowledge representation of the application data.
    pub data: U::UserDataVar,
    /// The zero knowledge representation of the required fields.
    pub zk_fields: ZKFieldsVar<F>,
}

impl<F: PrimeField + Absorb, U: UserData<F>> AllocVar<User<F, U>, F> for UserVar<F, U> {
    fn new_variable<T: Borrow<User<F, U>>>(
        cs: impl Into<Namespace<F>>,
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

// UserCommitment, Old Nullifier, Proof
/// This is a representation of the return value of an interaction. When a user interacts with a
/// service provider, the user generates a proof that
///  - the proper serial number was revealed
///  - the callback entry was added
///  - the user is an actual member of the bulletin
///  - any application specific predicate defined through an interaction
///
/// Here, the return value of an interaction consists of
///  - the commitment to the new user (public)
///  - the old revealed serial number or nullifier (public)
///  - a proof and a verifying key of the previous statements
pub struct ExecutedMethod<
    F: PrimeField + Absorb,
    S: SNARK<F>,
    A: Clone,
    T: RRTicket<F, A>,
    const N: usize,
> {
    pub new_object: Com<F>,
    pub old_nullifier: Nul<F>,
    pub cb_tik_list: [(CallbackCom<F, A, T>, T::Rand); N],
    pub cb_com_list: [Com<F>; N],
    pub proof: S::Proof,
}

pub struct ProveResult<F: PrimeField + Absorb, S: SNARK<F>> {
    pub object: Com<F>,
    pub proof: S::Proof,
}

impl<F: PrimeField + Absorb, U: UserData<F>> User<F, U>
where
    Standard: Distribution<F>,
{
    pub fn create(user: U, rng: &mut (impl CryptoRng + RngCore)) -> Self {
        Self {
            data: user,
            zk_fields: ZKFields {
                nul: rng.gen(),
                com_rand: rng.gen(),
                callback_hash: F::zero(),
                new_in_progress_callback_hash: F::zero(),
                old_in_progress_callback_hash: F::zero(),
                is_ingest_over: true,
            },
        }
    }

    pub fn interact<
        A: Clone + std::fmt::Debug,
        X: AllocVar<A, F> + Clone,
        T: RRTicket<F, A>,
        S: SNARK<F, Error = SynthesisError>,
        const N: usize,
    >(
        &mut self,
        rng: &mut (impl CryptoRng + RngCore),
        method: Interaction<F, U, A, X, N>,
        rpks: [T::Tik; N],
        pk: &S::ProvingKey,
        args: A,
    ) -> Result<ExecutedMethod<F, S, A, T, N>, SynthesisError> {
        // Steps:
        // a) update user/self [ old user ] --> method(user) [ new user ]
        // b) update user's zk fields properly (new nul, new comrand, proper cblist, etc)
        // c) generate proof of correctness for
        //      - a) the user was properly updated via the predicate
        //      - b) the zk statements (nul == old nul, proper cblist, etc)

        // (A) update the user object
        // Create the new zk_object from the method
        let mut new_user = (method.meth.0)(self, args.clone());

        // (B) update the new users zk fields properly

        new_user.zk_fields.nul = rng.gen();
        new_user.zk_fields.com_rand = rng.gen();

        let cb_tik_list = create_cbs_from_interaction(rng, method.clone(), rpks);

        let issued_callbacks: [CallbackCom<F, A, T>; N] = cb_tik_list
            .iter()
            .map(|(x, _)| x.clone())
            .collect::<Vec<CallbackCom<F, A, T>>>()
            .try_into()
            .unwrap();

        let issued_cb_coms = cb_tik_list
            .iter()
            .map(|(x, _)| x.commit())
            .collect::<Vec<_>>()
            .try_into()
            .unwrap();

        for i in 0..N {
            new_user.zk_fields.callback_hash = add_ticket_to_hc(
                new_user.zk_fields.callback_hash,
                issued_callbacks[i].clone().cb_entry,
            );
        }

        new_user.zk_fields.old_in_progress_callback_hash = new_user.zk_fields.callback_hash;

        // (C) Generate proof of correctness
        // Extract the zk fields from the objects to do bookkeeping

        let out_commit = new_user.commit();

        let out_nul = self.zk_fields.nul;

        let exec_method_circ: ExecMethodCircuit<F, U, A, X, T, N> = ExecMethodCircuit {
            priv_old_user: self.clone(),
            priv_new_user: new_user.clone(),
            priv_issued_callbacks: issued_callbacks,

            pub_new_com: out_commit,
            pub_old_nul: out_nul,
            pub_issued_callback_coms: issued_cb_coms,
            pub_args: args,

            associated_method: method,
        };

        let new_cs = ConstraintSystem::<F>::new_ref();
        exec_method_circ
            .clone()
            .generate_constraints(new_cs.clone())?;
        new_cs.is_satisfied()?;

        let proof = S::prove(pk, exec_method_circ, rng)?;

        // (D) Update current object
        *self = new_user;

        Ok(ExecutedMethod {
            new_object: out_commit,
            old_nullifier: out_nul,
            cb_tik_list,
            cb_com_list: issued_cb_coms,
            proof,
        })
    }

    pub fn prove_statement<
        A: Clone,
        X: AllocVar<A, F> + Clone,
        S: SNARK<F, Error = SynthesisError>,
    >(
        &mut self,
        rng: &mut (impl CryptoRng + RngCore),
        predicate: SingularPredicate<UserVar<F, U>, ComVar<F>, X>,
        pk: &S::ProvingKey,
        args: A,
    ) -> Result<ProveResult<F, S>, SynthesisError> {
        let ppcirc: ProvePredicateCircuit<F, U, A, X> = ProvePredicateCircuit {
            priv_user: self.clone(),
            pub_com: self.commit(),

            pub_args: args,
            associated_method: predicate,
        };

        let new_cs = ConstraintSystem::<F>::new_ref();
        ppcirc.clone().generate_constraints(new_cs.clone())?;
        new_cs.is_satisfied()?;

        let proof = S::prove(pk, ppcirc, rng)?;

        Ok(ProveResult {
            object: self.commit(),
            proof,
        })
    }

    pub fn prove_statement_and_in<
        A: Clone,
        D: Clone,
        DV: AllocVar<D, F> + Clone,
        X: AllocVar<A, F> + Clone,
        S: SNARK<F, Error = SynthesisError>,
        B: PublicUserBul<F, U, User = U> + Clone,
    >(
        &mut self,
        rng: &mut (impl CryptoRng + RngCore),
        predicate: SingularPredicate<UserVar<F, U>, ComVar<F>, X>,
        pk: &S::ProvingKey,
        bul: B,
        membership_data: D,
        args: A,
    ) -> Result<S::Proof, SynthesisError> {
        let ppcirc: ProvePredInCircuit<F, U, A, X, D, DV, B> = ProvePredInCircuit {
            priv_user: self.clone(),
            priv_extra_membership_data: membership_data,

            pub_args: args,
            associated_bul: bul,
            associated_method: predicate,
            _ph: PhantomData,
        };

        let new_cs = ConstraintSystem::<F>::new_ref();
        ppcirc.clone().generate_constraints(new_cs.clone())?;
        new_cs.is_satisfied()?;

        let proof = S::prove(pk, ppcirc, rng)?;

        Ok(proof)
    }
}

impl<F: PrimeField + Absorb, U: UserData<F>> User<F, U> {
    /// Commit to a user.
    pub fn commit(&self) -> Com<F> {
        let ser_data = self.data.serialize_elements();
        let ser_fields = self.zk_fields.serialize();
        let full_dat = [ser_data.as_slice(), ser_fields.as_slice()].concat();
        Poseidon::<2>::hash(&full_dat)
    }

    /// Commit to a user in zero knowledge.
    pub fn commit_in_zk(user_var: UserVar<F, U>) -> Result<ComVar<F>, SynthesisError> {
        let ser_data = U::serialize_in_zk(user_var.data)?;
        let ser_fields = user_var.zk_fields.serialize()?;
        let full_dat = [ser_data.as_slice(), ser_fields.as_slice()].concat();

        Poseidon::<2>::hash_in_zk(&full_dat)
    }
}
