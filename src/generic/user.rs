use crate::{
    crypto::{enc::AECipherSigZK, hash::FieldHash},
    generic::{
        bulletin::PublicUserBul,
        callbacks::{add_ticket_to_hc, create_cbs_from_interaction, CallbackCom},
        interaction::{
            ExecMethodCircuit, Interaction, ProvePredInCircuit, ProvePredicateCircuit,
            SingularPredicate,
        },
        object::{Com, ComVar, Nul, Ser, SerVar, ZKFields, ZKFieldsVar},
    },
};
use ark_crypto_primitives::sponge::Absorb;
use ark_ff::PrimeField;
use ark_r1cs_std::{
    alloc::{AllocVar, AllocationMode},
    eq::EqGadget,
    prelude::CondSelectGadget,
};
use ark_relations::{
    ns,
    r1cs::{ConstraintSynthesizer, ConstraintSystem, Namespace, SynthesisError},
};
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use ark_snark::SNARK;
use rand::{distributions::Standard, prelude::Distribution, CryptoRng, Rng, RngCore};
use std::borrow::Borrow;

use crate::generic::{
    bulletin::PublicCallbackBul,
    scan::{get_scan_interaction, PrivScanArgs, PrivScanArgsVar, PubScanArgs, PubScanArgsVar},
};

/// A trait that captures data which can be placed inside a user.
///
/// For any system, one needs to have some state associated with the user. Any struct implementing
/// this trait can be used as user state within an anonymous reputation system. The standard
/// example consists of a user with a single bit indicating if such a user is banned.
///
/// # Example (Banned Bit)
///
/// To capture the single bit, we can use a `bool`. Therefore, the struct will look something like
/// this:
///
/// ```rust
/// struct Data {
///     pub ban_status: bool,
/// }
/// ```
/// Now, we may implement AllocVar for this object, converting the `ban_status` to a `Boolean`
/// representation in-circuit. Totally, it will look something like this:
///
/// ```rust
/// # use ark_ff::ToConstraintField;
/// # use ark_ff::PrimeField;
/// # use ark_r1cs_std::prelude::UInt8;
/// # use rand::distributions::Standard;
/// # use rand::prelude::Distribution;
/// # use zk_callbacks::crypto::enc::CPACipher;
/// # use ark_r1cs_std::prelude::AllocationMode;
/// # use ark_relations::r1cs::SynthesisError;
/// # use std::borrow::Borrow;
/// # use ark_relations::r1cs::Namespace;
/// # use ark_r1cs_std::prelude::AllocVar;
/// # use ark_r1cs_std::prelude::Boolean;
/// # use ark_relations::ns;
/// # use ark_r1cs_std::fields::fp::FpVar;
/// # use ark_r1cs_std::convert::ToConstraintFieldGadget;
/// # use ark_r1cs_std::convert::ToBitsGadget;
/// # use rand::{Rng, RngCore, CryptoRng};
/// #[derive(Clone, PartialEq, Eq, Debug)]
/// struct Data {
///     pub ban_status: bool,
/// }
///
/// #[derive(Clone)]
/// struct DataVar<F: PrimeField> {
///     pub ban_status: Boolean<F>
/// }
///
/// impl<F: PrimeField> AllocVar<Data, F> for DataVar<F> {
///   fn new_variable<T: Borrow<Data>>(
///       cs: impl Into<Namespace<F>>,
///       f: impl FnOnce() -> Result<T, SynthesisError>,
///       mode: AllocationMode
/// ) -> Result<Self, SynthesisError> {
///       let ns = cs.into();
///       let cs = ns.cs();
///       let res = f();
///       res.and_then(|rec| {
///           let rec = rec.borrow();
///           let t = Boolean::new_variable(ns!(cs, "ban_status"), || Ok(rec.ban_status), mode)?;
///           Ok(Self { ban_status: t } )
///       })
/// }
/// }
/// ```
///
/// Finally, we can implement `UserData` by serializing the elements using `to_constraint_field`.
///
/// ```rust
/// # use ark_ff::ToConstraintField;
/// # use ark_ff::PrimeField;
/// # use ark_r1cs_std::prelude::UInt8;
/// # use rand::distributions::Standard;
/// # use rand::prelude::Distribution;
/// # use zk_callbacks::crypto::enc::CPACipher;
/// # use ark_r1cs_std::prelude::AllocationMode;
/// # use ark_relations::r1cs::SynthesisError;
/// # use std::borrow::Borrow;
/// # use ark_relations::r1cs::Namespace;
/// # use ark_r1cs_std::prelude::AllocVar;
/// # use ark_r1cs_std::prelude::Boolean;
/// # use ark_relations::ns;
/// # use ark_r1cs_std::fields::fp::FpVar;
/// # use ark_r1cs_std::convert::ToConstraintFieldGadget;
/// # use ark_r1cs_std::convert::ToBitsGadget;
/// # use zk_callbacks::generic::object::{Ser, SerVar};
/// # use ark_crypto_primitives::sponge::Absorb;
/// # use zk_callbacks::generic::user::UserData;
/// # use rand::{Rng, RngCore, CryptoRng};
/// # #[derive(Clone, PartialEq, Eq, Debug)]
/// # struct Data {
/// #     pub ban_status: bool,
/// # }
/// # #[derive(Clone)]
/// # struct DataVar<F: PrimeField> {
/// #     pub ban_status: Boolean<F>
/// # }
/// # impl<F: PrimeField> AllocVar<Data, F> for DataVar<F> {
/// #   fn new_variable<T: Borrow<Data>>(
/// #       cs: impl Into<Namespace<F>>,
/// #       f: impl FnOnce() -> Result<T, SynthesisError>,
/// #       mode: AllocationMode
/// # ) -> Result<Self, SynthesisError> {
/// #       let ns = cs.into();
/// #       let cs = ns.cs();
/// #       let res = f();
/// #       res.and_then(|rec| {
/// #           let rec = rec.borrow();
/// #           let t = Boolean::new_variable(ns!(cs, "ban_status"), || Ok(rec.ban_status), mode)?;
/// #           Ok(Self { ban_status: t } )
/// #       })
/// # }
/// # }
/// impl<F: PrimeField + Absorb> UserData<F> for Data {
///     type UserDataVar = DataVar<F>;
///
///     fn serialize_elements(&self) -> Vec<Ser<F>> {
///         let mut buf = Vec::new();
///         buf.extend_from_slice(&self.ban_status.to_field_elements().unwrap());
///         buf
///     }
///
///     fn serialize_in_zk(user_var: DataVar<F>) -> Result<Vec<SerVar<F>>, SynthesisError> {
///         let mut buf = Vec::new();
///         buf.extend_from_slice(&user_var.ban_status.to_constraint_field()?);
///         Ok(buf)
///     }
/// }
/// ```
/// With this, we may now define a user object. To do this, we use the [`User`] struct, see the
/// documentation for more details on how to use the user.
/// ```rust
/// # use ark_ff::ToConstraintField;
/// # use ark_ff::PrimeField;
/// # use ark_r1cs_std::prelude::UInt8;
/// # use rand::distributions::Standard;
/// # use rand::prelude::Distribution;
/// # use zk_callbacks::crypto::enc::CPACipher;
/// # use ark_r1cs_std::prelude::AllocationMode;
/// # use ark_relations::r1cs::SynthesisError;
/// # use std::borrow::Borrow;
/// # use ark_relations::r1cs::Namespace;
/// # use ark_r1cs_std::prelude::AllocVar;
/// # use ark_r1cs_std::prelude::Boolean;
/// # use ark_relations::ns;
/// # use ark_r1cs_std::fields::fp::FpVar;
/// # use ark_r1cs_std::convert::ToConstraintFieldGadget;
/// # use ark_r1cs_std::convert::ToBitsGadget;
/// # use zk_callbacks::generic::object::{Ser, SerVar};
/// # use ark_crypto_primitives::sponge::Absorb;
/// # use zk_callbacks::generic::user::UserData;
/// # use rand::{Rng, RngCore, CryptoRng};
/// # use rand::thread_rng;
/// # use zk_callbacks::generic::user::User;
/// # #[derive(Clone, PartialEq, Eq, Debug)]
/// # struct Data {
/// #     pub ban_status: bool,
/// # }
/// # #[derive(Clone)]
/// # struct DataVar<F: PrimeField> {
/// #     pub ban_status: Boolean<F>
/// # }
/// # impl<F: PrimeField> AllocVar<Data, F> for DataVar<F> {
/// #   fn new_variable<T: Borrow<Data>>(
/// #       cs: impl Into<Namespace<F>>,
/// #       f: impl FnOnce() -> Result<T, SynthesisError>,
/// #       mode: AllocationMode
/// # ) -> Result<Self, SynthesisError> {
/// #       let ns = cs.into();
/// #       let cs = ns.cs();
/// #       let res = f();
/// #       res.and_then(|rec| {
/// #           let rec = rec.borrow();
/// #           let t = Boolean::new_variable(ns!(cs, "ban_status"), || Ok(rec.ban_status), mode)?;
/// #           Ok(Self { ban_status: t } )
/// #       })
/// # }
/// # }
/// # impl<F: PrimeField + Absorb> UserData<F> for Data {
/// #     type UserDataVar = DataVar<F>;
/// #     fn serialize_elements(&self) -> Vec<Ser<F>> {
/// #         let mut buf = Vec::new();
/// #         buf.extend_from_slice(&self.ban_status.to_field_elements().unwrap());
/// #         buf
/// #     }
/// #     fn serialize_in_zk(user_var: DataVar<F>) -> Result<Vec<SerVar<F>>, SynthesisError> {
/// #         let mut buf = Vec::new();
/// #         buf.extend_from_slice(&user_var.ban_status.to_constraint_field()?);
/// #         Ok(buf)
/// #     }
/// # }
/// # use ark_bn254::{Fr as F};
/// # fn main() {
///     let mut rng = thread_rng();
///     let test_data = Data { ban_status: false };
///     let u: User<F, Data> = User::create(test_data, &mut rng);
/// # }
/// ```
///
/// # Example (Reputation)
///
/// For a more complex example, we may take an example where a user has more complex state; for
/// example, a reputation or karma score. Then a user struct will look like the following:
///
/// ```rust
/// # use ark_bn254::Fr;
/// struct Data {
///     karma: Fr,
///     is_banned: bool,
/// }
/// ```
/// where `F` is a field element from a choice field (bls12 or bn254 scalar fields, for example).
///
/// To make the implementation process easier, we may simply implement `UserData` using the
/// [`zk_object`] macro. This macro allows us to auto implement `UserData` along with defining an
/// in-circuit struct representation for the Data. This way, we can easily do the following:
///
/// ```rust
/// use zk_callbacks::zk_object;
/// use ark_bn254::Fr;
///
/// #[zk_object(Fr)]
/// #[derive(Default)]
/// struct Data {
///     karma: Fr,
///     is_banned: bool,
/// }
/// ```
///
/// As both `F` and `bool` implement UserData already, we may use the macro to implement
/// `UserData`. We may then use this in a similar manner to the previous example in a `User`
/// struct.
pub trait UserData<F: PrimeField + Absorb>: Clone + Eq + std::fmt::Debug {
    /// The in circuit representation of the user data.
    type UserDataVar: AllocVar<Self, F> + Clone;

    /// How to serialize the data of the user into a canonical representation of field elements.
    /// This is necessary so users can be committed to.
    fn serialize_elements(&self) -> Vec<Ser<F>>;

    /// Convert the data of the user into a serialized vector of field elements in-circuit.
    fn serialize_in_zk(user_var: Self::UserDataVar) -> Result<Vec<SerVar<F>>, SynthesisError>;
}

/// Struct representing the whole user object.
///
/// This struct consists of user data (which implements [`UserData`]), along with other data. The
/// user object consists of extra fields contained in `zk_fields`, along with a list of outstanding
/// callbacks (stored in `callbacks`), which are also encoded within the `zk_fields`.
///
/// Note that user implements `AllocVar`, which converts data and the zk_fields into an allocated
/// in-circuit representation, so proofs can be made for the user.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct User<F: PrimeField + Absorb, U: UserData<F>> {
    /// Any data stored within the user. Can be a banned status, reputation, or more.
    pub data: U,

    /// Consists of extra fields used within proofs: commitment randomness, nullifiers, and more.
    /// For all intents and purposes (unless dealing with advanced usage), this may be ignored.
    pub zk_fields: ZKFields<F>,

    /// A list of callbacks, serialized and stored. This may also be ignored (the [`User::get_cb`]
    /// function should be used instead.
    pub callbacks: Vec<Vec<u8>>,
}

impl<F: PrimeField + Absorb, U: UserData<F>> std::fmt::Octal for User<F, U> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "[U: {} callbacks, ingesting: {}]",
            self.callbacks.len(),
            !self.zk_fields.is_ingest_over
        )
    }
}

/// In-circuit representation of the user object.
///
/// Consists of both user data in circuit, along with the extra zero knowledge fields.
#[derive(Clone)]
pub struct UserVar<F: PrimeField + Absorb, U: UserData<F>> {
    /// User data, in-circuit.
    pub data: U::UserDataVar,
    /// Zero knowledge fields (nullifier, nonce, etc.) in circuit.
    pub zk_fields: ZKFieldsVar<F>,
}

impl<F: PrimeField + Absorb, U: UserData<F>> CondSelectGadget<F> for UserVar<F, U>
where
    U::UserDataVar: CondSelectGadget<F>,
{
    fn conditionally_select(
        cond: &ark_r1cs_std::prelude::Boolean<F>,
        true_value: &Self,
        false_value: &Self,
    ) -> Result<Self, SynthesisError> {
        let d = U::UserDataVar::conditionally_select(cond, &true_value.data, &false_value.data)?;
        let zkf = <ZKFieldsVar<F>>::conditionally_select(
            cond,
            &true_value.zk_fields,
            &false_value.zk_fields,
        )?;
        Ok(Self {
            data: d,
            zk_fields: zkf,
        })
    }
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

/// Output data after a method has been executed on a user.
///
/// When a user executes a method, it must prove correctness of execution. To do so, the user
/// publicly reveals the old nullifier and constructs a new object with a random nullifier.
/// Additionally, the user may have to append some callbacks.
///
/// On execution, the user will output data, such that the user may prove that
///* A prior user object existed in the storage structure
///* Some statement is enforced across the old and new objects: p(U, U') = 1
///
/// To verify the proof, some additional data is necessary, which is provided by this struct.
/// Additionally, on method execution the user also maintains a list of callback tickets, this list
/// may be handed to the service provider.
#[derive(Clone, Debug, CanonicalSerialize, CanonicalDeserialize)]
pub struct ExecutedMethod<
    F: PrimeField + Absorb,
    Snark: SNARK<F>,
    CBArgs: Clone,
    Crypto: AECipherSigZK<F, CBArgs>,
    const NUMCBS: usize,
> {
    /// A *commitment* to new object after the method update: Com(U') where U' = f(U)
    pub new_object: Com<F>,
    /// The nullifier of the old user, to ensure past users aren't being reused.
    pub old_nullifier: Nul<F>,
    /// A list of callback tickets added to the user from the interaction.
    pub cb_tik_list: [(CallbackCom<F, CBArgs, Crypto>, Crypto::Rand); NUMCBS],
    /// A list of commitments to the tickets added to the user.
    pub cb_com_list: [Com<F>; NUMCBS],
    /// Proof of valid user object update.
    pub proof: Snark::Proof,
}

/// Output data after a proof is made on the user object.
///
/// If one wants to make a standard proof for a user object, this struct captures the data
/// necessary to make such a statement. Note that this is **not necessarily anonymous**, as it
/// reveals the current object *commitment*. This struct is the output which is obtained after an
/// arbitrary proof *about* the user is created.
///
/// If you want to make a proof about the user object while remaining anonymous within some set,
/// you must prove membership of your object along with the statement; this can be done with
/// [`User::prove_statement_and_in`]. This struct is meant for just making statements, and is used
/// with [`User::prove_statement`].
#[derive(Clone, Debug, CanonicalSerialize, CanonicalDeserialize)]
pub struct ProveResult<F: PrimeField + Absorb, S: SNARK<F>> {
    /// The current user commitment.
    pub object: Com<F>,
    /// The proof of some statement on the user.
    pub proof: S::Proof,
}

impl<F: PrimeField + Absorb, U: UserData<F>> User<F, U>
where
    Standard: Distribution<F>,
{
    /// Create a new user from some user data with zero callbacks.
    ///
    /// # Example
    /// ```rust
    /// # use zk_callbacks::zk_object;
    /// # use zk_callbacks::generic::user::User;
    /// # use rand::thread_rng;
    /// # use ark_bn254::Fr;
    /// #[zk_object(Fr)]
    /// #[derive(Default)]
    /// struct Data {
    ///     karma: Fr,
    ///     is_banned: bool,
    /// }
    ///
    /// fn main () {
    ///     let mut rng = thread_rng();
    ///     let mut u = User::create(Data { karma: Fr::from(0), is_banned: false }, &mut rng);
    /// }
    /// ```
    ///
    /// Here, `u` is a single user object, with all the data associated to it.
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
            callbacks: vec![],
        }
    }

    /// Gets the i-th callback stored within the user. If this callback does not exist, this
    /// function will panic.
    ///
    /// # Example
    /// ```rust
    /// # use zk_callbacks::zk_object;
    /// # use zk_callbacks::generic::user::User;
    /// # use rand::thread_rng;
    /// # use ark_bn254::{Bn254 as E, Fr};
    /// # use ark_r1cs_std::eq::EqGadget;
    /// # use zk_callbacks::generic::interaction::Interaction;
    /// # use zk_callbacks::generic::interaction::Callback;
    /// # use zk_callbacks::generic::object::Id;
    /// # use zk_callbacks::generic::object::Time;
    /// # use ark_relations::r1cs::SynthesisError;
    /// # use zk_callbacks::generic::user::UserVar;
    /// # use ark_r1cs_std::fields::fp::FpVar;
    /// # use ark_groth16::Groth16;
    /// # use ark_r1cs_std::prelude::Boolean;
    /// # use zk_callbacks::impls::hash::Poseidon;
    /// # use zk_callbacks::impls::dummy::DummyStore;
    /// # use zk_callbacks::impls::centralized::crypto::{PlainTikCrypto};
    /// # type Groth = Groth16<E>;
    ///#  #[zk_object(Fr)]
    ///#  #[derive(Default)]
    ///#  struct Data {
    ///#      karma: Fr,
    ///#      is_banned: bool,
    ///#  }
    ///#
    ///#  fn method<'a>(old_user: &'a User<Fr, Data>, _pub: (), _priv: ()) -> User<Fr, Data> {
    ///#      old_user.clone()
    ///#  }
    ///#
    ///#  fn predicate<'a>(old_user: &'a UserVar<Fr, Data>, new_user: &'a UserVar<Fr, Data>, _pub: (), _priv: ()) -> Result<Boolean<Fr>, SynthesisError> {
    ///#      let o1 = old_user.data.karma.is_eq(&new_user.data.karma)?;
    ///#      let o2 = old_user.data.is_banned.is_eq(&new_user.data.is_banned)?;
    ///#      Ok(o1 & o2)
    ///#  }
    ///#
    ///#  fn callback<'a>(old_user: &'a User<Fr, Data>, args: Fr) -> User<Fr, Data> {
    ///#      let mut u = old_user.clone();
    ///#      u.data.karma = args;
    ///#      u
    ///#  }
    ///#
    ///#  fn enforce_callback<'a>(old_user: &'a UserVar<Fr, Data>, args: FpVar<Fr>) -> Result<UserVar<Fr, Data>, SynthesisError> {
    ///#      let mut u = old_user.clone();
    ///#      u.data.karma = args;
    ///#      Ok(u)
    ///#  }
    ///#
    ///#
    /// fn main () {
    ///     let cb = Callback {
    ///         method_id: Id::from(0),
    ///         expirable: false,
    ///         expiration: Time::from(10),
    ///         method: callback,
    ///         predicate: enforce_callback
    ///     };
    ///
    ///     let int = Interaction {
    ///         meth: (method, predicate),
    ///         callbacks: [cb.clone()],
    ///     };
    ///
    ///     let mut rng = thread_rng();
    ///
    ///     let (pk, vk) = int.generate_keys::<Poseidon<2>, Groth, PlainTikCrypto<Fr>, DummyStore>(&mut rng, Some(()), None, false);
    ///
    ///     let mut u = User::create(Data { karma: Fr::from(0), is_banned: false }, &mut rng);
    ///
    ///     // Execute the method, and append a single callback to the user callback list. This
    ///     // callback is a ticket associated to `cb`.
    ///     let _ = u.exec_method_create_cb::<Poseidon<2>, _, _, _, _, _, _, PlainTikCrypto<Fr>, Groth, DummyStore, 1>(&mut rng, int.clone(), [PlainTikCrypto(Fr::from(0))], ((), ()), true, &pk, (), (), false).unwrap();
    ///
    ///     // Get the first callback stored in the user.
    ///     let first_callback = u.get_cb
    ///         ::<Fr, PlainTikCrypto<Fr>>
    ///     (0);
    ///
    ///     // Ensure the callback is the correct callback method.
    ///     assert_eq!(first_callback.cb_entry.cb_method_id, cb.method_id);
    /// }
    /// ```
    pub fn get_cb<Args: Clone, Crypto: AECipherSigZK<F, Args>>(
        &self,
        index: usize,
    ) -> CallbackCom<F, Args, Crypto> {
        CallbackCom::deserialize_compressed(&*self.callbacks[index]).unwrap()
    }

    pub fn interact<
        H: FieldHash<F>,
        PubArgs: Clone + std::fmt::Debug,
        PubArgsVar: AllocVar<PubArgs, F> + Clone,
        PrivArgs: Clone + std::fmt::Debug,
        PrivArgsVar: AllocVar<PrivArgs, F> + Clone,
        CBArgs: Clone + std::fmt::Debug,
        CBArgsVar: AllocVar<CBArgs, F> + Clone,
        Crypto: AECipherSigZK<F, CBArgs>,
        Snark: SNARK<F, Error = SynthesisError>,
        Bul: PublicUserBul<F, U>,
        const NUMCBS: usize,
    >(
        &mut self,
        rng: &mut (impl CryptoRng + RngCore),
        method: Interaction<
            F,
            U,
            PubArgs,
            PubArgsVar,
            PrivArgs,
            PrivArgsVar,
            CBArgs,
            CBArgsVar,
            NUMCBS,
        >,
        rpks: [Crypto::SigPK; NUMCBS],
        bul_data: (Bul::MembershipWitness, Bul::MembershipPub),
        is_memb_data_const: bool,
        pk: &Snark::ProvingKey,
        pub_args: PubArgs,
        priv_args: PrivArgs,
        is_scan: bool,
        print_constraints: bool,
    ) -> Result<ExecutedMethod<F, Snark, CBArgs, Crypto, NUMCBS>, SynthesisError> {
        // Steps:
        // a) update user/self [ old user ] --> method(user) [ new user ]
        // b) update user's zk fields properly (new nul, new comrand, proper cblist, etc)
        // c) generate proof of correctness for
        //      - a) the user was properly updated via the predicate
        //      - b) the zk statements (nul == old nul, proper cblist, etc)

        // (A) update the user object
        // Create the new zk_object from the method
        let mut new_user = (method.meth.0)(self, pub_args.clone(), priv_args.clone());

        // (B) update the new users zk fields properly

        new_user.zk_fields.nul = rng.gen();
        new_user.zk_fields.com_rand = rng.gen();

        let cb_tik_list: [(CallbackCom<F, CBArgs, Crypto>, Crypto::Rand); NUMCBS] =
            create_cbs_from_interaction(rng, method.clone(), rpks);

        let issued_callbacks: [CallbackCom<F, CBArgs, Crypto>; NUMCBS] = cb_tik_list
            .iter()
            .map(|(x, _)| x.clone())
            .collect::<Vec<CallbackCom<F, CBArgs, Crypto>>>()
            .try_into()
            .unwrap();

        let issued_cb_coms = cb_tik_list
            .iter()
            .map(|(x, _)| x.commit::<H>())
            .collect::<Vec<_>>()
            .try_into()
            .unwrap();

        for item in issued_callbacks.iter().take(NUMCBS) {
            let mut cb = Vec::new();
            item.clone().serialize_compressed(&mut cb).unwrap();
            new_user.callbacks.push(cb);

            new_user.zk_fields.callback_hash = add_ticket_to_hc::<F, H, CBArgs, Crypto>(
                new_user.zk_fields.callback_hash,
                item.clone().cb_entry,
            );
        }

        if !is_scan {
            new_user.zk_fields.old_in_progress_callback_hash = new_user.zk_fields.callback_hash;
        }

        // (C) Generate proof of correctness
        // Extract the zk fields from the objects to do bookkeeping

        let out_commit = new_user.commit::<H>();

        let out_nul = self.zk_fields.nul;

        let exec_method_circ: ExecMethodCircuit<
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
            priv_old_user: self.clone(),
            priv_new_user: new_user.clone(),
            priv_issued_callbacks: issued_callbacks,
            priv_bul_membership_witness: bul_data.0,
            priv_args,

            pub_new_com: out_commit,
            pub_old_nul: out_nul,
            pub_issued_callback_coms: issued_cb_coms,
            pub_args,
            pub_bul_membership_data: bul_data.1,
            bul_memb_is_const: is_memb_data_const,

            associated_method: method,
            is_scan,
            _phantom_hash: core::marker::PhantomData,
        };

        let new_cs = ConstraintSystem::<F>::new_ref();
        exec_method_circ
            .clone()
            .generate_constraints(new_cs.clone())?;
        new_cs.is_satisfied()?;

        if print_constraints {
            println!("Constraints for interaction: {}", new_cs.num_constraints());
        }

        let proof = Snark::prove(pk, exec_method_circ, rng)?;

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

    pub fn exec_method_create_cb<
        H: FieldHash<F>,
        PubArgs: Clone + std::fmt::Debug,
        PubArgsVar: AllocVar<PubArgs, F> + Clone,
        PrivArgs: Clone + std::fmt::Debug,
        PrivArgsVar: AllocVar<PrivArgs, F> + Clone,
        CBArgs: Clone + std::fmt::Debug,
        CBArgsVar: AllocVar<CBArgs, F> + Clone,
        Crypto: AECipherSigZK<F, CBArgs>,
        Snark: SNARK<F, Error = SynthesisError>,
        Bul: PublicUserBul<F, U>,
        const NUMCBS: usize,
    >(
        &mut self,
        rng: &mut (impl CryptoRng + RngCore),
        method: Interaction<
            F,
            U,
            PubArgs,
            PubArgsVar,
            PrivArgs,
            PrivArgsVar,
            CBArgs,
            CBArgsVar,
            NUMCBS,
        >,
        rpks: [Crypto::SigPK; NUMCBS],
        bul_data: (Bul::MembershipWitness, Bul::MembershipPub),
        is_memb_data_const: bool,
        pk: &Snark::ProvingKey,
        pub_args: PubArgs,
        priv_args: PrivArgs,
        print_constraints: bool,
    ) -> Result<ExecutedMethod<F, Snark, CBArgs, Crypto, NUMCBS>, SynthesisError> {
        self.interact::<H, PubArgs, PubArgsVar, PrivArgs, PrivArgsVar, CBArgs, CBArgsVar, Crypto, Snark, Bul, NUMCBS>(
            rng,
            method,
            rpks,
            bul_data,
            is_memb_data_const,
            pk,
            pub_args,
            priv_args,
            false,
            print_constraints,
        )
    }

    pub fn scan_callbacks<
        H: FieldHash<F>,
        CBArgs: Clone + std::fmt::Debug,
        CBArgsVar: AllocVar<CBArgs, F> + Clone,
        Crypto: AECipherSigZK<F, CBArgs, AV = CBArgsVar>,
        CBul: PublicCallbackBul<F, CBArgs, Crypto> + Clone,
        Snark: SNARK<F, Error = SynthesisError>,
        Bul: PublicUserBul<F, U>,
        const NUMSCANS: usize,
    >(
        &mut self,
        rng: &mut (impl CryptoRng + RngCore),
        bul_data: (Bul::MembershipWitness, Bul::MembershipPub),
        is_memb_data_const: bool,
        pk: &Snark::ProvingKey,
        pub_args: PubScanArgs<F, U, CBArgs, CBArgsVar, Crypto, CBul, NUMSCANS>,
        priv_args: PrivScanArgs<F, CBArgs, Crypto, CBul, NUMSCANS>,
        print_constraints: bool,
    ) -> Result<ExecutedMethod<F, Snark, CBArgs, Crypto, 0>, SynthesisError>
    where
        U::UserDataVar: CondSelectGadget<F> + EqGadget<F>,
    {
        self.interact::<H, PubScanArgs<F, U, CBArgs, CBArgsVar, Crypto, CBul, NUMSCANS>, PubScanArgsVar<F, U, CBArgs, CBArgsVar, Crypto, CBul, NUMSCANS>, PrivScanArgs<F, CBArgs, Crypto, CBul, NUMSCANS>, PrivScanArgsVar<F, CBArgs, Crypto, CBul, NUMSCANS>, CBArgs, CBArgsVar, Crypto, Snark, Bul, 0>(
            rng,
            get_scan_interaction::<F, U, CBArgs, CBArgsVar, Crypto, CBul, H, NUMSCANS>(),
            [],
            bul_data,
            is_memb_data_const,
            pk,
            pub_args,
            priv_args,
            true,
            print_constraints,
        )
    }

    pub fn prove_statement<
        H: FieldHash<F>,
        PubArgs: Clone,
        PubArgsVar: AllocVar<PubArgs, F> + Clone,
        PrivArgs: Clone,
        PrivArgsVar: AllocVar<PrivArgs, F> + Clone,
        Snark: SNARK<F, Error = SynthesisError>,
    >(
        &self,
        rng: &mut (impl CryptoRng + RngCore),
        predicate: SingularPredicate<F, UserVar<F, U>, ComVar<F>, PubArgsVar, PrivArgsVar>,
        pk: &Snark::ProvingKey,
        pub_args: PubArgs,
        priv_args: PrivArgs,
        print_constraints: bool,
    ) -> Result<ProveResult<F, Snark>, SynthesisError> {
        let ppcirc: ProvePredicateCircuit<F, U, PubArgs, PubArgsVar, PrivArgs, PrivArgsVar> =
            ProvePredicateCircuit {
                priv_user: self.clone(),
                pub_com: self.commit::<H>(),
                priv_args,

                pub_args,
                associated_method: predicate,
            };

        let new_cs = ConstraintSystem::<F>::new_ref();
        ppcirc.clone().generate_constraints(new_cs.clone())?;
        new_cs.is_satisfied()?;

        if print_constraints {
            println!(
                "Constraints for proving statement: {}",
                new_cs.num_constraints()
            );
        }

        let proof = Snark::prove(pk, ppcirc, rng)?;

        Ok(ProveResult {
            object: self.commit::<H>(),
            proof,
        })
    }

    pub fn prove_statement_and_in<
        H: FieldHash<F>,
        PubArgs: Clone,
        PubArgsVar: AllocVar<PubArgs, F> + Clone,
        PrivArgs: Clone,
        PrivArgsVar: AllocVar<PrivArgs, F> + Clone,
        Snark: SNARK<F, Error = SynthesisError>,
        Bul: PublicUserBul<F, U>,
    >(
        &self,
        rng: &mut (impl CryptoRng + RngCore),
        predicate: SingularPredicate<F, UserVar<F, U>, ComVar<F>, PubArgsVar, PrivArgsVar>,
        pk: &Snark::ProvingKey,
        memb_data: (Bul::MembershipWitness, Bul::MembershipPub),
        is_memb_data_const: bool,
        pub_args: PubArgs,
        priv_args: PrivArgs,
        print_constraints: bool,
    ) -> Result<Snark::Proof, SynthesisError> {
        let ppcirc: ProvePredInCircuit<F, H, U, PubArgs, PubArgsVar, PrivArgs, PrivArgsVar, Bul> =
            ProvePredInCircuit {
                priv_user: self.clone(),
                priv_extra_membership_data: memb_data.0,
                priv_args,
                pub_extra_membership_data: memb_data.1,
                bul_memb_is_const: is_memb_data_const,
                pub_args,
                associated_method: predicate,

                _phantom_hash: core::marker::PhantomData,
            };

        let new_cs = ConstraintSystem::<F>::new_ref();
        ppcirc.clone().generate_constraints(new_cs.clone())?;
        new_cs.is_satisfied()?;

        if print_constraints {
            println!(
                "Constraints for proving statement + in storage: {}",
                new_cs.num_constraints()
            );
        }

        let proof = Snark::prove(pk, ppcirc, rng)?;

        Ok(proof)
    }
}

impl<F: PrimeField + Absorb, U: UserData<F>> User<F, U> {
    pub fn commit<H: FieldHash<F>>(&self) -> Com<F> {
        let ser_data = self.data.serialize_elements();
        let ser_fields = self.zk_fields.serialize();
        let full_dat = [ser_data.as_slice(), ser_fields.as_slice()].concat();
        H::hash(&full_dat)
    }

    pub fn commit_in_zk<H: FieldHash<F>>(
        user_var: UserVar<F, U>,
    ) -> Result<ComVar<F>, SynthesisError> {
        let ser_data = U::serialize_in_zk(user_var.data)?;
        let ser_fields = user_var.zk_fields.serialize()?;
        let full_dat = [ser_data.as_slice(), ser_fields.as_slice()].concat();

        H::hash_in_zk(&full_dat)
    }
}
