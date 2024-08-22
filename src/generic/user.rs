use crate::crypto::enc::AECipherSigZK;
use crate::crypto::hash::FieldHash;
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
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use ark_snark::SNARK;
use rand::distributions::Standard;
use rand::prelude::Distribution;
use rand::Rng;
use rand::{CryptoRng, RngCore};
use std::borrow::Borrow;

pub trait UserData<F: PrimeField + Absorb>: Clone + Eq + std::fmt::Debug {
    type UserDataVar: AllocVar<Self, F> + Clone;

    fn serialize_elements(&self) -> Vec<Ser<F>>;

    fn serialize_in_zk(user_var: Self::UserDataVar) -> Result<Vec<SerVar<F>>, SynthesisError>;
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct User<F: PrimeField + Absorb, U: UserData<F>> {
    pub data: U,
    pub zk_fields: ZKFields<F>,

    pub callbacks: Vec<Vec<u8>>,
}

#[derive(Clone)]
pub struct UserVar<F: PrimeField + Absorb, U: UserData<F>> {
    pub data: U::UserDataVar,
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

#[derive(Clone, Debug, CanonicalSerialize, CanonicalDeserialize)]
pub struct ExecutedMethod<
    F: PrimeField + Absorb,
    Snark: SNARK<F>,
    Args: Clone,
    Crypto: AECipherSigZK<F, Args>,
    const NUMCBS: usize,
> {
    pub new_object: Com<F>,
    pub old_nullifier: Nul<F>,
    pub cb_tik_list: [(CallbackCom<F, Args, Crypto>, Crypto::Rand); NUMCBS],
    pub cb_com_list: [Com<F>; NUMCBS],
    pub proof: Snark::Proof,
}

#[derive(Clone, Debug, CanonicalSerialize, CanonicalDeserialize)]
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
            callbacks: vec![],
        }
    }

    pub fn interact<
        H: FieldHash<F>,
        Args: Clone + std::fmt::Debug,
        ArgsVar: AllocVar<Args, F> + Clone,
        Crypto: AECipherSigZK<F, Args>,
        Snark: SNARK<F, Error = SynthesisError>,
        Bul: PublicUserBul<F, U>,
        const NUMCBS: usize,
    >(
        &mut self,
        rng: &mut (impl CryptoRng + RngCore),
        method: Interaction<F, U, Args, ArgsVar, NUMCBS>,
        rpks: [Crypto::SigPK; NUMCBS],
        bul_data: (Bul::MembershipWitness, Bul::MembershipPub),
        pk: &Snark::ProvingKey,
        args: Args,
    ) -> Result<ExecutedMethod<F, Snark, Args, Crypto, NUMCBS>, SynthesisError> {
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

        let cb_tik_list: [(CallbackCom<F, Args, Crypto>, Crypto::Rand); NUMCBS] =
            create_cbs_from_interaction(rng, method.clone(), rpks);

        let issued_callbacks: [CallbackCom<F, Args, Crypto>; NUMCBS] = cb_tik_list
            .iter()
            .map(|(x, _)| x.clone())
            .collect::<Vec<CallbackCom<F, Args, Crypto>>>()
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

            new_user.zk_fields.callback_hash = add_ticket_to_hc::<F, H, Args, Crypto>(
                new_user.zk_fields.callback_hash,
                item.clone().cb_entry,
            );
        }

        new_user.zk_fields.old_in_progress_callback_hash = new_user.zk_fields.callback_hash;

        // (C) Generate proof of correctness
        // Extract the zk fields from the objects to do bookkeeping

        let out_commit = new_user.commit::<H>();

        let out_nul = self.zk_fields.nul;

        let exec_method_circ: ExecMethodCircuit<F, H, U, Args, ArgsVar, Crypto, Bul, NUMCBS> =
            ExecMethodCircuit {
                priv_old_user: self.clone(),
                priv_new_user: new_user.clone(),
                priv_issued_callbacks: issued_callbacks,
                priv_bul_membership_witness: bul_data.0,

                pub_new_com: out_commit,
                pub_old_nul: out_nul,
                pub_issued_callback_coms: issued_cb_coms,
                pub_args: args,
                pub_bul_membership_data: bul_data.1,

                associated_method: method,
                _phantom_hash: core::marker::PhantomData,
            };

        let new_cs = ConstraintSystem::<F>::new_ref();
        exec_method_circ
            .clone()
            .generate_constraints(new_cs.clone())?;
        new_cs.is_satisfied()?;

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

    pub fn prove_statement<
        H: FieldHash<F>,
        Args: Clone,
        ArgsVar: AllocVar<Args, F> + Clone,
        Snark: SNARK<F, Error = SynthesisError>,
    >(
        &mut self,
        rng: &mut (impl CryptoRng + RngCore),
        predicate: SingularPredicate<UserVar<F, U>, ComVar<F>, ArgsVar>,
        pk: &Snark::ProvingKey,
        args: Args,
    ) -> Result<ProveResult<F, Snark>, SynthesisError> {
        let ppcirc: ProvePredicateCircuit<F, U, Args, ArgsVar> = ProvePredicateCircuit {
            priv_user: self.clone(),
            pub_com: self.commit::<H>(),

            pub_args: args,
            associated_method: predicate,
        };

        let new_cs = ConstraintSystem::<F>::new_ref();
        ppcirc.clone().generate_constraints(new_cs.clone())?;
        new_cs.is_satisfied()?;

        let proof = Snark::prove(pk, ppcirc, rng)?;

        Ok(ProveResult {
            object: self.commit::<H>(),
            proof,
        })
    }

    pub fn prove_statement_and_in<
        H: FieldHash<F>,
        Args: Clone,
        ArgsVar: AllocVar<Args, F> + Clone,
        Snark: SNARK<F, Error = SynthesisError>,
        Bul: PublicUserBul<F, U>,
    >(
        &mut self,
        rng: &mut (impl CryptoRng + RngCore),
        predicate: SingularPredicate<UserVar<F, U>, ComVar<F>, ArgsVar>,
        pk: &Snark::ProvingKey,
        memb_data: (Bul::MembershipWitness, Bul::MembershipPub),
        args: Args,
    ) -> Result<Snark::Proof, SynthesisError> {
        let ppcirc: ProvePredInCircuit<F, H, U, Args, ArgsVar, Bul> = ProvePredInCircuit {
            priv_user: self.clone(),
            priv_extra_membership_data: memb_data.0,
            pub_extra_membership_data: memb_data.1,
            pub_args: args,
            associated_method: predicate,

            _phantom_hash: core::marker::PhantomData,
        };

        let new_cs = ConstraintSystem::<F>::new_ref();
        ppcirc.clone().generate_constraints(new_cs.clone())?;
        new_cs.is_satisfied()?;

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
