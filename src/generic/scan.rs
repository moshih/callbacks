use crate::crypto::enc::CPACipher;
use ark_crypto_primitives::sponge::Absorb;
use ark_ff::PrimeField;
use ark_r1cs_std::alloc::AllocVar;
use ark_relations::ns;
use ark_relations::r1cs::Result as ArkResult;

use crate::{
    crypto::{enc::AECipherSigZK, hash::FieldHash},
    generic::callbacks::add_ticket_to_hc,
    util::ArrayVar,
};

use super::{
    bulletin::PublicCallbackBul,
    callbacks::{CallbackCom, CallbackComVar},
    interaction::Callback,
    object::{Time, TimeVar},
    user::{User, UserData, UserVar},
};

#[derive(Clone)]
pub struct PubScanArgs<
    F: PrimeField + Absorb,
    U: UserData<F>,
    CBArgs: Clone,
    CBArgsVar: AllocVar<CBArgs, F>,
    Crypto: AECipherSigZK<F, CBArgs>,
    CBul: PublicCallbackBul<F, CBArgs, Crypto>,
> {
    pub memb_pub: CBul::MembershipPub,
    pub nmemb_pub: CBul::NonMembershipPub,
    pub cur_time: Time<F>,

    pub bulletin: CBul,
    pub cb_methods: Vec<Callback<F, U, CBArgs, CBArgsVar>>,
}

impl<
        F: PrimeField + Absorb,
        U: UserData<F>,
        CBArgs: Clone,
        CBArgsVar: AllocVar<CBArgs, F>,
        Crypto: AECipherSigZK<F, CBArgs>,
        CBul: PublicCallbackBul<F, CBArgs, Crypto> + Default,
    > Default for PubScanArgs<F, U, CBArgs, CBArgsVar, Crypto, CBul>
where
    CBul::MembershipPub: Default,
    CBul::NonMembershipPub: Default,
{
    fn default() -> Self {
        Self {
            memb_pub: CBul::MembershipPub::default(),
            nmemb_pub: CBul::NonMembershipPub::default(),
            cur_time: Time::<F>::zero(),
            bulletin: CBul::default(),
            cb_methods: vec![],
        }
    }
}

impl<
        F: PrimeField + Absorb,
        U: UserData<F>,
        CBArgs: Clone,
        CBArgsVar: AllocVar<CBArgs, F>,
        Crypto: AECipherSigZK<F, CBArgs>,
        CBul: PublicCallbackBul<F, CBArgs, Crypto>,
    > std::fmt::Debug for PubScanArgs<F, U, CBArgs, CBArgsVar, Crypto, CBul>
{
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "Public Scan Arguments")
    }
}

#[derive(Clone)]
pub struct PubScanArgsVar<
    F: PrimeField + Absorb,
    U: UserData<F>,
    CBArgs: Clone,
    CBArgsVar: AllocVar<CBArgs, F>,
    Crypto: AECipherSigZK<F, CBArgs>,
    CBul: PublicCallbackBul<F, CBArgs, Crypto>,
> {
    pub memb_pub: CBul::MembershipPubVar,
    pub nmemb_pub: CBul::NonMembershipPubVar,
    pub cur_time: TimeVar<F>,

    pub cb_methods: Vec<Callback<F, U, CBArgs, CBArgsVar>>,
}

impl<
        F: PrimeField + Absorb,
        U: UserData<F>,
        CBArgs: Clone,
        CBArgsVar: AllocVar<CBArgs, F>,
        Crypto: AECipherSigZK<F, CBArgs>,
        CBul: PublicCallbackBul<F, CBArgs, Crypto>,
    > std::fmt::Debug for PubScanArgsVar<F, U, CBArgs, CBArgsVar, Crypto, CBul>
{
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "Public Scan Arguments in ZK")
    }
}

impl<
        F: PrimeField + Absorb,
        U: UserData<F>,
        CBArgs: Clone,
        CBArgsVar: AllocVar<CBArgs, F> + Clone,
        Crypto: AECipherSigZK<F, CBArgs>,
        CBul: PublicCallbackBul<F, CBArgs, Crypto>,
    > AllocVar<PubScanArgs<F, U, CBArgs, CBArgsVar, Crypto, CBul>, F>
    for PubScanArgsVar<F, U, CBArgs, CBArgsVar, Crypto, CBul>
{
    fn new_variable<T: std::borrow::Borrow<PubScanArgs<F, U, CBArgs, CBArgsVar, Crypto, CBul>>>(
        cs: impl Into<ark_relations::r1cs::Namespace<F>>,
        f: impl FnOnce() -> Result<T, ark_relations::r1cs::SynthesisError>,
        mode: ark_r1cs_std::prelude::AllocationMode,
    ) -> Result<Self, ark_relations::r1cs::SynthesisError> {
        let ns = cs.into();
        let cs = ns.cs();
        let res = f();
        res.and_then(|rec| {
            let rec = rec.borrow();
            let memb_pub = CBul::MembershipPubVar::new_variable(
                ns!(cs, "memb_pub"),
                || Ok(rec.memb_pub.clone()),
                mode,
            )?;
            let nmemb_pub = CBul::NonMembershipPubVar::new_variable(
                ns!(cs, "nmemb_pub"),
                || Ok(rec.nmemb_pub.clone()),
                mode,
            )?;

            let mut cb_methods = vec![];
            for i in &rec.cb_methods {
                cb_methods.push(i.clone());
            }

            let cur_time = TimeVar::new_variable(ns!(cs, "cur_time"), || Ok(rec.cur_time), mode)?;
            Ok(Self {
                memb_pub,
                nmemb_pub,
                cur_time,

                cb_methods,
            })
        })
    }
}

#[derive(Clone)]
pub struct PrivScanArgs<
    F: PrimeField + Absorb,
    CBArgs: Clone,
    Crypto: AECipherSigZK<F, CBArgs>,
    CBul: PublicCallbackBul<F, CBArgs, Crypto>,
    const NUMCBS: usize,
> {
    pub priv_n_tickets: [CallbackCom<F, CBArgs, Crypto>; NUMCBS],
    pub memb_priv: CBul::MembershipWitness,
    pub nmemb_priv: CBul::NonMembershipWitness,
}

impl<
        F: PrimeField + Absorb,
        CBArgs: Clone + Default,
        Crypto: AECipherSigZK<F, CBArgs> + Default,
        CBul: PublicCallbackBul<F, CBArgs, Crypto>,
        const NUMCBS: usize,
    > Default for PrivScanArgs<F, CBArgs, Crypto, CBul, NUMCBS>
where
    CBul::MembershipWitness: Default,
    CBul::NonMembershipWitness: Default,
{
    fn default() -> Self {
        let pnt: [CallbackCom<F, CBArgs, Crypto>; NUMCBS] =
            core::array::from_fn(|_| CallbackCom::default());
        Self {
            memb_priv: CBul::MembershipWitness::default(),
            nmemb_priv: CBul::NonMembershipWitness::default(),
            priv_n_tickets: pnt,
        }
    }
}

impl<
        F: PrimeField + Absorb,
        CBArgs: Clone,
        Crypto: AECipherSigZK<F, CBArgs>,
        CBul: PublicCallbackBul<F, CBArgs, Crypto>,
        const NUMCBS: usize,
    > std::fmt::Debug for PrivScanArgs<F, CBArgs, Crypto, CBul, NUMCBS>
{
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "Private Scan Arguments")
    }
}

#[derive(Clone)]
pub struct PrivScanArgsVar<
    F: PrimeField + Absorb,
    CBArgs: Clone,
    Crypto: AECipherSigZK<F, CBArgs>,
    CBul: PublicCallbackBul<F, CBArgs, Crypto>,
    const NUMCBS: usize,
> {
    pub priv_n_tickets: [CallbackComVar<F, CBArgs, Crypto>; NUMCBS],
    pub memb_priv: CBul::MembershipWitnessVar,
    pub nmemb_priv: CBul::NonMembershipWitnessVar,
}

impl<
        F: PrimeField + Absorb,
        CBArgs: Clone,
        Crypto: AECipherSigZK<F, CBArgs>,
        CBul: PublicCallbackBul<F, CBArgs, Crypto>,
        const NUMCBS: usize,
    > std::fmt::Debug for PrivScanArgsVar<F, CBArgs, Crypto, CBul, NUMCBS>
{
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "Private Scan Arguments in ZK")
    }
}

impl<
        F: PrimeField + Absorb,
        CBArgs: Clone,
        Crypto: AECipherSigZK<F, CBArgs>,
        CBul: PublicCallbackBul<F, CBArgs, Crypto>,
        const NUMCBS: usize,
    > AllocVar<PrivScanArgs<F, CBArgs, Crypto, CBul, NUMCBS>, F>
    for PrivScanArgsVar<F, CBArgs, Crypto, CBul, NUMCBS>
{
    fn new_variable<T: std::borrow::Borrow<PrivScanArgs<F, CBArgs, Crypto, CBul, NUMCBS>>>(
        cs: impl Into<ark_relations::r1cs::Namespace<F>>,
        f: impl FnOnce() -> Result<T, ark_relations::r1cs::SynthesisError>,
        mode: ark_r1cs_std::prelude::AllocationMode,
    ) -> Result<Self, ark_relations::r1cs::SynthesisError> {
        let ns = cs.into();
        let cs = ns.cs();
        let res = f();
        res.and_then(|rec| {
            let rec = rec.borrow();

            let priv_n_tickets: ArrayVar<CallbackComVar<F, CBArgs, Crypto>, NUMCBS> =
                ArrayVar::new_variable(
                    ns!(cs, "priv_n_tickets"),
                    || Ok(rec.priv_n_tickets.clone()),
                    mode,
                )?;
            let memb_priv = CBul::MembershipWitnessVar::new_variable(
                ns!(cs, "memb_priv"),
                || Ok(rec.memb_priv.clone()),
                mode,
            )?;
            let nmemb_priv = CBul::NonMembershipWitnessVar::new_variable(
                ns!(cs, "nmemb_priv"),
                || Ok(rec.nmemb_priv.clone()),
                mode,
            )?;
            Ok(Self {
                priv_n_tickets: priv_n_tickets.0,
                memb_priv,
                nmemb_priv,
            })
        })
    }
}

pub fn scan_method<
    F: PrimeField + Absorb,
    U: UserData<F>,
    CBArgs: Clone,
    CBArgsVar: AllocVar<CBArgs, F>,
    Crypto: AECipherSigZK<F, CBArgs>,
    CBul: PublicCallbackBul<F, CBArgs, Crypto>,
    H: FieldHash<F>,
    const NUMCBS: usize,
>(
    user: &User<F, U>,
    pub_args: PubScanArgs<F, U, CBArgs, CBArgsVar, Crypto, CBul>,
    priv_args: PrivScanArgs<F, CBArgs, Crypto, CBul, NUMCBS>,
) -> User<F, U> {
    let mut out_user = user.clone();

    if out_user.zk_fields.is_ingest_over {
        out_user.zk_fields.is_ingest_over = false;
        out_user.zk_fields.old_in_progress_callback_hash = F::zero();
        out_user.zk_fields.new_in_progress_callback_hash = F::zero();
    }

    for i in priv_args.priv_n_tickets {
        out_user.zk_fields.old_in_progress_callback_hash = add_ticket_to_hc::<F, H, CBArgs, Crypto>(
            out_user.zk_fields.old_in_progress_callback_hash,
            i.cb_entry.clone(),
        );

        match pub_args.bulletin.verify_in(i.cb_entry.tik.clone()) {
            Some((ct, time)) => {
                if i.cb_entry.expirable && time > i.cb_entry.expiration {
                } else {
                    for x in &pub_args.cb_methods {
                        if x.method_id == i.cb_entry.cb_method_id {
                            let args = i.cb_entry.enc_key.decrypt(ct.clone());
                            out_user = (x.method)(&out_user, args);
                        }
                    }
                }
            }
            None => {
                assert!(pub_args.bulletin.verify_not_in(i.clone().cb_entry.tik));
                if i.cb_entry.expirable && pub_args.cur_time > i.cb_entry.expiration {
                } else {
                    out_user.zk_fields.new_in_progress_callback_hash =
                        add_ticket_to_hc::<F, H, CBArgs, Crypto>(
                            out_user.zk_fields.new_in_progress_callback_hash,
                            i.cb_entry,
                        );
                }
            }
        }
    }

    if out_user.zk_fields.old_in_progress_callback_hash == out_user.zk_fields.callback_hash {
        out_user.zk_fields.callback_hash = out_user.zk_fields.new_in_progress_callback_hash;
        out_user.zk_fields.new_in_progress_callback_hash = F::zero();
        out_user.zk_fields.old_in_progress_callback_hash = out_user.zk_fields.callback_hash;
        out_user.zk_fields.is_ingest_over = true;
    }
    out_user
}

pub fn scan_predicate<
    F: PrimeField + Absorb,
    U: UserData<F>,
    CBArgs: Clone,
    CBArgsVar: AllocVar<CBArgs, F>,
    Crypto: AECipherSigZK<F, CBArgs>,
    CBul: PublicCallbackBul<F, CBArgs, Crypto>,
    const NUMCBS: usize,
>(
    user_old: &UserVar<F, U>,
    user_new: &UserVar<F, U>,
    pub_args: PubScanArgsVar<F, U, CBArgs, CBArgsVar, Crypto, CBul>,
    priv_args: PrivScanArgsVar<F, CBArgs, Crypto, CBul, NUMCBS>,
) -> ArkResult<()> {
    Ok(())
}
