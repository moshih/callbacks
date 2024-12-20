use crate::crypto::enc::CPACipher;
use ark_crypto_primitives::sponge::Absorb;
use ark_ff::{PrimeField, ToConstraintField};
use ark_r1cs_std::cmp::CmpGadget;
use ark_r1cs_std::uint::UInt;
use ark_r1cs_std::{
    alloc::AllocVar, eq::EqGadget, fields::fp::FpVar, prelude::Boolean, select::CondSelectGadget,
};
use ark_relations::ns;
use ark_relations::r1cs::Result as ArkResult;
use ark_serialize::CanonicalSerialize;

use crate::{
    crypto::{enc::AECipherSigZK, hash::FieldHash},
    generic::callbacks::add_ticket_to_hc,
    util::ArrayVar,
};

use super::{
    bulletin::PublicCallbackBul,
    callbacks::{add_ticket_to_hc_zk, CallbackCom, CallbackComVar},
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
    const NUMCBS: usize,
> {
    pub memb_pub: [CBul::MembershipPub; NUMCBS],
    pub is_memb_data_const: bool,
    pub nmemb_pub: [CBul::NonMembershipPub; NUMCBS],
    pub is_nmemb_data_const: bool,
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
        const NUMCBS: usize,
    > Default for PubScanArgs<F, U, CBArgs, CBArgsVar, Crypto, CBul, NUMCBS>
where
    CBul::MembershipPub: Default,
    CBul::NonMembershipPub: Default,
{
    fn default() -> Self {
        Self {
            memb_pub: core::array::from_fn(|_| CBul::MembershipPub::default()),
            nmemb_pub: core::array::from_fn(|_| CBul::NonMembershipPub::default()),
            is_memb_data_const: false,
            is_nmemb_data_const: false,
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
        const NUMCBS: usize,
    > std::fmt::Debug for PubScanArgs<F, U, CBArgs, CBArgsVar, Crypto, CBul, NUMCBS>
{
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "Public Scan Arguments")
    }
}

impl<
        F: PrimeField + Absorb,
        U: UserData<F>,
        CBArgs: Clone,
        CBArgsVar: AllocVar<CBArgs, F>,
        Crypto: AECipherSigZK<F, CBArgs>,
        CBul: PublicCallbackBul<F, CBArgs, Crypto>,
        const NUMCBS: usize,
    > ToConstraintField<F> for PubScanArgs<F, U, CBArgs, CBArgsVar, Crypto, CBul, NUMCBS>
where
    CBul::MembershipPub: ToConstraintField<F>,
    CBul::NonMembershipPub: ToConstraintField<F>,
{
    fn to_field_elements(&self) -> Option<Vec<F>> {
        let mut out = vec![];
        if !self.is_memb_data_const {
            for i in 0..NUMCBS {
                out.extend(self.memb_pub[i].to_field_elements()?);
            }
        }
        if !self.is_nmemb_data_const {
            for i in 0..NUMCBS {
                out.extend(self.nmemb_pub[i].to_field_elements()?);
            }
        }

        out.extend(self.cur_time.to_field_elements()?);
        Some(out)
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
    const NUMCBS: usize,
> {
    pub memb_pub: [CBul::MembershipPubVar; NUMCBS],
    pub nmemb_pub: [CBul::NonMembershipPubVar; NUMCBS],
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
        const NUMCBS: usize,
    > std::fmt::Debug for PubScanArgsVar<F, U, CBArgs, CBArgsVar, Crypto, CBul, NUMCBS>
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
        const NUMCBS: usize,
    > AllocVar<PubScanArgs<F, U, CBArgs, CBArgsVar, Crypto, CBul, NUMCBS>, F>
    for PubScanArgsVar<F, U, CBArgs, CBArgsVar, Crypto, CBul, NUMCBS>
{
    fn new_variable<
        T: std::borrow::Borrow<PubScanArgs<F, U, CBArgs, CBArgsVar, Crypto, CBul, NUMCBS>>,
    >(
        cs: impl Into<ark_relations::r1cs::Namespace<F>>,
        f: impl FnOnce() -> Result<T, ark_relations::r1cs::SynthesisError>,
        mode: ark_r1cs_std::prelude::AllocationMode,
    ) -> Result<Self, ark_relations::r1cs::SynthesisError> {
        let ns = cs.into();
        let cs = ns.cs();
        let res = f();
        res.and_then(|rec| {
            let rec = rec.borrow();
            let memb_pub: [CBul::MembershipPubVar; NUMCBS] = match rec.is_memb_data_const {
                false => {
                    ArrayVar::new_variable(ns!(cs, "memb_pub"), || Ok(rec.memb_pub.clone()), mode)?
                        .0
                }
                true => ArrayVar::new_constant(cs.clone(), &rec.memb_pub)?.0,
            };

            let nmemb_pub: [CBul::NonMembershipPubVar; NUMCBS] = match rec.is_nmemb_data_const {
                false => {
                    ArrayVar::new_variable(
                        ns!(cs, "nmemb_pub"),
                        || Ok(rec.nmemb_pub.clone()),
                        mode,
                    )?
                    .0
                }
                true => ArrayVar::new_constant(cs.clone(), &rec.nmemb_pub)?.0,
            };

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
    pub enc_args: [Crypto::Ct; NUMCBS],
    pub post_times: [Time<F>; NUMCBS],
    pub memb_priv: [CBul::MembershipWitness; NUMCBS],
    pub nmemb_priv: [CBul::NonMembershipWitness; NUMCBS],
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
            memb_priv: core::array::from_fn(|_| CBul::MembershipWitness::default()),
            nmemb_priv: core::array::from_fn(|_| CBul::NonMembershipWitness::default()),
            enc_args: core::array::from_fn(|_| Crypto::Ct::default()),
            post_times: core::array::from_fn(|_| Time::<F>::default()),
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
    pub enc_args: [<Crypto::EncKey as CPACipher<F>>::CV; NUMCBS],
    pub post_times: [TimeVar<F>; NUMCBS],
    pub memb_priv: [CBul::MembershipWitnessVar; NUMCBS],
    pub nmemb_priv: [CBul::NonMembershipWitnessVar; NUMCBS],
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

            let memb_priv: [CBul::MembershipWitnessVar; NUMCBS] =
                ArrayVar::new_variable(ns!(cs, "memb_priv"), || Ok(rec.memb_priv.clone()), mode)?.0;
            let nmemb_priv: [CBul::NonMembershipWitnessVar; NUMCBS] =
                ArrayVar::new_variable(ns!(cs, "nmemb_priv"), || Ok(rec.nmemb_priv.clone()), mode)?
                    .0;
            let post_times: [TimeVar<F>; NUMCBS] =
                ArrayVar::new_variable(ns!(cs, "post_times"), || Ok(rec.post_times), mode)?.0;

            let enc_args: [<Crypto::EncKey as CPACipher<F>>::CV; NUMCBS] =
                ArrayVar::new_variable(ns!(cs, "enc_args"), || Ok(rec.enc_args.clone()), mode)?.0;

            Ok(Self {
                priv_n_tickets: priv_n_tickets.0,
                enc_args,
                post_times,
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
    pub_args: PubScanArgs<F, U, CBArgs, CBArgsVar, Crypto, CBul, NUMCBS>,
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

                let mut cb = Vec::new();
                i.clone().serialize_compressed(&mut cb).unwrap();
                for x in 0..out_user.callbacks.len() {
                    if out_user.callbacks[x] == cb {
                        out_user.callbacks.remove(x);
                    }
                }
            }
            None => {
                assert!(pub_args.bulletin.verify_not_in(i.clone().cb_entry.tik));
                if i.cb_entry.expirable && pub_args.cur_time > i.cb_entry.expiration {
                    let mut cb = Vec::new();
                    i.clone().serialize_compressed(&mut cb).unwrap();
                    for x in 0..out_user.callbacks.len() {
                        if out_user.callbacks[x] == cb {
                            out_user.callbacks.remove(x);
                        }
                    }
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
        out_user.zk_fields.new_in_progress_callback_hash = F::ZERO;
        out_user.zk_fields.old_in_progress_callback_hash = out_user.zk_fields.callback_hash;
        out_user.zk_fields.is_ingest_over = true;
    }
    out_user
}

pub fn scan_apply_method_zk<
    F: PrimeField + Absorb,
    U: UserData<F>,
    CBArgs: Clone,
    CBArgsVar: AllocVar<CBArgs, F>,
    Crypto: AECipherSigZK<F, CBArgs, AV = CBArgsVar>,
    CBul: PublicCallbackBul<F, CBArgs, Crypto>,
    H: FieldHash<F>,
    const NUMCBS: usize,
>(
    user_old: &UserVar<F, U>,
    pub_args: PubScanArgsVar<F, U, CBArgs, CBArgsVar, Crypto, CBul, NUMCBS>,
    priv_args: PrivScanArgsVar<F, CBArgs, Crypto, CBul, NUMCBS>,
) -> ArkResult<UserVar<F, U>>
where
    U::UserDataVar: CondSelectGadget<F> + EqGadget<F>,
{
    let mut inprog_user = user_old.clone();

    let updated_old = FpVar::<F>::conditionally_select(
        &user_old.zk_fields.is_ingest_over,
        &FpVar::Constant(F::zero()),
        &user_old.zk_fields.old_in_progress_callback_hash,
    )?;

    let updated_new = FpVar::<F>::conditionally_select(
        &user_old.zk_fields.is_ingest_over,
        &FpVar::Constant(F::zero()),
        &user_old.zk_fields.new_in_progress_callback_hash,
    )?;

    let updated_ingest = Boolean::conditionally_select(
        &user_old.zk_fields.is_ingest_over,
        &Boolean::FALSE,
        &user_old.zk_fields.is_ingest_over,
    )?;

    inprog_user.zk_fields.is_ingest_over = updated_ingest;
    inprog_user.zk_fields.old_in_progress_callback_hash = updated_old;
    inprog_user.zk_fields.new_in_progress_callback_hash = updated_new;

    // check the ids are sequentially assigned and in-order
    let mut r = F::ZERO;
    for j in 0..pub_args.cb_methods.len() {
        assert!(pub_args.cb_methods[j].method_id == r);
        r += F::ONE;
    }

    for i in 0..NUMCBS {
        add_ticket_to_hc_zk::<F, H, CBArgs, Crypto>(
            &mut inprog_user.zk_fields.old_in_progress_callback_hash,
            priv_args.priv_n_tickets[i].cb_entry.clone(),
        )?;

        let memb = CBul::enforce_memb_nmemb(
            (
                priv_args.priv_n_tickets[i].cb_entry.tik.clone(),
                priv_args.enc_args[i].clone(),
                priv_args.post_times[i].clone(),
            ),
            (
                priv_args.memb_priv[i].clone(),
                priv_args.nmemb_priv[i].clone(),
            ),
            (pub_args.memb_pub[i].clone(), pub_args.nmemb_pub[i].clone()),
        )?;

        // part 1: if we are in the membership setting
        //
        // if expired (do nothing)
        // if not expired
        //      1. call every callback on the user to get a list of "potential" users
        //      2. conditionally select the user based off the cb id

        let mut memb_world_user = inprog_user.clone();

        let mut potential = vec![];

        for j in 0..pub_args.cb_methods.len() {
            let dec = Crypto::EncKey::decrypt_in_zk(
                priv_args.priv_n_tickets[i].cb_entry.enc_key.clone(),
                priv_args.enc_args[i].clone(),
            )?;

            potential.push((
                (pub_args.cb_methods[j].predicate)(&memb_world_user, dec)?,
                FpVar::Constant(pub_args.cb_methods[j].method_id),
            ));
        }

        let mut cond_user_select = memb_world_user.clone();

        for k in 0..potential.len() {
            cond_user_select = UserVar::conditionally_select(
                &(priv_args.priv_n_tickets[i]
                    .cb_entry
                    .cb_method_id
                    .is_eq(&potential[k].1)?),
                &potential[k].0,
                &cond_user_select,
            )?;
        }

        let ut1 = <UInt<64, u64, F>>::from_fp(&priv_args.post_times[i])?.0;
        let ut2 = <UInt<64, u64, F>>::from_fp(&priv_args.priv_n_tickets[i].cb_entry.expiration)?.0;

        memb_world_user = UserVar::conditionally_select(
            &(priv_args.priv_n_tickets[i].clone().cb_entry.expirable & ((ut1.is_gt(&ut2))?)),
            &memb_world_user,
            &cond_user_select,
        )?;

        // part 2: nonmembership!
        //
        // a) conditionally select on expiry and update the callback hash
        //
        //
        //

        let mut nmemb_world_user = inprog_user.clone();

        let ut1 = <UInt<64, u64, F>>::from_fp(&pub_args.cur_time)?.0;
        let ut2 = <UInt<64, u64, F>>::from_fp(&priv_args.priv_n_tickets[i].cb_entry.expiration)?.0;

        let mut possibly_nonexpired_hc = nmemb_world_user
            .zk_fields
            .new_in_progress_callback_hash
            .clone();

        add_ticket_to_hc_zk::<F, H, CBArgs, Crypto>(
            &mut possibly_nonexpired_hc,
            priv_args.priv_n_tickets[i].cb_entry.clone(),
        )?;

        nmemb_world_user.zk_fields.new_in_progress_callback_hash =
            FpVar::<F>::conditionally_select(
                &(priv_args.priv_n_tickets[i].clone().cb_entry.expirable & ((ut1.is_gt(&ut2))?)),
                &nmemb_world_user.zk_fields.new_in_progress_callback_hash,
                &possibly_nonexpired_hc,
            )?;

        // together: using memb, select the correct user from part 1 / 2
        let correct_updated_user =
            UserVar::conditionally_select(&memb, &memb_world_user, &nmemb_world_user)?;

        inprog_user = correct_updated_user;
    }

    let updated_cbh = FpVar::<F>::conditionally_select(
        &(inprog_user
            .zk_fields
            .callback_hash
            .is_eq(&inprog_user.zk_fields.old_in_progress_callback_hash)?),
        &inprog_user.zk_fields.new_in_progress_callback_hash,
        &inprog_user.zk_fields.callback_hash,
    )?;

    let updated_new = FpVar::<F>::conditionally_select(
        &(inprog_user
            .zk_fields
            .callback_hash
            .is_eq(&inprog_user.zk_fields.old_in_progress_callback_hash)?),
        &FpVar::Constant(F::zero()),
        &inprog_user.zk_fields.new_in_progress_callback_hash,
    )?;

    let updated_old = FpVar::<F>::conditionally_select(
        &(inprog_user
            .zk_fields
            .callback_hash
            .is_eq(&inprog_user.zk_fields.old_in_progress_callback_hash)?),
        &updated_cbh,
        &inprog_user.zk_fields.old_in_progress_callback_hash,
    )?;

    let updated_ingest = Boolean::conditionally_select(
        &(inprog_user
            .zk_fields
            .callback_hash
            .is_eq(&inprog_user.zk_fields.old_in_progress_callback_hash)?),
        &Boolean::TRUE,
        &inprog_user.zk_fields.is_ingest_over,
    )?;

    inprog_user.zk_fields.callback_hash = updated_cbh;
    inprog_user.zk_fields.new_in_progress_callback_hash = updated_new;
    inprog_user.zk_fields.old_in_progress_callback_hash = updated_old;
    inprog_user.zk_fields.is_ingest_over = updated_ingest;

    Ok(inprog_user)
}

pub fn scan_predicate<
    F: PrimeField + Absorb,
    U: UserData<F>,
    CBArgs: Clone,
    CBArgsVar: AllocVar<CBArgs, F>,
    Crypto: AECipherSigZK<F, CBArgs, AV = CBArgsVar>,
    CBul: PublicCallbackBul<F, CBArgs, Crypto>,
    H: FieldHash<F>,
    const NUMCBS: usize,
>(
    user_old: &UserVar<F, U>,
    user_new: &UserVar<F, U>,
    pub_args: PubScanArgsVar<F, U, CBArgs, CBArgsVar, Crypto, CBul, NUMCBS>,
    priv_args: PrivScanArgsVar<F, CBArgs, Crypto, CBul, NUMCBS>,
) -> ArkResult<Boolean<F>>
where
    U::UserDataVar: CondSelectGadget<F> + EqGadget<F>,
{
    let out_user = scan_apply_method_zk::<F, U, CBArgs, CBArgsVar, Crypto, CBul, H, NUMCBS>(
        user_old, pub_args, priv_args,
    )?;

    let b = out_user.data.is_eq(&user_new.data)?;

    // let b = User::commit_in_zk::<H>(inprog_user)?
    //    .is_eq(&(User::commit_in_zk::<H>(user_new.clone())?))?;

    Ok(b)
}
