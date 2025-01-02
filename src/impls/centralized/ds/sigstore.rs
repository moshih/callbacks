use crate::{
    crypto::{enc::AECipherSigZK, hash::HasherZK},
    generic::{
        bulletin::{CallbackBulletin, JoinableBulletin, PublicCallbackBul, PublicUserBul, UserBul},
        callbacks::CallbackCom,
        object::{Com, Nul, Time, TimeVar},
        service::ServiceProvider,
        user::UserData,
    },
    impls::{
        centralized::{
            crypto::{PlainTikCrypto, PlainTikCryptoVar},
            ds::{
                sig::{uov::BleedingUOV, Signature},
                sigrange::SigRangeStore,
            },
        },
        hash::Poseidon,
    },
};
use ark_crypto_primitives::sponge::Absorb;
use ark_ff::PrimeField;
use ark_r1cs_std::{alloc::AllocVar, fields::fp::FpVar, prelude::Boolean};
use ark_relations::r1cs::SynthesisError;
use rand::{
    distributions::{Distribution, Standard},
    thread_rng, CryptoRng, Rng, RngCore,
};

#[derive(Clone, Default, Debug)]
pub struct SigObjStore<F: PrimeField + Absorb, S: Signature<F>> {
    privkey: S::Privkey,

    pub pubkey: S::Pubkey,

    pub coms: Vec<Com<F>>,
    pub old_nuls: Vec<Nul<F>>,
    pub cb_com_lists: Vec<Vec<Com<F>>>,
    pub sigs: Vec<S::Sig>,
}

impl<F: PrimeField + Absorb, S: Signature<F>> SigObjStore<F, S> {
    pub fn new(rng: &mut (impl CryptoRng + RngCore)) -> Self {
        let sk = S::gen_key(rng);
        Self {
            privkey: sk.clone(),
            pubkey: S::get_pubkey(&sk),
            coms: vec![],
            old_nuls: vec![],
            cb_com_lists: vec![],
            sigs: vec![],
        }
    }

    pub fn from(privkey: S::Privkey, db: Vec<(Com<F>, Nul<F>, Vec<Com<F>>, S::Sig)>) -> Self {
        let pubkey = S::get_pubkey(&privkey);
        let coms = db.iter().map(|(c, _, _, _)| c.clone()).collect();
        let old_nuls = db.iter().map(|(_, n, _, _)| n.clone()).collect();
        let cb_com_lists = db.iter().map(|(_, _, l, _)| l.clone()).collect();
        let sigs = db.into_iter().map(|(_, _, _, s)| s).collect();
        Self {
            privkey,
            pubkey,
            coms,
            old_nuls,
            cb_com_lists,
            sigs,
        }
    }

    pub fn get_pubkey(&self) -> S::Pubkey {
        self.pubkey.clone()
    }

    pub fn get_db(&self) -> Vec<(Com<F>, Nul<F>, Vec<Com<F>>, S::Sig)> {
        (0..(self.coms.len()))
            .map(|x| {
                (
                    self.coms[x],
                    self.old_nuls[x],
                    self.cb_com_lists[x].clone(),
                    self.sigs[x].clone(),
                )
            })
            .collect()
    }

    pub fn rotate_key(&mut self, new_key: S::Privkey) -> Result<(), ()> {
        self.pubkey = S::get_pubkey(&new_key);
        self.privkey = new_key;
        let mut rng = thread_rng();
        let mut v = vec![];
        for i in 0..self.coms.len() {
            let out = S::sign(&self.privkey, &mut rng, self.coms[i]);
            match out {
                Some(x) => {
                    v.push(x);
                }
                None => {
                    return Err(());
                }
            }
        }
        self.sigs = v;
        Ok(())
    }

    pub fn get_signature_of(&self, obj: &Com<F>) -> Option<S::Sig> {
        for (i, c) in self.coms.iter().enumerate() {
            if c == obj {
                return Some(self.sigs[i].clone());
            }
        }
        None
    }
}

impl<F: PrimeField + Absorb, U: UserData<F>, S: Signature<F>> PublicUserBul<F, U>
    for SigObjStore<F, S>
{
    type Error = ();

    type MembershipWitness = S::Sig;

    type MembershipWitnessVar = S::SigVar;

    type MembershipPub = S::Pubkey;

    type MembershipPubVar = S::PubkeyVar;

    fn verify_in<PubArgs, Snark: ark_snark::SNARK<F>, const NUMCBS: usize>(
        &self,
        object: Com<F>,
        old_nul: Nul<F>,
        cb_com_list: [Com<F>; NUMCBS],
        _args: PubArgs,
        _proof: Snark::Proof,
        _memb_data: Self::MembershipPub,
        _verif_key: &Snark::VerifyingKey,
    ) -> bool {
        for (i, c) in self.coms.iter().enumerate() {
            if c == &object
                && self.old_nuls[i] == old_nul
                && self.cb_com_lists[i] == cb_com_list.to_vec()
            {
                return true;
            }
        }
        false
    }

    fn enforce_membership_of(
        data_var: crate::generic::object::ComVar<F>,
        extra_witness: Self::MembershipWitnessVar,
        extra_pub: Self::MembershipPubVar,
    ) -> Result<Boolean<F>, SynthesisError> {
        S::verify_zk(extra_pub, extra_witness, data_var)
    }
}

impl<F: PrimeField + Absorb, U: UserData<F>, S: Signature<F>> UserBul<F, U> for SigObjStore<F, S> {
    fn has_never_recieved_nul(&self, nul: &Nul<F>) -> bool {
        for i in &self.old_nuls {
            if i == nul {
                return false;
            }
        }
        true
    }

    fn append_value<PubArgs, Snark: ark_snark::SNARK<F>, const NUMCBS: usize>(
        &mut self,
        object: Com<F>,
        old_nul: Nul<F>,
        cb_com_list: [Com<F>; NUMCBS],
        _args: PubArgs,
        _proof: Snark::Proof,
        _memb_data: Option<Self::MembershipPub>,
        _verif_key: &Snark::VerifyingKey,
    ) -> Result<(), Self::Error> {
        let mut rng = thread_rng();
        let out = S::sign(&self.privkey, &mut rng, object);
        match out {
            Some(x) => {
                self.coms.push(object);
                self.old_nuls.push(old_nul);
                self.cb_com_lists.push(cb_com_list.into());
                self.sigs.push(x);
                Ok(())
            }
            None => Err(()),
        }
    }
}

impl<F: PrimeField + Absorb, U: UserData<F>, S: Signature<F>> JoinableBulletin<F, U>
    for SigObjStore<F, S>
where
    Standard: Distribution<F>,
{
    type PubData = ();

    fn join_bul(
        &mut self,
        object: crate::generic::object::Com<F>,
        _pub_data: (),
    ) -> Result<(), Self::Error> {
        let mut rng = thread_rng();
        let out = S::sign(&self.privkey, &mut rng, object);
        match out {
            Some(x) => {
                self.coms.push(object);
                self.old_nuls.push(rng.gen());
                self.cb_com_lists.push(vec![]);
                self.sigs.push(x);
                Ok(())
            }
            None => Err(()),
        }
    }
}

pub trait NonmembStore<F: PrimeField + Absorb>
where
    Standard: Distribution<F>,
{
    type NonMembershipWitness: Clone;
    type NonMembershipWitnessVar: Clone + AllocVar<Self::NonMembershipWitness, F>;

    type NonMembershipPub: Clone;
    type NonMembershipPubVar: Clone + AllocVar<Self::NonMembershipPub, F>;

    fn new(rng: &mut (impl CryptoRng + RngCore)) -> Self;

    fn update_epoch(
        &mut self,
        rng: &mut (impl CryptoRng + RngCore),
        current_store: Vec<PlainTikCrypto<F>>,
    );

    fn get_epoch(&self) -> F;

    fn get_nmemb_witness(&self, tik: &PlainTikCrypto<F>) -> Option<Self::NonMembershipWitness>;

    fn verify_not_in(&self, tik: PlainTikCrypto<F>) -> bool;

    fn enforce_nonmembership_of(
        tikvar: PlainTikCryptoVar<F>,
        extra_witness: Self::NonMembershipWitnessVar,
        extra_pub: Self::NonMembershipPubVar,
    ) -> Result<Boolean<F>, SynthesisError>;
}

#[derive(Clone, Default, Debug)]
pub struct CallbackStore<F: PrimeField + Absorb, S: Signature<F>, B: NonmembStore<F>>
where
    Standard: Distribution<F>,
{
    privkey: S::Privkey,
    pub pubkey: S::Pubkey,
    pub memb_called_cbs: Vec<(PlainTikCrypto<F>, F, Time<F>)>,
    pub memb_cbs_sigs: Vec<S::Sig>,
    pub nmemb_bul: B,
}

impl<F: PrimeField + Absorb, S: Signature<F>, B: NonmembStore<F>> CallbackStore<F, S, B>
where
    Standard: Distribution<F>,
{
    pub fn new(rng: &mut (impl CryptoRng + RngCore)) -> Self {
        let sk = S::gen_key(rng);
        Self {
            privkey: sk.clone(),
            pubkey: S::get_pubkey(&sk),
            memb_called_cbs: vec![],
            memb_cbs_sigs: vec![],
            nmemb_bul: B::new(rng),
        }
    }

    pub fn from(
        privkey: S::Privkey,
        db: Vec<(PlainTikCrypto<F>, F, Time<F>, S::Sig)>,
        nmemb_bul: B,
    ) -> Self {
        let pubkey = S::get_pubkey(&privkey);
        let memb_cbs_sigs = db.iter().map(|(_, _, _, s)| s.clone()).collect();
        let memb_called_cbs = db.into_iter().map(|(t, a, e, _)| (t, a, e)).collect();
        Self {
            privkey,
            pubkey,
            memb_called_cbs,
            memb_cbs_sigs,
            nmemb_bul,
        }
    }

    pub fn from_only_memb(
        privkey: S::Privkey,
        db: Vec<(PlainTikCrypto<F>, F, Time<F>, S::Sig)>,
    ) -> Self {
        let mut rng = thread_rng();

        let mut nmemb_bul = B::new(&mut rng);

        let tiks = db.iter().map(|(t, _, _, _)| t.clone()).collect();

        nmemb_bul.update_epoch(&mut rng, tiks);

        Self::from(privkey, db, nmemb_bul)
    }

    pub fn get_pubkey(&self) -> S::Pubkey {
        self.pubkey.clone()
    }

    pub fn get_db(&self) -> Vec<(PlainTikCrypto<F>, F, Time<F>, S::Sig)> {
        (0..(self.memb_called_cbs.len()))
            .map(|x| {
                (
                    self.memb_called_cbs[x].0.clone(),
                    self.memb_called_cbs[x].1,
                    self.memb_called_cbs[x].2,
                    self.memb_cbs_sigs[x].clone(),
                )
            })
            .collect()
    }

    pub fn rotate_key(&mut self, new_key: S::Privkey) -> Result<(), ()> {
        self.pubkey = S::get_pubkey(&new_key);
        self.privkey = new_key;
        let mut rng = thread_rng();
        let mut v = vec![];
        for i in 0..self.memb_called_cbs.len() {
            let out = S::sign(
                &self.privkey,
                &mut rng,
                <Poseidon<2>>::hash(&[
                    self.memb_called_cbs[i].0 .0,
                    self.memb_called_cbs[i].1,
                    self.memb_called_cbs[i].2,
                ]),
            );

            match out {
                Some(x) => {
                    v.push(x);
                }
                None => {
                    return Err(());
                }
            }
        }

        self.memb_cbs_sigs = v;

        Ok(())
    }

    pub fn get_memb_witness(&self, tik: &PlainTikCrypto<F>) -> Option<S::Sig> {
        for (i, (t, _, _)) in (&self.memb_called_cbs).into_iter().enumerate() {
            if t == tik {
                return Some(self.memb_cbs_sigs[i].clone());
            }
        }
        None
    }

    pub fn get_nmemb_witness(&self, tik: &PlainTikCrypto<F>) -> Option<B::NonMembershipWitness> {
        self.nmemb_bul.get_nmemb_witness(tik)
    }

    pub fn get_epoch(&self) -> F {
        self.nmemb_bul.get_epoch()
    }

    pub fn update_epoch(&mut self, rng: &mut (impl CryptoRng + RngCore)) {
        self.nmemb_bul.update_epoch(
            rng,
            (&self.memb_called_cbs)
                .into_iter()
                .map(|x| x.0.clone())
                .collect(),
        );
    }
}

impl<F: PrimeField + Absorb, S: Signature<F>, B: NonmembStore<F>>
    PublicCallbackBul<F, F, PlainTikCrypto<F>> for CallbackStore<F, S, B>
where
    Standard: Distribution<F>,
{
    type Error = ();

    type MembershipWitness = S::Sig;

    type MembershipWitnessVar = S::SigVar;

    type NonMembershipWitness = B::NonMembershipWitness;

    type NonMembershipWitnessVar = B::NonMembershipWitnessVar;

    type MembershipPub = S::Pubkey;

    type MembershipPubVar = S::PubkeyVar;

    type NonMembershipPub = B::NonMembershipPub;

    type NonMembershipPubVar = B::NonMembershipPubVar;

    fn verify_in(&self, tik: PlainTikCrypto<F>) -> Option<(F, Time<F>)> {
        for (t, arg, time) in &self.memb_called_cbs {
            if t == &tik {
                return Some((*arg, *time));
            }
        }
        None
    }

    fn verify_not_in(&self, tik: PlainTikCrypto<F>) -> bool {
        self.nmemb_bul.verify_not_in(tik)
    }

    fn enforce_membership_of(
        tikvar: (PlainTikCryptoVar<F>, FpVar<F>, TimeVar<F>),
        extra_witness: Self::MembershipWitnessVar,
        extra_pub: Self::MembershipPubVar,
    ) -> Result<Boolean<F>, SynthesisError> {
        S::verify_zk(
            extra_pub,
            extra_witness,
            <Poseidon<2>>::hash_in_zk(&[tikvar.0 .0, tikvar.1, tikvar.2])?,
        )
    }

    fn enforce_nonmembership_of(
        tikvar: PlainTikCryptoVar<F>,
        extra_witness: Self::NonMembershipWitnessVar,
        extra_pub: Self::NonMembershipPubVar,
    ) -> Result<Boolean<F>, SynthesisError> {
        B::enforce_nonmembership_of(tikvar, extra_witness, extra_pub)
    }
}

impl<F: PrimeField + Absorb, S: Signature<F>, B: NonmembStore<F>>
    CallbackBulletin<F, F, PlainTikCrypto<F>> for CallbackStore<F, S, B>
where
    Standard: Distribution<F>,
{
    fn has_never_recieved_tik(&self, tik: &PlainTikCrypto<F>) -> bool {
        for (x, _, _) in &self.memb_called_cbs {
            if x == tik {
                return false;
            }
        }
        true
    }

    fn append_value(
        &mut self,
        tik: PlainTikCrypto<F>,
        enc_args: F,
        _signature: (),
        time: Time<F>,
    ) -> Result<(), Self::Error> {
        let mut rng = thread_rng();
        let out = S::sign(
            &self.privkey,
            &mut rng,
            <Poseidon<2>>::hash(&[tik.0, enc_args, time]),
        );

        match out {
            Some(x) => {
                self.memb_called_cbs.push((tik, enc_args, time));
                self.memb_cbs_sigs.push(x);
                Ok(())
            }
            None => Err(()),
        }
    }
}

#[derive(Clone)]
pub struct CentralStore<F: PrimeField + Absorb, S: Signature<F>, B: NonmembStore<F>>
where
    Standard: Distribution<F>,
{
    pub obj_bul: SigObjStore<F, S>,
    pub callback_bul: CallbackStore<F, S, B>,

    pub interaction_ids: Vec<u64>,
    pub cb_tickets: Vec<
        Vec<(
            CallbackCom<F, F, PlainTikCrypto<F>>,
            <PlainTikCrypto<F> as AECipherSigZK<F, F>>::Rand,
        )>,
    >,
}

impl<F: PrimeField + Absorb, S: Signature<F>, B: NonmembStore<F>>
    ServiceProvider<F, F, PlainTikCrypto<F>> for CentralStore<F, S, B>
where
    Standard: Distribution<F>,
{
    type Error = ();
    type InteractionData = u64;

    fn has_never_recieved_tik(&self, tik: PlainTikCrypto<F>) -> bool {
        for j in &self.cb_tickets {
            for (a, _) in j {
                if a.cb_entry.tik == tik {
                    return false;
                }
            }
        }
        true
    }

    fn store_interaction<U: UserData<F>, Snark: ark_snark::SNARK<F>, const NUMCBS: usize>(
        &mut self,
        interaction: crate::generic::user::ExecutedMethod<F, Snark, F, PlainTikCrypto<F>, NUMCBS>,
        data: u64,
    ) -> Result<(), Self::Error> {
        self.interaction_ids.push(data);
        self.cb_tickets.push(interaction.cb_tik_list.to_vec());
        Ok(())
    }
}

impl<F: PrimeField + Absorb, S: Signature<F>, B: NonmembStore<F>> CentralStore<F, S, B>
where
    Standard: Distribution<F>,
{
    pub fn new(rng: &mut (impl CryptoRng + RngCore)) -> Self {
        Self {
            callback_bul: CallbackStore::new(rng),
            obj_bul: SigObjStore::new(rng),
            interaction_ids: vec![],
            cb_tickets: vec![],
        }
    }
}

pub type SigStore<F, S> = CentralStore<F, S, SigRangeStore<F, S>>;

pub type UOVObjStore<F> = SigObjStore<F, BleedingUOV<F>>;
pub type UOVCallbackStore<F> = CallbackStore<F, BleedingUOV<F>, SigRangeStore<F, BleedingUOV<F>>>;
pub type UOVStore<F> = CentralStore<F, BleedingUOV<F>, SigRangeStore<F, BleedingUOV<F>>>;
