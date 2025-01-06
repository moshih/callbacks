use crate::{
    crypto::hash::HasherZK,
    generic::{
        bulletin::{CallbackBul, JoinableBulletin, PublicCallbackBul, PublicUserBul, UserBul},
        callbacks::CallbackCom,
        object::{Com, Nul, Time, TimeVar},
        service::ServiceProvider,
        user::UserData,
    },
    impls::{
        centralized::{
            crypto::{FakeSigPubkey, FakeSigPubkeyVar, NoSigOTP},
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

/// This is a centralized object storage system, with proofs of membership.
///
/// To add an object, object commitments are signed with a private key associated to the server.
///
/// To prove membership, users will then prove knowledge of a signature that verifies under the
/// public key with their user object commitment.
///
/// Note that this implements [`PublicUserBul`] and [`UserBul`].
#[derive(Clone, Default, Debug)]
pub struct SigObjStore<F: PrimeField + Absorb, S: Signature<F>> {
    privkey: S::Privkey,

    /// The public key to verify object commitments in the bulletin.
    pub pubkey: S::Pubkey,

    /// The object commitments.
    pub coms: Vec<Com<F>>,

    /// The old nullifiers for each object.
    pub old_nuls: Vec<Nul<F>>,

    /// The callback commitments given by the users.
    pub cb_com_lists: Vec<Vec<Com<F>>>,

    /// The signatures on each object.
    pub sigs: Vec<S::Sig>,
}

impl<F: PrimeField + Absorb, S: Signature<F>> SigObjStore<F, S> {
    /// Construct a new SigObjStore.
    ///
    /// Generates a new private key and public key pair.
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

    /// Given an already existing database, initialize the store from this database.
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

    /// Get the public key.
    pub fn get_pubkey(&self) -> S::Pubkey {
        self.pubkey.clone()
    }

    /// Get the full database.
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

    /// Rotate keys. Resigns all object commitments with the new key.
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

    /// Get the signature of a specific object. Returns None if the object is not contained in the
    /// bulletin.
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

    fn get_membership_data(&self, object: Com<F>) -> Option<(S::Pubkey, S::Sig)> {
        let sig = self.get_signature_of(&object);
        sig.map(|t| (self.get_pubkey().clone(), t))
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
    type Error = ();

    fn has_never_received_nul(&self, nul: &Nul<F>) -> bool {
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

/// This is a centralized nonmembership storage system for tickets.
///
/// Specifically, this trait encompasses nonmembership for plain tickets.
///
///
/// While proofs of membership remain static (a ticket which was once a member will always be a
/// member), this is not true for nonmembership.
///
/// For example, one may have a proof of nonmembership for a ticket at some point in the past, but
/// it could change when the ticket is appended to the bulletin.
///
/// Therefore, this trait also captures the time with the `epoch`. To update all proofs of
/// nonmembership for tickets, one has to call [`NonmembStore::update_epoch`].
///
/// Verifying nonmembership should also account for the epoch. Any nonmembership proof should be
/// unique with respect to the epoch, so any nonmembership witness must encode the information of
/// the epoch.
pub trait NonmembStore<F: PrimeField + Absorb>
where
    Standard: Distribution<F>,
{
    /// A nonmembership witness.
    type NonMembershipWitness: Clone + Default;
    /// A nonmembership witness in-circuit.
    type NonMembershipWitnessVar: Clone + AllocVar<Self::NonMembershipWitness, F>;

    /// Nonmembership public data.
    type NonMembershipPub: Clone + Default;
    /// Nonmembership public data in-circuit.
    type NonMembershipPubVar: Clone + AllocVar<Self::NonMembershipPub, F>;

    /// Construct a new nonmembership store.
    fn new(rng: &mut (impl CryptoRng + RngCore)) -> Self;

    /// Update the epoch.
    ///
    /// This takes in a list of tickets in the bulletin. This should be *all* the tickets in the
    /// bulletin. This will step the epoch and construct new proofs of nonmembership for elements
    /// not in this set.
    fn update_epoch(
        &mut self,
        rng: &mut (impl CryptoRng + RngCore),
        current_store: Vec<FakeSigPubkey<F>>,
    );

    /// Get the current epoch.
    fn get_epoch(&self) -> F;

    /// Get nonmembership data for a specific ticket. If the ticket is a member, this should return
    /// None.
    fn get_nmemb(
        &self,
        tik: &FakeSigPubkey<F>,
    ) -> Option<(Self::NonMembershipPub, Self::NonMembershipWitness)>;

    /// Return true if the ticket is a non-member, and false if the ticket is a member.
    fn verify_not_in(&self, tik: FakeSigPubkey<F>) -> bool;

    /// Prove nonmembership in-circuit for a ticket. Returns `true` if not a member, and `false` if
    /// a member.
    fn enforce_nonmembership_of(
        tikvar: FakeSigPubkeyVar<F>,
        extra_witness: Self::NonMembershipWitnessVar,
        extra_pub: Self::NonMembershipPubVar,
    ) -> Result<Boolean<F>, SynthesisError>;
}

/// A centralized callback storage system with proofs of membership and nonmembership.
///
/// To add a ticket, the ticket is signed by the private key associated to the callback bulletin.
/// Along with this **the ticket is also inserted into a nonmembership store**, which implements
/// [`NonmembStore`].
///
/// To prove membership, users may then prove knowledge of a signature on the callback ticket which verifies under the
/// public key.
///
/// To prove nonmembership, one uses the [`NonmembStore`] circuit.
#[derive(Clone, Default, Debug)]
pub struct CallbackStore<F: PrimeField + Absorb, S: Signature<F>, B: NonmembStore<F>>
where
    Standard: Distribution<F>,
{
    privkey: S::Privkey,
    /// The public key for verifying membership of tickets.
    pub pubkey: S::Pubkey,
    /// The called tickets.
    pub memb_called_cbs: Vec<(FakeSigPubkey<F>, F, Time<F>)>,
    /// The signatures on the called tickets.
    pub memb_cbs_sigs: Vec<S::Sig>,
    /// A nonmembership bulletin for proofs of nonmembership on called tickets.
    pub nmemb_bul: B,
}

impl<F: PrimeField + Absorb, S: Signature<F>, B: NonmembStore<F>> CallbackStore<F, S, B>
where
    Standard: Distribution<F>,
{
    /// Construct a new callback store.
    ///
    /// Generates a random public key / private key pair.
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

    /// Given an already existing database and a nonmembership store, initialize the store from
    /// this database.
    pub fn from(
        privkey: S::Privkey,
        db: Vec<(FakeSigPubkey<F>, F, Time<F>, S::Sig)>,
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

    /// Given an already existing database, initialize the store from this databse.
    ///
    /// This constructs a new nonmembership bulletin, and steps the epoch using the database to
    /// commit all tickets so proofs of nonmembership can be generated. See [`NonmembStore`] for
    /// more information.
    pub fn from_only_memb(
        privkey: S::Privkey,
        db: Vec<(FakeSigPubkey<F>, F, Time<F>, S::Sig)>,
    ) -> Self {
        let mut rng = thread_rng();

        let mut nmemb_bul = B::new(&mut rng);

        let tiks = db.iter().map(|(t, _, _, _)| t.clone()).collect();

        nmemb_bul.update_epoch(&mut rng, tiks);

        Self::from(privkey, db, nmemb_bul)
    }

    /// Get the public key for membership.
    pub fn get_pubkey(&self) -> S::Pubkey {
        self.pubkey.clone()
    }

    /// Get the database (this is the membership database).
    pub fn get_db(&self) -> Vec<(FakeSigPubkey<F>, F, Time<F>, S::Sig)> {
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

    /// Rotate the key for membership. All tickets are resigned under the new private key.
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
                    self.memb_called_cbs[i].0.to(),
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

    /// Get a membership witness (a signature) for a specific ticket. If the ticket is not in the
    /// bulletin, this should return None.
    pub fn get_memb_witness(&self, tik: &FakeSigPubkey<F>) -> Option<S::Sig> {
        for (i, (t, _, _)) in (self.memb_called_cbs).iter().enumerate() {
            if t == tik {
                return Some(self.memb_cbs_sigs[i].clone());
            }
        }
        None
    }

    /// Get a nonmembership witness for a ticket. If the ticket is in the bulletin, then this
    /// should return None.
    pub fn get_nmemb_witness(&self, tik: &FakeSigPubkey<F>) -> Option<B::NonMembershipWitness> {
        self.nmemb_bul.get_nmemb(tik).map(|x| x.1)
    }

    /// Get the epoch of the nonmembership bulletin. See [`NonmembStore`] for more details.
    pub fn get_epoch(&self) -> F {
        self.nmemb_bul.get_epoch()
    }

    /// Update the epoch of the nonmembership bulletin with the current tickets in the membership
    /// bulletin.
    ///
    /// This commits any outstanding tickets so proofs of nonmembership can be generated. See
    /// [`NonmembStore`] for more details.
    pub fn update_epoch(&mut self, rng: &mut (impl CryptoRng + RngCore)) {
        self.nmemb_bul.update_epoch(
            rng,
            (self.memb_called_cbs).iter().map(|x| x.0.clone()).collect(),
        );
    }
}

impl<F: PrimeField + Absorb, S: Signature<F>, B: NonmembStore<F>>
    PublicCallbackBul<F, F, NoSigOTP<F>> for CallbackStore<F, S, B>
where
    Standard: Distribution<F>,
{
    type MembershipWitness = S::Sig;

    type MembershipWitnessVar = S::SigVar;

    type NonMembershipWitness = B::NonMembershipWitness;

    type NonMembershipWitnessVar = B::NonMembershipWitnessVar;

    type MembershipPub = S::Pubkey;

    type MembershipPubVar = S::PubkeyVar;

    type NonMembershipPub = B::NonMembershipPub;

    type NonMembershipPubVar = B::NonMembershipPubVar;

    fn verify_in(&self, tik: FakeSigPubkey<F>) -> Option<(F, Time<F>)> {
        for (t, arg, time) in &self.memb_called_cbs {
            if t == &tik {
                return Some((*arg, *time));
            }
        }
        None
    }

    fn verify_not_in(&self, tik: FakeSigPubkey<F>) -> bool {
        self.nmemb_bul.verify_not_in(tik)
    }

    fn get_membership_data(
        &self,
        tik: FakeSigPubkey<F>,
    ) -> (
        S::Pubkey,
        S::Sig,
        B::NonMembershipPub,
        B::NonMembershipWitness,
    ) {
        let d = self.nmemb_bul.get_nmemb(&tik);
        match d {
            Some((p, w)) => (self.get_pubkey(), S::Sig::default(), p, w),
            None => (
                self.get_pubkey(),
                self.get_memb_witness(&tik).unwrap(),
                B::NonMembershipPub::default(),
                B::NonMembershipWitness::default(),
            ),
        }
    }

    fn enforce_membership_of(
        tikvar: (FakeSigPubkeyVar<F>, FpVar<F>, TimeVar<F>),
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
        tikvar: FakeSigPubkeyVar<F>,
        extra_witness: Self::NonMembershipWitnessVar,
        extra_pub: Self::NonMembershipPubVar,
    ) -> Result<Boolean<F>, SynthesisError> {
        B::enforce_nonmembership_of(tikvar, extra_witness, extra_pub)
    }
}

impl<F: PrimeField + Absorb, S: Signature<F>, B: NonmembStore<F>> CallbackBul<F, F, NoSigOTP<F>>
    for CallbackStore<F, S, B>
where
    Standard: Distribution<F>,
{
    type Error = ();

    fn has_never_received_tik(&self, tik: &FakeSigPubkey<F>) -> bool {
        for (x, _, _) in &self.memb_called_cbs {
            if x == tik {
                return false;
            }
        }
        true
    }

    fn append_value(
        &mut self,
        tik: FakeSigPubkey<F>,
        enc_args: F,
        _signature: (),
        time: Time<F>,
    ) -> Result<(), Self::Error> {
        let mut rng = thread_rng();
        let out = S::sign(
            &self.privkey,
            &mut rng,
            <Poseidon<2>>::hash(&[tik.to(), enc_args, time]),
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

/// A centralized storage system for both objects and tickets.
///
/// This consists of object commitment storage, and callback ticket storage.
///
/// Along with that, the central store stores interactions, and so acts as a centralized service
/// provider *and* both bulletins.
#[derive(Clone)]
pub struct CentralStore<F: PrimeField + Absorb, S: Signature<F>, B: NonmembStore<F>>
where
    Standard: Distribution<F>,
{
    /// The object bulletin storing commitments.
    pub obj_bul: SigObjStore<F, S>,

    /// The callback bulletin storing tickets.
    pub callback_bul: CallbackStore<F, S, B>,

    /// A list of interactions which have occurred by their interaction id.
    pub interaction_ids: Vec<u64>,
    /// A list of tickets which have not yet been called but handed to the service, each associated
    /// to the interaction id at the same index.
    pub cb_tickets: Vec<Vec<(CallbackCom<F, F, NoSigOTP<F>>, F)>>,
}

impl<F: PrimeField + Absorb, S: Signature<F>, B: NonmembStore<F>> ServiceProvider<F, F, NoSigOTP<F>>
    for CentralStore<F, S, B>
where
    Standard: Distribution<F>,
{
    type Error = ();
    type InteractionData = u64;

    fn has_never_received_tik(&self, tik: FakeSigPubkey<F>) -> bool {
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
        interaction: crate::generic::user::ExecutedMethod<F, Snark, F, NoSigOTP<F>, NUMCBS>,
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
    /// Construct a new central store.
    pub fn new(rng: &mut (impl CryptoRng + RngCore)) -> Self {
        Self {
            callback_bul: CallbackStore::new(rng),
            obj_bul: SigObjStore::new(rng),
            interaction_ids: vec![],
            cb_tickets: vec![],
        }
    }
}

/// Type alias for a central store which uses signed ranges for nonmembership.
pub type SigStore<F, S> = CentralStore<F, S, SigRangeStore<F, S>>;

/// A user object store which uses UOV signatures.
pub type UOVObjStore<F> = SigObjStore<F, BleedingUOV<F>>;

/// A callback storage system which uses UOV signatures.
pub type UOVCallbackStore<F> = CallbackStore<F, BleedingUOV<F>, SigRangeStore<F, BleedingUOV<F>>>;

/// A central storage system which uses UOV signatures.
pub type UOVStore<F> = CentralStore<F, BleedingUOV<F>, SigRangeStore<F, BleedingUOV<F>>>;
