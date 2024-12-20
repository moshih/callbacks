use crate::crypto::hash::HasherZK;
use crate::generic::asynchr::bulletin::{
    CallbackBulletin, JoinableBulletin, PublicCallbackBul, PublicUserBul, UserBul,
};
use crate::generic::asynchr::service::ServiceProvider;
use crate::generic::bulletin;
use crate::generic::callbacks::CallbackCom;
use crate::generic::object::{Com, ComVar, Nul, Time, TimeVar};
use crate::generic::user::UserData;
use crate::impls::centralized::crypto::{PlainTikCrypto, PlainTikCryptoVar};
use crate::impls::centralized::sig::{Pubkey, PubkeyVar, Sig, SigVar};
use crate::impls::hash::Poseidon;
use ark_crypto_primitives::sponge::Absorb;
use ark_ff::PrimeField;
use ark_r1cs_std::fields::fp::FpVar;
use ark_r1cs_std::prelude::Boolean;
use ark_relations::r1cs::SynthesisError;
use ark_serialize::Compress;
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use ark_snark::SNARK;
use rand::distributions::Standard;
use rand::prelude::Distribution;
use rand::{thread_rng, Rng};
use std::cmp::Ordering;

use super::sig::{CompressedPrivKey, PrivKey, SignedRange, SignedRangeVar};

pub trait DbHandle {
    type Error: std::fmt::Debug;

    #[allow(async_fn_in_trait)]
    async fn get_user_privkey(&self) -> Vec<u8>;

    #[allow(async_fn_in_trait)]
    async fn set_user_privkey(&mut self, v: &[u8]);

    #[allow(async_fn_in_trait)]
    async fn insert_updated_object(
        &mut self,
        object: &[u8],
        old_nul: &[u8],
        cb_com_list: &[u8],
        sig: &[u8],
    ) -> Result<(), Self::Error>;

    #[allow(async_fn_in_trait)]
    async fn object_is_in(&self, object: &[u8], old_nul: &[u8], cb_com_list: &[u8]) -> bool;

    #[allow(async_fn_in_trait)]
    async fn has_never_recieved_nul(&self, nul: &[u8]) -> bool;

    type ExternalVerifData;

    #[allow(async_fn_in_trait)]
    async fn verify_new_object(
        &self,
        object: &[u8],
        data: Self::ExternalVerifData,
    ) -> Result<(), Self::Error>;

    #[allow(async_fn_in_trait)]
    async fn insert_interaction_and_tickets(
        &mut self,
        interaction_id: u64,
        interaction: &[u8],
        internal_tickets: &[Vec<u8>],
    ) -> Result<(), Self::Error>;

    #[allow(async_fn_in_trait)]
    async fn get_cbmemb_privkey(&self) -> Vec<u8>;

    #[allow(async_fn_in_trait)]
    async fn set_cbmemb_privkey(&mut self, v: &[u8]);

    #[allow(async_fn_in_trait)]
    async fn get_cbnmemb_privkey(&self) -> Vec<u8>;

    #[allow(async_fn_in_trait)]
    async fn set_cbnmemb_privkey(&mut self, v: &[u8]);

    #[allow(async_fn_in_trait)]
    async fn has_never_recieved_tik(&self, tik: &[u8]) -> bool;

    #[allow(async_fn_in_trait)]
    async fn publish_called_ticket(
        &mut self,
        ticket: &[u8],
        enc_args: &[u8],
        bbcb_sig: &[u8],
        time: &[u8],
    ) -> Result<(), Self::Error>;

    #[allow(async_fn_in_trait)]
    async fn get_all_called_tickets(&self) -> Vec<&[u8]>;

    #[allow(async_fn_in_trait)]
    async fn has_ticket_been_called(&self, ticket: &[u8]) -> Option<(&[u8], &[u8], &[u8])>;

    #[allow(async_fn_in_trait)]
    async fn has_ticket_not_been_called(&self, ticket: &[u8]) -> bool;
}

pub struct CentralObjectStore<D: DbHandle, F: PrimeField + Absorb>(
    pub D,
    pub Vec<u8>,
    pub Vec<u8>,
    pub PrivKey<F>,
    pub PrivKey<F>,
    pub PrivKey<F>,
);

impl<D: DbHandle, F: PrimeField + Absorb> CentralObjectStore<D, F>
where
    Standard: Distribution<F>,
{
    pub async fn start(d: D, epoch: Time<F>) -> Self
    where
        Standard: Distribution<F>,
    {
        let just_tickets = d.get_all_called_tickets().await;

        let mut tiks = vec![];

        for i in just_tickets {
            let out_tik = <PlainTikCrypto<F>>::deserialize_with_mode(
                i,
                Compress::Yes,
                ark_serialize::Validate::No,
            )
            .unwrap();
            tiks.push(out_tik);
        }

        tiks.sort();

        let mut rng = thread_rng();

        let v = d.get_user_privkey().await;
        let ukey = CompressedPrivKey::deserialize_with_mode(
            &*v,
            Compress::Yes,
            ark_serialize::Validate::No,
        )
        .unwrap()
        .into_key();

        let v = d.get_cbmemb_privkey().await;
        let pkey = CompressedPrivKey::deserialize_with_mode(
            &*v,
            Compress::Yes,
            ark_serialize::Validate::No,
        )
        .unwrap()
        .into_key();

        let v = d.get_cbnmemb_privkey().await;
        let npkey = CompressedPrivKey::deserialize_with_mode(
            &*v,
            Compress::Yes,
            ark_serialize::Validate::No,
        )
        .unwrap()
        .into_key();

        let mut updated_ranges = vec![];

        let mut bot = F::ZERO;
        for top in &tiks {
            if bot != top.0 {
                updated_ranges.push((bot, top.0));
            }
            bot = top.0 + F::ONE;
        }

        if bot != F::ZERO {
            updated_ranges.push((
                bot,
                F::from_bigint(F::MODULUS_MINUS_ONE_DIV_TWO).unwrap() - F::ONE,
            ));
        }

        if tiks.is_empty() {
            updated_ranges.push((
                F::ZERO,
                F::from_bigint(F::MODULUS_MINUS_ONE_DIV_TWO).unwrap() - F::ONE,
            ));
        }

        let mut sv = vec![];
        for range in updated_ranges {
            let out = npkey
                .sign_message::<Poseidon<2>>(
                    &mut rng,
                    <Poseidon<2>>::hash(&[range.0, range.1, epoch]),
                )
                .unwrap();
            sv.push(SignedRange {
                range,
                sig: out,
                epoch,
            });
        }

        let mut sr = Vec::new();
        sv.serialize_with_mode(&mut sr, Compress::Yes).unwrap();

        let mut ep = Vec::new();
        epoch.serialize_with_mode(&mut ep, Compress::Yes).unwrap();

        CentralObjectStore(d, sr, ep, ukey, pkey, npkey)
    }

    pub async fn rotate_keys(&mut self, ukey: Vec<u8>, cbkey: Vec<u8>, ncbkey: Vec<u8>) {
        self.0.set_user_privkey(&ukey).await;
        self.0.set_cbmemb_privkey(&cbkey).await;
        self.0.set_cbnmemb_privkey(&ncbkey).await;

        self.3 = CompressedPrivKey::deserialize_with_mode(
            &*ukey,
            Compress::Yes,
            ark_serialize::Validate::No,
        )
        .unwrap()
        .into_key();

        self.4 = CompressedPrivKey::deserialize_with_mode(
            &*cbkey,
            Compress::Yes,
            ark_serialize::Validate::No,
        )
        .unwrap()
        .into_key();

        self.5 = CompressedPrivKey::deserialize_with_mode(
            &*ncbkey,
            Compress::Yes,
            ark_serialize::Validate::No,
        )
        .unwrap()
        .into_key();

        let just_tickets = self.0.get_all_called_tickets().await;

        let mut tiks = vec![];

        for i in just_tickets {
            let out_tik = <PlainTikCrypto<F>>::deserialize_with_mode(
                i,
                Compress::Yes,
                ark_serialize::Validate::No,
            )
            .unwrap();
            tiks.push(out_tik);
        }

        tiks.sort();

        let mut rng = thread_rng();

        let mut updated_ranges = vec![];

        let mut bot = F::ZERO;
        for top in &tiks {
            if bot != top.0 {
                updated_ranges.push((bot, top.0));
            }
            bot = top.0 + F::ONE;

            let (arg, _, time) = PublicCallbackBul::verify_in(self, top.clone())
                .await
                .unwrap();
            CallbackBulletin::append_value(self, top.clone(), arg, (), time)
                .await
                .expect("An unknown error occurred.\n");
        }

        if bot != F::ZERO {
            updated_ranges.push((
                bot,
                F::from_bigint(F::MODULUS_MINUS_ONE_DIV_TWO).unwrap() - F::ONE,
            ));
        }

        if tiks.is_empty() {
            updated_ranges.push((
                F::ZERO,
                F::from_bigint(F::MODULUS_MINUS_ONE_DIV_TWO).unwrap() - F::ONE,
            ));
        }

        let epoch =
            F::deserialize_with_mode(&*self.2, Compress::Yes, ark_serialize::Validate::No).unwrap();

        let mut sv = vec![];
        for range in updated_ranges {
            let out = self
                .5
                .sign_message::<Poseidon<2>>(
                    &mut rng,
                    <Poseidon<2>>::hash(&[range.0, range.1, epoch]),
                )
                .unwrap();
            sv.push(SignedRange {
                range,
                sig: out,
                epoch,
            });
        }

        let mut sr = Vec::new();
        sv.serialize_with_mode(&mut sr, Compress::Yes).unwrap();
    }

    pub async fn update_epoch(&mut self)
    where
        Standard: Distribution<F>,
    {
        let time =
            <Time<F>>::deserialize_with_mode(&*self.2, Compress::Yes, ark_serialize::Validate::No)
                .unwrap();

        let t = time + F::ONE;
        let mut t2 = Vec::new();
        t.serialize_with_mode(&mut t2, Compress::Yes).unwrap();
        self.2 = t2;
        let just_tickets = self.0.get_all_called_tickets().await;

        let mut tiks = vec![];

        for i in just_tickets {
            let out_tik = <PlainTikCrypto<F>>::deserialize_with_mode(
                i,
                Compress::Yes,
                ark_serialize::Validate::No,
            )
            .unwrap();
            tiks.push(out_tik);
        }

        tiks.sort();

        let mut rng = thread_rng();
        let pkey = &self.5;

        let mut updated_ranges = vec![];

        let mut bot = F::ZERO;
        for top in &tiks {
            if bot != top.0 {
                updated_ranges.push((bot, top.0));
            }
            bot = top.0 + F::ONE;
        }

        if bot != F::ZERO {
            updated_ranges.push((
                bot,
                F::from_bigint(F::MODULUS_MINUS_ONE_DIV_TWO).unwrap() - F::ONE,
            ));
        }

        if tiks.is_empty() {
            updated_ranges.push((
                F::ZERO,
                F::from_bigint(F::MODULUS_MINUS_ONE_DIV_TWO).unwrap() - F::ONE,
            ));
        }

        let mut sv = vec![];
        for range in updated_ranges {
            let out = pkey
                .sign_message::<Poseidon<2>>(&mut rng, <Poseidon<2>>::hash(&[range.0, range.1, t]))
                .unwrap();
            sv.push(SignedRange {
                range,
                sig: out,
                epoch: t,
            });
        }

        let mut sr = Vec::new();
        sv.serialize_with_mode(&mut sr, Compress::Yes).unwrap();
        self.1 = sr;
    }
}

impl<F: PrimeField + Absorb, U: UserData<F>, D: DbHandle> PublicUserBul<F, U>
    for CentralObjectStore<D, F>
{
    type Error = D::Error;

    type MembershipWitness = Sig<F>; // signature but the entirety of humanity.
    type MembershipWitnessVar = SigVar<F>;

    type MembershipPub = Pubkey<F>;

    type MembershipPubVar = PubkeyVar<F>;

    async fn verify_in<Args, Snark: SNARK<F>, const NUMCBS: usize>(
        &self,
        object: Com<F>,
        old_nul: Nul<F>,
        cb_com_list: [Com<F>; NUMCBS],
        _args: Args,
        _proof: Snark::Proof,
        _memb_data: Self::MembershipPub,
        _verif_key: &Snark::VerifyingKey,
    ) -> bool {
        let mut object_serial = Vec::new();
        object
            .serialize_with_mode(&mut object_serial, Compress::Yes)
            .unwrap();
        let mut old_nul_serial = Vec::new();
        old_nul
            .serialize_with_mode(&mut old_nul_serial, Compress::Yes)
            .unwrap();
        let mut cb_com_list_serial = Vec::new();
        cb_com_list
            .serialize_with_mode(&mut cb_com_list_serial, Compress::Yes)
            .unwrap();
        self.0
            .object_is_in(&object_serial, &old_nul_serial, &cb_com_list_serial)
            .await
    }

    fn enforce_membership_of(
        data_var: ComVar<F>,
        extra_witness: Self::MembershipWitnessVar,
        extra_pub: Self::MembershipPubVar,
    ) -> Result<(), SynthesisError> {
        Pubkey::verify_zk::<Poseidon<2>>(extra_pub, extra_witness, data_var)
    }
}

impl<F: PrimeField + Absorb, U: UserData<F>, D: DbHandle> UserBul<F, U> for CentralObjectStore<D, F>
where
    Standard: Distribution<F>,
{
    async fn has_never_recieved_nul(&self, nul: &Nul<F>) -> bool {
        let mut nul_serial = Vec::new();
        nul.serialize_with_mode(&mut nul_serial, Compress::Yes)
            .unwrap();
        self.0.has_never_recieved_nul(&nul_serial).await
    }

    async fn append_value<Args, Snark: SNARK<F>, const NUMCBS: usize>(
        &mut self,
        object: Com<F>,
        old_nul: Nul<F>,
        cb_com_list: [Com<F>; NUMCBS],
        _args: Args,
        _proof: Snark::Proof,
        _memb_data: Option<Self::MembershipPub>,
        _verif_key: &Snark::VerifyingKey,
    ) -> Result<(), Self::Error> {
        let mut object_serial = Vec::new();
        object
            .serialize_with_mode(&mut object_serial, Compress::Yes)
            .unwrap();
        let mut old_nul_serial = Vec::new();
        old_nul
            .serialize_with_mode(&mut old_nul_serial, Compress::Yes)
            .unwrap();

        let mut cb_com_list_serial = Vec::new();
        cb_com_list
            .serialize_with_mode(&mut cb_com_list_serial, Compress::Yes)
            .unwrap();

        let mut rng = thread_rng();

        let out = self.3.sign_message::<Poseidon<2>>(&mut rng, object);

        let mut sig = Vec::new();
        out.serialize_with_mode(&mut sig, Compress::Yes).unwrap();

        self.0
            .insert_updated_object(&object_serial, &old_nul_serial, &cb_com_list_serial, &sig)
            .await
    }
}

impl<F: PrimeField + Absorb, U: UserData<F>, D: DbHandle> JoinableBulletin<F, U>
    for CentralObjectStore<D, F>
where
    Standard: Distribution<F>,
{
    type PubData = D::ExternalVerifData;

    async fn join_bul(
        &mut self,
        object: Com<F>,
        pub_data: Self::PubData,
    ) -> Result<(), Self::Error> {
        let mut object_serial = Vec::new();
        object
            .serialize_with_mode(&mut object_serial, Compress::Yes)
            .unwrap();
        self.0.verify_new_object(&object_serial, pub_data).await?;

        let mut rng = thread_rng();

        let out = self.3.sign_message::<Poseidon<2>>(&mut rng, object);

        let mut sig = Vec::new();
        out.serialize_with_mode(&mut sig, Compress::Yes).unwrap();

        let nul: F = rng.gen();
        let cb: F = rng.gen();

        let mut ns = Vec::new();
        nul.serialize_with_mode(&mut ns, Compress::Yes).unwrap();

        let mut cbs = Vec::new();
        cb.serialize_with_mode(&mut cbs, Compress::Yes).unwrap();

        self.0
            .insert_updated_object(&object_serial, &ns, &cbs, &sig)
            .await
    }
}

impl<F: PrimeField + Absorb, D: DbHandle> PublicCallbackBul<F, F, PlainTikCrypto<F>>
    for CentralObjectStore<D, F>
where
    rand::distributions::Standard: rand::distributions::Distribution<F>,
{
    type Error = D::Error;
    type MembershipPub = Pubkey<F>;
    type MembershipPubVar = PubkeyVar<F>;
    type NonMembershipPub = Pubkey<F>;
    type NonMembershipPubVar = PubkeyVar<F>;
    type MembershipWitness = Sig<F>;
    type MembershipWitnessVar = SigVar<F>;
    type NonMembershipWitness = SignedRange<F>;
    type NonMembershipWitnessVar = SignedRangeVar<F>;

    async fn verify_in(&self, tik: PlainTikCrypto<F>) -> Option<(F, (), Time<F>)> {
        let mut tik_serial = Vec::new();
        tik.serialize_with_mode(&mut tik_serial, Compress::Yes)
            .unwrap();
        self.0
            .has_ticket_been_called(&tik_serial)
            .await
            .map(|(a, _, c)| {
                let args = F::deserialize_with_mode(a, Compress::Yes, ark_serialize::Validate::No)
                    .unwrap();
                let sig = ();
                let time =
                    Time::<F>::deserialize_with_mode(c, Compress::Yes, ark_serialize::Validate::No)
                        .unwrap();
                (args, sig, time)
            })
    }

    async fn verify_not_in(&self, tik: PlainTikCrypto<F>) -> bool {
        let mut tik_serial = Vec::new();
        tik.serialize_with_mode(&mut tik_serial, Compress::Yes)
            .unwrap();

        self.0.has_ticket_not_been_called(&tik_serial).await
    }

    fn enforce_membership_of(
        tikvar: (PlainTikCryptoVar<F>, FpVar<F>, TimeVar<F>),
        extra_witness: Self::MembershipWitnessVar,
        extra_pub: Self::MembershipPubVar,
    ) -> Result<Boolean<F>, SynthesisError> {
        Pubkey::verify_bool_zk::<Poseidon<2>>(
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
        let c0 = tikvar
            .0
            .is_cmp_unchecked(&extra_witness.range.0, Ordering::Greater, true)?;
        let c1 = tikvar
            .0
            .is_cmp_unchecked(&extra_witness.range.1, Ordering::Less, false)?;

        let range_correct = c0 & c1;

        let c2 = Pubkey::verify_bool_zk::<Poseidon<2>>(
            extra_pub,
            extra_witness.sig,
            <Poseidon<2>>::hash_in_zk(&[
                extra_witness.range.0,
                extra_witness.range.1,
                extra_witness.epoch,
            ])?,
        )?;

        Ok(range_correct & c2)
    }
}

impl<F: PrimeField + Absorb, D: DbHandle> CallbackBulletin<F, F, PlainTikCrypto<F>>
    for CentralObjectStore<D, F>
where
    rand::distributions::Standard: rand::distributions::Distribution<F>,
{
    async fn has_never_recieved_tik(&self, tik: &PlainTikCrypto<F>) -> bool {
        let mut tik_serial = Vec::new();
        tik.serialize_with_mode(&mut tik_serial, Compress::Yes)
            .unwrap();
        self.0.has_ticket_been_called(&tik_serial).await.is_none()
    }

    async fn append_value(
        &mut self,
        tik: PlainTikCrypto<F>,
        enc_args: F,
        _sig: (),
        time: Time<F>,
    ) -> Result<(), Self::Error> {
        let mut tik_serial = Vec::new();
        tik.serialize_with_mode(&mut tik_serial, Compress::Yes)
            .unwrap();
        let mut enc_args_serial = Vec::new();
        enc_args
            .serialize_with_mode(&mut enc_args_serial, Compress::Yes)
            .unwrap();

        let mut time_ser = Vec::new();
        time.serialize_with_mode(&mut time_ser, Compress::Yes)
            .unwrap();

        let mut rng = thread_rng();

        let out = self
            .4
            .sign_message::<Poseidon<2>>(&mut rng, <Poseidon<2>>::hash(&[tik.0, enc_args, time]));

        let mut out_sig = Vec::new();
        out.serialize_with_mode(&mut out_sig, Compress::Yes)
            .unwrap();

        self.0
            .publish_called_ticket(&tik_serial, &enc_args_serial, &out_sig, &time_ser)
            .await
    }
}

impl<D: DbHandle, F: PrimeField + Absorb> ServiceProvider<F, F, PlainTikCrypto<F>>
    for CentralObjectStore<D, F>
where
    Standard: Distribution<F>,
{
    type InteractionData = u64;
    type Error = D::Error;

    async fn has_never_recieved_tik(&self, ticket: PlainTikCrypto<F>) -> bool {
        let mut tik_serial = Vec::new();
        ticket
            .serialize_with_mode(&mut tik_serial, Compress::Yes)
            .unwrap();
        self.0.has_never_recieved_tik(&tik_serial).await
    }

    async fn store_interaction<U: UserData<F>, Snark: SNARK<F>, const NUMCBS: usize>(
        &mut self,
        interaction: crate::generic::user::ExecutedMethod<F, Snark, F, PlainTikCrypto<F>, NUMCBS>,
        data: u64,
    ) -> Result<(), Self::Error> {
        let mut tickets = Vec::new();
        for i in interaction.cb_tik_list.clone() {
            let mut tik_serial = Vec::new();
            i.0.serialize_with_mode(&mut tik_serial, Compress::Yes)
                .unwrap();
            tickets.push(tik_serial);
        }
        let mut inter_serial = Vec::new();
        interaction
            .serialize_with_mode(&mut inter_serial, Compress::Yes)
            .unwrap();
        self.0
            .insert_interaction_and_tickets(data, &inter_serial, &tickets)
            .await
    }
}

impl<F: PrimeField + Absorb, D: DbHandle> CentralObjectStore<D, F> {
    pub async fn call_ticket(
        &mut self,
        internal_ticket: &[u8],
        arguments: F,
    ) -> Result<(), D::Error>
    where
        rand::distributions::Standard: rand::distributions::Distribution<F>,
    {
        let cc = CallbackCom::<F, F, PlainTikCrypto<F>>::deserialize_with_mode(
            internal_ticket,
            Compress::Yes,
            ark_serialize::Validate::No,
        )
        .unwrap();
        let called = self.call(cc, arguments, PlainTikCrypto(F::zero()))?;

        let time =
            <Time<F>>::deserialize_with_mode(&*self.2, Compress::Yes, ark_serialize::Validate::No)
                .unwrap();

        self.verify_call_and_append(called.0, called.1, (), time)
            .await
            .map_err(|_| "Error verifying and appending.")
            .unwrap();

        Ok(())
    }
}

// TODO: do the same things with the DB handle for the network handle
pub trait NetworkHandle {
    type Error;

    fn object_is_in(&self, object: &[u8], old_nul: &[u8], cb_com_list: &[u8]) -> bool;

    fn has_ticket_been_called(&self, ticket: &[u8]) -> Option<(&[u8], &[u8], &[u8])>;

    fn has_ticket_not_been_called(&self, ticket: &[u8]) -> bool;
}

pub struct CentralNetBulStore<N: NetworkHandle>(pub N);

impl<F: PrimeField + Absorb, U: UserData<F>, N: NetworkHandle> bulletin::PublicUserBul<F, U>
    for CentralNetBulStore<N>
{
    type Error = N::Error;

    type MembershipWitness = Sig<F>; // signature but the entirety of humanity.

    type MembershipWitnessVar = SigVar<F>;

    type MembershipPub = Pubkey<F>;

    type MembershipPubVar = PubkeyVar<F>;

    fn verify_in<Args, Snark: SNARK<F>, const NUMCBS: usize>(
        &self,
        object: Com<F>,
        old_nul: Nul<F>,
        cb_com_list: [Com<F>; NUMCBS],
        _args: Args,
        _proof: Snark::Proof,
        _memb_data: Self::MembershipPub,
        _verif_key: &Snark::VerifyingKey,
    ) -> bool {
        let mut object_serial = Vec::new();
        object
            .serialize_with_mode(&mut object_serial, Compress::Yes)
            .unwrap();
        let mut old_nul_serial = Vec::new();
        old_nul
            .serialize_with_mode(&mut old_nul_serial, Compress::Yes)
            .unwrap();
        let mut cb_com_list_serial = Vec::new();
        cb_com_list
            .serialize_with_mode(&mut cb_com_list_serial, Compress::Yes)
            .unwrap();
        self.0
            .object_is_in(&object_serial, &old_nul_serial, &cb_com_list_serial)
    }

    fn enforce_membership_of(
        data_var: ComVar<F>,
        extra_witness: Self::MembershipWitnessVar,
        extra_pub: Self::MembershipPubVar,
    ) -> Result<(), SynthesisError> {
        Pubkey::verify_zk::<Poseidon<2>>(extra_pub, extra_witness, data_var)
    }
}

impl<F: PrimeField + Absorb, N: NetworkHandle> bulletin::PublicCallbackBul<F, F, PlainTikCrypto<F>>
    for CentralNetBulStore<N>
where
    rand::distributions::Standard: rand::distributions::Distribution<F>,
{
    type Error = N::Error;

    type MembershipPub = Pubkey<F>;
    type MembershipPubVar = PubkeyVar<F>;
    type MembershipWitness = Sig<F>;
    type MembershipWitnessVar = SigVar<F>;
    type NonMembershipPub = Pubkey<F>;
    type NonMembershipPubVar = PubkeyVar<F>;
    type NonMembershipWitness = SignedRange<F>;
    type NonMembershipWitnessVar = SignedRangeVar<F>;

    fn verify_in(&self, tik: PlainTikCrypto<F>) -> Option<(F, Time<F>)> {
        let mut tik_serial = Vec::new();
        tik.serialize_with_mode(&mut tik_serial, Compress::Yes)
            .unwrap();
        self.0.has_ticket_been_called(&tik_serial).map(|(a, _, c)| {
            let args =
                F::deserialize_with_mode(a, Compress::Yes, ark_serialize::Validate::No).unwrap();
            let time =
                Time::<F>::deserialize_with_mode(c, Compress::Yes, ark_serialize::Validate::No)
                    .unwrap();
            (args, time)
        })
    }

    fn verify_not_in(&self, tik: PlainTikCrypto<F>) -> bool {
        let mut tik_serial = Vec::new();
        tik.serialize_with_mode(&mut tik_serial, Compress::Yes)
            .unwrap();

        self.0.has_ticket_not_been_called(&tik_serial)
    }

    fn enforce_membership_of(
        tikvar: (PlainTikCryptoVar<F>, FpVar<F>, TimeVar<F>),
        extra_witness: Self::MembershipWitnessVar,
        extra_pub: Self::MembershipPubVar,
    ) -> Result<Boolean<F>, SynthesisError> {
        Pubkey::verify_bool_zk::<Poseidon<2>>(
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
        let c0 = tikvar
            .0
            .is_cmp_unchecked(&extra_witness.range.0, Ordering::Greater, true)?;
        let c1 = tikvar
            .0
            .is_cmp_unchecked(&extra_witness.range.1, Ordering::Less, false)?;

        let range_correct = c0 & c1;

        let c2 = Pubkey::verify_bool_zk::<Poseidon<2>>(
            extra_pub,
            extra_witness.sig,
            <Poseidon<2>>::hash_in_zk(&[
                extra_witness.range.0,
                extra_witness.range.1,
                extra_witness.epoch,
            ])?,
        )?;

        Ok(range_correct & c2)
    }
}
