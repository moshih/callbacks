use crate::generic::bulletin::{JoinableBulletin, PublicUserBul, UserBul};
use crate::generic::object::{Com, ComVar, Nul};
use crate::generic::user::UserData;
use crate::util::UnitVar;
use ark_crypto_primitives::sponge::Absorb;
use ark_ff::PrimeField;
use ark_relations::r1cs::SynthesisError;
use ark_serialize::CanonicalSerialize;
use ark_serialize::Compress;
use ark_snark::SNARK;

pub trait DbHandle {
    fn insert_updated_object(
        &mut self,
        object: Vec<u8>,
        old_nul: Vec<u8>,
        cb_com_list: Vec<u8>,
        sig: Vec<u8>,
    );

    fn is_in(&self, object: Vec<u8>, old_nul: Vec<u8>, cb_com_list: Vec<u8>) -> bool;

    fn has_never_recieved_nul(&self, nul: Vec<u8>) -> bool;

    fn add_and_verify_new_object<F: PrimeField, Snark: SNARK<F>, D>(
        &mut self,
        object: Com<F>,
        proof: Snark::Proof,
        verif_key: Snark::VerifyingKey,
        data: D,
    ) -> Result<(), &'static str>;
}

pub struct CentralObjectStore<D: DbHandle>(pub D);

impl<F: PrimeField + Absorb, U: UserData<F>, D: DbHandle> PublicUserBul<F, U>
    for CentralObjectStore<D>
{
    type Error = &'static str;

    type MembershipWitness = (); // signature but the entirety of humanity.

    type MembershipWitnessVar = UnitVar;

    type MembershipPub = ();

    type MembershipPubVar = UnitVar;

    fn verify_in<Args, Snark: SNARK<F>, const NUMCBS: usize>(
        &self,
        object: Com<F>,
        old_nul: Nul<F>,
        cb_com_list: [Com<F>; NUMCBS],
        _args: Args,
        _proof: Snark::Proof,
        _pub_data: (Snark::VerifyingKey, Self::MembershipPub),
    ) -> bool {
        let mut object_serial: Vec<u8> = Vec::new();
        object
            .serialize_with_mode(&mut object_serial, Compress::No)
            .unwrap();
        let mut old_nul_serial: Vec<u8> = Vec::new();
        old_nul
            .serialize_with_mode(&mut old_nul_serial, Compress::No)
            .unwrap();
        let mut cb_com_list_serial: Vec<u8> = Vec::new();
        cb_com_list
            .serialize_with_mode(&mut cb_com_list_serial, Compress::No)
            .unwrap();
        self.0
            .is_in(object_serial, old_nul_serial, cb_com_list_serial)
    }

    fn enforce_membership_of(
        data_var: ComVar<F>,
        extra_witness: Self::MembershipWitnessVar,
        extra_pub: Self::MembershipPubVar,
    ) -> Result<(), SynthesisError> {
        Ok(()) // CHECK SIGNATURE
    }
}

impl<F: PrimeField + Absorb, U: UserData<F>, D: DbHandle> UserBul<F, U> for CentralObjectStore<D> {
    fn has_never_recieved_nul(&self, nul: &Nul<F>) -> bool {
        let mut nul_serial: Vec<u8> = Vec::new();
        nul.serialize_with_mode(&mut nul_serial, Compress::No)
            .unwrap();
        self.0.has_never_recieved_nul(nul_serial)
    }

    fn append_value<Args, Snark: SNARK<F>, const NUMCBS: usize>(
        &mut self,
        object: Com<F>,
        old_nul: Nul<F>,
        cb_com_list: [Com<F>; NUMCBS],
        _args: Args,
        _proof: Snark::Proof,
        pub_data: (Snark::VerifyingKey, Self::MembershipPub),
    ) -> Result<(), Self::Error> {
        let mut object_serial: Vec<u8> = Vec::new();
        object
            .serialize_with_mode(&mut object_serial, Compress::No)
            .unwrap();
        let mut old_nul_serial: Vec<u8> = Vec::new();
        old_nul
            .serialize_with_mode(&mut old_nul_serial, Compress::No)
            .unwrap();
        let mut pub_data_serial: Vec<u8> = Vec::new();
        pub_data
            .serialize_with_mode(&mut pub_data_serial, Compress::No)
            .unwrap();
        let mut cb_com_list_serial: Vec<u8> = Vec::new();
        cb_com_list
            .serialize_with_mode(&mut cb_com_list_serial, Compress::No)
            .unwrap();

        self.0.insert_updated_object(
            object_serial,
            old_nul_serial,
            cb_com_list_serial,
            pub_data_serial,
        );

        Ok(())
    }
}

impl<F: PrimeField + Absorb, U: UserData<F>, D: DbHandle> JoinableBulletin<F, U>
    for CentralObjectStore<D>
{
    fn join_bul<Snark: SNARK<F>, PubData>(
        &mut self,
        object: Com<F>,
        proof: Snark::Proof,
        pub_data: (Snark::VerifyingKey, PubData),
    ) -> Result<(), Self::Error> {
        self.0
            .add_and_verify_new_object::<F, Snark, PubData>(object, proof, pub_data.0, pub_data.1)
    }
}

pub trait NetworkHandle {
    fn is_in(&self, object: Vec<u8>, old_nul: Vec<u8>, cb_com_list: Vec<u8>) -> bool;
}

pub struct CentralNetBulStore<N: NetworkHandle>(pub N);

impl<F: PrimeField + Absorb, U: UserData<F>, N: NetworkHandle> PublicUserBul<F, U>
    for CentralNetBulStore<N>
{
    type Error = &'static str;

    type MembershipWitness = (); // signature but the entirety of humanity.

    type MembershipWitnessVar = UnitVar;

    type MembershipPub = ();

    type MembershipPubVar = UnitVar;

    fn verify_in<Args, Snark: SNARK<F>, const NUMCBS: usize>(
        &self,
        object: Com<F>,
        old_nul: Nul<F>,
        cb_com_list: [Com<F>; NUMCBS],
        _args: Args,
        _proof: Snark::Proof,
        _pub_data: (Snark::VerifyingKey, Self::MembershipPub),
    ) -> bool {
        let mut object_serial: Vec<u8> = Vec::new();
        object
            .serialize_with_mode(&mut object_serial, Compress::No)
            .unwrap();
        let mut old_nul_serial: Vec<u8> = Vec::new();
        old_nul
            .serialize_with_mode(&mut old_nul_serial, Compress::No)
            .unwrap();
        let mut cb_com_list_serial: Vec<u8> = Vec::new();
        cb_com_list
            .serialize_with_mode(&mut cb_com_list_serial, Compress::No)
            .unwrap();
        self.0
            .is_in(object_serial, old_nul_serial, cb_com_list_serial)
    }

    fn enforce_membership_of(
        data_var: ComVar<F>,
        extra_witness: Self::MembershipWitnessVar,
        extra_pub: Self::MembershipPubVar,
    ) -> Result<(), SynthesisError> {
        Ok(()) // CHECK SIGNATURE
    }
}
