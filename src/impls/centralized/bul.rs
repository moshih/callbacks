use crate::generic::bulletin::{JoinableBulletin, PublicUserBul, UserBul};
use crate::generic::object::{Com, ComVar, Nul};
use crate::generic::user::UserData;
use crate::util::UnitVar;
use ark_crypto_primitives::sponge::Absorb;
use ark_ff::PrimeField;
use ark_r1cs_std::ToBytesGadget;
use ark_relations::r1cs::SynthesisError;
use ark_serialize::CanonicalSerialize;
use ark_serialize::Compress;
use ark_snark::SNARK;

pub trait DbHandle {
    type Error;

    async fn async_insert_updated_object(
        &mut self,
        object: &[u8],
        old_nul: &[u8],
        cb_com_list: &[u8],
        sig: &[u8],
    ) -> Result<(), Self::Error>;

    fn insert_updated_object(
        &mut self,
        object: &[u8],
        old_nul: &[u8],
        cb_com_list: &[u8],
        sig: &[u8],
    ) -> Result<(), Self::Error>;

    fn is_in(&self, object: &[u8], old_nul: &[u8], cb_com_list: &[u8]) -> bool;

    fn has_never_recieved_nul(&self, nul: &[u8]) -> bool;

    type ExternalVerifData;

    fn verify_new_object(
        &self,
        object: &[u8],
        data: Self::ExternalVerifData,
    ) -> Result<(), Self::Error>;
}

pub struct CentralObjectStore<D: DbHandle>(pub D);

impl<F: PrimeField + Absorb, U: UserData<F>, D: DbHandle> PublicUserBul<F, U>
    for CentralObjectStore<D>
{
    type Error = D::Error;

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
        let mut object_serial = Vec::new();
        object
            .serialize_with_mode(&mut object_serial, Compress::No)
            .unwrap();
        let mut old_nul_serial = Vec::new();
        old_nul
            .serialize_with_mode(&mut old_nul_serial, Compress::No)
            .unwrap();
        let mut cb_com_list_serial = Vec::new();
        cb_com_list
            .serialize_with_mode(&mut cb_com_list_serial, Compress::No)
            .unwrap();
        self.0
            .is_in(&object_serial, &old_nul_serial, &cb_com_list_serial)
    }

    fn enforce_membership_of(
        data_var: ComVar<F>,
        extra_witness: Self::MembershipWitnessVar,
        extra_pub: Self::MembershipPubVar,
    ) -> Result<(), SynthesisError> {
        let bytes_rep = data_var.to_bytes();

        Ok(()) // CHECK SIGNATURE
    }
}

impl<F: PrimeField + Absorb, U: UserData<F>, D: DbHandle> UserBul<F, U> for CentralObjectStore<D> {
    fn has_never_recieved_nul(&self, nul: &Nul<F>) -> bool {
        let mut nul_serial = Vec::new();
        nul.serialize_with_mode(&mut nul_serial, Compress::No)
            .unwrap();
        self.0.has_never_recieved_nul(&nul_serial)
    }

    fn append_value<Args, Snark: SNARK<F>, const NUMCBS: usize>(
        &mut self,
        object: Com<F>,
        old_nul: Nul<F>,
        cb_com_list: [Com<F>; NUMCBS],
        _args: Args,
        _proof: Snark::Proof,
        _pub_data: (Snark::VerifyingKey, Self::MembershipPub),
    ) -> Result<(), Self::Error> {
        let mut object_serial = Vec::new();
        object
            .serialize_with_mode(&mut object_serial, Compress::No)
            .unwrap();
        let mut old_nul_serial = Vec::new();
        old_nul
            .serialize_with_mode(&mut old_nul_serial, Compress::No)
            .unwrap();

        let mut cb_com_list_serial = Vec::new();
        cb_com_list
            .serialize_with_mode(&mut cb_com_list_serial, Compress::No)
            .unwrap();

        // ADD SIGNING THE OBJECT HERE

        self.0
            .insert_updated_object(&object_serial, &old_nul_serial, &cb_com_list_serial, &[])
    }
}

impl<F: PrimeField + Absorb, U: UserData<F>, D: DbHandle> JoinableBulletin<F, U>
    for CentralObjectStore<D>
{
    type PubData = D::ExternalVerifData;

    fn join_bul(&mut self, object: Com<F>, pub_data: Self::PubData) -> Result<(), Self::Error> {
        let mut object_serial = Vec::new();
        object
            .serialize_with_mode(&mut object_serial, Compress::No)
            .unwrap();
        self.0.verify_new_object(&object_serial, pub_data)?;

        // Sign object here

        self.0.insert_updated_object(&object_serial, &[], &[], &[])
    }
}

pub trait NetworkHandle {
    type Error;

    fn is_in(&self, object: &[u8], old_nul: &[u8], cb_com_list: &[u8]) -> bool;
}

pub struct CentralNetBulStore<N: NetworkHandle>(pub N);

impl<F: PrimeField + Absorb, U: UserData<F>, N: NetworkHandle> PublicUserBul<F, U>
    for CentralNetBulStore<N>
{
    type Error = N::Error;

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
        let mut object_serial = Vec::new();
        object
            .serialize_with_mode(&mut object_serial, Compress::No)
            .unwrap();
        let mut old_nul_serial = Vec::new();
        old_nul
            .serialize_with_mode(&mut old_nul_serial, Compress::No)
            .unwrap();
        let mut cb_com_list_serial = Vec::new();
        cb_com_list
            .serialize_with_mode(&mut cb_com_list_serial, Compress::No)
            .unwrap();
        self.0
            .is_in(&object_serial, &old_nul_serial, &cb_com_list_serial)
    }

    fn enforce_membership_of(
        data_var: ComVar<F>,
        extra_witness: Self::MembershipWitnessVar,
        extra_pub: Self::MembershipPubVar,
    ) -> Result<(), SynthesisError> {
        Ok(()) // CHECK SIGNATURE
    }
}
