use crate::generic::bulletin::{JoinableBulletin, PublicUserBul, UserBul};
use crate::generic::user::UserData;
use crate::util::UnitVar;
use ark_crypto_primitives::sponge::Absorb;
use ark_ff::PrimeField;

#[derive(Clone)]
pub struct DummyObjectStore;

impl<F: PrimeField + Absorb, U: UserData<F>> PublicUserBul<F, U> for DummyObjectStore {
    type Error = ();

    type MembershipPub = ();
    type MembershipWitness = ();

    type MembershipPubVar = UnitVar;
    type MembershipWitnessVar = UnitVar;

    fn verify_in<Args, Snark: ark_snark::SNARK<F>, const NUMCBS: usize>(
        &self,
        _object: crate::generic::object::Com<F>,
        _old_nul: crate::generic::object::Nul<F>,
        _cb_com_list: [crate::generic::object::Com<F>; NUMCBS],
        _args: Args,
        _proof: Snark::Proof,
        _pub_data: (Snark::VerifyingKey, Self::MembershipPub),
    ) -> bool {
        true
    }

    fn enforce_membership_of(
        _data_var: crate::generic::object::ComVar<F>,
        _extra_witness: Self::MembershipWitnessVar,
        _extra_pub: Self::MembershipPubVar,
    ) -> Result<(), ark_relations::r1cs::SynthesisError> {
        Ok(())
    }
}

impl<F: PrimeField + Absorb, U: UserData<F>> UserBul<F, U> for DummyObjectStore {
    fn has_never_recieved_nul(&self, _nul: &crate::generic::object::Nul<F>) -> bool {
        true
    }

    fn append_value<Args, Snark: ark_snark::SNARK<F>, const NUMCBS: usize>(
        &mut self,
        _object: crate::generic::object::Com<F>,
        _old_nul: crate::generic::object::Nul<F>,
        _cb_com_list: [crate::generic::object::Com<F>; NUMCBS],
        _args: Args,
        _proof: Snark::Proof,
        _pub_data: (Snark::VerifyingKey, Self::MembershipPub),
    ) -> Result<(), Self::Error> {
        Ok(())
    }
}

impl<F: PrimeField + Absorb, U: UserData<F>> JoinableBulletin<F, U> for DummyObjectStore {
    fn join_bul<Snark: ark_snark::SNARK<F>, PubData>(
        &mut self,
        _object: crate::generic::object::Com<F>,
        _proof: Snark::Proof,
        _pub_data: (Snark::VerifyingKey, PubData),
    ) -> Result<(), Self::Error> {
        Ok(())
    }
}
