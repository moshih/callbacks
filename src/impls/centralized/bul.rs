use crate::generic::bulletin::{PublicUserBul, UserBul};
use crate::generic::object::{Com, ComVar, Nul};
use crate::generic::user::UserData;
use crate::generic::user::UserVar;
use crate::util::UnitVar;
use ark_crypto_primitives::sponge::Absorb;
use ark_ff::PrimeField;
use ark_r1cs_std::eq::EqGadget;
use ark_r1cs_std::fields::fp::FpVar;
use ark_relations::r1cs::SynthesisError;
use ark_snark::SNARK;
use std::collections::HashMap;

// Object
// Nullifier
// Signature (Field Element)
// Callback List?

#[derive(Clone, Hash, Eq, PartialEq)]
pub struct COData<F: PrimeField> {
    pub object: Com<F>,
    pub old_nul: Nul<F>,
    pub cb_com_list: Vec<Com<F>>,
}

#[derive(Clone)]
pub struct CentralObjectStore<F: PrimeField> {
    pub data: HashMap<COData<F>, F>,
    pub nuls: Vec<Nul<F>>,
    pub pubkey: F,
}

impl<F: PrimeField + Absorb, U: UserData<F>> PublicUserBul<F, U> for CentralObjectStore<F> {
    type Error = ();

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
        self.data.contains_key(
            &(COData {
                object,
                old_nul,
                cb_com_list: cb_com_list.to_vec(),
            }),
        )
    }

    fn enforce_membership_of(
        data_var: ComVar<F>,
        extra_witness: Self::MembershipWitnessVar,
        extra_pub: Self::MembershipPubVar,
    ) -> Result<(), SynthesisError> {
        Ok(()) // CHECK SIGNATURE
    }
}

impl<F: PrimeField + Absorb, U: UserData<F>> UserBul<F, U> for CentralObjectStore<F> {
    fn has_never_recieved_nul(&self, nul: &Nul<F>) -> bool {
        !self.nuls.contains(nul)
    }

    fn append_value<const NUMCBS: usize>(
        &mut self,
        object: Com<F>,
        old_nul: Nul<F>,
        cb_com_list: [Com<F>; NUMCBS],
    ) -> Result<(), Self::Error> {
        let new_co = COData {
            object,
            old_nul,
            cb_com_list: cb_com_list.to_vec(),
        };
        self.data
            .insert(new_co, F::zero()) // CHANGE TO SIGN DATA
            .ok_or(())
            .map_or(Err(()), |_x| Ok(()))
    }
}
