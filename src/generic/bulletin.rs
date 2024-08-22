use crate::crypto::enc::AECipherSigZK;
use crate::crypto::rr::RRVerifier;
use crate::generic::object::{Com, ComVar, Nul};
use crate::generic::user::UserData;
use ark_crypto_primitives::sponge::Absorb;
use ark_ff::PrimeField;
use ark_ff::ToConstraintField;
use ark_r1cs_std::prelude::AllocVar;
use ark_relations::r1cs::SynthesisError;
use ark_snark::SNARK;

#[derive(Debug, Clone)]
pub enum BulError<E> {
    VerifyError,
    AppendError(E),
}

pub trait PublicUserBul<F: PrimeField + Absorb, U: UserData<F>> {
    type Error;

    type MembershipWitness: Clone + Default;
    type MembershipWitnessVar: AllocVar<Self::MembershipWitness, F> + Clone;
    type MembershipPub: Clone + Default + ToConstraintField<F>;
    type MembershipPubVar: AllocVar<Self::MembershipPub, F> + Clone;

    #[allow(clippy::too_many_arguments)]
    fn verify_in<Args, Snark: SNARK<F>, const NUMCBS: usize>(
        &self,
        object: Com<F>,
        old_nul: Nul<F>,
        cb_com_list: [Com<F>; NUMCBS],
        args: Args,
        proof: Snark::Proof,
        memb_data: Self::MembershipPub,
        verif_key: &Snark::VerifyingKey,
    ) -> bool;

    fn enforce_membership_of(
        data_var: ComVar<F>,
        extra_witness: Self::MembershipWitnessVar,
        extra_pub: Self::MembershipPubVar,
    ) -> Result<(), SynthesisError>;
}

pub trait UserBul<F: PrimeField + Absorb, U: UserData<F>>: PublicUserBul<F, U> {
    fn has_never_recieved_nul(&self, nul: &Nul<F>) -> bool;

    #[allow(clippy::too_many_arguments)]
    fn append_value<Args, Snark: SNARK<F>, const NUMCBS: usize>(
        &mut self,
        object: Com<F>,
        old_nul: Nul<F>,
        cb_com_list: [Com<F>; NUMCBS],
        args: Args,
        proof: Snark::Proof,
        memb_data: Self::MembershipPub, // membership for the PREVIOUS object, meant to verify the proof: NOT membership for current object
        verif_key: &Snark::VerifyingKey,
    ) -> Result<(), Self::Error>;

    #[allow(clippy::too_many_arguments)]
    fn verify_interaction<Args: ToConstraintField<F>, Snark: SNARK<F>, const NUMCBS: usize>(
        &self,
        object: Com<F>,
        old_nul: Nul<F>,
        args: Args,
        cb_com_list: [Com<F>; NUMCBS],
        proof: Snark::Proof,
        memb_data: Self::MembershipPub,
        verif_key: &Snark::VerifyingKey,
    ) -> bool {
        if !self.has_never_recieved_nul(&old_nul) {
            return false;
        }

        let mut pub_inputs = vec![object, old_nul];
        pub_inputs.extend::<Vec<F>>(args.to_field_elements().unwrap());
        pub_inputs.extend::<Vec<F>>(cb_com_list.to_field_elements().unwrap());
        pub_inputs.extend::<Vec<F>>(memb_data.to_field_elements().unwrap());

        Snark::verify(verif_key, &pub_inputs, &proof).unwrap_or(false)
    }

    #[allow(clippy::too_many_arguments)]
    fn verify_interact_and_append<
        Args: ToConstraintField<F> + Clone,
        Snark: SNARK<F>,
        const NUMCBS: usize,
    >(
        &mut self,
        object: Com<F>,
        old_nul: Nul<F>,
        args: Args,
        cb_com_list: [Com<F>; NUMCBS],
        proof: Snark::Proof,
        memb_data: Self::MembershipPub,
        verif_key: &Snark::VerifyingKey,
    ) -> Result<(), BulError<Self::Error>> {
        let out = self.verify_interaction::<Args, Snark, NUMCBS>(
            object,
            old_nul,
            args.clone(),
            cb_com_list,
            proof.clone(),
            memb_data.clone(),
            verif_key,
        );

        if !out {
            return Err(BulError::VerifyError);
        }

        self.append_value::<Args, Snark, NUMCBS>(
            object,
            old_nul,
            cb_com_list,
            args,
            proof,
            memb_data,
            verif_key,
        )
        .map_err(BulError::AppendError)?;

        Ok(())
    }
}

pub trait PublicCallbackBul<F: PrimeField, Args: Clone, Crypto: AECipherSigZK<F, Args>> {
    type Error;

    type MembershipWitness;
    type MembershipWitnessVar: AllocVar<Self::MembershipWitness, F>;
    type NonMembershipWitness;
    type NonMembershipWitnessVar: AllocVar<Self::NonMembershipWitness, F>;

    type MembershipPub;
    type MembershipPubVar: AllocVar<Self::MembershipPub, F>;
    type NonMembershipPub;
    type NonMembershipPubVar: AllocVar<Self::NonMembershipPub, F>;

    fn verify_in(&self, tik: Crypto::SigPK, enc_args: Crypto::Ct) -> bool;

    fn enforce_membership_of(
        tikvar: Crypto::SigPKV,
        extra_witness: Self::MembershipWitnessVar,
        extra_pub: Self::MembershipPubVar,
    ) -> Result<(), SynthesisError>;

    fn enforce_nonmembership_of(
        tikvar: Crypto::SigPKV,
        extra_witness: Self::NonMembershipWitnessVar,
        extra_pub: Self::NonMembershipPubVar,
    ) -> Result<(), SynthesisError>;
}

pub trait CallbackBulletin<F: PrimeField, Args: Clone, Crypto: AECipherSigZK<F, Args>>:
    PublicCallbackBul<F, Args, Crypto>
{
    fn has_never_recieved_tik(&self, tik: &Crypto::SigPK) -> bool;

    fn append_value(&mut self, tik: Crypto::SigPK, enc_args: Crypto::Ct)
        -> Result<(), Self::Error>;

    fn verify_call(
        &self,
        tik: Crypto::SigPK,
        enc_args: Crypto::Ct,
        signature: Crypto::Sig,
    ) -> bool {
        if !self.has_never_recieved_tik(&tik) {
            return false;
        }
        tik.verify(enc_args.clone(), signature)
    }

    fn verify_call_and_append(
        &mut self,
        tik: Crypto::SigPK,
        enc_args: Crypto::Ct,
        signature: Crypto::Sig,
    ) -> Result<(), BulError<Self::Error>> {
        let out = self.verify_call(tik.clone(), enc_args.clone(), signature);

        if !out {
            return Err(BulError::VerifyError);
        }

        self.append_value(tik, enc_args)
            .map_err(BulError::AppendError)?;

        Ok(())
    }
}

pub trait JoinableBulletin<F: PrimeField + Absorb, U: UserData<F>>: UserBul<F, U> {
    type PubData;

    fn join_bul(&mut self, object: Com<F>, pub_data: Self::PubData) -> Result<(), Self::Error>;
}
