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

    fn verify_in<Args, Snark: SNARK<F>, const NUMCBS: usize>(
        &self,
        object: Com<F>,
        old_nul: Nul<F>,
        cb_com_list: [Com<F>; NUMCBS],
        args: Args,
        proof: Snark::Proof,
        pub_data: (Snark::VerifyingKey, Self::MembershipPub),
    ) -> bool;

    fn enforce_membership_of(
        data_var: ComVar<F>,
        extra_witness: Self::MembershipWitnessVar,
        extra_pub: Self::MembershipPubVar,
    ) -> Result<(), SynthesisError>;
}

pub trait UserBul<F: PrimeField + Absorb, U: UserData<F>>: PublicUserBul<F, U> {
    fn has_never_recieved_nul(&self, nul: &Nul<F>) -> bool;

    fn append_value<Args, Snark: SNARK<F>, const NUMCBS: usize>(
        &mut self,
        object: Com<F>,
        old_nul: Nul<F>,
        cb_com_list: [Com<F>; NUMCBS],
        args: Args,
        proof: Snark::Proof,
        pub_data: (Snark::VerifyingKey, Self::MembershipPub),
    ) -> Result<(), Self::Error>;

    fn verify_interaction<Args: ToConstraintField<F>, Snark: SNARK<F>, const NUMCBS: usize>(
        &self,
        object: Com<F>,
        old_nul: Nul<F>,
        args: Args,
        cb_com_list: [Com<F>; NUMCBS],
        proof: Snark::Proof,
        pub_data: (Snark::VerifyingKey, Self::MembershipPub),
    ) -> bool {
        let circuit_key = pub_data.0;
        let public_membership_input = pub_data.1;
        if !self.has_never_recieved_nul(&old_nul) {
            return false;
        }

        let mut pub_inputs = vec![object, old_nul];
        pub_inputs.extend::<Vec<F>>(args.to_field_elements().unwrap());
        pub_inputs.extend::<Vec<F>>(cb_com_list.to_field_elements().unwrap());
        pub_inputs.extend::<Vec<F>>(public_membership_input.to_field_elements().unwrap());

        Snark::verify(&circuit_key, &pub_inputs, &proof).unwrap_or(false)
    }

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
        pub_data: (Snark::VerifyingKey, Self::MembershipPub),
    ) -> Result<(), BulError<Self::Error>> {
        let out = self.verify_interaction::<Args, Snark, NUMCBS>(
            object,
            old_nul,
            args.clone(),
            cb_com_list,
            proof.clone(),
            pub_data.clone(),
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
            pub_data,
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
        extra_witness: Self::MembershipWitness,
        extra_pub: Self::MembershipPub,
    ) -> Result<(), SynthesisError>;

    fn enforce_nonmembership_of(
        tikvar: Crypto::SigPKV,
        extra_witness: Self::NonMembershipWitness,
        extra_pub: Self::NonMembershipPub,
    ) -> Result<(), SynthesisError>;
}

pub trait CallbackBulletin<Args: Clone, F: PrimeField, Crypto: AECipherSigZK<F, Args>>:
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
    fn join_bul<Snark: SNARK<F>, PubData>(
        &mut self,
        object: Com<F>,
        proof: Snark::Proof,
        pub_data: (Snark::VerifyingKey, PubData),
    ) -> Result<(), Self::Error>;
}
