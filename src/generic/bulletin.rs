use crate::crypto::rr::RRTicket;
use crate::crypto::rr::RRVerifier;
use crate::generic::object::{Com, Nul, Ticket, TicketVar};
use crate::generic::user::UserData;
use crate::generic::user::UserVar;
use ark_crypto_primitives::sponge::Absorb;
use ark_ff::PrimeField;
use ark_ff::ToConstraintField;
use ark_relations::r1cs::SynthesisError;
use ark_snark::SNARK;

pub trait PublicUserBul<F: PrimeField + Absorb, U: UserData<F>> {
    type User = U;

    fn verify_in<const N: usize>(
        &self,
        object: Com<F>,
        old_nul: Nul<F>,
        cb_com_list: [Com<F>; N],
    ) -> bool;

    fn enforce_membership_of<A>(
        &self,
        data_var: UserVar<F, U>,
        extra_input: A,
    ) -> Result<(), SynthesisError>;
}

pub trait UserBul<F: PrimeField + Absorb, U: UserData<F>>: PublicUserBul<F, U> {
    type User = U;

    fn append_value<const N: usize>(
        &self,
        object: Com<F>,
        old_nul: Nul<F>,
        cb_com_list: [Com<F>; N],
    ) -> Result<(), ()>;

    fn verify_interaction<A: ToConstraintField<F>, S: SNARK<F>, const N: usize>(
        &self,
        object: Com<F>,
        old_nul: Nul<F>,
        args: A,
        cb_com_list: [Com<F>; N],
        proof: S::Proof,
        circuit_key: S::VerifyingKey,
    ) -> bool {
        let mut pub_inputs = vec![object, old_nul];
        pub_inputs.extend::<Vec<F>>(args.to_field_elements().unwrap());
        pub_inputs.extend::<Vec<F>>(cb_com_list.to_field_elements().unwrap());

        S::verify(&circuit_key, &pub_inputs, &proof).unwrap_or(false)
    }

    fn verify_interact_and_append<A: ToConstraintField<F>, S: SNARK<F>, const N: usize>(
        &self,
        object: Com<F>,
        old_nul: Nul<F>,
        args: A,
        cb_com_list: [Com<F>; N],
        proof: S::Proof,
        circuit_key: S::VerifyingKey,
    ) -> Result<(), ()> {
        let out = self.verify_interaction::<A, S, N>(
            object,
            old_nul,
            args,
            cb_com_list,
            proof,
            circuit_key,
        );

        if !out {
            return Err(());
        }

        self.append_value(object, old_nul, cb_com_list)?;

        Ok(())
    }
}

pub trait PublicCallbackBul<E: Clone, F: PrimeField, T: RRTicket<F, E>> {
    fn verify_in(&self, tik: Ticket<T::Tik>, enc_args: E) -> bool;

    fn enforce_membership_of<A>(
        &self,
        tikvar: TicketVar<T::TikVar>,
        extra_input: A,
    ) -> Result<(), SynthesisError>;

    fn enforce_nonmembership_of<A>(
        &self,
        tikvar: TicketVar<T::TikVar>,
        extra_input: A,
    ) -> Result<(), SynthesisError>;
}

pub trait CallbackBulletin<E: Clone, F: PrimeField, T: RRTicket<F, E>>:
    PublicCallbackBul<E, F, T>
{
    fn append_value(&self, tik: Ticket<T::Tik>, enc_args: E) -> Result<(), ()>;

    fn verify_call(&self, tik: Ticket<T::Tik>, enc_args: E, signature: T::Sig) -> bool {
        tik.verify(enc_args.clone(), signature)
    }

    fn verify_call_and_append<S>(
        &self,
        tik: Ticket<T::Tik>,
        enc_args: E,
        signature: T::Sig,
    ) -> Result<(), ()> {
        let out = self.verify_call(tik.clone(), enc_args.clone(), signature);

        if !out {
            return Err(());
        }

        self.append_value(tik, enc_args)?;

        Ok(())
    }
}
