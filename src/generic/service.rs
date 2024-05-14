use crate::crypto::rr::RRTicket;
use crate::generic::bulletin::PublicUserBul;
use crate::generic::callbacks::CallbackCom;
use crate::generic::user::ExecutedMethod;
use crate::generic::user::UserData;
use ark_crypto_primitives::sponge::Absorb;
use ark_ff::PrimeField;
use ark_snark::SNARK;

pub trait ServiceProvider<SK, PK> {
    fn call<F: PrimeField + Absorb, A: Clone, T: RRTicket<F, A>>(
        &self,
        ticket: CallbackCom<F, A, T>,
        arguments: A,
        sk: SK,
    ) -> Result<(), ()> {
        todo!();
    }

    fn has_never_recieved_tik<F: PrimeField, Absorb, A: Clone, T: RRTicket<F, A>>(
        ticket: T,
    ) -> bool;

    fn approve_interaction<
        F: PrimeField + Absorb,
        S: SNARK<F>,
        U: UserData<F>,
        A: Clone,
        T: RRTicket<F, A>,
        B: PublicUserBul<F, U>,
        const N: usize,
    >(
        &self,
        interaction_request: ExecutedMethod<F, S, A, T, N>,
        bul: B,
    ) {
    }
}
