use crate::crypto::enc::AECipherSigZK;
use crate::crypto::rr::RRSigner;
use crate::generic::asynchr::bulletin::BulError;
use crate::generic::asynchr::bulletin::PublicCallbackBul;
use crate::generic::asynchr::bulletin::PublicUserBul;
use crate::generic::callbacks::CallbackCom;
use crate::generic::user::ExecutedMethod;
use crate::generic::user::UserData;
use ark_crypto_primitives::sponge::Absorb;
use ark_ff::PrimeField;
use ark_ff::ToConstraintField;
use ark_snark::SNARK;

type Called<F, A, Crypto> = (
    <Crypto as AECipherSigZK<F, A>>::SigPK,
    <Crypto as AECipherSigZK<F, A>>::Ct,
    <Crypto as AECipherSigZK<F, A>>::Sig,
);

pub trait ServiceProvider {
    type Error;

    fn call<
        F: PrimeField + Absorb,
        A: Clone,
        Crypto: AECipherSigZK<F, A>,
        Bul: PublicCallbackBul<F, A, Crypto>,
    >(
        &self,
        ticket: CallbackCom<F, A, Crypto>,
        arguments: A,
        sk: Crypto::SigSK,
    ) -> Result<Called<F, A, Crypto>, Bul::Error> {
        let (enc, sig) = Crypto::encrypt_and_sign(arguments, ticket.cb_entry.enc_key, sk);
        Ok((ticket.cb_entry.tik, enc, sig))
    }

    async fn has_never_recieved_tik<
        F: PrimeField + Absorb,
        Args: Clone,
        Crypto: AECipherSigZK<F, Args>,
    >(
        &self,
        ticket: Crypto::SigPK,
    ) -> bool;

    async fn store_interaction<
        F: PrimeField + Absorb,
        U: UserData<F>,
        Snark: SNARK<F>,
        Args: Clone + ToConstraintField<F>,
        Crypto: AECipherSigZK<F, Args>,
        const NUMCBS: usize,
    >(
        &self,
        interaction: ExecutedMethod<F, Snark, Args, Crypto, NUMCBS>,
    ) -> Result<(), Self::Error>;

    async fn approve_interaction<
        F: PrimeField + Absorb,
        U: UserData<F>,
        Snark: SNARK<F>,
        Args: Clone + ToConstraintField<F>,
        Crypto: AECipherSigZK<F, Args>,
        Bul: PublicUserBul<F, U>,
        const NUMCBS: usize,
    >(
        &self,
        interaction_request: &ExecutedMethod<F, Snark, Args, Crypto, NUMCBS>,
        sk: Crypto::SigSK,
        args: Args,
        bul: Bul,
        pub_data: (Snark::VerifyingKey, Bul::MembershipPub),
    ) -> bool {
        let out = bul
            .verify_in::<Args, Snark, NUMCBS>(
                interaction_request.new_object,
                interaction_request.old_nullifier,
                interaction_request.cb_com_list,
                args.clone(),
                interaction_request.proof.clone(),
                pub_data.clone(),
            )
            .await;
        if !out {
            return false;
        }

        for i in 0..NUMCBS {
            let cb = interaction_request.cb_tik_list[i].0.clone();
            let rand = interaction_request.cb_tik_list[i].1.clone();
            let vpk = sk.rerand(rand).sk_to_pk();
            if vpk != cb.cb_entry.tik {
                return false;
            }

            if !self
                .has_never_recieved_tik::<F, Args, Crypto>(cb.cb_entry.tik)
                .await
            {
                return false;
            }
        }

        let circuit_key = pub_data.0;
        let public_membership_input = pub_data.1;

        let mut pub_inputs = vec![
            interaction_request.new_object,
            interaction_request.old_nullifier,
        ];
        pub_inputs.extend::<Vec<F>>(args.to_field_elements().unwrap());
        pub_inputs.extend::<Vec<F>>(interaction_request.cb_com_list.to_field_elements().unwrap());
        pub_inputs.extend(public_membership_input.to_field_elements().unwrap());
        Snark::verify(&circuit_key, &pub_inputs, &interaction_request.proof).unwrap_or(false)
    }

    async fn approve_interaction_and_store<
        F: PrimeField + Absorb,
        U: UserData<F>,
        Snark: SNARK<F>,
        Args: Clone + ToConstraintField<F>,
        Crypto: AECipherSigZK<F, Args>,
        Bul: PublicUserBul<F, U>,
        const NUMCBS: usize,
    >(
        &self,
        interaction_request: ExecutedMethod<F, Snark, Args, Crypto, NUMCBS>,
        sk: Crypto::SigSK,
        args: Args,
        bul: Bul,
        pub_data: (Snark::VerifyingKey, Bul::MembershipPub),
    ) -> Result<(), BulError<Self::Error>> {
        let out = self
            .approve_interaction(&interaction_request, sk, args, bul, pub_data)
            .await;

        if !out {
            return Err(BulError::VerifyError);
        }

        self.store_interaction::<F, U, Snark, Args, Crypto, NUMCBS>(interaction_request)
            .await
            .map_err(BulError::AppendError)
    }
}
