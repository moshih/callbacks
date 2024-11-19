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

    type InteractionData;

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
        CBArgs: Clone,
        Crypto: AECipherSigZK<F, CBArgs>,
    >(
        &self,
        ticket: Crypto::SigPK,
    ) -> bool;

    async fn store_interaction<
        F: PrimeField + Absorb,
        U: UserData<F>,
        Snark: SNARK<F>,
        CBArgs: Clone + ToConstraintField<F>,
        Crypto: AECipherSigZK<F, CBArgs>,
        const NUMCBS: usize,
    >(
        &self,
        interaction: ExecutedMethod<F, Snark, CBArgs, Crypto, NUMCBS>,
        data: Self::InteractionData,
    ) -> Result<(), Self::Error>;

    async fn approve_interaction<
        F: PrimeField + Absorb,
        U: UserData<F>,
        Snark: SNARK<F>,
        PubArgs: Clone + ToConstraintField<F>,
        CBArgs: Clone,
        Crypto: AECipherSigZK<F, CBArgs>,
        Bul: PublicUserBul<F, U>,
        const NUMCBS: usize,
    >(
        &self,
        interaction_request: &ExecutedMethod<F, Snark, CBArgs, Crypto, NUMCBS>,
        sk: Crypto::SigSK,
        args: PubArgs,
        bul: &Bul,
        memb_data: Bul::MembershipPub,
        verif_key: &Snark::VerifyingKey,
    ) -> bool {
        let out = bul
            .verify_in::<PubArgs, Snark, NUMCBS>(
                interaction_request.new_object,
                interaction_request.old_nullifier,
                interaction_request.cb_com_list,
                args.clone(),
                interaction_request.proof.clone(),
                memb_data.clone(),
                verif_key,
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
                .has_never_recieved_tik::<F, CBArgs, Crypto>(cb.cb_entry.tik)
                .await
            {
                return false;
            }
        }

        let mut pub_inputs = vec![
            interaction_request.new_object,
            interaction_request.old_nullifier,
        ];
        pub_inputs.extend::<Vec<F>>(args.to_field_elements().unwrap());
        pub_inputs.extend::<Vec<F>>(interaction_request.cb_com_list.to_field_elements().unwrap());
        pub_inputs.extend(memb_data.to_field_elements().unwrap());
        Snark::verify(verif_key, &pub_inputs, &interaction_request.proof).unwrap_or(false)
    }

    async fn approve_interaction_and_store<
        F: PrimeField + Absorb,
        U: UserData<F>,
        Snark: SNARK<F>,
        PubArgs: Clone + ToConstraintField<F>,
        CBArgs: Clone + ToConstraintField<F>,
        Crypto: AECipherSigZK<F, CBArgs>,
        Bul: PublicUserBul<F, U>,
        const NUMCBS: usize,
    >(
        &self,
        interaction_request: ExecutedMethod<F, Snark, CBArgs, Crypto, NUMCBS>,
        sk: Crypto::SigSK,
        args: PubArgs,
        bul: &Bul,
        memb_data: Bul::MembershipPub,
        verif_key: &Snark::VerifyingKey,
        data: Self::InteractionData,
    ) -> Result<(), BulError<Self::Error>> {
        let out = self
            .approve_interaction(&interaction_request, sk, args, bul, memb_data, verif_key)
            .await;

        if !out {
            return Err(BulError::VerifyError);
        }

        self.store_interaction::<F, U, Snark, CBArgs, Crypto, NUMCBS>(interaction_request, data)
            .await
            .map_err(BulError::AppendError)
    }
}
