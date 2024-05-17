use rand::CryptoRng;
use rand::RngCore;

pub trait RRSigner<S, M, R, V: RRVerifier<S, M, R>> {
    type Vk = V;
    fn sign_message(&self, message: &M) -> S;

    fn sk_to_pk(&self) -> V;

    fn gen() -> Self;

    fn rerand(&self, randomness: R) -> Self;
}

pub trait RRVerifier<S, M, R> {
    fn verify(&self, message: M, signature: S) -> bool;

    fn rerand(&self, rng: &mut (impl CryptoRng + RngCore)) -> (R, Self);
}
