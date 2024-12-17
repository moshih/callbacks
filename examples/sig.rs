use ark_bn254::Fr as F;
use rand::thread_rng;
use zk_callbacks::impls::{hash::Poseidon, sigtest::PrivKey};

fn main() {
    let mut rng = thread_rng();

    let sk: PrivKey<F> = PrivKey::gen_key(&mut rng);

    let pk = sk.get_full_pubkey();

    let sk2: PrivKey<F> = PrivKey::gen_key(&mut rng);

    let pk2 = sk2.get_full_pubkey();

    let out = sk
        .sign_message::<Poseidon<2>>(&mut rng, F::from(128903))
        .unwrap();

    let check = pk2.verify::<Poseidon<2>>(out, F::from(128903));

    println!("{:?}", check);
}
