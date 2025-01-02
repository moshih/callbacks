use ark_bls12_381::Fr as F;
use zk_callbacks::{
    generic::{
        object::ZKFields,
        user::{User, UserData},
    },
    impls::hash::CircPoseidon,
};
use zk_object::zk_object;

#[zk_object(F)]
#[derive(Default)]
struct ForumUser {
    is_banned: bool,
    reputation: F,
}

fn main() {
    let data = ForumUser {
        is_banned: false,
        reputation: F::from(0),
    };

    let zk_fields = ZKFields {
        nul: F::from(727),
        com_rand: F::from(6969),
        callback_hash: F::from(0),
        new_in_progress_callback_hash: F::from(0),
        old_in_progress_callback_hash: F::from(0),
        is_ingest_over: true,
    };

    let out = User {
        data: data.clone(),
        zk_fields: zk_fields.clone(),
        callbacks: vec![],
    };
    for d in data.serialize_elements() {
        if d != F::from(0) {
            print!("{} ", d);
        } else {
            print!("0 ");
        }
    }
    for d in zk_fields.serialize() {
        if d != F::from(0) {
            print!("{} ", d);
        } else {
            print!("0 ");
        }
    }
    println!();

    println!("{}", out.commit::<CircPoseidon<2>>());
}
