use ark_bls12_381::{Bls12_381 as E, Fr as F};
use ark_groth16::Groth16;
use ark_r1cs_std::boolean::Boolean;
use ark_r1cs_std::eq::EqGadget;
use ark_relations::r1cs::Result as ArkResult;
use ark_snark::SNARK;
use rand::thread_rng;
use zk_callbacks::generic::interaction::Interaction;
use zk_callbacks::generic::user::{User, UserVar};
use zk_object::zk_object;

#[zk_object]
struct TestUserData {
    is_banned: bool,
    field2: u8,
}

type Args = ();

fn int_meth<'a>(tu: &'a User<TestUserData>, args: Args) -> User<TestUserData> {
    tu.clone()
}

fn int_meth_pred<'a>(
    tu_old: &'a UserVar<TestUserData>,
    tu_new: &'a UserVar<TestUserData>,
    args: Args,
) -> ArkResult<()> {
    tu_old.data.is_banned.enforce_equal(&Boolean::FALSE)?;
    Ok(())
}

static INTERACTION: Interaction<TestUserData, Args, 0> = Interaction {
    meth: (int_meth, int_meth_pred),
    callbacks: [],
};

fn main() {
    let mut u = User {
        data: TestUserData {
            is_banned: false,
            field2: 30,
        },
        zk_fields: zk_callbacks::generic::object::ZKFields {
            nul: F::from(0),
            com_rand: F::from(0),
            callback_hash: F::from(0),
            new_in_progress_callback_hash: F::from(0),
            old_in_progress_callback_hash: F::from(0),
            last_interaction: F::from(0),
            current_callback_ingest: F::from(0),
            last_callback_ingest: F::from(0),
            is_ingest_over: true,
        },
    };

    let mut rng = thread_rng();

    let (com, nul, pf, vk) = u
        .interact::<Args, Groth16<E>, 0>(&mut rng, INTERACTION.clone(), ())
        .unwrap();

    let mut pub_inputs = vec![com, nul];

    println!("{:?}", Groth16::<E>::verify(&vk, &pub_inputs, &pf).unwrap());
}
