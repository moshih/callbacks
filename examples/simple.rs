use ark_bn254::{Bn254 as E, Fr as F};
use ark_groth16::Groth16;
use ark_r1cs_std::boolean::Boolean;
use ark_r1cs_std::eq::EqGadget;
use ark_relations::r1cs::Result as ArkResult;
use ark_relations::r1cs::ToConstraintField;
use ark_snark::SNARK;
use rand::thread_rng;
use zk_callbacks::generic::interaction::Callback;
use zk_callbacks::generic::interaction::Interaction;
use zk_callbacks::generic::object::Id;
use zk_callbacks::generic::object::Time;
use zk_callbacks::generic::user::{User, UserVar};
use zk_callbacks::impls::centralized::CentralTik;
use zk_callbacks::util::UnitVar;
use zk_object::zk_object;

#[zk_object(F)]
#[derive(Default)]
struct TestUserData {
    is_banned: bool,
    field2: u8,
}

fn int_meth<'a>(tu: &'a User<F, TestUserData>, _args: ()) -> User<F, TestUserData> {
    tu.clone()
}

fn int_meth_pred<'a>(
    tu_old: &'a UserVar<F, TestUserData>,
    tu_new: &'a UserVar<F, TestUserData>,
    _args: UnitVar,
) -> ArkResult<()> {
    tu_old.data.is_banned.enforce_equal(&Boolean::FALSE)?;
    tu_old
        .data
        .is_banned
        .enforce_equal(&tu_new.data.is_banned)?;
    Ok(())
}

fn cb_meth<'a>(tu: &'a User<F, TestUserData>, _args: ()) -> User<F, TestUserData> {
    let mut out = tu.clone();
    out.data.is_banned = true;
    out
}

fn cb_pred<'a>(
    tu_old: &'a UserVar<F, TestUserData>,
    tu_new: &'a UserVar<F, TestUserData>,
    _args: UnitVar,
) -> ArkResult<()> {
    tu_old.data.is_banned.enforce_equal(&Boolean::FALSE)?;
    tu_new.data.is_banned.enforce_equal(&Boolean::TRUE)?;
    Ok(())
}

fn main() {
    let cb: Callback<F, TestUserData, (), UnitVar> = Callback {
        method_id: Id::from(0),
        expirable: false,
        expiration: Time::from(0),
        method: cb_meth,
        predicate: cb_pred,
    };

    let interaction: Interaction<F, TestUserData, (), UnitVar, 1> = Interaction {
        meth: (int_meth, int_meth_pred),
        callbacks: [cb.clone()],
    };

    let mut rng = thread_rng();

    let (pk, vk) = interaction.generate_keys::<Groth16<E>, CentralTik<F>>(&mut rng);

    let mut u = User::create(
        TestUserData {
            is_banned: false,
            field2: 30,
        },
        &mut rng,
    );

    let exec_method = u
        .interact::<(), UnitVar, CentralTik<F>, Groth16<E>, 1>(
            &mut rng,
            interaction.clone(),
            [CentralTik(F::from(0))],
            &pk,
            (),
        )
        .unwrap();

    let exec_method2 = u
        .interact::<(), UnitVar, CentralTik<F>, Groth16<E>, 1>(
            &mut rng,
            interaction.clone(),
            [CentralTik(F::from(0))],
            &pk,
            (),
        )
        .unwrap();

    let mut pub_inputs = vec![exec_method.new_object, exec_method.old_nullifier];
    pub_inputs.extend::<Vec<F>>(().to_field_elements().unwrap());
    pub_inputs.extend::<Vec<F>>(exec_method.cb_com_list.to_field_elements().unwrap());

    println!(
        "{:?}",
        Groth16::<E>::verify(&vk, &pub_inputs, &exec_method.proof).unwrap()
    );

    println!("{:?}", u);

    let mut pub_inputs = vec![exec_method2.new_object, exec_method2.old_nullifier];
    pub_inputs.extend::<Vec<F>>(().to_field_elements().unwrap());
    pub_inputs.extend::<Vec<F>>(exec_method2.cb_com_list.to_field_elements().unwrap());

    println!(
        "{:?}",
        Groth16::<E>::verify(&vk, &pub_inputs, &exec_method2.proof).unwrap()
    );

    println!("{:?}", u);
}
