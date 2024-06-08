use ark_bn254::{Bn254 as E, Fr as F};
use ark_groth16::Groth16;
use ark_r1cs_std::boolean::Boolean;
use ark_r1cs_std::eq::EqGadget;
use ark_r1cs_std::fields::fp::FpVar;
use ark_relations::r1cs::Result as ArkResult;
use ark_relations::r1cs::ToConstraintField;
use ark_snark::SNARK;
use rand::thread_rng;
use std::collections::HashMap;
use zk_callbacks::generic::interaction::generate_keys_for_statement_in;
use zk_callbacks::generic::interaction::Callback;
use zk_callbacks::generic::interaction::Interaction;
use zk_callbacks::generic::object::Id;
use zk_callbacks::generic::object::Time;
use zk_callbacks::generic::user::{User, UserVar};
use zk_callbacks::impls::centralized::bul::CentralObjectStore;
use zk_callbacks::impls::centralized::crypto::PlainTikCrypto;
use zk_callbacks::util::UnitVar;
use zk_object::zk_object;

#[zk_object(F)]
#[derive(Default)]
struct TestUserData {
    token1: F,
    token2: F,
}

fn int_meth<'a>(tu: &'a User<F, TestUserData>, _args: F) -> User<F, TestUserData> {
    tu.clone()
}

fn int_meth_pred<'a>(
    tu_old: &'a UserVar<F, TestUserData>,
    tu_new: &'a UserVar<F, TestUserData>,
    _args: FpVar<F>,
) -> ArkResult<()> {
    tu_old
        .data
        .token1
        .enforce_equal(&FpVar::Constant(F::from(1)))?; // enforce a user has a token
    tu_old.data.token1.enforce_equal(&tu_new.data.token1)?;
    Ok(())
}

fn some_pred<'a, 'b>(
    _tu: &'a UserVar<F, TestUserData>,
    _com: &'b FpVar<F>,
    _args: UnitVar,
) -> ArkResult<()> {
    Ok(())
}

fn cb_meth<'a>(tu: &'a User<F, TestUserData>, _args: F) -> User<F, TestUserData> {
    let mut out = tu.clone();
    out.data.token1 = F::from(0); // revoke a token
    out
}

fn cb_pred<'a>(
    tu_old: &'a UserVar<F, TestUserData>,
    tu_new: &'a UserVar<F, TestUserData>,
    _args: FpVar<F>,
) -> ArkResult<()> {
    tu_old
        .data
        .token1
        .enforce_equal(&FpVar::Constant(F::from(0)))?;
    Ok(())
}

fn main() {
    let cb: Callback<F, TestUserData, F, FpVar<F>> = Callback {
        method_id: Id::from(0),
        expirable: false,
        expiration: Time::from(0),
        method: cb_meth,
        predicate: cb_pred,
    };

    let interaction: Interaction<F, TestUserData, F, FpVar<F>, 1> = Interaction {
        meth: (int_meth, int_meth_pred),
        callbacks: [cb.clone()],
    };

    let mut rng = thread_rng();

    let _co_store = CentralObjectStore {
        data: HashMap::new(),
        nuls: vec![],
        pubkey: F::from(0),
    };

    let (pk, vk) =
        interaction.generate_keys::<Groth16<E>, PlainTikCrypto<F>, CentralObjectStore<F>>(&mut rng);

    let (pki, _vki) = generate_keys_for_statement_in::<
        F,
        TestUserData,
        (),
        UnitVar,
        Groth16<E>,
        CentralObjectStore<F>,
    >(some_pred, &mut rng);

    let mut u = User::create(
        TestUserData {
            token1: F::from(1),
            token2: F::from(3),
        },
        &mut rng,
    );

    u.prove_statement_and_in::<(), UnitVar, Groth16<E>, CentralObjectStore<F>>(
        &mut rng,
        some_pred,
        &pki,
        ((), ()),
        (),
    )
    .unwrap();

    let exec_method = u
        .interact::<F, FpVar<F>, PlainTikCrypto<F>, Groth16<E>, CentralObjectStore<F>, 1>(
            &mut rng,
            interaction.clone(),
            [PlainTikCrypto(F::from(0))],
            ((), ()),
            &pk,
            F::from(0),
        )
        .unwrap();

    let exec_method2 = u
        .interact::<F, FpVar<F>, PlainTikCrypto<F>, Groth16<E>, CentralObjectStore<F>, 1>(
            &mut rng,
            interaction.clone(),
            [PlainTikCrypto(F::from(0))],
            ((), ()),
            &pk,
            F::from(0),
        )
        .unwrap();

    let mut pub_inputs = vec![exec_method.new_object, exec_method.old_nullifier];
    pub_inputs.extend::<Vec<F>>(F::from(0).to_field_elements().unwrap());
    pub_inputs.extend::<Vec<F>>(exec_method.cb_com_list.to_field_elements().unwrap());

    println!(
        "{:?}",
        Groth16::<E>::verify(&vk, &pub_inputs, &exec_method.proof).unwrap()
    );

    println!("{:?}", u);

    let mut pub_inputs = vec![exec_method2.new_object, exec_method2.old_nullifier];
    pub_inputs.extend::<Vec<F>>(F::from(0).to_field_elements().unwrap());
    pub_inputs.extend::<Vec<F>>(exec_method2.cb_com_list.to_field_elements().unwrap());
    pub_inputs.extend::<Vec<F>>(().to_field_elements().unwrap());

    println!(
        "{:?}",
        Groth16::<E>::verify(&vk, &pub_inputs, &exec_method2.proof).unwrap()
    );

    println!("{:?}", u);
}
