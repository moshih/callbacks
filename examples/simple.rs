use ark_bn254::{Bn254 as E, Fr as F};
use ark_groth16::Groth16;
use ark_r1cs_std::eq::EqGadget;
use ark_r1cs_std::fields::fp::FpVar;
use ark_relations::r1cs::Result as ArkResult;
use ark_serialize::CanonicalDeserialize;
use rand::thread_rng;
use zk_callbacks::generic::callbacks::CallbackCom;
use zk_callbacks::generic::interaction::generate_keys_for_statement_in;
use zk_callbacks::generic::interaction::Callback;
use zk_callbacks::generic::interaction::Interaction;
use zk_callbacks::generic::object::Id;
use zk_callbacks::generic::object::Time;
use zk_callbacks::generic::scan::{scan_method, scan_predicate};
use zk_callbacks::generic::scan::{PrivScanArgs, PrivScanArgsVar, PubScanArgs, PubScanArgsVar};
use zk_callbacks::generic::service::ServiceProvider;
use zk_callbacks::generic::user::{User, UserVar};
use zk_callbacks::impls::centralized::crypto::PlainTikCrypto;
use zk_callbacks::impls::dummy::DummyStore;
use zk_callbacks::impls::hash::Poseidon;
use zk_callbacks::util::UnitVar;
use zk_object::zk_object;

#[zk_object(F)]
#[derive(Default)]
pub struct TestUserData2 {
    pub token1: F,
    pub token2: F,
}

const NUMSCANS: usize = 1;

type CBArg = F;
type CBArgVar = FpVar<F>;

type U = User<F, TestUserData2>;
type UV = UserVar<F, TestUserData2>;
type CB = Callback<F, TestUserData2, F, FpVar<F>>;

type Int1 = Interaction<F, TestUserData2, (), UnitVar, (), UnitVar, CBArg, CBArgVar, 1>;

type PubScan = PubScanArgs<F, TestUserData2, F, FpVar<F>, PlainTikCrypto<F>, DummyStore>;
type PubScanVar = PubScanArgsVar<F, TestUserData2, F, FpVar<F>, PlainTikCrypto<F>, DummyStore>;
type PrivScan = PrivScanArgs<F, F, PlainTikCrypto<F>, DummyStore, NUMSCANS>;
type PrivScanVar = PrivScanArgsVar<F, F, PlainTikCrypto<F>, DummyStore, NUMSCANS>;

type IntScan =
    Interaction<F, TestUserData2, PubScan, PubScanVar, PrivScan, PrivScanVar, CBArg, CBArgVar, 0>;

fn int_meth<'a>(tu: &'a U, _pub_args: (), _priv_args: ()) -> U {
    tu.clone()
}

fn int_meth_pred<'a>(
    tu_old: &'a UV,
    tu_new: &'a UV,
    _pub_args: UnitVar,
    _priv_args: UnitVar,
) -> ArkResult<()> {
    tu_old
        .data
        .token1
        .enforce_equal(&FpVar::Constant(F::from(1)))?; // enforce a user has a token
    tu_old.data.token1.enforce_equal(&tu_new.data.token1)?;
    Ok(())
}

fn some_pred<'a, 'b>(
    _tu: &'a UV,
    _com: &'b FpVar<F>,
    _pub_args: UnitVar,
    _priv_args: UnitVar,
) -> ArkResult<()> {
    Ok(())
}

fn cb_meth<'a>(tu: &'a U, _args: F) -> U {
    let mut out = tu.clone();
    out.data.token1 = F::from(0); // revoke a token
    out
}

fn cb_pred<'a>(tu_old: &'a UV, _tu_new: &'a UV, _args: FpVar<F>) -> ArkResult<()> {
    tu_old
        .data
        .token1
        .enforce_equal(&FpVar::Constant(F::from(0)))?;
    Ok(())
}

fn main() {
    // SERVER SETUP

    // create a single callback type
    let cb: CB = Callback {
        method_id: Id::from(0),
        expirable: false,
        expiration: Time::from(0),
        method: cb_meth,
        predicate: cb_pred,
    };

    // The store for user objects
    let co_store = DummyStore;

    // The store for callbacks
    let cb_store = DummyStore;

    // The list of valid callback methods
    let cb_methods = vec![cb.clone()];

    // The first type of allowed interaction: a standard interaction
    let interaction: Int1 = Interaction {
        meth: (int_meth, int_meth_pred),
        callbacks: [cb.clone()],
    };

    // The second type of allowed interaction: a callback interaction
    let cb_interaction: IntScan = Interaction {
        meth: (
            scan_method::<
                F,
                TestUserData2,
                F,
                FpVar<F>,
                PlainTikCrypto<F>,
                DummyStore,
                Poseidon<2>,
                NUMSCANS,
            >,
            scan_predicate,
        ),
        callbacks: [],
    };

    // Generate keys for interaction 1, callback interaction, and proving a specific statement
    // about users
    let mut rng = thread_rng();

    let (pk, vk) = interaction
        .generate_keys::<Poseidon<2>, Groth16<E>, PlainTikCrypto<F>, DummyStore>(&mut rng, false);

    let (pks, vks) = cb_interaction
        .generate_keys::<Poseidon<2>, Groth16<E>, PlainTikCrypto<F>, DummyStore>(&mut rng, true);

    let (pki, _vki) = generate_keys_for_statement_in::<
        F,
        Poseidon<2>,
        TestUserData2,
        (),
        UnitVar,
        (),
        UnitVar,
        Groth16<E>,
        DummyStore,
    >(some_pred, &mut rng);

    // END SERVER, START USER

    // Create a single user
    let mut u = User::create(
        TestUserData2 {
            token1: F::from(1),
            token2: F::from(3),
        },
        &mut rng,
    );

    // Prove a statement about itself (and how it lies within the store)
    u.prove_statement_and_in::<Poseidon<2>, (), UnitVar, (), UnitVar, Groth16<E>, DummyStore>(
        &mut rng,
        some_pred,
        &pki,
        ((), ()),
        (),
        (),
    )
    .unwrap();

    println!("Initial user; Just proved a statement:\n {:?} \n\n", u);

    // Update the user in accordance with the first interaction
    let exec_method = u
        .interact::<Poseidon<2>, (), UnitVar, (), UnitVar, F, FpVar<F>, PlainTikCrypto<F>, Groth16<E>, DummyStore, 1>(
            &mut rng,
            interaction.clone(),
            [PlainTikCrypto(F::from(0))],
            ((), ()),
            &pk,
            (),
            (),
            false,
        )
        .unwrap();

    println!("User after executing interaction:\n {:?} \n\n", u);

    // Server checks proof on interaction with the verification key, approves it, and stores the new object into the store
    let res = co_store.approve_interaction_and_store::<F, TestUserData2, Groth16<E>, (), F, PlainTikCrypto<F>, DummyStore, 1>(
        exec_method,
        PlainTikCrypto(F::from(0)),
        (),
        &co_store,
        (),
        &vk,
        (),
    );

    println!("Result of checking proof and storing: {:?} \n\n", res);

    // User now updates its object again, again in accordance with the first interaction (each of
    // these two interactions have added callbacks to the user)
    let exec_method2 = u
        .interact::<Poseidon<2>, (), UnitVar, (), UnitVar, F, FpVar<F>, PlainTikCrypto<F>, Groth16<E>, DummyStore, 1>(
            &mut rng,
            interaction.clone(),
            [PlainTikCrypto(F::from(0))],
            ((), ()),
            &pk,
            (),
            (),
            false,
        )
        .unwrap();

    println!("User after executing second interaction:\n {:?} \n\n", u);

    // The server approves the interaction and stores it again
    let res = co_store.approve_interaction_and_store::<F, TestUserData2, Groth16<E>, (), F, PlainTikCrypto<F>, DummyStore, 1>(
        exec_method2,
        PlainTikCrypto(F::from(0)),
        (),
        &co_store,
        (),
        &vk,
        (),
    );

    println!("Result of checking proof and storing: {:?} \n\n", res);

    // Setup a scan for a single callback (the first one in the list)
    let ps = PubScanArgs {
        memb_pub: (),
        nmemb_pub: (),
        cur_time: F::from(0),
        bulletin: cb_store,
        cb_methods,
    };

    let prs = PrivScanArgs {
        priv_n_tickets: [
            CallbackCom::deserialize_compressed(&*u.callbacks[0]).unwrap(),
            // CallbackCom::deserialize_compressed(&*u.callbacks[1]).unwrap(),
        ],
        memb_priv: (),
        nmemb_priv: (),
    };

    let scan_one = u.interact::<Poseidon<2>, PubScan, PubScanVar, PrivScan, PrivScanVar, F, FpVar<F>, PlainTikCrypto<F>, Groth16<E>, DummyStore, 0>(&mut rng, cb_interaction.clone(), [], ((), ()), &pks, ps.clone(), prs, true);

    println!("User after a single scan is performed:\n {:?} \n\n", u);

    let prs = PrivScanArgs {
        priv_n_tickets: [
            // CallbackCom::deserialize_compressed(&*u.callbacks[0]).unwrap(),
            CallbackCom::deserialize_compressed(&*u.callbacks[1]).unwrap(),
        ],
        memb_priv: (),
        nmemb_priv: (),
    };

    let scan_two = u.interact::<Poseidon<2>, PubScan, PubScanVar, PrivScan, PrivScanVar, F, FpVar<F>, PlainTikCrypto<F>, Groth16<E>, DummyStore, 0>(&mut rng, cb_interaction.clone(), [], ((), ()), &pks, ps.clone(), prs, true);

    println!("User after the second scan is performed:\n {:?} \n\n", u);
}
