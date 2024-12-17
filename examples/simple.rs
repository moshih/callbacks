use ark_bn254::{Bn254 as E, Fr as F};
use ark_r1cs_std::prelude::Boolean;
use ark_groth16::Groth16;
use zk_callbacks::impls::centralized::sigtest::Sig;
use ark_r1cs_std::eq::EqGadget;
use ark_r1cs_std::fields::fp::FpVar;
use ark_relations::r1cs::Result as ArkResult;
use ark_relations::r1cs::ToConstraintField;
use ark_serialize::CanonicalDeserialize;
use ark_snark::SNARK;
use rand::thread_rng;
use zk_callbacks::generic::bulletin::JoinableBulletin;
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
use zk_callbacks::impls::centralized::sigtest::SigStore;
use zk_callbacks::impls::hash::Poseidon;
use zk_callbacks::util::UnitVar;
use zk_object::scannable_zk_object;

#[scannable_zk_object(F)]
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

type PubScan = PubScanArgs<F, TestUserData2, F, FpVar<F>, PlainTikCrypto<F>, SigStore<F>, NUMSCANS>;
type PubScanVar =
    PubScanArgsVar<F, TestUserData2, F, FpVar<F>, PlainTikCrypto<F>, SigStore<F>, NUMSCANS>;
type PrivScan = PrivScanArgs<F, F, PlainTikCrypto<F>, SigStore<F>, NUMSCANS>;
type PrivScanVar = PrivScanArgsVar<F, F, PlainTikCrypto<F>, SigStore<F>, NUMSCANS>;

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
) -> ArkResult<Boolean<F>> {
    let b1 = tu_old
        .data
        .token1
        .is_eq(&FpVar::Constant(F::from(1)))?; // enforce a user has a token
    let b2 = tu_old.data.token1.is_eq(&tu_new.data.token1)?;
    Ok(b1 & b2)
}

fn some_pred<'a, 'b>(
    _tu: &'a UV,
    _com: &'b FpVar<F>,
    _pub_args: UnitVar,
    _priv_args: UnitVar,
) -> ArkResult<Boolean<F>> {
    Ok(Boolean::TRUE)
}

fn cb_meth<'a>(tu: &'a U, _args: F) -> U {
    let mut out = tu.clone();
    out.data.token1 = F::from(0); // revoke a token
    out
}

fn cb_pred<'a>(tu_old: &'a UV,  _args: FpVar<F>) -> ArkResult<UV> {
    let mut tu_new = tu_old.clone();
    tu_new.data.token1 = FpVar::Constant(F::from(0));
    Ok(tu_new)
}

fn main() {
    // SERVER SETUP
    let mut rng = thread_rng();

    // create a single callback type
    let cb: CB = Callback {
        method_id: Id::from(0),
        expirable: false,
        expiration: Time::from(0),
        method: cb_meth,
        predicate: cb_pred,
    };

    println!("[SERVER] INIT...");
    // The store for user objects
    let mut co_store = SigStore::new(&mut rng);

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
                SigStore<F>,
                Poseidon<2>,
                NUMSCANS,
            >,
            scan_predicate::<
                F,
                TestUserData2,
                F,
                FpVar<F>,
                PlainTikCrypto<F>,
                SigStore<F>,
                Poseidon<2>,
                NUMSCANS,
            >,
        ),
        callbacks: [],
    };

    // Generate keys for interaction 1, callback interaction, and proving a specific statement
    // about users

    println!("[SERVER] KEY GENERATION...");
    let (pk, vk) = interaction
        .generate_keys::<Poseidon<2>, Groth16<E>, PlainTikCrypto<F>, SigStore<F>>(&mut rng, false);

    let (pks, vks) = cb_interaction
        .generate_keys::<Poseidon<2>, Groth16<E>, PlainTikCrypto<F>, SigStore<F>>(&mut rng, true);

    let (pki, vki) = generate_keys_for_statement_in::<
        F,
        Poseidon<2>,
        TestUserData2,
        (),
        UnitVar,
        (),
        UnitVar,
        Groth16<E>,
        SigStore<F>,
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
    println!("[USER] created... {:?} \n\n", u);


    // Join in as a user
    let _ = <SigStore<F> as JoinableBulletin<F, TestUserData2>>::join_bul(
        &mut co_store,
        u.commit::<Poseidon<2>>(),
        (),
    );
    println!("[USER] joined! \n");


    // Prove a statement about itself (and how it lies within the store)
    let proof = u
        .prove_statement_and_in::<Poseidon<2>, (), UnitVar, (), UnitVar, Groth16<E>, SigStore<F>>(
            &mut rng,
            some_pred,
            &pki,
            (
                co_store
                    .get_signature_of(&u.commit::<Poseidon<2>>())
                    .unwrap(),
                co_store.pubkey.clone(),
            ),
            (),
            (),
            true
        )
        .unwrap();
    println!("[USER] Generated a proof... \n");

    let mut pub_inputs = vec![];
    pub_inputs.extend::<Vec<F>>(().to_field_elements().unwrap()); // pub args
    pub_inputs.extend::<Vec<F>>(co_store.pubkey.clone().to_field_elements().unwrap()); // pub membership data
    let out = Groth16::<E>::verify(&vki, &pub_inputs, &proof);

    println!("[SERVER] Verifying... Output: {:?} \n\n", out);

    // Update the user in accordance with the first interaction
    let exec_method = u
        .interact::<Poseidon<2>, (), UnitVar, (), UnitVar, F, FpVar<F>, PlainTikCrypto<F>, Groth16<E>, SigStore<F>, 1>(
            &mut rng,
            interaction.clone(),
            [PlainTikCrypto(F::from(0))],
            (
                co_store
                    .get_signature_of(&u.commit::<Poseidon<2>>())
                    .unwrap(),
                co_store.pubkey.clone(),
            ),
            &pk,
            (),
            (),
            false,
            true
        )
        .unwrap();

    println!("[USER] Executed interaction! New user: {:?} \n\n", u);

    // Server checks proof on interaction with the verification key, approves it, and stores the new object into the store
    let res = co_store
        .approve_interaction_and_store::<TestUserData2, Groth16<E>, (), SigStore<F>, 1>(
            exec_method,
            PlainTikCrypto(F::from(0)),
            (),
            &co_store.clone(),
            co_store.pubkey.clone(),
            &vk,
            (),
        );

    println!("[SERVER] Checking proof and storing... Output: {:?} \n\n", res);

    // User now updates its object again, again in accordance with the first interaction (each of
    // these two interactions have added callbacks to the user)
    let exec_method2 = u
        .interact::<Poseidon<2>, (), UnitVar, (), UnitVar, F, FpVar<F>, PlainTikCrypto<F>, Groth16<E>, SigStore<F>, 1>(
            &mut rng,
            interaction.clone(),
            [PlainTikCrypto(F::from(0))],
            (
                co_store
                    .get_signature_of(&u.commit::<Poseidon<2>>())
                    .unwrap(),
                co_store.pubkey.clone(),
            ),
            &pk,
            (),
            (),
            false,
            true,
        )
        .unwrap();

    println!("[USER] Executed interaction! New user: {:?} \n\n", u);

    // The server approves the interaction and stores it again
    let res = co_store
        .approve_interaction_and_store::<TestUserData2, Groth16<E>, (), SigStore<F>, 1>(
            exec_method2,
            PlainTikCrypto(F::from(0)),
            (),
            &co_store.clone(),
            co_store.pubkey.clone(),
            &vk,
            (),
        );

    println!("[SERVER] Checking proof and storing... Output: {:?} \n\n", res);

    // Setup a scan for a single callback (the first one in the list)
    let ps = PubScanArgs {
        memb_pub: [co_store.pubkey_cb.clone()], // , co_store.pubkey_cb.clone()],
        nmemb_pub: [co_store.pubkey_ncb.clone()], // , co_store.pubkey_ncb.clone()],
        cur_time: F::from(0),
        bulletin: co_store.clone(),
        cb_methods,
    };

    let prs = PrivScanArgs {
        priv_n_tickets: [
            CallbackCom::deserialize_compressed(&*u.callbacks[0]).unwrap(),
            // CallbackCom::deserialize_compressed(&*u.callbacks[1]).unwrap(),
        ],
        enc_args: [F::from(0)], //F::from(0)],
        post_times: [F::from(0)], // F::from(0)],
        memb_priv: [Sig::default()], // Sig::default()],
        nmemb_priv: [co_store.ncalled_cbs[0].clone()], // co_store.ncalled_cbs[0].clone()],
    };

    let scan_one = u.interact::<Poseidon<2>, PubScan, PubScanVar, PrivScan, PrivScanVar, F, FpVar<F>, PlainTikCrypto<F>, Groth16<E>, SigStore<F>, 0>
        (&mut rng, cb_interaction.clone(), [], 
            (
                co_store
                    .get_signature_of(&u.commit::<Poseidon<2>>())
                    .unwrap(),
                co_store.pubkey.clone(),
            ),
        &pks, ps.clone(), prs, true, true).unwrap();

    println!("[USER] Scanning a single ticket... {:?} \n\n", u);

    let res = co_store
        .approve_interaction_and_store::<TestUserData2, Groth16<E>, PubScan, SigStore<F>, 0>(
            scan_one,
            PlainTikCrypto(F::from(0)),
            ps.clone(),
            &co_store.clone(),
            co_store.pubkey.clone(),
            &vks,
            (),
        );

    println!("[SERVER] Checking proof and storing... Output: {:?} \n\n", res);
}
