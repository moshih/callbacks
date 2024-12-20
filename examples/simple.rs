use ark_bn254::{Bn254 as E, Fr as F};
use ark_r1cs_std::prelude::Boolean;
use zk_callbacks::generic::bulletin::CallbackBulletin;
use zk_callbacks::generic::bulletin::PublicCallbackBul;
use zk_callbacks::generic::bulletin::UserBul;
use ark_groth16::Groth16;
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
use zk_callbacks::impls::centralized::sig::SigStore;
use zk_callbacks::impls::hash::Poseidon;
use zk_callbacks::util::UnitVar;
use zk_object::scannable_zk_object;
use std::time::SystemTime;

// Initialize a zk-object!

#[scannable_zk_object(F)]
#[derive(Default)]
pub struct TestUserData2 {
    pub token1: F,
    pub token2: F,
}

// How many callbacks we'll be scanning in when we go to the server for a scan (this can vary! In
// this example its constant, you will just have to generate multiple proving keys for different #
// of callbacks).
const NUMSCANS: usize = 1;

// Argument for the callback (we only have a single callback here, and the argument is a single
// field element.
type CBArg = F;
type CBArgVar = FpVar<F>;

// The wrapper "User" type around our zk-object.
type U = User<F, TestUserData2>;
type UV = UserVar<F, TestUserData2>;

// The type for the callback (what data it takes in: a user and an argument, in this case a field
// element).
type CB = Callback<F, TestUserData2, CBArg, CBArgVar>;

// The first type of interaction (doing a method update, which does nothing so far)
type Int1 = Interaction<F, TestUserData2, (), UnitVar, (), UnitVar, CBArg, CBArgVar, 1>;

// The scanning type: Most of this is unneccessary to understand, but really what it states is 
//  - The field and user (F, TestUserData2)
//  - The callback argument (F, FpVar<F>)
//  - The method of providing ticket authenticity and hiding arguments (PlainTikCrypto<F>)
//  - The callback bulletin (SigStore<F>)
//  - The number of callbacks
//
//  Note that the PlainTikCrypto in this case is centralized: there is no need to provide
//  authenticity, so signatures are (), and encryption is via a OTP
//
//  The actual type consists of membership data and the current time (public data).
type PubScan = PubScanArgs<F, TestUserData2, F, FpVar<F>, PlainTikCrypto<F>, SigStore<F>, NUMSCANS>;
type PubScanVar =
    PubScanArgsVar<F, TestUserData2, F, FpVar<F>, PlainTikCrypto<F>, SigStore<F>, NUMSCANS>;

// The private scanning type:
//  - The field (F)
//  - The callback argument (F),
//  - The crypto (PlainTikCrypto<F>),
//  - The callback bulletin (SigStore<F>),
//  - The number of callbacks
//
//  The actual type contains the tickets you pass into the proof of proper scanning, and private
//  witness membership data.
type PrivScan = PrivScanArgs<F, F, PlainTikCrypto<F>, SigStore<F>, NUMSCANS>;
type PrivScanVar = PrivScanArgsVar<F, F, PlainTikCrypto<F>, SigStore<F>, NUMSCANS>;

// The second type of interaction (updating the user due to a scan)
type IntScan =
    Interaction<F, TestUserData2, PubScan, PubScanVar, PrivScan, PrivScanVar, CBArg, CBArgVar, 0>;

// Two types of interactions: updating the user normally with Int1, or updating the user with a
// scan through IntScan.

// The user is incrementing the token by 1 each time the method is called.
fn int_meth<'a>(tu: &'a U, _pub_args: (), _priv_args: ()) -> U {
    let mut a = tu.clone();
    a.data.token1 += F::from(1);

    // We could update token2 here! If you want :), there's nothing enforcing we need to keep it
    // the same.
    a
}

// Enforce that token1 in [0, 1, 2] (user can pretty much pick token2). Additionally, enforce
// that token1 is identical to (before + 1). This is effectively a rate limit: The user can
// only do an interaction twice before being unable to produce a proof.
//
// Note that there are no enforcements on token2, so it can be whatever the user wants.
fn int_meth_pred<'a>(
    tu_old: &'a UV,
    tu_new: &'a UV,
    _pub_args: UnitVar,
    _priv_args: UnitVar,
) -> ArkResult<Boolean<F>> {
    let l0 = tu_new
        .data
        .token1
        .is_eq(&FpVar::Constant(F::from(0)))?; 
    let l1 = tu_new
        .data
        .token1
        .is_eq(&FpVar::Constant(F::from(1)))?; 
    let l2 = tu_new
        .data
        .token1
        .is_eq(&FpVar::Constant(F::from(2)))?; 
    let o2 = tu_old.data.token1.clone() + FpVar::Constant(F::from(1));
    let b2 = tu_new.data.token1.is_eq(&o2)?;
    Ok((l0 | l1 | l2) & b2)
}

// We can also prove arbitrary predicates to the server. Here, we just prove that our token2 value
// is 3. Could be for some kind of lottery or something?
fn some_pred<'a, 'b>(
    tu: &'a UV,
    _com: &'b FpVar<F>,
    _pub_args: UnitVar,
    _priv_args: UnitVar,
) -> ArkResult<Boolean<F>> {
    tu.data.token2.is_eq(&FpVar::Constant(F::from(3)))
}

// The callback method here allows the *server* to call a method on the user: Here the argument (F)
// being passed in can be selected by the server, and the user is forced to set their token1 to
// `args`.
fn cb_meth<'a>(tu: &'a U, args: F) -> U {
    let mut out = tu.clone();
    out.data.token1 = args;
    out
}

// The proof that enforces the callback that the server calls.
fn cb_pred<'a>(tu_old: &'a UV,  args: FpVar<F>) -> ArkResult<UV> {
    let mut tu_new = tu_old.clone();
    tu_new.data.token1 = args;
    Ok(tu_new)
}

fn main() {
    // SERVER SETUP
    let mut rng = thread_rng();

    // create a single callback type
    let cb: CB = Callback {
        method_id: Id::from(0),
        expirable: false,
        expiration: Time::from(300),
        method: cb_meth,
        predicate: cb_pred,
    };

    // irrelevant callback type, we create it to test the checks
    let cb2: CB = Callback {
        method_id: Id::from(1),
        expirable: true,
        expiration: Time::from(1),
        method: cb_meth,
        predicate: cb_pred,
    };

    println!("[SERVER] INIT...");
    // The store for user objects

    let start = SystemTime::now();

    let mut co_store = SigStore::new(&mut rng);

    println!("\t (time) Generated data structures: {:?}", start.elapsed().unwrap());

    // The list of valid callback methods
    let cb_methods = vec![cb.clone(), cb2.clone()];

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
    
    // For circuit generation
    let ex = PubScanArgs {
        memb_pub: [co_store.pubkey_cb.clone(); NUMSCANS],
        is_memb_data_const: true,
        nmemb_pub: [co_store.pubkey_ncb.clone(); NUMSCANS],
        is_nmemb_data_const: true,
        cur_time: F::from(0),
        bulletin: co_store.clone(),
        cb_methods: cb_methods.clone(),
    };

    println!("[SERVER] PROOF KEY GENERATION...");

    let start = SystemTime::now();

    // generate keys for the method described initially
    let (pk, vk) = interaction // see interaction
        .generate_keys::<Poseidon<2>, Groth16<E>, PlainTikCrypto<F>, SigStore<F>>(&mut rng, Some(co_store.pubkey.clone()), None, false);

    // generate keys for the callback scan
    let (pks, vks) = cb_interaction // see cb_interaction
        .generate_keys::<Poseidon<2>, Groth16<E>, PlainTikCrypto<F>, SigStore<F>>(&mut rng, Some(co_store.pubkey.clone()), Some(ex), true);

    // generate keys for the arbitrary predicate
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
    >(&mut rng, some_pred, Some(co_store.pubkey.clone()), None);

    println!("\t (time) Generated proof keys: {:?}", start.elapsed().unwrap());
    println!("[SERVER] Init done! \n\n");

    // END SERVER, START USER







    // Create a single user
    
    println!("[USER] Creation... ");
    let mut u = User::create(
        TestUserData2 {
            token1: F::from(0), // Try changing this to 1 or 2 to see what happens!
            token2: F::from(3), // Try changing this off of 3 to see what happens!
        },
        &mut rng,
    );
    println!("[USER] Created! User: {:o}", u);







    // Join in as a user
    let _ = <SigStore<F> as JoinableBulletin<F, TestUserData2>>::join_bul(
        &mut co_store,
        u.commit::<Poseidon<2>>(),
        (),
    );
    println!("[USER] joined! \n\n");








    println!("[USER] Generating proof... ");
    let start = SystemTime::now();
    // Prove a statement about itself (and how it lies within the store)
    let proof = u
        .prove_statement_and_in::<Poseidon<2>, (), UnitVar, (), UnitVar, Groth16<E>, SigStore<F>>(
            &mut rng,
            some_pred, // Specifically, this statement here (see some_pred above)
            &pki,
            (
                co_store
                    .get_signature_of(&u.commit::<Poseidon<2>>()) // private membership data (for
                    // the user)
                    .unwrap(),
                co_store.pubkey.clone(), // public membership data (the sig pubkey)
            ),
            true,
            (),
            (),
            true
        )
        .unwrap();

    println!("\t (time) Generated proof in + statement: {:?}", start.elapsed().unwrap());
    println!("[USER] Proof generated! \n\n");








    println!("[SERVER] Verifying proof... ");
    let start = SystemTime::now();

    let mut pub_inputs = vec![];
    pub_inputs.extend::<Vec<F>>(().to_field_elements().unwrap()); // pub args
    // pub_inputs.extend::<Vec<F>>(co_store.pubkey.clone().to_field_elements().unwrap()); // pub membership data (if not constant)
    // The public membership data in this case is constant, so we don't need to pass it in as an
    // argument
    let out = Groth16::<E>::verify(&vki, &pub_inputs, &proof);

    println!("\t (time) Verified proof: {:?}", start.elapsed().unwrap());
    println!("[SERVER] Verified proof Output: {:?} \n\n", out);









    println!("[USER] Interacting (proving)...");
    let start = SystemTime::now();
    // Update the user in accordance with the first interaction
    let exec_method = u
        .interact::<Poseidon<2>, (), UnitVar, (), UnitVar, F, FpVar<F>, PlainTikCrypto<F>, Groth16<E>, SigStore<F>, 1>(
            &mut rng,
            interaction.clone(), // see interaction
            [PlainTikCrypto(F::from(0))],
            (
                co_store
                    .get_signature_of(&u.commit::<Poseidon<2>>())
                    .unwrap(),
                co_store.pubkey.clone(),
            ),
            true,
            &pk,
            (),
            (),
            false,
            true
        )
        .unwrap();

    println!("\t (time) Interaction (proving) time: {:?}", start.elapsed().unwrap());
    println!("[USER] Executed interaction! New user: {:o} \n\n", u);








    println!("[BULLETIN / SERVER] Verifying and storing...");
    let start = SystemTime::now();

    let out = <SigStore<F> as UserBul<F, TestUserData2>>::verify_interact_and_append::<(), Groth16<E>, 1>(&mut co_store, exec_method.new_object.clone(), exec_method.old_nullifier.clone(), (), exec_method.cb_com_list.clone(), exec_method.proof.clone(), None, &vk);
    let s1 = start.elapsed().unwrap();
    // Server checks proof on interaction with the verification key, approves it, and stores the new object into the store
    
    let start = SystemTime::now();

    let res = co_store
        .approve_interaction_and_store::<TestUserData2, Groth16<E>, (), SigStore<F>, 1>(
            exec_method, // output of interaction
            PlainTikCrypto(F::from(0)), // for authenticity: verify rerandomization of key produces
            // proper tickets (here it doesn't matter)
            (), 
            &co_store.clone(),
            co_store.pubkey.clone(),
            true,
            &vk,
            332, // interaction number
        );

    println!("\t (time) Verify + append: {:?}", s1);
    println!("\t (time) Verify + store interaction: {:?}", start.elapsed().unwrap());
    println!("[BULLETIN] Checked proof and stored user... Output: {:?}", out);
    println!("[SERVER] Checking proof and storing interaction... Output: {:?} \n\n", res);







    // User now updates its object again, again in accordance with the first interaction (each of
    // these two interactions have added callbacks to the user)
    //
    println!("[USER] Interacting (proving)...");
    let start = SystemTime::now();

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
            true,
            &pk,
            (),
            (),
            false,
            true,
        )
        .unwrap();

    println!("\t (time) Interaction (proving) time: {:?}", start.elapsed().unwrap());

    println!("[USER] Executed interaction! New user: {:o} \n\n", u);












    println!("[BULLETIN / SERVER] Verifying and storing...");
    let start = SystemTime::now();

    let out = <SigStore<F> as UserBul<F, TestUserData2>>::verify_interact_and_append::<(), Groth16<E>, 1>(&mut co_store, exec_method2.new_object.clone(), exec_method2.old_nullifier.clone(), (), exec_method2.cb_com_list.clone(), exec_method2.proof.clone(), None, &vk);

    let s1 = start.elapsed().unwrap();
    let start = SystemTime::now();

    // The server approves the interaction and stores it again
    let res = co_store
        .approve_interaction_and_store::<TestUserData2, Groth16<E>, (), SigStore<F>, 1>(
            exec_method2,
            PlainTikCrypto(F::from(0)),
            (),
            &co_store.clone(),
            co_store.pubkey.clone(),
            true,
            &vk,
            389,
        );

    println!("\t (time) Verify + append: {:?}", s1);
    println!("\t (time) Verify + store interaction: {:?}", start.elapsed().unwrap());
    println!("[BULLETIN] Checking proof and storing new user... Output: {:?}", out);
    println!("[SERVER] Checking proof and storing interaction... Output: {:?} \n\n", res);











    println!("[USER] Scanning a ticket... ");
    // Setup a scan for a single callback (the first one in the list)
    let ps = PubScanArgs { // Create the public scanning arguments
        memb_pub: [co_store.pubkey_cb.clone()], // Public membership data (pubkey)
        is_memb_data_const: true, // it is constant
        nmemb_pub: [co_store.pubkey_ncb.clone()], // Public nonmemb data (pubkey for range sigs)
        is_nmemb_data_const: true,
        cur_time: co_store.epoch, // *current* time as of this proof generation
        bulletin: co_store.clone(), // bulletin handle
        cb_methods: cb_methods.clone(), // Vec of callbacks (used to check which method to call)
    };


    let cb = CallbackCom::deserialize_compressed(&*u.callbacks[0]).unwrap(); // First ticket in the
    // list!
    let tik: PlainTikCrypto<F> = cb.clone().cb_entry.tik;

    let prs = PrivScanArgs { // Private arguments
        priv_n_tickets: [
            cb, // The callback ticket (should be private)
        ],
        post_times: [co_store.verify_in(tik.clone()).map_or(F::from(0), |(_, p2)| p2)], // Get
        // *server* post time for ticket if it exists
        enc_args: [co_store.verify_in(tik.clone()).map_or(F::from(0), |(p1, _)| p1)], // Get
        // server posted encrypted arguments for ticket
        memb_priv: [co_store.get_cb_signature_of(&tik).unwrap_or_default()], // Signature on ticket
        nmemb_priv: [co_store.get_cb_sig_range_of(&tik).unwrap_or_default()], // Signature on
        // ticket
    };

    let start = SystemTime::now();

    let scan_one = u.interact::<Poseidon<2>, PubScan, PubScanVar, PrivScan, PrivScanVar, F, FpVar<F>, PlainTikCrypto<F>, Groth16<E>, SigStore<F>, 0>
        (&mut rng, cb_interaction.clone(), [],  // Note cb_interaction: the scan is still an
            // interaction
            (
                co_store
                    .get_signature_of(&u.commit::<Poseidon<2>>())
                    .unwrap(),
                co_store.pubkey.clone(),
            ),
            true,
        &pks, ps.clone(), prs, true, true).unwrap();
    println!("\t (time) Scanning (interaction proving) time: {:?}", start.elapsed().unwrap());

    println!("[USER] Scanned single ticket... {:o} \n\n", u);









    println!("[BULLETIN / SERVER] Verifying and storing scan...");
    let start = SystemTime::now();

    let out = <SigStore<F> as UserBul<F, TestUserData2>>::verify_interact_and_append::<PubScan, Groth16<E>, 0>(&mut co_store, scan_one.new_object.clone(), scan_one.old_nullifier.clone(), ps.clone(), scan_one.cb_com_list.clone(), scan_one.proof.clone(), None, &vks);

    let s1 = start.elapsed().unwrap();

    let start = SystemTime::now();

    let res = co_store
        .approve_interaction_and_store::<TestUserData2, Groth16<E>, PubScan, SigStore<F>, 0>(
            scan_one,
            PlainTikCrypto(F::from(0)),
            ps.clone(),
            &co_store.clone(),
            co_store.pubkey.clone(),
            true,
            &vks,
            441,
        );

    println!("\t (time) Verify + append: {:?}", s1);
    println!("\t (time) Verify + store scan: {:?}", start.elapsed().unwrap());

    println!("[BULLETIN] Checking proof and storing new user... Output: {:?}", out);
    println!("[SERVER] Checking proof for first scan... Output: {:?} \n\n", res);










    println!("[SERVER] Calling *the second callback*... ");

    let called = co_store.call(co_store.cb_tickets[1][0].0.clone(), F::from(41), PlainTikCrypto(F::from(0))).unwrap();
    co_store.verify_call_and_append(called.0, called.1, called.2, Time::from(0)).unwrap();
    co_store.update_epoch(&mut rng);
    println!("[SERVER] Called!... \n\n");









    println!("[USER] Scanning the second ticket... ");
    
    // Setup a scan for the second callback
    let ps = PubScanArgs {
        memb_pub: [co_store.pubkey_cb.clone()], 
        is_memb_data_const: true,
        nmemb_pub: [co_store.pubkey_ncb.clone()], 
        is_nmemb_data_const: true,
        cur_time: co_store.epoch,
        bulletin: co_store.clone(),
        cb_methods: cb_methods.clone(),
    };

    let cb = CallbackCom::deserialize_compressed(&*u.callbacks[1]).unwrap();
    let tik: PlainTikCrypto<F> = cb.clone().cb_entry.tik;

    let prs = PrivScanArgs {
        priv_n_tickets: [
            cb,
        ],
        post_times: [co_store.verify_in(tik.clone()).map_or(F::from(0), |(_, p2)| p2)],
        enc_args: [co_store.verify_in(tik.clone()).map_or(F::from(0), |(p1, _)| p1)],
        memb_priv: [co_store.get_cb_signature_of(&tik).unwrap_or_default()],
        nmemb_priv: [co_store.get_cb_sig_range_of(&tik).unwrap_or_default()],
    };

    let start = SystemTime::now();

    let scan_second = u.interact::<Poseidon<2>, PubScan, PubScanVar, PrivScan, PrivScanVar, F, FpVar<F>, PlainTikCrypto<F>, Groth16<E>, SigStore<F>, 0>
        (&mut rng, cb_interaction.clone(), [], 
            (
                co_store
                    .get_signature_of(&u.commit::<Poseidon<2>>())
                    .unwrap(),
                co_store.pubkey.clone(),
            ),
            true,
        &pks, ps.clone(), prs, true, true).unwrap();

    println!("\t (time) Scanning time: {:?}", start.elapsed().unwrap());
    println!("[USER] Scanning the second ticket... {:o} \n\n", u);










    println!("[BULLETIN / SERVER] Verifying and storing scan...");
    let start = SystemTime::now();

    let out = <SigStore<F> as UserBul<F, TestUserData2>>::verify_interact_and_append::<PubScan, Groth16<E>, 0>(&mut co_store, scan_second.new_object.clone(), scan_second.old_nullifier.clone(), ps.clone(), scan_second.cb_com_list.clone(), scan_second.proof.clone(), None, &vks);
    let s1 = start.elapsed().unwrap();

    let start = SystemTime::now();

    let res = co_store
        .approve_interaction_and_store::<TestUserData2, Groth16<E>, PubScan, SigStore<F>, 0>(
            scan_second,
            PlainTikCrypto(F::from(0)),
            ps.clone(),
            &co_store.clone(),
            co_store.pubkey.clone(),
            true,
            &vks,
            441,
        );


    println!("\t (time) Verify + append: {:?}", s1);
    println!("\t (time) Verify + store scan: {:?}", start.elapsed().unwrap());
    println!("[BULLETIN] Checking proof and storing new user... Output: {:?}", out);
    println!("[SERVER] Checking proof for second scan... Output: {:?} \n\n", res);

    // println!("User at the end : {:?}", u);
}
