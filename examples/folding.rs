use ark_bn254::{constraints::GVar, G1Projective as Projective};
use ark_bn254::{Bn254 as E, Fr as F};
use ark_groth16::Groth16;
use ark_grumpkin::{constraints::GVar as GVar2, Projective as Projective2};
use ark_r1cs_std::eq::EqGadget;
use ark_r1cs_std::fields::fp::FpVar;
use ark_r1cs_std::prelude::Boolean;
use ark_relations::r1cs::Result as ArkResult;
use ark_serialize::CanonicalDeserialize;
use folding_schemes::commitment::kzg::KZG;
use folding_schemes::commitment::pedersen::Pedersen;
use folding_schemes::folding::nova::Nova;
use folding_schemes::folding::nova::PreprocessorParam;
use folding_schemes::frontend::FCircuit;
use folding_schemes::transcript::poseidon::poseidon_canonical_config;
use folding_schemes::FoldingScheme;
use rand::thread_rng;
use zk_callbacks::generic::bulletin::JoinableBulletin;
use zk_callbacks::generic::bulletin::PublicCallbackBul;
use zk_callbacks::generic::bulletin::UserBul;
use zk_callbacks::generic::callbacks::CallbackCom;
use zk_callbacks::generic::fold::FoldSer;
use zk_callbacks::generic::fold::FoldableUserData;
use zk_callbacks::generic::fold::FoldingScan;
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

#[scannable_zk_object(F)]
#[derive(Default)]
pub struct TestFolding {
    pub token1: F,
    pub token2: F,
}

impl FoldSer<F, TestFoldingZKVar> for TestFolding {
    fn repr_len() -> usize {
        2
    }

    fn to_fold_repr(&self) -> Vec<zk_callbacks::generic::object::Ser<F>> {
        vec![self.token1.clone(), self.token2.clone()]
    }

    fn from_fold_repr(ser: &[zk_callbacks::generic::object::Ser<F>]) -> Self {
        Self {
            token1: ser[0].clone(),
            token2: ser[1].clone(),
        }
    }

    fn from_fold_repr_zk(
        var: &[zk_callbacks::generic::object::SerVar<F>],
    ) -> Result<TestFoldingZKVar, ark_relations::r1cs::SynthesisError> {
        Ok(TestFoldingZKVar {
            token1: var[0].clone(),
            token2: var[1].clone(),
        })
    }

    fn to_fold_repr_zk(
        var: &TestFoldingZKVar,
    ) -> Result<Vec<zk_callbacks::generic::object::SerVar<F>>, ark_relations::r1cs::SynthesisError>
    {
        Ok(vec![var.token1.clone(), var.token2.clone()])
    }
}

impl FoldableUserData<F> for TestFolding {}

const NUMSCANS: usize = 1;
type CBArg = F;
type CBArgVar = FpVar<F>;
type U = User<F, TestFolding>;
type UV = UserVar<F, TestFolding>;
type CB = Callback<F, TestFolding, CBArg, CBArgVar>;
type Int1 = Interaction<F, TestFolding, (), UnitVar, (), UnitVar, CBArg, CBArgVar, 1>;
type PubScan = PubScanArgs<F, TestFolding, F, FpVar<F>, PlainTikCrypto<F>, SigStore<F>, NUMSCANS>;
type PubScanVar =
    PubScanArgsVar<F, TestFolding, F, FpVar<F>, PlainTikCrypto<F>, SigStore<F>, NUMSCANS>;

type PrivScan = PrivScanArgs<F, F, PlainTikCrypto<F>, SigStore<F>, NUMSCANS>;
type PrivScanVar = PrivScanArgsVar<F, F, PlainTikCrypto<F>, SigStore<F>, NUMSCANS>;

type IntScan =
    Interaction<F, TestFolding, PubScan, PubScanVar, PrivScan, PrivScanVar, CBArg, CBArgVar, 0>;

fn int_meth<'a>(tu: &'a U, _pub_args: (), _priv_args: ()) -> U {
    let mut a = tu.clone();
    a.data.token1 += F::from(1);

    a
}

fn int_meth_pred<'a>(
    tu_old: &'a UV,
    tu_new: &'a UV,
    _pub_args: UnitVar,
    _priv_args: UnitVar,
) -> ArkResult<Boolean<F>> {
    let l0 = tu_new.data.token1.is_eq(&FpVar::Constant(F::from(0)))?;
    let l1 = tu_new.data.token1.is_eq(&FpVar::Constant(F::from(1)))?;
    let l2 = tu_new.data.token1.is_eq(&FpVar::Constant(F::from(2)))?;
    let o2 = tu_old.data.token1.clone() + FpVar::Constant(F::from(1));
    let b2 = tu_new.data.token1.is_eq(&o2)?;
    Ok((l0 | l1 | l2) & b2)
}
fn cb_meth<'a>(tu: &'a U, args: F) -> U {
    let mut out = tu.clone();
    out.data.token1 = args;
    out
}

fn cb_pred<'a>(tu_old: &'a UV, args: FpVar<F>) -> ArkResult<UV> {
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

    let mut co_store = SigStore::new(&mut rng);

    let cb_methods = vec![cb.clone(), cb2.clone()];

    let interaction: Int1 = Interaction {
        meth: (int_meth, int_meth_pred),
        callbacks: [cb.clone()],
    };

    let cb_interaction: IntScan = Interaction {
        meth: (
            scan_method::<
                F,
                TestFolding,
                F,
                FpVar<F>,
                PlainTikCrypto<F>,
                SigStore<F>,
                Poseidon<2>,
                NUMSCANS,
            >,
            scan_predicate::<
                F,
                TestFolding,
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

    let ex = PubScanArgs {
        memb_pub: [co_store.pubkey_cb.clone(); NUMSCANS],
        is_memb_data_const: true,
        nmemb_pub: [co_store.pubkey_ncb.clone(); NUMSCANS],
        is_nmemb_data_const: true,
        cur_time: F::from(0),
        bulletin: co_store.clone(),
        cb_methods: cb_methods.clone(),
    };

    // generate keys for the method described initially
    let (pk, vk) =
        interaction // see interaction
            .generate_keys::<Poseidon<2>, Groth16<E>, PlainTikCrypto<F>, SigStore<F>>(
                &mut rng,
                Some(co_store.pubkey.clone()),
                None,
                false,
            );

    // generate keys for the callback scan
    let (_pks, _vks) =
        cb_interaction // see cb_interaction
            .generate_keys::<Poseidon<2>, Groth16<E>, PlainTikCrypto<F>, SigStore<F>>(
                &mut rng,
                Some(co_store.pubkey.clone()),
                Some(ex),
                true,
            );

    let mut u = User::create(
        TestFolding {
            token1: F::from(0),
            token2: F::from(3),
        },
        &mut rng,
    );

    let _ = <SigStore<F> as JoinableBulletin<F, TestFolding>>::join_bul(
        &mut co_store,
        u.commit::<Poseidon<2>>(),
        (),
    );

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

    let _out =
        <SigStore<F> as UserBul<F, TestFolding>>::verify_interact_and_append::<(), Groth16<E>, 1>(
            &mut co_store,
            exec_method.new_object.clone(),
            exec_method.old_nullifier.clone(),
            (),
            exec_method.cb_com_list.clone(),
            exec_method.proof.clone(),
            None,
            &vk,
        );
    // Server checks proof on interaction with the verification key, approves it, and stores the new object into the store

    let _ = co_store.approve_interaction_and_store::<TestFolding, Groth16<E>, (), SigStore<F>, 1>(
        exec_method,                // output of interaction
        PlainTikCrypto(F::from(0)), // for authenticity: verify rerandomization of key produces
        // proper tickets (here it doesn't matter)
        (),
        &co_store.clone(),
        co_store.pubkey.clone(),
        true,
        &vk,
        332, // interaction number
    );

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

    let _ = <SigStore<F> as UserBul<F, TestFolding>>::verify_interact_and_append::<(), Groth16<E>, 1>(
        &mut co_store,
        exec_method2.new_object.clone(),
        exec_method2.old_nullifier.clone(),
        (),
        exec_method2.cb_com_list.clone(),
        exec_method2.proof.clone(),
        None,
        &vk,
    );

    // The server approves the interaction and stores it again
    let _ = co_store.approve_interaction_and_store::<TestFolding, Groth16<E>, (), SigStore<F>, 1>(
        exec_method2,
        PlainTikCrypto(F::from(0)),
        (),
        &co_store.clone(),
        co_store.pubkey.clone(),
        true,
        &vk,
        389,
    );

    type NF = Nova<
        Projective,
        GVar,
        Projective2,
        GVar2,
        FoldingScan<F, TestFolding, CBArg, CBArgVar, PlainTikCrypto<F>, SigStore<F>, Poseidon<2>>,
        KZG<'static, E>,
        Pedersen<Projective2>,
        false,
    >;

    // Setup a scan for a single callback (the first one in the list)
    let ps = PubScanArgs {
        // Create the public scanning arguments
        memb_pub: [co_store.pubkey_cb.clone()], // Public membership data (pubkey)
        is_memb_data_const: true,               // it is constant
        nmemb_pub: [co_store.pubkey_ncb.clone()], // Public nonmemb data (pubkey for range sigs)
        is_nmemb_data_const: true,
        cur_time: co_store.epoch, // *current* time as of this proof generation
        bulletin: co_store.clone(), // bulletin handle
        cb_methods: cb_methods.clone(), // Vec of callbacks (used to check which method to call)
    };

    let f_circ: FoldingScan<
        F,
        TestFolding,
        CBArg,
        CBArgVar,
        PlainTikCrypto<F>,
        SigStore<F>,
        Poseidon<2>,
    > = FoldingScan::new(ps.clone()).unwrap();

    let poseidon_config = poseidon_canonical_config::<F>();
    let nova_preprocess_params = PreprocessorParam::new(poseidon_config, f_circ.clone());
    let nova_params = NF::preprocess(&mut rng, &nova_preprocess_params).unwrap();

    let init_state = vec![u.commit::<Poseidon<2>>()];

    let cb = CallbackCom::deserialize_compressed(&*u.callbacks[0]).unwrap();
    let tik: PlainTikCrypto<F> = cb.clone().cb_entry.tik;

    let prs1: PrivScanArgs<F, CBArg, PlainTikCrypto<F>, SigStore<F>, 1> = PrivScanArgs {
        priv_n_tickets: [cb],
        post_times: [co_store
            .verify_in(tik.clone())
            .map_or(F::from(0), |(_, p2)| p2)],
        enc_args: [co_store
            .verify_in(tik.clone())
            .map_or(F::from(0), |(p1, _)| p1)],
        memb_priv: [co_store.get_cb_signature_of(&tik).unwrap_or_default()],
        nmemb_priv: [co_store.get_cb_sig_range_of(&tik).unwrap_or_default()],
    };

    // let _cb = CallbackCom::deserialize_compressed(&*u.callbacks[1]).unwrap();
    // let _tik: PlainTikCrypto<F> = cb.clone().cb_entry.tik;

    // let _prs2: PrivScanArgs<F, CBArg, PlainTikCrypto<F>, SigStore<F>, 1> = PrivScanArgs {
    //     priv_n_tickets: [cb],
    //     post_times: [co_store
    //         .verify_in(tik.clone())
    //         .map_or(F::from(0), |(_, p2)| p2)],
    //     enc_args: [co_store
    //         .verify_in(tik.clone())
    //         .map_or(F::from(0), |(p1, _)| p1)],
    //     memb_priv: [co_store.get_cb_signature_of(&tik).unwrap_or_default()],
    //     nmemb_priv: [co_store.get_cb_sig_range_of(&tik).unwrap_or_default()],
    // };

    let mut folding_scheme = NF::init(&nova_params, f_circ, init_state.clone()).unwrap();

    folding_scheme
        .prove_step(rng, [u.to_fold_repr(), prs1.to_fold_repr()].concat(), None)
        .unwrap();

    // println!("User at the end : {:?}", u);
}
