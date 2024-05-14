use crate::crypto::hash::HasherZK;
use crate::crypto::hash::Poseidon;
use crate::crypto::rr::RRTicket;
use crate::crypto::rr::RRVerifier;
use crate::generic::interaction::Interaction;
use crate::generic::object::{
    CBHash, CBHashVar, Com, ComRand, ComRandVar, ComVar, EncKey, EncKeyVar, Id, IdVar, Ser, SerVar,
    Ticket, TicketVar, Time, TimeVar,
};
use crate::generic::user::UserData;
use ark_crypto_primitives::sponge::Absorb;
use ark_ff::PrimeField;
use ark_ff::ToConstraintField;
use ark_r1cs_std::alloc::AllocVar;
use ark_r1cs_std::alloc::AllocationMode;
use ark_r1cs_std::boolean::Boolean;
use ark_r1cs_std::ToConstraintFieldGadget;
use ark_relations::ns;
use ark_relations::r1cs::Namespace;
use ark_relations::r1cs::SynthesisError;
use rand::distributions::Standard;
use rand::prelude::Distribution;
use rand::Rng;
use rand::{CryptoRng, RngCore};
use std::borrow::Borrow;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CallbackTicket<F: PrimeField + Absorb, A: Clone, T: RRTicket<F, A>> {
    pub tik: Ticket<T::Tik>,
    pub cb_method_id: Id<F>,
    pub expirable: bool,
    pub expiration: Time<F>,
    pub enc_key: EncKey<F>,
}

#[derive(Clone)]
pub struct CallbackTicketVar<F: PrimeField + Absorb, A: Clone, T: RRTicket<F, A>> {
    pub tik: TicketVar<T::TikVar>,
    pub cb_method_id: IdVar<F>,
    pub expirable: Boolean<F>,
    pub expiration: TimeVar<F>,
    pub enc_key: EncKeyVar<F>,
}

impl<A: Clone, T: RRTicket<F, A>, F: PrimeField + Absorb> CallbackTicket<F, A, T> {
    pub(crate) fn serialize(&self) -> Vec<Ser<F>> {
        [
            self.tik.to_field_elements().unwrap(),
            self.cb_method_id.to_field_elements().unwrap(),
            self.expirable.to_field_elements().unwrap(),
            self.expiration.to_field_elements().unwrap(),
            self.enc_key.to_field_elements().unwrap(),
        ]
        .concat()
    }
}

impl<A: Clone, T: RRTicket<F, A>, F: PrimeField + Absorb> CallbackTicketVar<F, A, T> {
    pub(crate) fn serialize(&self) -> Result<Vec<SerVar<F>>, SynthesisError> {
        Ok([
            self.tik.to_constraint_field()?,
            self.cb_method_id.to_constraint_field()?,
            self.expirable.to_constraint_field()?,
            self.expiration.to_constraint_field()?,
            self.enc_key.to_constraint_field()?,
        ]
        .concat())
    }
}

impl<A: Clone, T: RRTicket<F, A>, F: PrimeField + Absorb> AllocVar<CallbackTicket<F, A, T>, F>
    for CallbackTicketVar<F, A, T>
{
    fn new_variable<K: Borrow<CallbackTicket<F, A, T>>>(
        cs: impl Into<Namespace<F>>,
        f: impl FnOnce() -> Result<K, SynthesisError>,
        mode: AllocationMode,
    ) -> Result<Self, SynthesisError> {
        let ns = cs.into();
        let cs = ns.cs();
        let res = f();
        res.and_then(|rec| {
            let rec = rec.borrow();
            let tik = TicketVar::new_variable(ns!(cs, "tik"), || Ok(rec.tik.clone()), mode)?;
            let cb_method_id =
                IdVar::new_variable(ns!(cs, "cb_method_id"), || Ok(rec.cb_method_id), mode)?;

            let expirable =
                Boolean::new_variable(ns!(cs, "expirable"), || Ok(rec.expirable), mode)?;

            let expiration =
                TimeVar::new_variable(ns!(cs, "expiration"), || Ok(rec.expiration), mode)?;

            let enc_key = EncKeyVar::new_variable(ns!(cs, "enc_key"), || Ok(rec.enc_key), mode)?;

            Ok(CallbackTicketVar {
                tik,
                cb_method_id,
                expirable,
                expiration,
                enc_key,
            })
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CallbackCom<F: PrimeField + Absorb, A: Clone, T: RRTicket<F, A>> {
    pub cb_entry: CallbackTicket<F, A, T>,
    pub com_rand: ComRand<F>,
}

#[derive(Clone)]
pub struct CallbackComVar<F: PrimeField + Absorb, A: Clone, T: RRTicket<F, A>> {
    pub cb_entry: CallbackTicketVar<F, A, T>,
    pub com_rand: ComRandVar<F>,
}

impl<A: Clone, T: RRTicket<F, A>, F: PrimeField + Absorb> CallbackCom<F, A, T> {
    pub(crate) fn commit(&self) -> Com<F> {
        let ser_fields = self.cb_entry.serialize();
        let com_rand_ser = self.com_rand.to_field_elements().unwrap();
        let full_dat = [ser_fields.as_slice(), com_rand_ser.as_slice()].concat();
        Poseidon::<2>::hash(&full_dat)
    }

    pub(crate) fn commit_in_zk(
        cb_var: CallbackComVar<F, A, T>,
    ) -> Result<ComVar<F>, SynthesisError> {
        let ser_fields = cb_var.cb_entry.serialize()?;
        let com_rand_ser = cb_var.com_rand.to_constraint_field()?;

        let full_dat = [ser_fields.as_slice(), com_rand_ser.as_slice()].concat();
        Poseidon::<2>::hash_in_zk(&full_dat)
    }
}

impl<A: Clone, T: RRTicket<F, A>, F: PrimeField + Absorb> AllocVar<CallbackCom<F, A, T>, F>
    for CallbackComVar<F, A, T>
{
    fn new_variable<K: Borrow<CallbackCom<F, A, T>>>(
        cs: impl Into<Namespace<F>>,
        f: impl FnOnce() -> Result<K, SynthesisError>,
        mode: AllocationMode,
    ) -> Result<Self, SynthesisError> {
        let ns = cs.into();
        let cs = ns.cs();
        let res = f();
        res.and_then(|rec| {
            let rec = rec.borrow();
            let cb_entry = CallbackTicketVar::new_variable(
                ns!(cs, "cb_entry"),
                || Ok(rec.cb_entry.clone()),
                mode,
            )?;

            let com_rand =
                ComRandVar::new_variable(ns!(cs, "com_rand"), || Ok(rec.com_rand), mode)?;

            Ok(CallbackComVar { cb_entry, com_rand })
        })
    }
}

type CBList<F, T, A, const N: usize> = [(CallbackCom<F, A, T>, <T as RRTicket<F, A>>::Rand); N];

pub(crate) fn create_defaults<
    F: PrimeField + Absorb,
    U: UserData<F>,
    A: Clone + std::fmt::Debug,
    X: AllocVar<A, F>,
    T: RRTicket<F, A>,
    const N: usize,
>(
    rng: &mut (impl CryptoRng + RngCore),
    interaction: Interaction<F, U, A, X, N>,
) -> [CallbackCom<F, A, T>; N]
where
    Standard: Distribution<F>,
{
    interaction
        .callbacks
        .iter()
        .enumerate()
        .map(|(_, cb)| {
            let ticket_value = T::Tik::default();
            let enc_key: EncKey<F> = rng.gen();
            let com_rand = rng.gen();

            let cb_data: CallbackTicket<F, A, T> = CallbackTicket {
                tik: ticket_value,
                cb_method_id: cb.method_id,
                expirable: cb.expirable,
                expiration: cb.expiration,
                enc_key,
            };

            let cb = CallbackCom {
                cb_entry: cb_data,
                com_rand,
            };
            cb
        })
        .collect::<Vec<_>>()
        .try_into()
        .unwrap()
}

pub fn create_cbs_from_interaction<
    F: PrimeField + Absorb,
    U: UserData<F>,
    A: Clone + std::fmt::Debug,
    X: AllocVar<A, F>,
    T: RRTicket<F, A>,
    const N: usize,
>(
    rng: &mut (impl CryptoRng + RngCore),
    interaction: Interaction<F, U, A, X, N>,
    rpk_identities: [T::Tik; N],
) -> CBList<F, T, A, N>
where
    Standard: Distribution<F>,
{
    interaction
        .callbacks
        .iter()
        .enumerate()
        .map(|(i, cb)| {
            let (rand, ticket_value) = rpk_identities[i].rerand(rng);
            let enc_key: EncKey<F> = rng.gen();
            let com_rand = rng.gen();

            let cb_data: CallbackTicket<F, A, T> = CallbackTicket {
                tik: ticket_value,
                cb_method_id: cb.method_id,
                expirable: cb.expirable,
                expiration: cb.expiration,
                enc_key,
            };

            let cb = CallbackCom {
                cb_entry: cb_data,
                com_rand,
            };
            (cb, rand)
        })
        .collect::<Vec<_>>()
        .try_into()
        .unwrap()
}

pub fn add_ticket_to_hc<F: PrimeField + Absorb, A: Clone, T: RRTicket<F, A>>(
    hash_chain: CBHash<F>,
    ticket: CallbackTicket<F, A, T>,
) -> CBHash<F> {
    let serialized_ticket = ticket.serialize();
    Poseidon::<2>::hash(&[&[hash_chain], serialized_ticket.as_slice()].concat())
}

pub fn add_ticket_to_hc_zk<F: PrimeField + Absorb, A: Clone, T: RRTicket<F, A>>(
    hash_chain: &mut CBHashVar<F>,
    ticket: CallbackTicketVar<F, A, T>,
) -> Result<(), SynthesisError> {
    let ser_ticket = ticket.serialize()?;
    let ser_hc = hash_chain.to_constraint_field()?;

    let full_dat = [ser_hc.as_slice(), ser_ticket.as_slice()].concat();

    *hash_chain = Poseidon::<2>::hash_in_zk(&full_dat)?;

    Ok(())
}
