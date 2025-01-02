use std::cmp::Ordering;

#[cfg(feature = "folding")]
#[cfg(any(feature = "folding", doc))]
#[doc(cfg(feature = "folding"))]
use crate::generic::fold::FoldSer;

use crate::{
    crypto::hash::HasherZK,
    impls::{
        centralized::{
            crypto::{PlainTikCrypto, PlainTikCryptoVar},
            ds::sig::Signature,
        },
        hash::Poseidon,
    },
};
use ark_crypto_primitives::sponge::Absorb;
use ark_ff::PrimeField;
use ark_r1cs_std::{alloc::AllocVar, fields::fp::FpVar};
use ark_relations::{ns, r1cs::SynthesisError};
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use rand::{distributions::Standard, prelude::Distribution, thread_rng};

use crate::impls::centralized::ds::sigstore::NonmembStore;

#[derive(Clone, Default, Debug, CanonicalSerialize, CanonicalDeserialize)]
pub struct SignedRange<F: PrimeField, S: Signature<F>> {
    pub range: (F, F),
    pub epoch: F,
    pub sig: S::Sig,
}

#[derive(Clone)]
pub struct SignedRangeVar<F: PrimeField, S: Signature<F>> {
    pub range: (FpVar<F>, FpVar<F>),
    pub epoch: FpVar<F>,
    pub sig: S::SigVar,
}

impl<F: PrimeField, S: Signature<F>> AllocVar<SignedRange<F, S>, F> for SignedRangeVar<F, S> {
    fn new_variable<T: std::borrow::Borrow<SignedRange<F, S>>>(
        cs: impl Into<ark_relations::r1cs::Namespace<F>>,
        f: impl FnOnce() -> Result<T, SynthesisError>,
        mode: ark_r1cs_std::prelude::AllocationMode,
    ) -> Result<Self, SynthesisError> {
        let ns = cs.into();
        let cs = ns.cs();
        let res = f();
        res.and_then(|rec| {
            let rec = rec.borrow();
            let r0 = <FpVar<F>>::new_variable(ns!(cs, "r0"), || Ok(rec.range.0), mode)?;
            let r1 = <FpVar<F>>::new_variable(ns!(cs, "r1"), || Ok(rec.range.1), mode)?;
            let epoch = <FpVar<F>>::new_variable(ns!(cs, "epoch"), || Ok(rec.epoch), mode)?;

            let sig = S::SigVar::new_variable(ns!(cs, "sig"), || Ok(rec.sig.clone()), mode)?;
            Ok(SignedRangeVar {
                range: (r0, r1),
                epoch,
                sig,
            })
        })
    }
}

#[cfg(feature = "folding")]
#[cfg(any(feature = "folding", doc))]
#[doc(cfg(feature = "folding"))]
impl<F: PrimeField, S: Signature<F>> FoldSer<F, SignedRangeVar<F, S>> for SignedRange<F, S>
where
    S::Sig: FoldSer<F, S::SigVar>,
{
    fn repr_len() -> usize {
        3 + S::Sig::repr_len()
    }

    fn to_fold_repr(&self) -> Vec<crate::generic::object::Ser<F>> {
        let mut v = vec![];
        v.push(self.range.0);
        v.push(self.range.1);
        v.push(self.epoch);
        v.extend(self.sig.to_fold_repr());
        v
    }

    fn from_fold_repr(ser: &[crate::generic::object::Ser<F>]) -> Self {
        let r0 = ser[0];
        let r1 = ser[1];
        let r2 = ser[2];
        let sig = S::Sig::from_fold_repr(&ser[3..]);
        Self {
            range: (r0, r1),
            epoch: r2,
            sig,
        }
    }

    fn from_fold_repr_zk(
        var: &[crate::generic::object::SerVar<F>],
    ) -> Result<SignedRangeVar<F, S>, SynthesisError> {
        let r0 = var[0].clone();
        let r1 = var[1].clone();
        let r2 = var[2].clone();
        let sig = S::Sig::from_fold_repr_zk(&var[3..])?;
        Ok(SignedRangeVar {
            range: (r0, r1),
            epoch: r2,
            sig,
        })
    }

    fn to_fold_repr_zk(
        var: &SignedRangeVar<F, S>,
    ) -> Result<Vec<crate::generic::object::SerVar<F>>, SynthesisError> {
        let mut v = vec![];
        v.push(var.range.0.clone());
        v.push(var.range.1.clone());
        v.push(var.epoch.clone());
        v.extend(S::Sig::to_fold_repr_zk(&var.sig)?);
        Ok(v)
    }
}

#[derive(Clone, Default, Debug)]
pub struct SigRangeStore<F: PrimeField + Absorb, S: Signature<F>>
where
    Standard: Distribution<F>,
{
    privkey: S::Privkey,

    pub pubkey: S::Pubkey,
    pub ncalled_cbs: Vec<SignedRange<F, S>>,

    pub epoch: F,
}

impl<F: PrimeField + Absorb, S: Signature<F>> SigRangeStore<F, S>
where
    Standard: Distribution<F>,
{
    pub fn from(privkey: S::Privkey, db: Vec<SignedRange<F, S>>, epoch: F) -> Self {
        let pubkey = S::get_pubkey(&privkey);
        Self {
            privkey,
            pubkey,
            ncalled_cbs: db,
            epoch,
        }
    }

    pub fn get_pubkey(&self) -> S::Pubkey {
        self.pubkey.clone()
    }

    pub fn get_db(&self) -> Vec<SignedRange<F, S>> {
        self.ncalled_cbs.clone()
    }

    pub fn rotate_key(&mut self, new_key: S::Privkey) -> Result<(), ()> {
        self.pubkey = S::get_pubkey(&new_key);
        self.privkey = new_key;
        let mut sv: Vec<SignedRange<F, S>> = vec![];

        let mut rng = thread_rng();

        for range in &self.ncalled_cbs {
            let sig = S::sign(
                &self.privkey,
                &mut rng,
                <Poseidon<2>>::hash(&[range.range.0, range.range.1, range.epoch]),
            );
            match sig {
                Some(s) => {
                    sv.push(SignedRange {
                        range: (range.range.0, range.range.1),
                        epoch: range.epoch,
                        sig: s,
                    });
                }
                None => {
                    return Err(());
                }
            }
        }

        self.ncalled_cbs = sv;

        Ok(())
    }
}

impl<F: PrimeField + Absorb, S: Signature<F>> NonmembStore<F> for SigRangeStore<F, S>
where
    Standard: Distribution<F>,
{
    type NonMembershipWitness = SignedRange<F, S>;

    type NonMembershipWitnessVar = SignedRangeVar<F, S>;

    type NonMembershipPub = S::Pubkey;

    type NonMembershipPubVar = S::PubkeyVar;

    fn new(rng: &mut (impl rand::CryptoRng + rand::RngCore)) -> Self {
        let sk = S::gen_key(rng);
        let init_range = (
            F::ZERO,
            F::from_bigint(F::MODULUS_MINUS_ONE_DIV_TWO).unwrap() - F::ONE,
        );
        let sig = S::sign(
            &sk,
            rng,
            <Poseidon<2>>::hash(&[init_range.0, init_range.1, F::ZERO]),
        )
        .unwrap();
        let first_range = SignedRange {
            range: init_range,
            epoch: F::ZERO,
            sig,
        };
        Self {
            privkey: sk.clone(),
            pubkey: S::get_pubkey(&sk),
            ncalled_cbs: vec![first_range],
            epoch: F::ZERO,
        }
    }

    fn get_epoch(&self) -> F {
        self.epoch
    }

    fn update_epoch(
        &mut self,
        rng: &mut (impl rand::CryptoRng + rand::RngCore),
        current_store: Vec<PlainTikCrypto<F>>,
    ) {
        self.epoch += F::ONE;

        let mut v = vec![];

        for i in &current_store {
            v.push(i.0);
        }

        v.sort();

        let mut updated_ranges = vec![];

        let mut bot = F::ZERO;

        for top in v {
            if bot != top {
                updated_ranges.push((bot, top));
            }
            bot = top + F::ONE;
        }

        // There's a small problem here: if we get a ticket at (top - 1), then there is exactly 1
        // left over at the top, in which case the range becomes [max, max). But then if someone
        // gets the max ticket, this check is not satisfied.
        if bot != F::ZERO {
            updated_ranges.push((
                bot,
                F::from_bigint(F::MODULUS_MINUS_ONE_DIV_TWO).unwrap() - F::ONE,
            ));
        }

        let mut sv = vec![];

        for range in updated_ranges {
            let sig = S::sign(
                &self.privkey,
                rng,
                <Poseidon<2>>::hash(&[range.0, range.1, self.epoch]),
            )
            .unwrap();
            sv.push(SignedRange {
                range,
                epoch: self.epoch,
                sig,
            });
        }

        if sv.is_empty() {
            let init_range = (
                F::ZERO,
                F::from_bigint(F::MODULUS_MINUS_ONE_DIV_TWO).unwrap() - F::ONE,
            );
            let sig = S::sign(
                &self.privkey,
                rng,
                <Poseidon<2>>::hash(&[init_range.0, init_range.1, self.epoch]),
            )
            .unwrap();
            let first_range = SignedRange {
                range: init_range,
                epoch: self.epoch,
                sig,
            };
            sv.push(first_range);
        }

        self.ncalled_cbs = sv;
    }

    fn get_nmemb_witness(&self, tik: &PlainTikCrypto<F>) -> Option<Self::NonMembershipWitness> {
        for sr in &self.ncalled_cbs {
            if sr.range.0 <= tik.0 && tik.0 < sr.range.1 {
                return Some(sr.clone());
            }
        }
        None
    }

    fn verify_not_in(&self, tik: PlainTikCrypto<F>) -> bool {
        for sr in &self.ncalled_cbs {
            if sr.range.0 <= tik.0 && tik.0 < sr.range.1 {
                return true;
            }
        }
        false
    }

    fn enforce_nonmembership_of(
        tikvar: PlainTikCryptoVar<F>,
        extra_witness: Self::NonMembershipWitnessVar,
        extra_pub: Self::NonMembershipPubVar,
    ) -> Result<ark_r1cs_std::prelude::Boolean<F>, SynthesisError> {
        let c0 = tikvar
            .0
            .is_cmp_unchecked(&extra_witness.range.0, Ordering::Greater, true)?;
        let c1 = tikvar
            .0
            .is_cmp_unchecked(&extra_witness.range.1, Ordering::Less, false)?;

        let range_correct = c0 & c1;

        let c2 = S::verify_zk(
            extra_pub,
            extra_witness.sig,
            <Poseidon<2>>::hash_in_zk(&[
                extra_witness.range.0,
                extra_witness.range.1,
                extra_witness.epoch,
            ])?,
        )?;

        Ok(range_correct & c2)
    }
}
