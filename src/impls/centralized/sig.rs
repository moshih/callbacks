use std::cmp::Ordering;

use crate::crypto::enc::AECipherSigZK;
use crate::crypto::hash::{FieldHash, HasherZK};
use crate::generic::bulletin::{
    CallbackBulletin, JoinableBulletin, PublicCallbackBul, PublicUserBul, UserBul,
};
use crate::generic::callbacks::CallbackCom;
use crate::generic::fold::FoldSer;
use crate::generic::object::{Com, Nul, Time, TimeVar};
use crate::generic::service::ServiceProvider;
use crate::generic::user::UserData;
use ark_crypto_primitives::sponge::Absorb;
use ark_ff::{PrimeField, ToConstraintField};
use ark_r1cs_std::alloc::AllocVar;
use ark_r1cs_std::eq::EqGadget;
use ark_r1cs_std::fields::fp::FpVar;
use ark_r1cs_std::prelude::Boolean;
use ark_relations::ns;
use ark_relations::r1cs::SynthesisError;
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use nalgebra::{DMatrix, DVector};
use rand::distributions::{Distribution, Standard};
use rand::{thread_rng, Rng};
use rand::{CryptoRng, RngCore};

use super::super::hash::Poseidon;
use super::crypto::{PlainTikCrypto, PlainTikCryptoVar};

const MODE: i8 = 1;

const SIZE_N: usize = if MODE == -1 {
    15
} else if MODE == 0 {
    80
} else if MODE == 1 {
    112
} else {
    160
};

const SIZE_M: usize = if MODE == -1 {
    6
} else if MODE == 0 {
    35
} else if MODE == 1 {
    44
} else {
    64
};

#[derive(Clone, Debug, CanonicalSerialize, CanonicalDeserialize)]
pub struct Sig<F: PrimeField> {
    pub preimage: Vec<F>,
}

impl<F: PrimeField> Default for Sig<F> {
    fn default() -> Self {
        Self {
            preimage: [F::ZERO; SIZE_N].to_vec(),
        }
    }
}

#[derive(Clone)]
pub struct SigVar<F: PrimeField> {
    pub preimage: Vec<FpVar<F>>,
}

impl<F: PrimeField> Default for SigVar<F> {
    fn default() -> Self {
        let k = [const { FpVar::Constant(F::ZERO) }; SIZE_N];
        Self {
            preimage: k.to_vec(),
        }
    }
}

#[cfg(feature = "folding")]
impl<F: PrimeField> FoldSer<F, SigVar<F>> for Sig<F> {
    fn repr_len() -> usize {
        SIZE_N
    }

    fn to_fold_repr(&self) -> Vec<crate::generic::object::Ser<F>> {
        self.preimage.clone()
    }

    fn from_fold_repr(ser: &[crate::generic::object::Ser<F>]) -> Self {
        Self {
            preimage: ser.to_vec(),
        }
    }

    fn from_fold_repr_zk(
        var: &[crate::generic::object::SerVar<F>],
    ) -> Result<SigVar<F>, SynthesisError> {
        Ok(SigVar {
            preimage: var.to_vec(),
        })
    }

    fn to_fold_repr_zk(
        var: &SigVar<F>,
    ) -> Result<Vec<crate::generic::object::SerVar<F>>, SynthesisError> {
        Ok(var.preimage.clone())
    }
}

impl<F: PrimeField> AllocVar<Sig<F>, F> for SigVar<F> {
    fn new_variable<T: std::borrow::Borrow<Sig<F>>>(
        cs: impl Into<ark_relations::r1cs::Namespace<F>>,
        f: impl FnOnce() -> Result<T, SynthesisError>,
        mode: ark_r1cs_std::prelude::AllocationMode,
    ) -> Result<Self, SynthesisError> {
        let ns = cs.into();
        let cs = ns.cs();
        let res = f();
        res.and_then(|rec| {
            let rec = rec.borrow();
            let preimage = Vec::<FpVar<F>>::new_variable(
                ns!(cs, "preimage"),
                || Ok(rec.preimage.clone()),
                mode,
            )?;
            Ok(SigVar { preimage })
        })
    }
}

#[derive(Clone, Debug, CanonicalSerialize, CanonicalDeserialize)]
pub struct Pubkey<F: PrimeField> {
    pub data: Vec<F>,
}

impl<F: PrimeField> Default for Pubkey<F> {
    fn default() -> Self {
        Self {
            data: [F::ZERO; SIZE_M * SIZE_N * SIZE_N].to_vec(),
        }
    }
}

#[derive(Clone)]
pub struct PubkeyVar<F: PrimeField> {
    pub data: Vec<FpVar<F>>,
}

impl<F: PrimeField> Default for PubkeyVar<F> {
    fn default() -> Self {
        let k = [const { FpVar::Constant(F::ZERO) }; SIZE_M * SIZE_N * SIZE_N];
        Self { data: k.to_vec() }
    }
}

impl<F: PrimeField> AllocVar<Pubkey<F>, F> for PubkeyVar<F> {
    fn new_variable<T: std::borrow::Borrow<Pubkey<F>>>(
        cs: impl Into<ark_relations::r1cs::Namespace<F>>,
        f: impl FnOnce() -> Result<T, SynthesisError>,
        mode: ark_r1cs_std::prelude::AllocationMode,
    ) -> Result<Self, SynthesisError> {
        let ns = cs.into();
        let cs = ns.cs();
        let res = f();
        res.and_then(|rec| {
            let rec = rec.borrow();
            let data =
                Vec::<FpVar<F>>::new_variable(ns!(cs, "data"), || Ok(rec.data.clone()), mode)?;
            Ok(PubkeyVar { data })
        })
    }
}

impl<F: PrimeField> ToConstraintField<F> for Pubkey<F> {
    fn to_field_elements(&self) -> Option<Vec<F>> {
        Some(self.data.clone())
    }
}

#[derive(Clone, Default, Debug)]
pub struct PrivKey<F: PrimeField> {
    pub o: DMatrix<F>,
    pub s_i: Vec<DMatrix<F>>,
    pub p1s: Vec<DMatrix<F>>,
    pub p2s: Vec<DMatrix<F>>,
    pub p3s: Vec<DMatrix<F>>,
}

#[derive(Clone, Default, Debug, CanonicalSerialize, CanonicalDeserialize)]
pub struct CompressedPrivKey<F: PrimeField> {
    pub seed: Vec<F>,
}

impl<F: PrimeField + Absorb> CompressedPrivKey<F>
where
    Standard: Distribution<F>,
{
    pub fn gen_ckey(rng: &mut (impl CryptoRng + RngCore)) -> Self {
        let mut out = vec![];
        for _ in 0..32 {
            out.push(rng.gen());
        }
        Self { seed: out }
    }

    pub fn into_key(&self) -> PrivKey<F> {
        let mut state = self.seed.clone();

        fn update_state<F: PrimeField + Absorb>(state: &mut Vec<F>) -> F {
            for i in 0..state.len() {
                state[i] = <Poseidon<2>>::hash(&[state[i]]);
            }
            <Poseidon<2>>::hash(&state)
        }

        let mut o = DMatrix::from_element(SIZE_N - SIZE_M, SIZE_M, F::ZERO);

        for j in 0..SIZE_M {
            for i in 0..(SIZE_N - SIZE_M) {
                o[(i, j)] = update_state(&mut state);
            }
        }

        let mut p1s = vec![];
        let mut p2s = vec![];
        let mut p3s = vec![];
        let mut s_i = vec![];

        for _ in 0..(SIZE_M) {
            let mut p1 = DMatrix::from_element(SIZE_N - SIZE_M, SIZE_N - SIZE_M, F::ZERO);

            for j in 0..(SIZE_N - SIZE_M) {
                for i in 0..(SIZE_N - SIZE_M) {
                    p1[(i, j)] = update_state(&mut state);
                }
            }
            p1s.push(p1.clone());

            let mut p2 = DMatrix::from_element(SIZE_N - SIZE_M, SIZE_M, F::ZERO);

            for j in 0..SIZE_M {
                for i in 0..(SIZE_N - SIZE_M) {
                    p2[(i, j)] = update_state(&mut state);
                }
            }
            p2s.push(p2.clone());

            let mut p3 = -(o.transpose() * &p1 * &o) - &o.transpose() * &p2;

            for c in 0..SIZE_M {
                for r in 0..c {
                    p3[(r, c)] = p3[(r, c)] + p3[(c, r)];
                    p3[(c, r)] = F::ZERO;
                }
            }
            p3s.push(p3);

            let si = (&p1 + p1.transpose()) * &o + p2;
            s_i.push(si);
        }
        PrivKey {
            o,
            s_i,
            p1s,
            p2s,
            p3s,
        }
    }
}

impl<F: PrimeField + Absorb> PrivKey<F>
where
    Standard: Distribution<F>,
{
    pub fn gen_key(rng: &mut (impl CryptoRng + RngCore)) -> Self {
        let mut o = DMatrix::from_element(SIZE_N - SIZE_M, SIZE_M, F::ZERO);

        for j in 0..SIZE_M {
            for i in 0..(SIZE_N - SIZE_M) {
                o[(i, j)] = rng.gen();
            }
        }

        let mut p1s = vec![];
        let mut p2s = vec![];
        let mut p3s = vec![];
        let mut s_i = vec![];

        for _ in 0..(SIZE_M) {
            let mut p1 = DMatrix::from_element(SIZE_N - SIZE_M, SIZE_N - SIZE_M, F::ZERO);

            for j in 0..(SIZE_N - SIZE_M) {
                for i in 0..(SIZE_N - SIZE_M) {
                    p1[(i, j)] = rng.gen();
                }
            }
            p1s.push(p1.clone());

            let mut p2 = DMatrix::from_element(SIZE_N - SIZE_M, SIZE_M, F::ZERO);

            for j in 0..SIZE_M {
                for i in 0..(SIZE_N - SIZE_M) {
                    p2[(i, j)] = rng.gen();
                }
            }
            p2s.push(p2.clone());

            let mut p3 = -(o.transpose() * &p1 * &o) - &o.transpose() * &p2;

            for c in 0..SIZE_M {
                for r in 0..c {
                    p3[(r, c)] = p3[(r, c)] + p3[(c, r)];
                    p3[(c, r)] = F::ZERO;
                }
            }
            p3s.push(p3);

            let si = (&p1 + p1.transpose()) * &o + p2;
            s_i.push(si);
        }
        PrivKey {
            o,
            s_i,
            p1s,
            p2s,
            p3s,
        }
    }

    pub fn get_full_pubkey(&self) -> Pubkey<F> {
        let mut pk = vec![];
        for k in 0..SIZE_M {
            for r in 0..(SIZE_N - SIZE_M) {
                for i in 0..(SIZE_N - SIZE_M) {
                    pk.push(self.p1s[k][(r, i)]);
                }

                for i in 0..(SIZE_M) {
                    pk.push(self.p2s[k][(r, i)]);
                }
            }

            for r in 0..(SIZE_M) {
                for _ in 0..(SIZE_N - SIZE_M) {
                    pk.push(F::ZERO);
                }
                for i in 0..(SIZE_M) {
                    pk.push(self.p3s[k][(r, i)]);
                }
            }
        }

        Pubkey { data: pk }
    }

    pub fn sign_message<H: FieldHash<F>>(
        &self,
        rng: &mut (impl CryptoRng + RngCore),
        msg: F,
    ) -> Option<Sig<F>> {
        let mut t = DVector::from_element(SIZE_M, F::ZERO);

        t[0] = H::hash(&[msg]);
        for i in 1..SIZE_M {
            t[i] = H::hash(&[t[i - 1]]);
        }

        let mut v = DVector::from_element(SIZE_N - SIZE_M, F::ZERO);

        for i in 0..(SIZE_N - SIZE_M) {
            v[i] = rng.gen();
        }

        let mut ml = DMatrix::from_element(SIZE_M, SIZE_M, F::ZERO);

        for (i, mut row) in ml.row_iter_mut().enumerate() {
            row.copy_from(&(v.transpose() * &self.s_i[i]));
        }

        let mut y: DVector<F> = DVector::from_element(SIZE_M, F::ZERO);

        for i in 0..SIZE_M {
            y[i] = (v.transpose() * &self.p1s[i] * &v)[0];
        }

        let mut ml = ml.insert_column(SIZE_M, F::ZERO);

        for i in 0..SIZE_M {
            ml[(i, SIZE_M)] = t[i] - y[i];
        }

        let out = rref_solve(&ml);

        match out {
            Some(x) => {
                let mut baro = DMatrix::from_element(SIZE_N, SIZE_M, F::ZERO);
                baro.index_mut((0..(SIZE_N - SIZE_M), 0..SIZE_M))
                    .copy_from(&self.o);

                baro.index_mut(((SIZE_N - SIZE_M)..SIZE_N, 0..SIZE_M))
                    .copy_from(&DMatrix::identity(SIZE_M, SIZE_M));

                let mut barv = DVector::from_element(SIZE_N, F::ZERO);
                barv.index_mut((0..(SIZE_N - SIZE_M), 0)).copy_from(&v);

                let s = barv + baro * x;
                let mut output = vec![];

                for i in 0..SIZE_N {
                    output.push(s[i]);
                }

                Some(Sig { preimage: output })
            }
            None => None,
        }
    }
}

fn rref_solve<F: PrimeField>(matrix: &DMatrix<F>) -> Option<DVector<F>> {
    let mut m = matrix.clone();

    let rows = m.nrows();
    let cols = m.ncols();
    let mut l = 0;

    'o: for r in 0..rows {
        if cols <= l {
            break;
        }
        let mut i = r;

        while m[(i, l)] == F::ZERO {
            i += 1;
            if rows == i {
                i = r;
                l += 1;
                if cols == l {
                    break 'o;
                }
            }
        }

        for j in 0..cols {
            let t = m[(r, j)];
            m[(r, j)] = m[(i, j)];
            m[(i, j)] = t;
        }

        if m[(r, l)] != F::ZERO {
            let t = m[(r, l)];
            for j in 0..cols {
                m[(r, j)] *= t.inverse().unwrap();
            }
        }

        for j in 0..rows {
            if j != r {
                let lv = m[(j, l)];
                for k in 0..cols {
                    let op = m[(r, k)];
                    m[(j, k)] -= lv * op;
                }
            }
        }

        l += 1;
    }

    for r in 0..rows {
        let mut ctr = 0;
        for j in 0..(cols - 1) {
            if m[(r, j)] == F::ZERO {
                ctr += 1;
            }
        }
        if ctr == (cols - 1) {
            return None;
        }
    }

    Some(m.column(cols - 1).into_owned())
}

impl<F: PrimeField> Pubkey<F> {
    pub fn verify<H: FieldHash<F>>(&self, signature: Sig<F>, msg: F) -> bool {
        let mut check = true;
        let mut t = DVector::from_element(SIZE_M, F::ZERO);

        t[0] = H::hash(&[msg]);
        for i in 1..SIZE_M {
            t[i] = H::hash(&[t[i - 1]]);
        }

        let s = DVector::from_vec(signature.preimage);

        for i in 0..SIZE_M {
            let pi = DMatrix::from_vec(
                SIZE_N,
                SIZE_N,
                self.data[(i * SIZE_N * SIZE_N)..((i + 1) * SIZE_N * SIZE_N)].to_vec(),
            );

            check &= (s.transpose() * pi * &s)[0] == t[i];
        }

        check
    }

    pub fn verify_zk<H: FieldHash<F>>(
        pubkey: PubkeyVar<F>,
        signature: SigVar<F>,
        msg: FpVar<F>,
    ) -> Result<(), ark_relations::r1cs::SynthesisError> {
        let mut t = vec![];
        t.push(H::hash_in_zk(&[msg])?);
        for i in 1..SIZE_M {
            t.push(H::hash_in_zk(&t[(i - 1)..i])?);
        }

        for i in 0..SIZE_M {
            // let mut x = FpVar::Constant(F::zero());
            let x = (0..SIZE_N)
                .map(|j| {
                    let sl = &pubkey.data[(i * (SIZE_N * SIZE_N) + j * SIZE_N)
                        ..(i * (SIZE_N * SIZE_N) + (j + 1) * SIZE_N)];

                    &signature.preimage[j]
                        * (0..SIZE_N)
                            .map(|k| &signature.preimage[k] * &sl[k])
                            .sum::<FpVar<F>>()
                })
                .sum();

            t[i].enforce_equal(&x)?;
        }

        Ok(())
    }

    pub fn verify_bool_zk<H: FieldHash<F>>(
        pubkey: PubkeyVar<F>,
        signature: SigVar<F>,
        msg: FpVar<F>,
    ) -> Result<Boolean<F>, ark_relations::r1cs::SynthesisError> {
        let mut t = vec![];
        t.push(H::hash_in_zk(&[msg])?);
        for i in 1..SIZE_M {
            t.push(H::hash_in_zk(&t[(i - 1)..i])?);
        }

        let mut check = Boolean::TRUE;

        for i in 0..SIZE_M {
            // let mut x = FpVar::Constant(F::zero());
            let x = (0..SIZE_N)
                .map(|j| {
                    let sl = &pubkey.data[(i * (SIZE_N * SIZE_N) + j * SIZE_N)
                        ..(i * (SIZE_N * SIZE_N) + (j + 1) * SIZE_N)];

                    &signature.preimage[j]
                        * (0..SIZE_N)
                            .map(|k| &signature.preimage[k] * &sl[k])
                            .sum::<FpVar<F>>()
                })
                .sum();

            check &= (t[i].is_eq(&x))?;
        }

        Ok(check)
    }
}

#[derive(Clone, Default, Debug, CanonicalSerialize, CanonicalDeserialize)]
pub struct SignedRange<F: PrimeField> {
    pub range: (F, F),
    pub epoch: F,
    pub sig: Sig<F>,
}

#[derive(Clone)]
pub struct SignedRangeVar<F: PrimeField> {
    pub range: (FpVar<F>, FpVar<F>),
    pub epoch: FpVar<F>,
    pub sig: SigVar<F>,
}

#[cfg(feature = "folding")]
impl<F: PrimeField> FoldSer<F, SignedRangeVar<F>> for SignedRange<F> {
    fn repr_len() -> usize {
        3 + <Sig<F>>::repr_len()
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
        let sig = Sig::from_fold_repr(&ser[3..]);
        Self {
            range: (r0, r1),
            epoch: r2,
            sig,
        }
    }

    fn from_fold_repr_zk(
        var: &[crate::generic::object::SerVar<F>],
    ) -> Result<SignedRangeVar<F>, SynthesisError> {
        let r0 = var[0].clone();
        let r1 = var[1].clone();
        let r2 = var[2].clone();
        let sig = Sig::from_fold_repr_zk(&var[3..])?;
        Ok(SignedRangeVar {
            range: (r0, r1),
            epoch: r2,
            sig,
        })
    }

    fn to_fold_repr_zk(
        var: &SignedRangeVar<F>,
    ) -> Result<Vec<crate::generic::object::SerVar<F>>, SynthesisError> {
        let mut v = vec![];
        v.push(var.range.0.clone());
        v.push(var.range.1.clone());
        v.push(var.epoch.clone());
        v.extend(Sig::to_fold_repr_zk(&var.sig)?);
        Ok(v)
    }
}

impl<F: PrimeField> AllocVar<SignedRange<F>, F> for SignedRangeVar<F> {
    fn new_variable<T: std::borrow::Borrow<SignedRange<F>>>(
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

            let sig = <SigVar<F>>::new_variable(ns!(cs, "sig"), || Ok(rec.sig.clone()), mode)?;
            Ok(SignedRangeVar {
                range: (r0, r1),
                epoch,
                sig,
            })
        })
    }
}

#[derive(Clone, Default, Debug)]
pub struct SigStore<F: PrimeField + Absorb>
where
    Standard: Distribution<F>,
{
    // Private stored data (private keys)
    privkey: PrivKey<F>,
    privkey_cb: PrivKey<F>,
    privkey_ncb: PrivKey<F>,

    interaction_ids: Vec<u64>,
    pub cb_tickets: Vec<
        Vec<(
            CallbackCom<F, F, PlainTikCrypto<F>>,
            <PlainTikCrypto<F> as AECipherSigZK<F, F>>::Rand,
        )>,
    >,

    // Public data at some endpoint
    pub pubkey: Pubkey<F>,
    pub pubkey_cb: Pubkey<F>,
    pub pubkey_ncb: Pubkey<F>,

    // Public object bulletin data
    pub coms: Vec<Com<F>>,
    pub old_nuls: Vec<Nul<F>>,
    pub cb_com_lists: Vec<Vec<Com<F>>>,
    pub sigs: Vec<Sig<F>>,

    // Public callback bulletin for membership
    pub called_cbs: Vec<(PlainTikCrypto<F>, F, Time<F>)>,
    pub called_cb_sigs: Vec<Sig<F>>,

    // Public callback bulletin for nonmembership
    pub ncalled_cbs: Vec<SignedRange<F>>,

    // Public epoch data (time)
    pub epoch: F,
}

impl<F: PrimeField + Absorb> SigStore<F>
where
    Standard: Distribution<F>,
{
    pub fn new(rng: &mut (impl CryptoRng + RngCore)) -> Self {
        let sk = PrivKey::gen_key(rng);
        let skcb = PrivKey::gen_key(rng);
        let skncb = PrivKey::gen_key(rng);
        let init_range = (
            F::ZERO,
            F::from_bigint(F::MODULUS_MINUS_ONE_DIV_TWO).unwrap() - F::ONE,
        );
        let sig = skncb
            .sign_message::<Poseidon<2>>(
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
            privkey_cb: skcb.clone(),
            privkey_ncb: skncb.clone(),

            interaction_ids: vec![],
            cb_tickets: vec![],

            pubkey: sk.get_full_pubkey(),
            pubkey_cb: skcb.get_full_pubkey(),
            pubkey_ncb: skncb.get_full_pubkey(),

            coms: vec![],
            old_nuls: vec![],
            cb_com_lists: vec![],
            sigs: vec![],

            called_cbs: vec![],
            called_cb_sigs: vec![],

            ncalled_cbs: vec![first_range],

            epoch: F::ZERO,
        }
    }

    pub fn get_signature_of(&self, user_obj: &Com<F>) -> Option<Sig<F>> {
        for (i, c) in self.coms.iter().enumerate() {
            if c == user_obj {
                return Some(self.sigs[i].clone());
            }
        }
        None
    }

    pub fn get_cb_signature_of(&self, tik: &PlainTikCrypto<F>) -> Option<Sig<F>> {
        for (i, (t, _, _)) in (&self.called_cbs).into_iter().enumerate() {
            if t == tik {
                return Some(self.called_cb_sigs[i].clone());
            }
        }
        None
    }

    pub fn get_cb_sig_range_of(&self, tik: &PlainTikCrypto<F>) -> Option<SignedRange<F>> {
        for sr in &self.ncalled_cbs {
            if sr.range.0 <= tik.0 && tik.0 < sr.range.1 {
                return Some(sr.clone());
            }
        }
        None
    }

    pub fn update_epoch(&mut self, rng: &mut (impl CryptoRng + RngCore)) {
        self.epoch += F::ONE;

        let mut v = vec![];

        for i in &self.called_cbs {
            v.push(i.0 .0);
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
            let sig = self
                .privkey_ncb
                .sign_message::<Poseidon<2>>(
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

        if sv.len() == 0 {
            let init_range = (
                F::ZERO,
                F::from_bigint(F::MODULUS_MINUS_ONE_DIV_TWO).unwrap() - F::ONE,
            );
            let sig = self
                .privkey_ncb
                .sign_message::<Poseidon<2>>(
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
}

impl<F: PrimeField + Absorb, U: UserData<F>> PublicUserBul<F, U> for SigStore<F>
where
    Standard: Distribution<F>,
{
    type Error = ();

    type MembershipPub = Pubkey<F>;
    type MembershipWitness = Sig<F>;

    type MembershipPubVar = PubkeyVar<F>;
    type MembershipWitnessVar = SigVar<F>;

    // We don't need to verify the object has been inserted into the object bulletin because we ARE
    // the object bulletin.
    fn verify_in<Args, Snark: ark_snark::SNARK<F>, const NUMCBS: usize>(
        &self,
        object: crate::generic::object::Com<F>,
        old_nul: crate::generic::object::Nul<F>,
        cb_com_list: [crate::generic::object::Com<F>; NUMCBS],
        _args: Args,
        _proof: Snark::Proof,
        _memb_data: Self::MembershipPub,
        _verif_key: &Snark::VerifyingKey,
    ) -> bool {
        for (i, c) in self.coms.iter().enumerate() {
            if c == &object
                && self.old_nuls[i] == old_nul
                && self.cb_com_lists[i] == cb_com_list.to_vec()
            {
                return true;
            }
        }
        false
    }

    fn enforce_membership_of(
        data: crate::generic::object::ComVar<F>,
        wit: Self::MembershipWitnessVar,
        epub: Self::MembershipPubVar,
    ) -> Result<(), ark_relations::r1cs::SynthesisError> {
        Pubkey::verify_zk::<Poseidon<2>>(epub, wit, data)
    }
}

impl<F: PrimeField + Absorb, U: UserData<F>> UserBul<F, U> for SigStore<F>
where
    Standard: Distribution<F>,
{
    fn has_never_recieved_nul(&self, nul: &crate::generic::object::Nul<F>) -> bool {
        for i in &self.old_nuls {
            if i == nul {
                return false;
            }
        }
        true
    }

    fn append_value<Args, Snark: ark_snark::SNARK<F>, const NUMCBS: usize>(
        &mut self,
        object: crate::generic::object::Com<F>,
        old_nul: crate::generic::object::Nul<F>,
        cb_com_list: [crate::generic::object::Com<F>; NUMCBS],
        _args: Args,
        _proof: Snark::Proof,
        _memb_data: Option<Self::MembershipPub>,
        _verif_key: &Snark::VerifyingKey,
    ) -> Result<(), Self::Error> {
        let mut rng = thread_rng();
        let out = self.privkey.sign_message::<Poseidon<2>>(&mut rng, object);
        match out {
            Some(x) => {
                self.coms.push(object);
                self.old_nuls.push(old_nul);
                self.cb_com_lists.push(cb_com_list.into());
                self.sigs.push(x);
                Ok(())
            }
            None => Err(()),
        }
    }
}

impl<F: PrimeField + Absorb, U: UserData<F>> JoinableBulletin<F, U> for SigStore<F>
where
    Standard: Distribution<F>,
{
    type PubData = ();

    fn join_bul(
        &mut self,
        object: crate::generic::object::Com<F>,
        _pub_data: (),
    ) -> Result<(), Self::Error> {
        let mut rng = thread_rng();
        let out = self.privkey.sign_message::<Poseidon<2>>(&mut rng, object);
        match out {
            Some(x) => {
                self.coms.push(object);
                self.old_nuls.push(rng.gen());
                self.cb_com_lists.push(vec![]);
                self.sigs.push(x);
                Ok(())
            }
            None => Err(()),
        }
    }
}

impl<F: PrimeField + Absorb> PublicCallbackBul<F, F, PlainTikCrypto<F>> for SigStore<F>
where
    Standard: Distribution<F>,
{
    type Error = ();

    type MembershipPub = Pubkey<F>;
    type MembershipPubVar = PubkeyVar<F>;
    type MembershipWitness = Sig<F>;
    type MembershipWitnessVar = SigVar<F>;
    type NonMembershipPub = Pubkey<F>;
    type NonMembershipPubVar = PubkeyVar<F>;
    type NonMembershipWitness = SignedRange<F>;
    type NonMembershipWitnessVar = SignedRangeVar<F>;

    fn verify_in(&self, tik: PlainTikCrypto<F>) -> Option<(F, Time<F>)> {
        for (t, arg, time) in &self.called_cbs {
            if t == &tik {
                return Some((*arg, *time));
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

    fn enforce_membership_of(
        tikvar: (PlainTikCryptoVar<F>, FpVar<F>, TimeVar<F>),
        extra_witness: Self::MembershipWitnessVar,
        extra_pub: Self::MembershipPubVar,
    ) -> Result<Boolean<F>, SynthesisError> {
        Pubkey::verify_bool_zk::<Poseidon<2>>(
            extra_pub,
            extra_witness,
            <Poseidon<2>>::hash_in_zk(&[tikvar.0 .0, tikvar.1, tikvar.2])?,
        )
    }

    fn enforce_nonmembership_of(
        tikvar: PlainTikCryptoVar<F>,
        extra_witness: Self::NonMembershipWitnessVar,
        extra_pub: Self::NonMembershipPubVar,
    ) -> Result<Boolean<F>, SynthesisError> {
        let c0 = tikvar
            .0
            .is_cmp_unchecked(&extra_witness.range.0, Ordering::Greater, true)?;
        let c1 = tikvar
            .0
            .is_cmp_unchecked(&extra_witness.range.1, Ordering::Less, false)?;

        let range_correct = c0 & c1;

        let c2 = Pubkey::verify_bool_zk::<Poseidon<2>>(
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

impl<F: PrimeField + Absorb> CallbackBulletin<F, F, PlainTikCrypto<F>> for SigStore<F>
where
    Standard: Distribution<F>,
{
    fn has_never_recieved_tik(&self, tik: &PlainTikCrypto<F>) -> bool {
        for (x, _, _) in &self.called_cbs {
            if x == tik {
                return false;
            }
        }
        true
    }

    fn append_value(
        &mut self,
        tik: PlainTikCrypto<F>,
        enc_args: F,
        _sig: (),
        _time: Time<F>,
    ) -> Result<(), Self::Error> {
        let mut rng = thread_rng();
        let out = self.privkey_cb.sign_message::<Poseidon<2>>(
            &mut rng,
            <Poseidon<2>>::hash(&[tik.0, enc_args, self.epoch]),
        );

        match out {
            Some(x) => {
                self.called_cbs.push((tik, enc_args, self.epoch));
                self.called_cb_sigs.push(x);
                Ok(())
            }
            None => Err(()),
        }
    }
}

impl<F: PrimeField + Absorb> ServiceProvider<F, F, PlainTikCrypto<F>> for SigStore<F>
where
    Standard: Distribution<F>,
{
    type Error = ();
    type InteractionData = u64;

    fn has_never_recieved_tik(&self, tik: PlainTikCrypto<F>) -> bool {
        for j in &self.cb_tickets {
            for (a, _) in j {
                if a.cb_entry.tik == tik {
                    return false;
                }
            }
        }
        true
    }

    fn store_interaction<U: UserData<F>, Snark: ark_snark::SNARK<F>, const NUMCBS: usize>(
        &mut self,
        interaction: crate::generic::user::ExecutedMethod<F, Snark, F, PlainTikCrypto<F>, NUMCBS>,
        data: u64,
    ) -> Result<(), Self::Error> {
        self.interaction_ids.push(data);
        self.cb_tickets.push(interaction.cb_tik_list.to_vec());
        Ok(())
        // let mut rng = thread_rng();
        // let out = self
        //     .privkey
        //     .sign_message::<Poseidon<2>>(&mut rng, interaction.new_object);
        // match out {
        //     Some(x) => {
        //         self.coms.push(interaction.new_object);
        //         self.old_nuls.push(interaction.old_nullifier);
        //         self.cb_com_lists.push(interaction.cb_com_list.into());
        //         self.sigs.push(x);
        //         self.cb_tickets.push(interaction.cb_tik_list.to_vec());
        //         Ok(())
        //     }
        //     None => Err(()),
        // }
    }
}
