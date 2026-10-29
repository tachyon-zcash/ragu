//! Two-layer Lagrange folding of revdot claims.
//!
//! For m claims interpolate A, B, and their scalar targets at 0..m.
//! Correct inputs make revdot(A, B) - K vanish at those m points, so its
//! correction is Z(T) Q(T), with only m-1 coefficients for Q. Each Q stage
//! must be committed before its corresponding challenge. Both vector sides
//! use the same interpolation weights, with one challenge per layer.
//!
//! This specializes the Lagrange/vanishing-polynomial identity used by
//! [ProtoGalaxy](https://eprint.iacr.org/2023/1106) to scalar revdot claims.
//!
//! The saving is in what is carried and checked: a reduction of m claims
//! commits m-1 quotient coefficients, and the collapse circuits fold those
//! with the claims' targets. The prover still forms every revdot product of
//! each group, the diagonal included, to assemble revdot(A, B) - K before
//! dividing by Z, so its product count grows with the square of the group
//! size while the carried count depends only on the slot budget.
//!
//! A challenge equal to one of the nodes 0..m makes Z vanish and the weights
//! select that node's claim alone, so the fold then checks one claim.
//! For a challenge uniform on a support S, the node-hit probability is
//! |S intersect {0, ..., m-1}| / |S|, at most m/|S|. Pasta nested challenges
//! are injective lifts of 128-bit endoscalars, so their support has size 2^128,
//! rather than the full nested field size. The dummy proof's all-one
//! challenges sit on node 1 by construction; see `dummy_proof` in `proof/mod.rs`.

use alloc::{vec, vec::Vec};
use core::{borrow::Borrow, cell::RefCell, marker::PhantomData};

use ragu_circuits::polynomials::{Rank, sparse};
use ragu_core::{Coeff, Result, drivers::Driver};
use ragu_primitives::{
    Element,
    vec::{CollectFixed, ConstLen, FixedVec, Len},
};
use udon::field::Field;

/// Operations for forming linear combinations of foldable values.
pub trait Foldable<F: Field>: Default + Clone {
    fn fold_scale(&mut self, by: F);
    fn fold_add_assign(&mut self, other: &Self);
}

impl<F: Field, R: Rank> Foldable<F> for sparse::Polynomial<F, R> {
    fn fold_scale(&mut self, by: F) {
        self.scale(by);
    }
    fn fold_add_assign(&mut self, other: &Self) {
        self.add_assign(other);
    }
}

/// Generic Horner fold over any [`Foldable`] type.
pub(crate) fn fold<T: Foldable<F>, F: Field>(
    items: impl IntoIterator<Item = impl Borrow<T>>,
    scale_factor: F,
) -> T {
    items.into_iter().fold(T::default(), |mut acc, item| {
        acc.fold_scale(scale_factor);
        acc.fold_add_assign(item.borrow());
        acc
    })
}

/// The group count and group size for two-layer revdot folding.
///
/// The first layer reduces `NumGroups` groups of up to `GroupSize` claims;
/// the second layer reduces the resulting group claims to one. Each reduction
/// uses one quotient coefficient fewer than its input count.
///
/// For a fixed slot budget `NumGroups * GroupSize`, the carried coefficient
/// count `NumGroups * (GroupSize - 1) + NumGroups - 1` is the budget less one
/// whatever the split, while the prover's revdot product count
/// `NumGroups * GroupSize^2 + NumGroups^2` favours small groups.
pub trait Parameters: 'static + Send + Sync + Copy + Default {
    type NumGroups: Len;
    type GroupSize: Len;
}

/// Number of quotient coefficients for a reduction of L claims.
pub struct NumErrorTerms<L: Len>(PhantomData<L>);
impl<L: Len> Len for NumErrorTerms<L> {
    fn len() -> usize {
        L::len().saturating_sub(1)
    }
}

fn weights<F: Field>(r: F, m: usize) -> Vec<F> {
    (0..m)
        .map(|i| {
            let numerator: F = (0..m)
                .filter(|&j| i != j)
                .map(|j| r - F::from(j as u64))
                .product();
            let denominator: F = (0..m)
                .filter(|&j| i != j)
                .map(|j| F::from(i as u64) - F::from(j as u64))
                .product();
            numerator * denominator.invert().expect("distinct interpolation nodes")
        })
        .collect()
}

fn combine<T: Foldable<F>, F: Field>(source: &[impl Borrow<T>], weights: &[F]) -> T {
    let mut result = T::default();
    for (value, &weight) in source.iter().zip(weights) {
        let mut term = value.borrow().clone();
        term.fold_scale(weight);
        result.fold_add_assign(&term);
    }
    result
}

/// Interpolates every padded first-layer group at the challenge.
pub fn fold_inner<T: Foldable<F>, F: Field, P: Parameters>(
    source: &[impl Borrow<T>],
    challenge: F,
) -> FixedVec<T, P::NumGroups> {
    assert!(
        source.len() <= P::GroupSize::len() * P::NumGroups::len(),
        "too many fold sources"
    );
    let weights = weights(challenge, P::GroupSize::len());
    source
        .chunks(P::GroupSize::len())
        .map(|chunk| combine(chunk, &weights))
        .chain(core::iter::repeat_with(T::default))
        .take(P::NumGroups::len())
        .collect_fixed()
        .expect("fixed group count")
}

/// Interpolates the second-layer groups at the challenge.
pub fn fold_outer<T: Foldable<F>, F: Field, P: Parameters>(
    source: FixedVec<T, P::NumGroups>,
    challenge: F,
) -> T {
    combine(&source, &weights(challenge, P::NumGroups::len()))
}

fn multiply<F: Field>(a: &[F], b: &[F]) -> Vec<F> {
    let mut result = vec![F::ZERO; a.len() + b.len() - 1];
    for (i, &a) in a.iter().enumerate() {
        for (j, &b) in b.iter().enumerate() {
            result[i + j] += a * b;
        }
    }
    result
}

fn bases<F: Field>(m: usize) -> (Vec<Vec<F>>, Vec<F>) {
    let z = (0..m).fold(vec![F::ONE], |p, i| {
        multiply(&p, &[-F::from(i as u64), F::ONE])
    });
    let basis = (0..m)
        .map(|i| {
            let mut p = vec![F::ONE];
            let mut denominator = F::ONE;
            for j in 0..m {
                if i != j {
                    p = multiply(&p, &[-F::from(j as u64), F::ONE]);
                    denominator *= F::from(i as u64) - F::from(j as u64);
                }
            }
            let inverse = denominator.invert().expect("distinct interpolation nodes");
            for coefficient in &mut p {
                *coefficient *= inverse;
            }
            p
        })
        .collect();
    (basis, z)
}

/// Divides each group's revdot(A, B) - K by Z, one quotient per group.
///
/// Every revdot product of a group is formed, the diagonal included, so the
/// prover's product count is quadratic in the group size; only the quotient
/// coefficients are committed.
fn errors<B: ragu_backend::Backend, F: Field, R: Rank, Outer: Len, Inner: Len>(
    a: &[impl Borrow<sparse::Polynomial<F, R>>],
    b: &[impl Borrow<sparse::Polynomial<F, R>>],
) -> FixedVec<FixedVec<F, NumErrorTerms<Inner>>, Outer> {
    assert_eq!(a.len(), b.len());
    assert!(a.len() <= Outer::len() * Inner::len());
    let m = Inner::len();
    let (basis, z) = bases::<F>(m);
    a.chunks(m)
        .zip(b.chunks(m))
        .map(|(a, b)| {
            // Honest inputs use their actual diagonal targets. The recursive
            // verifier independently uses the public k(y) targets, so false
            // input claims cannot be hidden by this prover-side construction.
            let mut residual = vec![F::ZERO; 2 * m - 1];
            // Borrow before scheduling so callers need not make their wrappers Sync.
            let pairs = a.iter().enumerate().flat_map(|(i, a)| {
                let a = a.borrow();
                b.iter()
                    .enumerate()
                    .map(move |(j, b)| (i, j, a, b.borrow()))
            });
            // The backend may compute products concurrently, returning them in
            // input order for deterministic residual accumulation.
            for (i, j, product) in B::map(pairs, |(i, j, a, b)| (i, j, B::sparse_revdot(a, b))) {
                for (k, c) in multiply(&basis[i], &basis[j]).into_iter().enumerate() {
                    residual[k] += product * c;
                }
                if i == j {
                    for (k, &c) in basis[i].iter().enumerate() {
                        residual[k] -= product * c;
                    }
                }
            }
            let mut quotient = vec![F::ZERO; m - 1];
            for k in (0..m - 1).rev() {
                let leading = residual[k + m];
                quotient[k] = leading;
                for (j, &c) in z.iter().enumerate() {
                    residual[k + j] -= leading * c;
                }
            }
            assert!(
                residual.iter().all(|&c| c == F::ZERO),
                "quotient division left a remainder"
            );
            quotient
                .into_iter()
                .collect_fixed()
                .expect("fixed quotient length")
        })
        .chain(core::iter::repeat_with(|| FixedVec::from_fn(|_| F::ZERO)))
        .take(Outer::len())
        .collect_fixed()
        .expect("fixed group count")
}

/// Computes each first-layer quotient before its folding challenge.
#[cfg(test)]
pub fn inner_error_terms<F: Field, R: Rank, P: Parameters>(
    a: &[impl Borrow<sparse::Polynomial<F, R>>],
    b: &[impl Borrow<sparse::Polynomial<F, R>>],
) -> FixedVec<FixedVec<F, NumErrorTerms<P::GroupSize>>, P::NumGroups> {
    inner_error_terms_with_backend::<ragu_backend::ReferenceBackend, F, R, P>(a, b)
}

/// Computes each first-layer quotient through the selected backend.
pub fn inner_error_terms_with_backend<
    B: ragu_backend::Backend,
    F: Field,
    R: Rank,
    P: Parameters,
>(
    a: &[impl Borrow<sparse::Polynomial<F, R>>],
    b: &[impl Borrow<sparse::Polynomial<F, R>>],
) -> FixedVec<FixedVec<F, NumErrorTerms<P::GroupSize>>, P::NumGroups> {
    errors::<B, F, R, P::NumGroups, P::GroupSize>(a, b)
}

/// Computes the second-layer quotient before its folding challenge.
#[cfg(test)]
pub fn outer_error_terms<F: Field, R: Rank, P: Parameters>(
    a: &[impl Borrow<sparse::Polynomial<F, R>>],
    b: &[impl Borrow<sparse::Polynomial<F, R>>],
) -> FixedVec<F, NumErrorTerms<P::NumGroups>> {
    outer_error_terms_with_backend::<ragu_backend::ReferenceBackend, F, R, P>(a, b)
}

/// Computes the second-layer quotient through the selected backend.
pub fn outer_error_terms_with_backend<
    B: ragu_backend::Backend,
    F: Field,
    R: Rank,
    P: Parameters,
>(
    a: &[impl Borrow<sparse::Polynomial<F, R>>],
    b: &[impl Borrow<sparse::Polynomial<F, R>>],
) -> FixedVec<F, NumErrorTerms<P::NumGroups>> {
    errors::<B, F, R, ConstLen<1>, P::NumGroups>(a, b)
        .into_iter()
        .next()
        .expect("one outer quotient")
}

struct Basis<'dr, D: Driver<'dr>> {
    weights: Vec<Element<'dr, D>>,
    z: Element<'dr, D>,
}
impl<'dr, D: Driver<'dr>> Basis<'dr, D> {
    fn new(dr: &mut D, r: &Element<'dr, D>, m: usize) -> Result<Self> {
        assert!(m > 0);
        let factors: Vec<_> = (0..m)
            .map(|i| {
                let node = Element::constant(dr, D::F::from(i as u64));
                r.sub(dr, &node)
            })
            .collect();
        let mut prefix = vec![Element::one(), factors[0].clone()];
        for i in 1..m {
            prefix.push(prefix[i].mul(dr, &factors[i])?);
        }
        let mut suffix = vec![Element::one(); m + 1];
        suffix[m - 1] = factors[m - 1].clone();
        for i in (1..m - 1).rev() {
            suffix[i] = factors[i].mul(dr, &suffix[i + 1])?;
        }
        let weights = (0..m)
            .map(|i| {
                let numerator = if i == 0 {
                    suffix[1].clone()
                } else if i == m - 1 {
                    prefix[m - 1].clone()
                } else {
                    prefix[i].mul(dr, &suffix[i + 1])?
                };
                let denominator: D::F = (0..m)
                    .filter(|&j| i != j)
                    .map(|j| D::F::from(i as u64) - D::F::from(j as u64))
                    .product();
                Ok(numerator.scale(
                    dr,
                    Coeff::Arbitrary(denominator.invert().expect("distinct interpolation nodes")),
                ))
            })
            .collect::<Result<Vec<_>>>()?;
        Ok(Self {
            weights,
            z: prefix.pop().expect("vanishing product"),
        })
    }
    fn linear(&self, dr: &mut D, values: &[Element<'dr, D>]) -> Result<Element<'dr, D>> {
        let mut result = Element::zero(dr);
        for (value, weight) in values.iter().zip(&self.weights) {
            let term = value.mul(dr, weight)?;
            result = result.add(dr, &term);
        }
        Ok(result)
    }
    fn corrected(
        &self,
        dr: &mut D,
        r: &Element<'dr, D>,
        targets: &[Element<'dr, D>],
        quotient: &[Element<'dr, D>],
    ) -> Result<Element<'dr, D>> {
        let target = self.linear(dr, targets)?;
        if quotient.is_empty() {
            return Ok(target);
        }
        let mut q = quotient.last().expect("quotient").clone();
        for coefficient in quotient[..quotient.len() - 1].iter().rev() {
            q = q.mul(dr, r)?.add(dr, coefficient);
        }
        let correction = self.z.mul(dr, &q)?;
        Ok(target.add(dr, &correction))
    }
}

/// Cached interpolation context shared by all groups of a folding layer.
pub struct ClaimFolder<'dr, D: Driver<'dr>> {
    challenge: Element<'dr, D>,
    contexts: RefCell<Vec<(usize, Basis<'dr, D>)>>,
}
impl<'dr, D: Driver<'dr>> ClaimFolder<'dr, D> {
    /// Binds the fold to its single interpolation challenge.
    pub fn new(mu: &Element<'dr, D>) -> Self {
        Self {
            challenge: mu.clone(),
            contexts: RefCell::new(Vec::new()),
        }
    }
    fn reduce<S: Len>(
        &self,
        dr: &mut D,
        quotient: &FixedVec<Element<'dr, D>, NumErrorTerms<S>>,
        targets: &FixedVec<Element<'dr, D>, S>,
    ) -> Result<Element<'dr, D>> {
        let mut contexts = self.contexts.borrow_mut();
        let position = match contexts.iter().position(|(m, _)| *m == S::len()) {
            Some(position) => position,
            None => {
                let basis = Basis::new(dr, &self.challenge, S::len())?;
                contexts.push((S::len(), basis));
                contexts.len() - 1
            }
        };
        contexts[position]
            .1
            .corrected(dr, &self.challenge, targets, quotient)
    }
    /// Evaluates a first-layer corrected scalar claim.
    pub fn fold_inner<P: Parameters>(
        &self,
        dr: &mut D,
        quotient: &FixedVec<Element<'dr, D>, NumErrorTerms<P::GroupSize>>,
        targets: &FixedVec<Element<'dr, D>, P::GroupSize>,
    ) -> Result<Element<'dr, D>> {
        self.reduce::<P::GroupSize>(dr, quotient, targets)
    }
    /// Evaluates the second-layer corrected scalar claim.
    pub fn fold_outer<P: Parameters>(
        &self,
        dr: &mut D,
        quotient: &FixedVec<Element<'dr, D>, NumErrorTerms<P::NumGroups>>,
        targets: &FixedVec<Element<'dr, D>, P::NumGroups>,
    ) -> Result<Element<'dr, D>> {
        self.reduce::<P::NumGroups>(dr, quotient, targets)
    }
}

/// Two-layer interpolation of trace evaluations, with one basis per layer
/// shared by every vector folded through it.
pub struct EvaluationFolder<'dr, D: Driver<'dr>, P: Parameters> {
    inner: Basis<'dr, D>,
    outer: Basis<'dr, D>,
    _parameters: PhantomData<P>,
}
impl<'dr, D: Driver<'dr>, P: Parameters> EvaluationFolder<'dr, D, P> {
    /// Builds both layers' bases at the layer challenges.
    pub fn new(dr: &mut D, first: &Element<'dr, D>, second: &Element<'dr, D>) -> Result<Self> {
        Ok(Self {
            inner: Basis::new(dr, first, P::GroupSize::len())?,
            outer: Basis::new(dr, second, P::NumGroups::len())?,
            _parameters: PhantomData,
        })
    }
    /// Reconstructs a trace evaluation from its per-claim sources, taking
    /// missing claims and groups as zero.
    pub fn fold(&self, dr: &mut D, sources: &[Element<'dr, D>]) -> Result<Element<'dr, D>> {
        assert!(sources.len() <= P::GroupSize::len() * P::NumGroups::len());
        let groups = sources
            .chunks(P::GroupSize::len())
            .map(|chunk| self.inner.linear(dr, chunk))
            .collect::<Result<Vec<_>>>()?;
        self.outer.linear(dr, &groups)
    }
}

#[cfg(test)]
mod tests {
    use ragu_backend::ReferenceBackend;
    use ragu_circuits::polynomials::TestRank;
    use ragu_core::{drivers::emulator::Emulator, maybe::Maybe, pasta::Fp};

    use super::*;

    #[derive(Clone, Copy, Default)]
    struct P;
    impl Parameters for P {
        type NumGroups = ConstLen<3>;
        type GroupSize = ConstLen<7>;
    }

    #[test]
    fn interpolation_handles_nodes_and_singleton_domains() -> Result<()> {
        for m in [1, 2, 7, 12, 14, 19] {
            for r in (0..m + 3).map(|i| Fp::from(i as u64)) {
                let dr = &mut Emulator::execute();
                let challenge = Element::constant(dr, r);
                let basis = Basis::new(dr, &challenge, m)?;
                let actual: Vec<_> = basis.weights.iter().map(|w| *w.value().take()).collect();
                assert_eq!(actual, weights(r, m));
                let expected_z: Fp = (0..m).map(|i| r - Fp::from(i as u64)).product();
                assert_eq!(*basis.z.value().take(), expected_z);
            }
        }
        Ok(())
    }

    #[test]
    fn quotient_fold_closes_and_rejects_a_false_target() -> Result<()> {
        let a: Vec<sparse::Polynomial<Fp, TestRank>> = (0..17)
            .map(|i| sparse::Polynomial::from_coeffs(vec![Fp::from(i + 1); TestRank::num_coeffs()]))
            .collect();
        let b: Vec<_> = a
            .iter()
            .map(|p| {
                let mut p = p.clone();
                p.scale(Fp::from(3));
                p
            })
            .collect();
        let q = inner_error_terms_with_backend::<ReferenceBackend, _, TestRank, P>(&a, &b);
        for r in [Fp::ZERO, Fp::ONE, Fp::from(6), Fp::from(17), Fp::from(29)] {
            let aa = fold_inner::<_, _, P>(&a, r);
            let bb = fold_inner::<_, _, P>(&b, r);
            let dr = &mut Emulator::execute();
            let challenge = Element::constant(dr, r);
            let folder = ClaimFolder::new(&challenge);
            let targets: Vec<_> = a.iter().zip(&b).map(|(a, b)| a.revdot(b)).collect();
            let cs = FixedVec::<Fp, ConstLen<3>>::from_fn(|g| {
                let qq = FixedVec::from_fn(|k| Element::constant(dr, q[g][k]));
                let ky = FixedVec::from_fn(|i| {
                    Element::constant(dr, targets.get(7 * g + i).copied().unwrap_or(Fp::ZERO))
                });
                let c = folder.fold_inner::<P>(dr, &qq, &ky).unwrap();
                assert_eq!(*c.value().take(), aa[g].revdot(&bb[g]));
                *c.value().take()
            });
            let outer =
                outer_error_terms_with_backend::<ReferenceBackend, _, TestRank, P>(&aa, &bb);
            let sigma = Fp::from(31);
            let challenge = Element::constant(dr, sigma);
            let folder = ClaimFolder::new(&challenge);
            let qq = FixedVec::from_fn(|i| Element::constant(dr, outer[i]));
            let ky = FixedVec::from_fn(|i| Element::constant(dr, cs[i]));
            let c = folder.fold_outer::<P>(dr, &qq, &ky)?;
            assert_eq!(
                *c.value().take(),
                fold_outer::<_, _, P>(aa, sigma).revdot(&fold_outer::<_, _, P>(bb, sigma))
            );
        }
        let dr = &mut Emulator::execute();
        let challenge = Element::constant(dr, Fp::from(17));
        let folder = ClaimFolder::new(&challenge);
        let qq = FixedVec::from_fn(|k| Element::constant(dr, q[0][k]));
        let ky = FixedVec::from_fn(|i| {
            Element::constant(
                dr,
                a[i].revdot(&b[i]) + if i == 0 { Fp::ONE } else { Fp::ZERO },
            )
        });
        let false_c = folder.fold_inner::<P>(dr, &qq, &ky)?;
        assert_ne!(
            *false_c.value().take(),
            fold_inner::<_, _, P>(&a, Fp::from(17))[0]
                .revdot(&fold_inner::<_, _, P>(&b, Fp::from(17))[0])
        );
        Ok(())
    }
}

#[cfg(test)]
#[path = "../../tests/backend_equivalence/fold_revdot.rs"]
mod backend_equivalence;
