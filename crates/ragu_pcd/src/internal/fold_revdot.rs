//! Two-layer Lagrange folding of revdot claims.
//!
//! For $m$ claims, interpolate $A(T)$, $B(T)$ and their scalar targets $K(T)$
//! at the nodes $0, 1, \ldots, m - 1$. Correct inputs make
//! $\operatorname{revdot}(A, B) - K$ vanish at those $m$ nodes, so it equals
//! $Z(T) \cdot Q(T)$, where $Z$ vanishes on the nodes and $Q$ has only $m - 1$
//! coefficients. Each $Q$ stage must be committed before its corresponding
//! challenge. Both vector sides use the same interpolation weights, with one
//! challenge per layer.
//!
//! This specializes the Lagrange/vanishing-polynomial identity used by
//! [ProtoGalaxy](https://eprint.iacr.org/2023/1106) to scalar revdot claims.
//!
//! The saving is in what is carried and checked: a reduction of $m$ claims
//! commits $m - 1$ quotient coefficients, and the collapse circuits fold those
//! with the claims' targets. The prover still forms every revdot product of
//! each group, the diagonal included, to assemble
//! $\operatorname{revdot}(A, B) - K$ before dividing by $Z$, so its product
//! count grows with the square of the group size while the carried count
//! depends only on the slot budget.
//!
//! If any claim is false, then for the committed $Q$ the residual
//! $\operatorname{revdot}(A, B) - K - Z \cdot Q$ is nonzero at that claim's
//! node, so it is a nonzero polynomial of degree at most $2m - 2$. A challenge
//! uniform on a support $S$ is one of its roots with probability at most
//! $(2m - 2) / |S|$, which bounds each layer's soundness error.
//!
//! A challenge equal to a node makes $Z$ vanish and the weights select that
//! node's claim alone, so the fold then checks one claim. A challenge uniform
//! on $S$ hits a node with probability at most $m / |S|$. Pasta nested
//! challenges are injective lifts of 143-bit endoscalars
//! ([`ragu_primitives::ENDOSCALAR_BITS`]), so their support has size $2^{143}$.
//! The dummy proof that stands in for absent predecessors uses all-one
//! challenges, which sit on node $1$ by construction. That is harmless: a
//! dummy is never verified on its own, and the bootstrap step that consumes
//! it leaves its claim unconstrained.

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
/// The first layer reduces $n$ = `NumGroups` groups of up to $m$ = `GroupSize`
/// claims; the second layer reduces the resulting group claims to one. Each
/// reduction uses one quotient coefficient fewer than its input count.
///
/// For a fixed slot budget $b = n \cdot m$, the carried coefficient count
/// $n \cdot (m - 1) + n - 1 = b - 1$ is the same whatever the split. The
/// prover's revdot product count $n \cdot m^2 + n^2 = b \cdot m + (b / m)^2$
/// is not monotonic in $m$: it is smallest near $m = (2b)^{1/3}$ and grows
/// on either side. The native split of fourteen groups of seven ($b = 98$)
/// sits near that minimum.
pub trait Parameters: 'static + Send + Sync + Copy + Default {
    type NumGroups: Len;
    type GroupSize: Len;
}

/// Number of quotient coefficients for a reduction of $L$ claims.
pub struct NumErrorTerms<L: Len>(PhantomData<L>);
impl<L: Len> Len for NumErrorTerms<L> {
    fn len() -> usize {
        L::len().saturating_sub(1)
    }
}

/// For each interpolation node $i$ of $0, \ldots, m - 1$, the inverse of
/// $\prod_{j \neq i} (i - j)$, with one inversion for all of them.
fn node_denominator_inverses<F: Field>(m: usize) -> Vec<F> {
    let mut denominators: Vec<F> = (0..m)
        .map(|i| {
            (0..m)
                .filter(|&j| i != j)
                .map(|j| F::from(i as u64) - F::from(j as u64))
                .product()
        })
        .collect();
    assert!(
        denominators
            .iter()
            .all(|denominator| *denominator != F::ZERO),
        "distinct interpolation nodes"
    );
    let mut scratch = vec![F::ZERO; m];
    F::batch_invert(&mut denominators, &mut scratch);
    denominators
}

/// The Lagrange weights at `r` over the interpolation nodes $0, \ldots, m - 1$.
pub(crate) fn weights<F: Field>(r: F, m: usize) -> Vec<F> {
    let inverses = node_denominator_inverses::<F>(m);
    (0..m)
        .map(|i| {
            let numerator: F = (0..m)
                .filter(|&j| i != j)
                .map(|j| r - F::from(j as u64))
                .product();
            numerator * inverses[i]
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

fn bases<B: ragu_backend::Backend, F: Field>(m: usize) -> (Vec<Vec<F>>, Vec<F>) {
    let z = (0..m).fold(vec![F::ONE], |p, i| {
        multiply(&p, &[-F::from(i as u64), F::ONE])
    });
    let inverses = node_denominator_inverses::<F>(m);
    // A basis polynomial reads nothing of another.
    let basis = B::map(0..m, |i| {
        let mut p = vec![F::ONE];
        for j in 0..m {
            if i != j {
                p = multiply(&p, &[-F::from(j as u64), F::ONE]);
            }
        }
        for coefficient in &mut p {
            *coefficient *= inverses[i];
        }
        p
    })
    .collect();
    (basis, z)
}

/// Divides each group's $\operatorname{revdot}(A, B) - K$ by $Z$, one quotient
/// per group.
///
/// Every revdot product of a group is formed, the diagonal included, so the
/// prover's product count is quadratic in the group size; only the quotient
/// coefficients are committed.
fn errors<B: ragu_backend::Backend, F: Field, R: Rank, Outer: Len, Inner: Len>(
    a: &[impl Borrow<sparse::Polynomial<F, R>>],
    b: &[impl Borrow<sparse::Polynomial<F, R>>],
) -> FixedVec<FixedVec<F, NumErrorTerms<Inner>>, Outer> {
    assert_eq!(a.len(), b.len());
    quotients::<B, F, Outer, Inner>(a.len(), |start, len| {
        let (a, b) = (&a[start..start + len], &b[start..start + len]);
        // Borrow before scheduling so callers need not make their wrappers Sync.
        let pairs = a.iter().flat_map(|a| {
            let a = a.borrow();
            b.iter().map(move |b| (a, b.borrow()))
        });
        // The backend may compute products concurrently, returning them in
        // input order for deterministic residual accumulation.
        B::map(pairs, |(a, b)| B::sparse_revdot(a, b)).collect()
    })
}

/// The index pairs whose revdot products [`quotients`] consumes for `count`
/// claims in groups of `m`: every pair within each group, group by group,
/// each group in row-major order.
pub(crate) fn product_pairs(count: usize, m: usize) -> impl Iterator<Item = (usize, usize)> {
    (0..count).step_by(m).flat_map(move |start| {
        let len = m.min(count - start);
        (0..len).flat_map(move |i| (0..len).map(move |j| (start + i, start + j)))
    })
}

/// Divides each group's $\operatorname{revdot}(A, B) - K$ by $Z$, one quotient
/// per group of `Inner` consecutive claims among `count`.
///
/// `products(start, len)` returns the revdot products of the group of `len`
/// claims starting at claim `start`: the product of $a_i$ and $b_j$ at index
/// `i * len + j`.
pub(crate) fn quotients<B: ragu_backend::Backend, F: Field, Outer: Len, Inner: Len>(
    count: usize,
    mut products: impl FnMut(usize, usize) -> Vec<F>,
) -> FixedVec<FixedVec<F, NumErrorTerms<Inner>>, Outer> {
    assert!(count <= Outer::len() * Inner::len());
    let m = Inner::len();
    let (basis, z) = bases::<B, F>(m);
    // The groups' products, asked for in claim order.
    let groups: Vec<(usize, Vec<F>)> = (0..count)
        .step_by(m)
        .map(|start| {
            let len = m.min(count - start);
            let products = products(start, len);
            assert_eq!(products.len(), len * len);
            (len, products)
        })
        .collect();
    // Honest inputs use their actual diagonal targets. The recursive
    // verifier independently uses the public k(y) targets, so false
    // input claims cannot be hidden by this prover-side construction.
    //
    // A group's residual is the sum over its pairs of
    // `product * basis[i] * basis[j]`, less the sum over the diagonal of
    // `product * basis[i]`. Row `i`'s products are combined over `basis[j]`
    // first and the combination multiplied by `basis[i]` once: the same
    // polynomial, with one polynomial multiplication per row instead of one
    // per pair. A row's share of the residual reads nothing of another's,
    // so the rows of every group go through the backend, and each group
    // sums its own in order.
    let rows = groups
        .iter()
        .enumerate()
        .flat_map(|(group, (len, _))| (0..*len).map(move |i| (group, i)));
    let shares: Vec<Vec<F>> = B::map(rows, |(group, i)| {
        let (len, products) = &groups[group];
        let mut row = vec![F::ZERO; m];
        for (j, product) in products[i * len..(i + 1) * len].iter().enumerate() {
            for (sum, &c) in row.iter_mut().zip(&basis[j]) {
                *sum += *product * c;
            }
        }
        let mut share = multiply(&basis[i], &row);
        let diagonal = products[i * len + i];
        for (k, &c) in basis[i].iter().enumerate() {
            share[k] -= diagonal * c;
        }
        share
    })
    .collect();
    let mut shares = shares.into_iter();
    groups
        .iter()
        .map(|(len, _)| {
            let mut residual = vec![F::ZERO; 2 * m - 1];
            for share in shares.by_ref().take(*len) {
                for (sum, c) in residual.iter_mut().zip(share) {
                    *sum += c;
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

/// The first-layer quotients of `count` claims from their revdot products,
/// as [`quotients`] takes them.
pub(crate) fn inner_error_terms_from_products<B: ragu_backend::Backend, F: Field, P: Parameters>(
    count: usize,
    products: impl FnMut(usize, usize) -> Vec<F>,
) -> FixedVec<FixedVec<F, NumErrorTerms<P::GroupSize>>, P::NumGroups> {
    quotients::<B, F, P::NumGroups, P::GroupSize>(count, products)
}

/// The second-layer quotient of the folded groups from their revdot
/// products: every pair of the `P::NumGroups` groups, in row-major order.
pub(crate) fn outer_error_terms_from_products<B: ragu_backend::Backend, F: Field, P: Parameters>(
    products: Vec<F>,
) -> FixedVec<F, NumErrorTerms<P::NumGroups>> {
    let mut products = Some(products);
    quotients::<B, F, ConstLen<1>, P::NumGroups>(P::NumGroups::len(), |_, _| {
        products.take().expect("one outer group")
    })
    .into_iter()
    .next()
    .expect("one outer quotient")
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
