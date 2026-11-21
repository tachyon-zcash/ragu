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
//!
//! # The randomizer
//!
//! A quotient's coefficients are fixed functions of the revdot products of
//! its group, and a proof stores them. To keep them from revealing the
//! claims' polynomials, the prover folds two polynomials $a_r$ and $b_r$
//! whose coefficients are all uniformly random, in the layout that
//! [`randomized`] gives the grid:
//!
//! - the last node of every group but the last holds the claim
//!   $(a_r, b_r; c_r)$ with $c_r = \operatorname{revdot}(a_r, b_r)$, so each
//!   such group holds one claim fewer;
//! - the last group holds the claim $(a_r, 0; 0)$ and nothing else.
//!
//! Both claims hold for any two polynomials. In a group of $m$
//! nodes the quotient is the image, under a bijection, of the $m - 1$ values
//! $\operatorname{revdot}(a_r, b_k) + \operatorname{revdot}(a_k, b_r)$ over
//! the group's other claims $k$: the products $\ell_r \ell_k / Z$ are a
//! basis of the polynomials with $m - 1$ coefficients. The second layer's
//! quotient is likewise the image of $\operatorname{revdot}(a_r, b'\_g)$ over
//! the folded groups $g$, which the first layer, seeing only the sums, does
//! not determine. That needs the pairs $(a_k, b_k)$ to be linearly
//! independent, which claims about two different children are. Neither side
//! alone is: the $a$ sides of a final mask's claim are a Horner list of
//! polynomials that other claims hold, and the $b$ sides of the masks
//! satisfy identities among themselves, which is why the groups hold the
//! whole claim and not half of it.
//!
//! A proof also stores the folded $A$ and $B$ in full. Given the other
//! claims' polynomials, $A$ and $B$ determine $a_r$ and $b_r$, and with
//! them every quotient coefficient. The randomizer therefore hides the
//! quotients only from an observer who does not know the claims'
//! polynomials. The three free coefficients of a polynomial
//! ([`Blind`](ragu_circuits::Blind)) do not make up for that: a parent's
//! commitment to it and two evaluations of it use them up. What does is a
//! child whose own folded $A$ and $B$ were randomized and are not shown to
//! the observer. Those two polynomials are claims of the fold, and every
//! coefficient of them is unknown.
//! [`Application::rerandomize`](crate::Application::rerandomize) runs two
//! passes for this reason.

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
/// on either side. The native split of fifteen groups of eight ($b = 120$)
/// sits near that minimum.
pub trait Parameters: 'static + Send + Sync + Copy + Default {
    type NumGroups: Len;
    type GroupSize: Len;
}

/// The groups a fold of `claims` claims needs with `group_size` nodes per
/// group, in the layout of [`randomized`]: every group but the last holds
/// `group_size - 1` claims beside the randomizer's, and the last group holds
/// the randomizer's half-claim.
pub const fn num_groups(claims: usize, group_size: usize) -> usize {
    assert!(group_size > 1, "a group holds the randomizer and a claim");
    claims.div_ceil(group_size - 1) + 1
}

/// The claims the grid of `P` holds beside the randomizer's.
pub fn capacity<P: Parameters>() -> usize {
    (P::NumGroups::len() - 1) * (P::GroupSize::len() - 1)
}

/// Lays `real`, one side or the targets of the claims in order, out over the
/// whole grid of `P` with the randomizer's entries (see the
/// [module documentation](self#the-randomizer)): every group but the last
/// takes the next `GroupSize - 1` entries of `real`, or `zero` once `real`
/// has run out, and then `full`; the last group takes `half` and then
/// `zero`.
///
/// For the $a$ sides `full` and `half` are both $a_r$. For the $b$ sides
/// `full` is $b_r$ and `half` is zero. For the targets `full` is $c_r$ and
/// `half` is zero.
///
/// The result has `NumGroups * GroupSize` entries. Entries of `real` past
/// [`capacity`] are not taken, so a caller with a finite list checks its
/// length.
pub fn randomized<T: Clone, P: Parameters>(
    real: impl IntoIterator<Item = T>,
    zero: T,
    full: T,
    half: T,
) -> impl Iterator<Item = T> {
    let groups = P::NumGroups::len();
    let size = P::GroupSize::len();
    assert!(groups > 1 && size > 1, "the grid has no room for a claim");
    let mut real = real.into_iter();
    (0..groups * size).map(move |slot| {
        let (group, node) = (slot / size, slot % size);
        if group + 1 == groups {
            if node == 0 {
                half.clone()
            } else {
                zero.clone()
            }
        } else if node + 1 == size {
            full.clone()
        } else {
            real.next().unwrap_or_else(|| zero.clone())
        }
    })
}

/// Number of quotient coefficients for a reduction of $L$ claims.
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
    /// Reconstructs the evaluation of the folded $A$ from the evaluations of
    /// the claims' $a$ sides, `real` in claim order, and of the randomizer's
    /// $a_r$. Every group holds $a_r$: every group but the last at its last
    /// node, and the last group at its first.
    ///
    /// This is the interpolation of the grid that [`randomized`] lays out,
    /// with one product for the node that every group but the last weights
    /// alike, and none for a node that holds nothing.
    ///
    /// # Panics
    ///
    /// Panics if the grid does not hold every claim.
    pub fn fold_a(
        &self,
        dr: &mut D,
        real: &[Element<'dr, D>],
        randomizer: &Element<'dr, D>,
    ) -> Result<Element<'dr, D>> {
        let mut groups = self.groups(dr, real, randomizer)?;
        groups.push(randomizer.mul(dr, &self.inner.weights[0])?);
        self.outer.linear(dr, &groups)
    }

    /// Reconstructs the evaluation of the folded $B$ from the evaluations of
    /// the claims' $b$ sides, `real` in claim order, and of the randomizer's
    /// $b_r$. Every group but the last holds $b_r$ at its last node, and
    /// the last group's $b$ side is zero. See [`fold_a`](Self::fold_a).
    ///
    /// # Panics
    ///
    /// Panics if the grid does not hold every claim.
    pub fn fold_b(
        &self,
        dr: &mut D,
        real: &[Element<'dr, D>],
        randomizer: &Element<'dr, D>,
    ) -> Result<Element<'dr, D>> {
        let groups = self.groups(dr, real, randomizer)?;
        self.outer.linear(dr, &groups)
    }

    /// The first layer's fold of every group but the last, each holding its
    /// claims and then the randomizer's evaluation at its last node.
    fn groups(
        &self,
        dr: &mut D,
        real: &[Element<'dr, D>],
        randomizer: &Element<'dr, D>,
    ) -> Result<Vec<Element<'dr, D>>> {
        let size = P::GroupSize::len();
        assert!(
            real.len() <= capacity::<P>(),
            "the fold's grid does not hold every claim"
        );
        let randomizer = randomizer.mul(dr, &self.inner.weights[size - 1])?;
        let mut groups = real
            .chunks(size - 1)
            .map(|chunk| Ok(self.inner.linear(dr, chunk)?.add(dr, &randomizer)))
            .collect::<Result<Vec<_>>>()?;
        // A group without a claim holds the randomizer's alone.
        groups.resize(P::NumGroups::len() - 1, randomizer);
        Ok(groups)
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
    fn randomized_lays_the_claims_out_with_the_randomizer() {
        // Three groups of seven: two groups of six claims and the
        // randomizer's, then the group of its half-claim.
        assert_eq!(num_groups(12, 7), 3);
        assert_eq!(num_groups(13, 7), 4);
        assert_eq!(capacity::<P>(), 12);
        let grid: Vec<u32> = randomized::<_, P>(1..=10, 0, 77, 88).collect();
        assert_eq!(
            grid,
            [
                [1, 2, 3, 4, 5, 6, 77],
                [7, 8, 9, 10, 0, 0, 77],
                [88, 0, 0, 0, 0, 0, 0]
            ]
            .concat()
        );
        // An unending list, as the targets are, fills the claims' nodes.
        let grid: Vec<u32> = randomized::<_, P>(1.., 0, 77, 88).collect();
        assert_eq!(grid[7..14], [7, 8, 9, 10, 11, 12, 77]);
        assert_eq!(grid.len(), 21);
    }

    /// The rank of `rows` over the field.
    fn rank(mut rows: Vec<Vec<Fp>>) -> usize {
        let mut rank = 0;
        for i in 0..rows.len() {
            let Some(column) = rows[i].iter().position(|c| *c != Fp::ZERO) else {
                continue;
            };
            rank += 1;
            let inverse = rows[i][column].invert().unwrap();
            let (head, tail) = rows.split_at_mut(i + 1);
            for row in tail {
                let factor = row[column] * inverse;
                if factor != Fp::ZERO {
                    for (x, p) in row.iter_mut().zip(&head[i]) {
                        *x -= *p * factor;
                    }
                }
            }
        }
        rank
    }

    /// Every quotient coefficient of both layers over a grid, the first
    /// layer's group by group and then the second layer's.
    fn quotients(
        a: &[sparse::Polynomial<Fp, TestRank>],
        b: &[sparse::Polynomial<Fp, TestRank>],
    ) -> Vec<Fp> {
        let mu = Fp::from(1009);
        let inner = inner_error_terms::<_, TestRank, P>(a, b);
        let outer = outer_error_terms::<_, TestRank, P>(
            &fold_inner::<_, _, P>(a, mu),
            &fold_inner::<_, _, P>(b, mu),
        );
        inner
            .iter()
            .flat_map(|group| group.iter().copied())
            .chain(outer.iter().copied())
            .collect()
    }

    /// The rank of the quotient coefficients as a function of the two
    /// polynomials `layout` places in the grid, by differences along every
    /// coefficient of each: the coefficients are affine in either
    /// polynomial once the other is fixed.
    fn randomizer_rank(
        layout: impl Fn(
            &sparse::Polynomial<Fp, TestRank>,
            &sparse::Polynomial<Fp, TestRank>,
        ) -> (
            Vec<sparse::Polynomial<Fp, TestRank>>,
            Vec<sparse::Polynomial<Fp, TestRank>>,
        ),
    ) -> usize {
        let mut rng = <rand::rngs::StdRng as rand::SeedableRng>::seed_from_u64(7);
        let dense = |rng: &mut rand::rngs::StdRng| -> Vec<Fp> {
            (0..TestRank::num_coeffs())
                .map(|_| Fp::random(|bytes| rand::Rng::fill_bytes(rng, bytes)))
                .collect()
        };
        let (ra, rb) = (dense(&mut rng), dense(&mut rng));
        let at = |ra: &[Fp], rb: &[Fp]| {
            let (a, b) = layout(
                &sparse::Polynomial::from_coeffs(ra.to_vec()),
                &sparse::Polynomial::from_coeffs(rb.to_vec()),
            );
            quotients(&a, &b)
        };
        let base = at(&ra, &rb);
        let mut columns = Vec::new();
        for side in 0..2 {
            for i in 0..TestRank::num_coeffs() {
                let (mut ra, mut rb) = (ra.clone(), rb.clone());
                if side == 0 {
                    ra[i] += Fp::ONE;
                } else {
                    rb[i] += Fp::ONE;
                }
                columns.push(
                    at(&ra, &rb)
                        .into_iter()
                        .zip(&base)
                        .map(|(moved, base)| moved - *base)
                        .collect::<Vec<_>>(),
                );
            }
        }
        rank(columns)
    }

    /// The reason for the randomizer's layout. With the randomizer's claim
    /// in every group and its half-claim in a group of its own, the quotient
    /// coefficients take every value as the randomizer varies: one
    /// coefficient per claim in the first layer, and all of the second
    /// layer's. A randomizer that is one more claim in one group moves only
    /// that group's quotient and the second layer's, and one that is a whole
    /// claim in the last group as well leaves the second layer's quotient a
    /// function of the first layer's.
    #[test]
    fn the_randomizer_determines_every_quotient() {
        let mut rng = <rand::rngs::StdRng as rand::SeedableRng>::seed_from_u64(11);
        let mut dense = || {
            sparse::Polynomial::<Fp, TestRank>::from_coeffs(
                (0..TestRank::num_coeffs())
                    .map(|_| Fp::random(|bytes| rand::Rng::fill_bytes(&mut rng, bytes)))
                    .collect(),
            )
        };
        // Twelve claims: two full groups of six.
        let claims: Vec<_> = (0..12).map(|_| (dense(), dense())).collect();
        let zero = sparse::Polynomial::<Fp, TestRank>::default();
        let groups = <P as Parameters>::NumGroups::len();
        let sides = |grid: Vec<(
            sparse::Polynomial<Fp, TestRank>,
            sparse::Polynomial<Fp, TestRank>,
        )>| { grid.into_iter().unzip::<_, _, Vec<_>, Vec<_>>() };

        let proposed = randomizer_rank(|ra, rb| {
            sides(
                randomized::<_, P>(
                    claims.iter().cloned(),
                    (zero.clone(), zero.clone()),
                    (ra.clone(), rb.clone()),
                    (ra.clone(), zero.clone()),
                )
                .collect(),
            )
        });
        assert_eq!(proposed, claims.len() + groups - 1);

        // One more claim, in the last group: the second layer's quotient
        // moves, and of the first layer's only the randomizer's own product.
        let one_slot = randomizer_rank(|ra, rb| {
            let mut grid = claims.clone();
            grid.resize(14, (zero.clone(), zero.clone()));
            grid.push((ra.clone(), rb.clone()));
            sides(grid)
        });
        assert_eq!(one_slot, groups - 1 + 1);

        // The whole claim in every group, the last included.
        let symmetric = randomizer_rank(|ra, rb| {
            sides(
                randomized::<_, P>(
                    claims.iter().cloned(),
                    (zero.clone(), zero.clone()),
                    (ra.clone(), rb.clone()),
                    (ra.clone(), rb.clone()),
                )
                .collect(),
            )
        });
        assert_eq!(symmetric, claims.len() + 1);
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
