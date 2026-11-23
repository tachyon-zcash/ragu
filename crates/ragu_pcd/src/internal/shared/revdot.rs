//! Revdot claims: what one is, how a side assembles its claims, and how
//! they fold.
//!
//! # Revdot claims
//!
//! A **revdot claim** asserts that two polynomials $a(X)$ and $b(X)$ satisfy
//! a reversed inner product on their coefficient vectors (see
//! [`sparse::Polynomial::revdot`]). In the proof system, each circuit stage
//! produces a claim of the form
//!
//! $$\operatorname{revdot}(a(X), b(X)) = k(Y),$$
//!
//! where $k(Y)$ is the public-input polynomial restricted at a verifier
//! challenge. Verifiers check these claims, and the folding machinery reduces
//! many such claims into a single claim plus a bounded set of error terms.
//!
//! This module provides helpers to build the $(a, b)$ pairs for each claim
//! and to aggregate them across proof components.
//!
//! # Folding
//!
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
//! Both claims hold for any two polynomials. In a group of $m$ nodes, with
//! the diagonal targets including $c_r$ fixed, the quotient is an affine
//! bijective image of the $m - 1$ cross values
//! $\operatorname{revdot}(a_r, b_k) + \operatorname{revdot}(a_k, b_r)$ over
//! the group's other claims $k$: the products $\ell_r \ell_k / Z$ are a
//! basis of the polynomials with $m - 1$ coefficients. Without conditioning
//! on $c_r$, the quotient also contains a term quadratic in $(a_r,b_r)$.
//! The second layer has cross values against the folded groups $g$, which
//! the first layer, seeing only the sums, does not determine. Full linear
//! reach needs the pairs $(a_k, b_k)$ to be linearly independent. Neither
//! side suffices alone: the $a$ sides of a final mask's claim form a Horner
//! list of polynomials that other claims hold, and the $b$
//! sides of the masks satisfy identities among themselves, which is why the
//! groups hold the whole claim and not half of it. A test checks the pairs
//! of a rerandomization's second pass for an honestly produced input; that
//! no input can be chosen to make them dependent is not shown.
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

use alloc::{borrow::Cow, vec, vec::Vec};
use core::{borrow::Borrow, cell::RefCell, marker::PhantomData};

use ragu_backend::Backend;
use ragu_circuits::{
    polynomials::{Rank, sparse},
    registry::{CircuitIndex, Registry},
};
use ragu_core::{Coeff, Result, drivers::Driver};
use ragu_primitives::{
    Element,
    vec::{CollectFixed, ConstLen, FixedVec, Len},
};
use udon::field::Field;

/// Sum an iterator of polynomials, borrowing if only one element.
///
/// Returns `Cow::Borrowed` for a single polynomial, `Cow::Owned` for multiple.
/// Panics if the iterator is empty.
pub fn sum_polynomials<'rx, F: Field, R: Rank>(
    mut rxs: impl Iterator<Item = &'rx sparse::Polynomial<F, R>>,
) -> Cow<'rx, sparse::Polynomial<F, R>> {
    let first = rxs.next().expect("must provide at least one rx polynomial");
    match rxs.next() {
        None => Cow::Borrowed(first),
        Some(second) => {
            let mut sum = first.clone();
            sum.add_assign(second);
            for rx in rxs {
                sum.add_assign(rx);
            }
            Cow::Owned(sum)
        }
    }
}

/// Trait for providing claim component values from sources.
///
/// This trait abstracts over what a "source" provides. For polynomial contexts
/// (verify, fuse), it provides polynomial references. For evaluation contexts
/// (`compute_v`), it provides single element evaluations (at $xz$).
///
/// Implementors provide access to rx values for all proofs they manage. The
/// `RxComponent` associated type defines which components can be requested.
pub trait Source {
    /// The type identifying which rx component to retrieve.
    type RxComponent: Copy;

    /// Opaque type for rx values.
    type Rx;

    /// Type for application circuit identifiers.
    type AppCircuitId;

    /// Get an iterator over rx values for all proofs for the given component.
    fn rx(&self, component: Self::RxComponent) -> impl Iterator<Item = Self::Rx>;

    /// Get an iterator over the application circuit claims this source
    /// folds, each paired with the rxs its trace sums: the step's own
    /// polynomial and the application stage's, in that order.
    fn applications(&self) -> impl Iterator<Item = (Self::AppCircuitId, [Self::Rx; 2])>;
}

/// Processor that builds polynomial vectors for revdot claims.
///
/// Accumulates (a, b) polynomial pairs for each claim type, using
/// the registry polynomial to transform rx polynomials appropriately.
/// A claim's `b` that depends on a circuit's restriction is only recorded
/// here; [`finish`](Self::finish) computes them all and returns the
/// [`Claims`].
///
/// The type parameter `A` determines what is stored in the `a` vector:
/// - Verify path: `A = Cow<'rx, Polynomial>` (plain polynomial references)
/// - Fuse path: `A = TrackedPoly<'rx, FoldKey, F, R>` (polynomial +
///   commitment decomposition; see `fuse::shared::claims`)
pub struct Builder<'m, 'rx, A, F: Field, R: Rank, B: Backend> {
    pub registry: &'m Registry<'m, F, R>,
    pub y: F,
    pub z: F,
    pub tz: sparse::Polynomial<F, R>,
    /// The accumulated `a` polynomials.
    a: Vec<A>,
    /// How to obtain each claim's `b` polynomial, in claim order.
    b: Vec<Side<'rx, F, R>>,
    backend: PhantomData<B>,
}

/// A claim's `b` polynomial, or the circuit restriction it is derived from.
enum Side<'rx, F: Field, R: Rank> {
    /// The polynomial itself.
    Given(Cow<'rx, sparse::Polynomial<F, R>>),
    /// $r(zX) + s\_y + t(z)$ for the claim's own trace $r$ and the circuit's
    /// restriction $s\_y$.
    Circuit(CircuitIndex),
    /// The circuit's restriction $s\_y$.
    Bonding(CircuitIndex),
}

impl<F: Field, R: Rank> Side<'_, F, R> {
    fn circuit_id(&self) -> Option<CircuitIndex> {
        match self {
            Self::Circuit(id) | Self::Bonding(id) => Some(*id),
            Self::Given(_) => None,
        }
    }
}

/// The polynomial pairs of a list of revdot claims, in claim order.
pub struct Claims<'rx, A, F: Field, R: Rank> {
    /// The claims' `a` polynomials.
    pub a: Vec<A>,
    /// The claims' `b` polynomials.
    pub b: Vec<Cow<'rx, sparse::Polynomial<F, R>>>,
}

impl<'rx, A, F: Field, R: Rank> Claims<'rx, A, F, R> {
    /// Lays the claims out over the grid of the fold `P` with the fold
    /// randomizer's claims, whose sides are `a` and `b` (see
    /// [`randomized`]).
    /// Call it once.
    ///
    /// # Panics
    ///
    /// Panics if the grid does not hold every claim.
    pub fn randomize<P: crate::internal::revdot::Parameters>(
        &mut self,
        a: A,
        b: &'rx sparse::Polynomial<F, R>,
    ) where
        A: Clone + Default,
    {
        use crate::internal::revdot::{capacity, randomized};

        assert!(
            self.a.len() <= capacity::<P>(),
            "the fold's grid does not hold every claim"
        );
        let real = core::mem::take(&mut self.a);
        self.a = randomized::<_, P>(real, A::default(), a.clone(), a).collect();
        let real = core::mem::take(&mut self.b);
        self.b = randomized::<_, P>(
            real,
            Cow::Owned(sparse::Polynomial::default()),
            Cow::Borrowed(b),
            Cow::Owned(sparse::Polynomial::default()),
        )
        .collect();
    }
}

impl<'m, 'rx, A, F: Field, R: Rank, B: Backend> Builder<'m, 'rx, A, F, R, B>
where
    A: Borrow<sparse::Polynomial<F, R>>,
{
    /// Create a new claim builder.
    pub fn new(registry: &'m Registry<'m, F, R>, y: F, z: F) -> Self {
        Self {
            registry,
            y,
            z,
            tz: R::tz(z),
            a: Vec::new(),
            b: Vec::new(),
            backend: PhantomData,
        }
    }

    /// Push a claim whose `b` is given directly.
    pub fn raw_impl(&mut self, a: A, b: Cow<'rx, sparse::Polynomial<F, R>>) {
        self.a.push(a);
        self.b.push(Side::Given(b));
    }

    /// Push a circuit claim, whose `b` is $r(zX) + s\_y + t(z)$ for the
    /// polynomial $r$ that `a` borrows.
    pub fn circuit_impl(&mut self, circuit_id: CircuitIndex, a: A) {
        self.a.push(a);
        self.b.push(Side::Circuit(circuit_id));
    }

    /// Push a bonding claim. There is no dilation and no $t(z)$, so
    /// $b = s\_{y}$ and $k(y) = 0$.
    pub fn bonding_impl(&mut self, circuit_id: CircuitIndex, a: A) {
        self.a.push(a);
        self.b.push(Side::Bonding(circuit_id));
    }

    /// Computes every claim's `b` and returns the claims.
    ///
    /// The claim builders emit each internal circuit's claims consecutively.
    /// Each run shares its restriction and keeps the original claim order.
    pub fn finish(self) -> Claims<'rx, A, F, R>
    where
        A: Sync,
    {
        let Self {
            registry,
            y,
            z,
            tz,
            a,
            mut b,
            ..
        } = self;

        let mut traces = a.as_slice();
        let jobs = b
            .chunk_by_mut(|left, right| left.circuit_id() == right.circuit_id())
            .filter_map(|sides| {
                let (group, rest) = traces.split_at(sides.len());
                traces = rest;
                sides[0].circuit_id().map(|id| (id, group, sides))
            });
        // The serial backend consumes one run at a time.
        B::map(jobs, |(id, traces, sides)| {
            let mut restriction = B::registry_circuit_y(registry, id, y);
            let last = sides.len() - 1;
            for (i, (trace, side)) in traces.iter().zip(sides).enumerate() {
                let poly = if matches!(side, Side::Circuit(_)) {
                    let mut poly = trace.borrow().clone();
                    poly.dilate(z);
                    poly.add_assign(&restriction);
                    poly.add_assign(&tz);
                    poly
                } else if i == last {
                    core::mem::take(&mut restriction)
                } else {
                    restriction.clone()
                };
                *side = Side::Given(Cow::Owned(poly));
            }
        })
        .for_each(drop);

        let b = b
            .into_iter()
            .map(|side| match side {
                Side::Given(poly) => poly,
                _ => unreachable!("every claim's b polynomial is filled"),
            })
            .collect();

        Claims { a, b }
    }

    /// Horner-fold groups of polynomials. Each group is first summed, then
    /// the sums are Horner-folded with $z$.
    ///
    /// The fold gives group `i` coefficient $z^{n-1-i}$. Callers that track
    /// commitment decompositions must assign the same coefficients to the
    /// corresponding source keys.
    ///
    /// Folding is sound because the revdot identity for bonding polynomials is
    /// linear in the trace.
    pub fn fold_bonding_groups(
        &self,
        groups: impl Iterator<Item = impl Iterator<Item = &'rx sparse::Polynomial<F, R>>>,
    ) -> Cow<'rx, sparse::Polynomial<F, R>> {
        Cow::Owned(sparse::Polynomial::fold(
            groups.map(|g| sum_polynomials(g)),
            self.z,
        ))
    }
}

/// Operations for forming linear combinations of foldable values.
pub trait Foldable<F: Field>: Default + Clone {
    fn fold_scale(&mut self, by: F);
    fn fold_add_assign(&mut self, other: &Self);

    /// Adds `by * other` to `self`.
    ///
    /// The default scales a copy of `other`. Implementations may override it
    /// to add the scaled value in one pass, with the same result.
    fn fold_add_scaled(&mut self, other: &Self, by: F) {
        let mut term = other.clone();
        term.fold_scale(by);
        self.fold_add_assign(&term);
    }
}

impl<F: Field, R: Rank> Foldable<F> for sparse::Polynomial<F, R> {
    fn fold_scale(&mut self, by: F) {
        self.scale(by);
    }
    fn fold_add_assign(&mut self, other: &Self) {
        self.add_assign(other);
    }
    fn fold_add_scaled(&mut self, other: &Self, by: F) {
        self.add_scaled_assign(other, by);
    }
}

/// Generic fold over any [`Foldable`] type: the sum Horner's rule forms from
/// $k$ items, $\sum\_i s^{k-1-i} \cdot \text{item}\_i$ for the scale factor $s$.
///
/// Each item is added under its own power, so the running sum is never
/// rescaled.
pub(crate) fn fold<T: Foldable<F>, F: Field>(
    items: impl IntoIterator<Item = impl Borrow<T>>,
    scale_factor: F,
) -> T {
    let items: Vec<_> = items.into_iter().collect();
    let mut powers = vec![F::ONE; items.len()];
    for i in (0..items.len().saturating_sub(1)).rev() {
        powers[i] = powers[i + 1] * scale_factor;
    }
    combine(&items, &powers)
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

/// $\sum\_i w\_i \cdot \text{source}\_i$ for the weights $w$. A unit weight adds
/// its value unscaled.
fn combine<T: Foldable<F>, F: Field>(source: &[impl Borrow<T>], weights: &[F]) -> T {
    let mut result = T::default();
    for (value, &weight) in source.iter().zip(weights) {
        if weight == F::ONE {
            result.fold_add_assign(value.borrow());
        } else {
            result.fold_add_scaled(value.borrow(), weight);
        }
    }
    result
}

/// Interpolates every padded first-layer group at the challenge.
#[cfg(test)]
pub fn fold_inner<T: Foldable<F> + Send + Sync, F: Field, P: Parameters>(
    source: &[impl Borrow<T>],
    challenge: F,
) -> FixedVec<T, P::NumGroups> {
    fold_inner_with_backend::<ragu_backend::ReferenceBackend, T, F, P>(source, challenge)
}

/// Interpolates every padded first-layer group at the challenge, with the
/// groups as independent work for the selected backend.
pub fn fold_inner_with_backend<
    B: ragu_backend::Backend,
    T: Foldable<F> + Send + Sync,
    F: Field,
    P: Parameters,
>(
    source: &[impl Borrow<T>],
    challenge: F,
) -> FixedVec<T, P::NumGroups> {
    assert!(
        source.len() <= P::GroupSize::len() * P::NumGroups::len(),
        "too many fold sources"
    );
    let weights = weights(challenge, P::GroupSize::len());
    // Borrow before scheduling so callers need not make their wrappers Sync.
    let source: Vec<&T> = source.iter().map(Borrow::borrow).collect();
    B::map(source.chunks(P::GroupSize::len()), |chunk| {
        combine(chunk, &weights)
    })
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

/// The Jacobian rows of what the fold shows as the first claim's two sides
/// vary, with the folded $A$ and $B$ held fixed. They measure local
/// first-order movement; the quotient's quadratic terms in the perturbation
/// are absent. Their rank alone does not establish a joint hiding
/// distribution for a rerandomization's second pass.
///
/// The first claim of `a` and `b` is the child's own accumulator, whose two
/// sides the observer does not know. A proof shows $A$ and $B$, which ties
/// the randomizer `randomizer` to that claim: moving its sides by
/// $(\delta_a, \delta_b)$ moves $a_r$ and $b_r$ by $-\kappa_a \delta_a$ and
/// $-\kappa_b \delta_b$, each $\kappa$ the claim's weight over the
/// randomizer's at `mu` and `mu_prime`. Besides the randomizer's own reach,
/// the quotients then also move through the claim's products with the
/// others in its group.
///
/// A row is a linear form in $(\delta_a, \delta_b)$: the coefficients of the
/// polynomial it pairs with $\delta_a$ by revdot, then of the one it pairs
/// with $\delta_b$. There is one row for each first-layer quotient at each
/// of `GroupSize - 1` points off its nodes, one for the second layer's at
/// each of `NumGroups - 1` points off its nodes, its first layer folded at
/// `mu`, and one each for the targets of the claim and of the randomizer,
/// which the proof shows too.
#[cfg(test)]
pub(crate) fn accumulator_rows<F: Field, R: Rank, P: Parameters>(
    a: &[impl Borrow<sparse::Polynomial<F, R>>],
    b: &[impl Borrow<sparse::Polynomial<F, R>>],
    randomizer: (&sparse::Polynomial<F, R>, &sparse::Polynomial<F, R>),
    mu: F,
    mu_prime: F,
) -> Vec<Vec<F>> {
    type Poly<F, R> = sparse::Polynomial<F, R>;
    let (m, n) = (P::GroupSize::len(), P::NumGroups::len());
    let (ra, rb) = randomizer;
    let sum = |values: &[F]| values.iter().fold(F::ZERO, |acc, value| acc + *value);
    let grid_a: Vec<Poly<F, R>> = randomized::<_, P>(
        a.iter().map(|poly| poly.borrow().clone()),
        Poly::default(),
        ra.clone(),
        ra.clone(),
    )
    .collect();
    let grid_b: Vec<Poly<F, R>> = randomized::<_, P>(
        b.iter().map(|poly| poly.borrow().clone()),
        Poly::default(),
        rb.clone(),
        Poly::default(),
    )
    .collect();

    // How far each slot's sides move with the claim's: the claim's own
    // slot, and against it every slot of the randomizer's.
    let (inner, outer) = (weights(mu, m), weights(mu_prime, n));
    let own = inner[0] * outer[0];
    let full = inner[m - 1] * sum(&outer[..n - 1]);
    let ka = own
        * (full + inner[0] * outer[n - 1])
            .invert()
            .expect("a nonzero weight");
    let kb = own * full.invert().expect("a nonzero weight");
    let alpha: Vec<F> = randomized::<_, P>([F::ONE], F::ZERO, -ka, -ka).collect();
    let beta: Vec<F> = randomized::<_, P>([F::ONE], F::ZERO, -kb, F::ZERO).collect();

    // A quotient at a point off the nodes is
    // (revdot(A(t), B(t)) - sum_i l_i(t) revdot(a_i, b_i)) / Z(t); its move
    // pairs delta_a with (sum_i alpha_i l_i) B(t) - sum_i alpha_i l_i b_i,
    // over Z(t), and delta_b likewise.
    let part = |sides: &[Poly<F, R>], moves: &[F], l: &[F], z: F| {
        let moved: Vec<F> = moves.iter().zip(l).map(|(m, l)| *m * *l).collect();
        let mut form = combine::<Poly<F, R>, F>(sides, l);
        form.scale(sum(&moved));
        let mut own = combine::<Poly<F, R>, F>(sides, &moved);
        own.scale(-F::ONE);
        form.add_assign(&own);
        form.scale(z.invert().expect("a point off the nodes"));
        form
    };
    let row = |on_a: Poly<F, R>, on_b: Poly<F, R>| -> Vec<F> {
        on_a.iter_coeffs().chain(on_b.iter_coeffs()).collect()
    };
    let vanishing =
        |t: F, nodes: usize| (0..nodes).fold(F::ONE, |acc, i| acc * (t - F::from(i as u64)));

    let mut rows = Vec::new();
    for g in 0..n {
        let group = g * m..(g + 1) * m;
        for k in 0..m - 1 {
            let t = F::from((m + k) as u64);
            let (l, z) = (weights(t, m), vanishing(t, m));
            rows.push(row(
                part(&grid_b[group.clone()], &alpha[group.clone()], &l, z),
                part(&grid_a[group.clone()], &beta[group.clone()], &l, z),
            ));
        }
    }

    let fold = |grid: &[Poly<F, R>]| -> Vec<Poly<F, R>> {
        grid.chunks(m).map(|group| combine(group, &inner)).collect()
    };
    let folded_moves = |moves: &[F]| -> Vec<F> {
        moves
            .chunks(m)
            .map(|group| {
                group
                    .iter()
                    .zip(&inner)
                    .fold(F::ZERO, |acc, (m, l)| acc + *m * *l)
            })
            .collect()
    };
    let (folded_a, folded_b) = (fold(&grid_a), fold(&grid_b));
    let (folded_alpha, folded_beta) = (folded_moves(&alpha), folded_moves(&beta));
    for k in 0..n - 1 {
        let t = F::from((n + k) as u64);
        let (l, z) = (weights(t, n), vanishing(t, n));
        rows.push(row(
            part(&folded_b, &folded_alpha, &l, z),
            part(&folded_a, &folded_beta, &l, z),
        ));
    }

    // The two targets: c = revdot(a_0, b_0) and c_r = revdot(a_r, b_r).
    rows.push(row(b[0].borrow().clone(), a[0].borrow().clone()));
    let (mut on_a, mut on_b) = (rb.clone(), ra.clone());
    on_a.scale(-ka);
    on_b.scale(-kb);
    rows.push(row(on_a, on_b));
    rows
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
        variation_rank(|ra, rb| {
            let (a, b) = layout(ra, rb);
            quotients(&a, &b)
        })
    }

    /// The rank of what `observe` returns as a function of two polynomials,
    /// by differences along every coefficient of each: what it returns must
    /// be affine in either polynomial once the other is fixed.
    fn variation_rank(
        observe: impl Fn(
            &sparse::Polynomial<Fp, TestRank>,
            &sparse::Polynomial<Fp, TestRank>,
        ) -> Vec<Fp>,
    ) -> usize {
        let mut rng = <rand::rngs::StdRng as rand::SeedableRng>::seed_from_u64(7);
        let dense = |rng: &mut rand::rngs::StdRng| -> Vec<Fp> {
            (0..TestRank::num_coeffs())
                .map(|_| Fp::random(|bytes| rand::Rng::fill_bytes(rng, bytes)))
                .collect()
        };
        let (ra, rb) = (dense(&mut rng), dense(&mut rng));
        let at = |ra: &[Fp], rb: &[Fp]| {
            observe(
                &sparse::Polynomial::from_coeffs(ra.to_vec()),
                &sparse::Polynomial::from_coeffs(rb.to_vec()),
            )
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

    /// Checks local rank for one second-pass fold. Its shown $A$ and $B$ tie
    /// the randomizer to the first claim, the child's accumulator. The
    /// Jacobian in `accumulator_rows` and sampled finite variations agree on
    /// the rank of the quotient coefficients and two displayed targets.
    /// This does not establish their joint output distribution.
    #[test]
    fn the_accumulator_claim_leaves_every_quotient_reached() {
        type Poly = sparse::Polynomial<Fp, TestRank>;
        let mut rng = <rand::rngs::StdRng as rand::SeedableRng>::seed_from_u64(13);
        let mut dense = || {
            Poly::from_coeffs(
                (0..TestRank::num_coeffs())
                    .map(|_| Fp::random(|bytes| rand::Rng::fill_bytes(&mut rng, bytes)))
                    .collect(),
            )
        };
        // Twelve claims, the first the accumulator, and the randomizer.
        let claims: Vec<(Poly, Poly)> = (0..12).map(|_| (dense(), dense())).collect();
        let (ra, rb) = (dense(), dense());
        // `quotients` folds the first layer at 1009.
        let (mu, mu_prime) = (Fp::from(1009), Fp::from(31));
        let groups = <P as Parameters>::NumGroups::len();
        // The targets obey the fold identity and add one local direction.
        let expected = claims.len() + groups - 1 + 1;

        let (a, b): (Vec<Poly>, Vec<Poly>) = claims.iter().cloned().unzip();
        let rows = accumulator_rows::<_, _, P>(&a, &b, (&ra, &rb), mu, mu_prime);
        assert_eq!(rank(rows), expected);

        let (inner, outer) = (weights(mu, 7), weights(mu_prime, groups));
        let own = inner[0] * outer[0];
        let full = inner[6] * (outer[0] + outer[1]);
        let ka = own * (full + inner[0] * outer[2]).invert().unwrap();
        let kb = own * full.invert().unwrap();
        // `base - k (moved - from)`: the randomizer once the claim's side
        // has moved from `from` to `moved`.
        let tied = |base: &Poly, k: Fp, from: &Poly, moved: &Poly| {
            let mut side = from.clone();
            side.scale(-Fp::ONE);
            side.add_assign(moved);
            side.scale(-k);
            side.add_assign(base);
            side
        };
        let zero = Poly::default();
        let observed = variation_rank(|x, y| {
            let (sa, sb) = (
                tied(&ra, ka, &claims[0].0, x),
                tied(&rb, kb, &claims[0].1, y),
            );
            let mut grid = claims.clone();
            grid[0] = (x.clone(), y.clone());
            let (a, b): (Vec<Poly>, Vec<Poly>) = randomized::<_, P>(
                grid,
                (zero.clone(), zero.clone()),
                (sa.clone(), sb.clone()),
                (sa.clone(), zero.clone()),
            )
            .unzip();
            let mut shown = quotients(&a, &b);
            shown.extend([x.revdot(y), sa.revdot(&sb)]);
            shown
        });
        assert_eq!(observed, expected);
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
#[path = "../../../tests/backend_equivalence/fold_revdot.rs"]
mod backend_equivalence;
