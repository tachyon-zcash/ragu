//! The step's own randomizers: the polynomials a fuse folds and batches so
//! that the polynomials its proof stores in full are uniformly random.
//!
//! A proof stores its folded $A$ and $B$ and its batched $p$ in full, and
//! its stages hold the quotient coefficients of the fold. Each is a fixed
//! function of the children's polynomials unless the fuse mixes in
//! polynomials of its own that nothing else determines. On each side of the
//! cycle the step therefore draws three polynomials whose coefficients are
//! all uniformly random:
//!
//! - $a_r$ and $b_r$, which the fold takes as claims of its own (see
//!   [`fold_revdot`](crate::internal::fold_revdot#the-randomizer)), and
//!   which the batch opens as it opens a child's $a$ and $b$;
//! - a mask, which the batch folds into $p$ and no query names.
//!
//! Like the step's application polynomials, none of them is kept: the proof
//! holds their commitments and evaluations in its stages, and the fuse
//! proves the openings in its own batch.
//!
//! The randomizers do not hide a child from someone who knows the child's
//! polynomials. The fold's documentation says what they hide and from
//! whom, and [`Application::rerandomize`] is the method that relies on
//! them.
//!
//! # What a rerandomization shows
//!
//! [`Application::rerandomize`] fuses its input twice, each time with the
//! bootstrap proof as the right child. A fuse stores what it reads of its
//! children as stage values: their commitments, their challenges and their
//! accumulators' values. One pass would therefore show the input's
//! commitments in the clear. After the second pass the output holds the
//! first pass's commitments, which are fresh, its challenges, which are
//! functions of those commitments, and four kinds of value computed from
//! the first pass's polynomials:
//!
//! - A commitment and two evaluations of each polynomial the first pass's
//!   proof stores. The three free coefficients of a trace or a stage hide
//!   the rest of it (see [`Blind`](ragu_circuits::Blind)), and the first
//!   pass's folded $A$ and $B$ and batched $p$ are uniform in every
//!   coefficient, by the first pass's randomizers. The stages that keep
//!   their blind gate zero, the first pass's challenge and bridge-hash
//!   stages and its `ab` bridge, hold only values the output shows anyway:
//!   its challenges, its commitments and its last online commitment. On
//!   each side the first pass's accumulator value $v$ is one of the two
//!   evaluations of its $p$, and its value $c$ is
//!   $\operatorname{revdot}(A, B)$, a function of its uniform $A$ and $B$.
//! - The second pass's folded $A$ and $B$ and batched $p$, in full, which
//!   the second pass's randomizers make uniform. The output also shows the
//!   uniform polynomials folded or batched into each, those randomizers
//!   and the first pass's $A$, $B$ and $p$, as commitments and at a few
//!   points, so it shows what the rest of each sums to there: its
//!   commitment, and its value at $xz$ and $u$ for $A$, at $x$ and $u$ for
//!   $B$, and at $u$ for $p$. For $A$ and $p$, and for $B$ at $x$, these
//!   are sums of values the output shows term by term. $B$ folds the claim
//!   on each of the first pass's circuits with that circuit's trace $r_k$
//!   dilated, so its commitment and its value at $u$ are not: they show a
//!   commitment to $\sum_k \lambda_k r_k(zX)$ and its value at $u$. Three
//!   free coefficients per polynomial do not cover these. The first pass's
//!   randomizers do: the claim on its `collapse` circuit folds its inner
//!   error stage, whose quotient coefficients and randomizer target are
//!   functions of those randomizers that the values listed here do not
//!   determine. The nested `collapse` claim folds the first pass's nested
//!   inner error stage in the same way.
//! - The quotient coefficients of the second pass's fold, and the target
//!   $c_r = \operatorname{revdot}(a_r, b_r)$ of its randomizer's claim.
//!   With the second pass's $A$ and $B$ fixed, they are functions of the
//!   first pass's polynomials, and the fold places its randomizer's claims
//!   so that the quotient coefficients take every value as the first
//!   pass's folded $A$ and $B$ vary (see
//!   [`fold_revdot`](crate::internal::fold_revdot#the-randomizer)). Those
//!   two polynomials are uniform, and the first pass's proof is shown to no
//!   one. With the first pass's $c$ shown, $c_r$ is one more affine
//!   function of them. Taking every value needs the claims' pairs to be
//!   linearly independent, which a test checks for a proof made from an
//!   honestly produced input. An input reaches those claims only through
//!   the first pass's polynomials, whose free coefficients and randomizers
//!   are drawn after it is fixed, but it has not been shown that no input
//!   can be chosen to make the pairs dependent.
//! - The commitments of the second pass's quotient polynomials $f$ and
//!   $f_n$, which batch the openings that pass checks. Each folds in the
//!   quotient of the first pass's $p$ by $X - u$, at that proof's own $u$:
//!   a function of $p$ that its commitment and two evaluations do not
//!   determine, so the first pass's batch randomizer, which that $p$
//!   folds, makes each commitment uniform.
//!
//! Every other value the output holds, its own commitments and challenges,
//! its walks and its circuits' wires, is computed from these, from public
//! values and from the second pass's own randomness.
//!
//! This covers the standard profile. A profile with an extension, an online
//! batch or a mesh stores polynomials and values of its own in a proof and
//! commits some of its stages with a single random coefficient, which a
//! parent's commitment and two evaluations do not hide.

use ragu_circuits::polynomials::{Rank, sparse};
use ragu_core::Cycle;
use rand::CryptoRng;
use udon::{curve::Affine, field::Field};

use crate::{Application, profile::ProfiledCycle};

/// One side's randomizers, with their commitments.
#[derive(Clone)]
pub(crate) struct Randomizer<F: Field, G, R: Rank> {
    /// The fold randomizer $a_r$.
    pub(crate) a: sparse::Polynomial<F, R>,
    pub(crate) a_commitment: G,
    /// The fold randomizer $b_r$.
    pub(crate) b: sparse::Polynomial<F, R>,
    pub(crate) b_commitment: G,
    /// $c_r = \operatorname{revdot}(a_r, b_r)$, the target of the fold
    /// randomizer's claim.
    pub(crate) c: F,
    /// The batch randomizer.
    pub(crate) mask: sparse::Polynomial<F, R>,
    pub(crate) mask_commitment: G,
}

/// The native randomizers: polynomials over the circuit field, committed on
/// the host curve.
pub(crate) type NativeRandomizer<C, R> =
    Randomizer<<C as Cycle>::CircuitField, <C as Cycle>::HostCurve, R>;

/// The nested randomizers: polynomials over the scalar field, committed on
/// the nested curve.
pub(crate) type NestedRandomizer<C, R> =
    Randomizer<<C as Cycle>::ScalarField, <C as Cycle>::NestedCurve, R>;

/// Both sides' randomizers of one fuse.
#[derive(Clone)]
pub(crate) struct Randomizers<C: Cycle, R: Rank> {
    pub(crate) native: NativeRandomizer<C, R>,
    pub(crate) nested: NestedRandomizer<C, R>,
}

impl<C: ProfiledCycle, R: Rank, const HEADER_SIZE: usize, B: crate::SelectableBackend>
    Application<'_, C, R, HEADER_SIZE, B>
{
    /// Draws the fuse's randomizers and commits them.
    pub(crate) fn sample_randomizers<RNG: CryptoRng>(&self, rng: &mut RNG) -> Randomizers<C, R> {
        Randomizers {
            native: sample::<B, _, _, R, _, _>(rng, C::host_generators(self.params)),
            nested: sample::<B, _, _, R, _, _>(rng, C::nested_generators(self.params)),
        }
    }
}

fn sample<B, F, G, R, Gens, RNG>(rng: &mut RNG, generators: &Gens) -> Randomizer<F, G, R>
where
    B: ragu_backend::Backend,
    F: Field,
    G: Affine<Scalar = F>,
    R: Rank,
    Gens: ragu_core::FixedGenerators<G>,
    RNG: CryptoRng,
{
    let a = sparse::Polynomial::random(rng);
    let b = sparse::Polynomial::random(rng);
    let mask = sparse::Polynomial::random(rng);
    let mut commitments = [G::identity(); 3];
    G::batch_to_affine(
        &B::sparse_commit_batch([&a, &b, &mask], generators),
        &mut commitments,
    );
    let [a_commitment, b_commitment, mask_commitment] = commitments;
    let c = B::sparse_revdot(&a, &b);
    Randomizer {
        a,
        a_commitment,
        b,
        b_commitment,
        c,
        mask,
        mask_commitment,
    }
}

/// The randomizers of the last fuse on this thread, for the tests that
/// recompute a fold or a batch from a finished proof, which does not keep
/// them, and the reach of a fold randomizer over the claims it was folded
/// with.
#[cfg(test)]
pub(crate) mod observed {
    use alloc::{boxed::Box, vec::Vec};
    use core::{
        any::Any,
        borrow::Borrow,
        cell::{Cell, RefCell},
    };

    use ragu_circuits::polynomials::{Rank, sparse};
    use ragu_core::Cycle;
    use ragu_primitives::vec::Len;
    use udon::field::Field;

    use super::Randomizers;
    use crate::internal::fold_revdot::{self, Parameters};

    std::thread_local! {
        static LAST: RefCell<Option<Box<dyn Any>>> = const { RefCell::new(None) };
        static WATCHING: Cell<bool> = const { Cell::new(false) };
        static REACHES: RefCell<Vec<Reach>> = const { RefCell::new(Vec::new()) };
    }

    /// How far a fold randomizer moves the quotient coefficients of one
    /// fold.
    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    pub(crate) struct Reach {
        /// The rank of the quotient coefficients as a function of the
        /// randomizer.
        pub(crate) rank: usize,
        /// The coefficients that depend on the claims: one per claim in
        /// the first layer, and one per group that holds a claim in the
        /// second.
        pub(crate) coefficients: usize,
        /// The rank of the quotient coefficients and of the two targets the
        /// proof shows, as functions of the first claim's two sides with
        /// the folded $A$ and $B$ held fixed, the randomizer moving against
        /// them (see [`fold_revdot::accumulator_rows`]). Nothing cancels
        /// when it is two more than [`coefficients`](Self::coefficients).
        pub(crate) accumulator: usize,
    }

    /// Starts or stops recording the [`Reach`] of this thread's fuses, and
    /// forgets what was recorded.
    pub(crate) fn watch(watching: bool) {
        WATCHING.with(|cell| cell.set(watching));
        REACHES.with(|reaches| reaches.borrow_mut().clear());
    }

    /// The reaches recorded since [`watch`] was called, in the order the
    /// fuses folded: the native fold of a fuse and then its nested fold.
    pub(crate) fn reaches() -> Vec<Reach> {
        REACHES.with(|reaches| reaches.borrow().clone())
    }

    /// Records the reach of a randomizer over the claims `a` and `b`, which
    /// the fold `P` is about to lay out with it, if this thread is
    /// [watching](watch).
    ///
    /// A first-layer quotient is a bijective image of the values
    /// $\operatorname{revdot}(a_r, b_k) + \operatorname{revdot}(a_k, b_r)$
    /// over its group's claims $k$, and the second layer's of the values
    /// $\operatorname{revdot}(a_r, b'\_g)$ over the groups' folded $b$ sides
    /// (see [`fold_revdot`]). Both are linear in $(a_r, b_r)$, so the rank
    /// is that of the vectors $(b_k, a_k)$ and $(b'\_g, 0)$. The second
    /// layer's are taken at a fixed challenge.
    ///
    /// It also records the rank with `randomizer` tied to the first claim,
    /// as a proof that shows its $A$ and $B$ ties them, at fixed
    /// challenges.
    pub(crate) fn reach<F: Field, R: Rank, P: Parameters>(
        a: &[impl Borrow<sparse::Polynomial<F, R>>],
        b: &[impl Borrow<sparse::Polynomial<F, R>>],
        randomizer: (&sparse::Polynomial<F, R>, &sparse::Polynomial<F, R>),
    ) {
        if !WATCHING.with(Cell::get) {
            return;
        }
        let zero = sparse::Polynomial::<F, R>::default();
        let mut rows: Vec<Vec<F>> = a
            .iter()
            .zip(b)
            .map(|(a, b)| {
                b.borrow()
                    .iter_coeffs()
                    .chain(a.borrow().iter_coeffs())
                    .collect()
            })
            .collect();
        let grid: Vec<_> = fold_revdot::randomized::<_, P>(
            b.iter().map(|b| b.borrow().clone()),
            zero.clone(),
            zero.clone(),
            zero,
        )
        .collect();
        let (mu, mu_prime) = (
            F::from(0x9e37_79b9_7f4a_7c15),
            F::from(0x2545_f491_4f6c_dd1d),
        );
        let folded = fold_revdot::fold_inner::<sparse::Polynomial<F, R>, _, P>(&grid, mu);
        let occupied = a.len().div_ceil(P::GroupSize::len() - 1);
        rows.extend(folded.iter().take(occupied).map(|b| {
            b.iter_coeffs()
                .chain(core::iter::repeat_n(F::ZERO, R::num_coeffs()))
                .collect()
        }));
        let coefficients = rows.len();
        let reach = Reach {
            rank: rank(rows),
            coefficients,
            accumulator: rank(fold_revdot::accumulator_rows::<F, R, P>(
                a, b, randomizer, mu, mu_prime,
            )),
        };
        REACHES.with(|reaches| reaches.borrow_mut().push(reach));
    }

    /// The rank of `rows` over the field.
    fn rank<F: Field>(mut rows: Vec<Vec<F>>) -> usize {
        let mut rank = 0;
        for i in 0..rows.len() {
            let Some(column) = rows[i].iter().position(|c| *c != F::ZERO) else {
                continue;
            };
            rank += 1;
            let inverse = rows[i][column].invert().expect("a nonzero pivot");
            let (head, tail) = rows.split_at_mut(i + 1);
            for row in tail {
                let factor = row[column] * inverse;
                if factor != F::ZERO {
                    for (x, pivot) in row.iter_mut().zip(&head[i]) {
                        *x -= *pivot * factor;
                    }
                }
            }
        }
        rank
    }

    /// Records a fuse's randomizers.
    pub(crate) fn record<C: Cycle, R: Rank>(randomizers: &Randomizers<C, R>) {
        LAST.with(|last| *last.borrow_mut() = Some(Box::new(randomizers.clone())));
    }

    /// The randomizers of the last fuse this thread ran.
    ///
    /// # Panics
    ///
    /// Panics if this thread ran no fuse over `C` and `R`.
    pub(crate) fn last<C: Cycle, R: Rank>() -> Randomizers<C, R> {
        LAST.with(|last| {
            last.borrow()
                .as_ref()
                .and_then(|randomizers| randomizers.downcast_ref::<Randomizers<C, R>>())
                .cloned()
                .expect("this thread ran a fuse over these parameters")
        })
    }
}
