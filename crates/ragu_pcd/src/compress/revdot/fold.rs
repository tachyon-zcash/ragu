//! The fold in front of the split: from every revdot claim on one curve to
//! three.
//!
//! The claims are taken in groups of [`GROUP`], the last possibly shorter.
//! For each group the prover computes the off-diagonal products $e_{ij} =
//! \operatorname{revdot}(a_i, b_j)$, $i \ne j$, lays them out as the low
//! coefficients of one polynomial $E$ and commits to it. Only then are
//! $\mu, \nu$ squeezed, and each group folds into $A_g = \sum_i \mu^i a_i$
//! and $B_g = \sum_j \nu^j b_j$, so that
//!
//! $$\operatorname{revdot}(A_g, B_g) = \sum_i \mu^i \nu^i k_i + \sum_{i \ne j} \mu^i \nu^j e_{ij}.$$
//!
//! A second layer does the same over the groups' pairs with $\mu', \nu'$,
//! leaving one pair $(A, B)$ whose target is the doubly weighted sum of the
//! $k_i$ plus each layer's weighted error terms. Those weighted sums are
//! $\operatorname{revdot}(E, W)$ for the public polynomial $W$ that holds
//! the weights mirrored, so the prover sends each as $\varepsilon$ and the
//! split proves $(E, W, \varepsilon)$ beside $(A, B)$. Both sides use the
//! fuse's error-term order, group by group and row by row.
//!
//! The verifier never sees the error terms. It holds $\[E\]$ and $\varepsilon$
//! and derives $\[A\]$ from the instance's commitments, as the diagonal's
//! weights $\mu^i \nu^i$ and the off-diagonal's $\mu^i \nu^j$ are distinct
//! monomials: with $E$ fixed before $\mu, \nu$ exist, a false $k_i$ makes
//! the folded identity a nonzero polynomial in the challenges, which
//! vanishes at a random point with probability at most $2(m - 1) / |F|$
//! for a layer over $m$ claims or groups.
//!
//! The split opens five polynomials: the committed part of $A$ at $r$; the
//! circuit claims' $a$ under the $b$ weights at $rz$, since each such $b$
//! holds its $a$ dilated by $z$; the raw claims' committed $b$ under the $b$
//! weights at $r$; and the two $E$ at $r$. The rest of $A(r)$ and $B(r)$,
//! the registry restrictions, $t(z, X)$ and the wire bindings' expected
//! values and masks, the verifier evaluates itself.

use alloc::{vec, vec::Vec};

use ragu_backend::Backend;
use ragu_circuits::polynomials::{Rank, sparse};
use ragu_core::Result;
use udon::{curve::Affine, field::Field};

use crate::{
    compress::revdot::claims::{Kind, Shape},
    ipa::IpaTranscript,
};

/// The size of a first-layer group, the fuse's.
pub(crate) const GROUP: usize = 7;

/// The prover's messages of the fold on one curve.
#[derive(Clone, Debug)]
pub(crate) struct Fold<C: Affine> {
    /// The commitment to the first layer's error terms.
    pub inner: C,
    /// The commitment to the second layer's error terms.
    pub outer: C,
    /// The first layer's weighted error terms, $\varepsilon$.
    pub inner_epsilon: C::Scalar,
    /// The second layer's.
    pub outer_epsilon: C::Scalar,
}

impl<C: Affine> Fold<C> {
    /// Replays the messages on `transcript` in the prover's order and
    /// squeezes the weights where the prover did.
    pub(crate) fn replay<T: IpaTranscript<C>>(
        &self,
        transcript: &mut T,
    ) -> Result<Weights<C::Scalar>> {
        transcript.write_point(self.inner)?;
        let (mu, nu) = squeeze_pair(transcript)?;
        transcript.write_point(self.outer)?;
        let (mu_prime, nu_prime) = squeeze_pair(transcript)?;
        transcript.write_scalar(self.inner_epsilon)?;
        transcript.write_scalar(self.outer_epsilon)?;
        Ok(Weights {
            mu,
            nu,
            mu_prime,
            nu_prime,
        })
    }
}

/// One layer's pair of challenges.
pub(crate) fn squeeze_pair<C: Affine, T: IpaTranscript<C>>(
    transcript: &mut T,
) -> Result<(C::Scalar, C::Scalar)> {
    Ok((
        transcript.squeeze_challenge()?,
        transcript.squeeze_challenge()?,
    ))
}

/// The committed polynomials the fold leaves for the split to open, in the
/// order their openings are listed.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Derived {
    /// The committed part of $A$, opened at $r$.
    A,
    /// The circuit claims' $a$ under the $b$ weights, opened at $rz$.
    Dilated,
    /// The raw claims' committed $b$ under the $b$ weights, opened at $r$.
    B,
    /// The first layer's error terms, opened at $r$.
    Inner,
    /// The second layer's error terms, opened at $r$.
    Outer,
}

impl Derived {
    pub(crate) const ALL: [Derived; 5] = [
        Derived::A,
        Derived::Dilated,
        Derived::B,
        Derived::Inner,
        Derived::Outer,
    ];

    /// The point the split opens this polynomial at.
    pub(crate) fn point<F: Field>(self, r: F, z: F) -> F {
        match self {
            Derived::Dilated => r * z,
            _ => r,
        }
    }
}

/// How the claims fall into groups: claim `i` is slot `i % GROUP` of group
/// `i / GROUP`.
#[derive(Clone, Copy, Debug)]
pub(crate) struct Layout {
    claims: usize,
}

impl Layout {
    /// # Panics
    ///
    /// Panics unless the claims fill more than one group: with one, the
    /// second layer has no error terms, so its commitment is the identity,
    /// which the transcript refuses. The claim count is fixed by the
    /// protocol on each curve, so this is a programming error rather than
    /// a malformed proof.
    pub(crate) fn new(claims: usize) -> Self {
        assert!(claims > GROUP, "the fold needs at least two groups");
        Layout { claims }
    }

    pub(crate) fn groups(&self) -> usize {
        self.claims.div_ceil(GROUP)
    }

    /// The claims of `group`, by index.
    pub(crate) fn members(&self, group: usize) -> core::ops::Range<usize> {
        group * GROUP..((group + 1) * GROUP).min(self.claims)
    }

    /// The first layer's error terms in order: $(g, i, j)$ over the
    /// off-diagonal slots of each group.
    pub(crate) fn inner(&self) -> impl Iterator<Item = (usize, usize, usize)> + '_ {
        (0..self.groups())
            .flat_map(move |g| off_diagonal(self.members(g).len()).map(move |(i, j)| (g, i, j)))
    }

    /// The second layer's error terms in order: $(g, h)$ over the
    /// off-diagonal pairs of groups.
    pub(crate) fn outer(&self) -> impl Iterator<Item = (usize, usize)> {
        off_diagonal(self.groups())
    }
}

/// The pairs $(i, j)$ with $i \ne j$ below `n`, row by row.
fn off_diagonal(n: usize) -> impl Iterator<Item = (usize, usize)> {
    (0..n).flat_map(move |i| (0..n).filter(move |&j| j != i).map(move |j| (i, j)))
}

/// The fold's challenges, each layer's squeezed after its error commitment.
#[derive(Clone, Copy, Debug)]
pub(crate) struct Weights<F> {
    pub mu: F,
    pub nu: F,
    pub mu_prime: F,
    pub nu_prime: F,
}

impl<F: Field> Weights<F> {
    /// Claim `i`'s weight in $A$: $\mu'^g \mu^s$ for its group $g$ and slot
    /// $s$.
    pub(crate) fn a(&self, i: usize) -> F {
        power(self.mu_prime, i / GROUP) * power(self.mu, i % GROUP)
    }

    /// Claim `i`'s weight in $B$: $\nu'^g \nu^s$.
    pub(crate) fn b(&self, i: usize) -> F {
        power(self.nu_prime, i / GROUP) * power(self.nu, i % GROUP)
    }

    /// $W$ for the first layer: the weight of $e_{ij}$ in group $g$ is
    /// $\mu'^g \nu'^g \mu^i \nu^j$, the group's weight on the diagonal of
    /// the second layer times the pair's in its own.
    pub(crate) fn inner<R: Rank>(&self, layout: &Layout) -> sparse::Polynomial<F, R> {
        mirrored(layout.inner().map(|(g, i, j)| {
            power(self.mu_prime * self.nu_prime, g) * power(self.mu, i) * power(self.nu, j)
        }))
    }

    /// $W$ for the second layer: the weight of the groups' $e_{gh}$ is
    /// $\mu'^g \nu'^h$.
    pub(crate) fn outer<R: Rank>(&self, layout: &Layout) -> sparse::Polynomial<F, R> {
        mirrored(
            layout
                .outer()
                .map(|(g, h)| power(self.mu_prime, g) * power(self.nu_prime, h)),
        )
    }
}

fn power<F: Field>(base: F, exponent: usize) -> F {
    base.pow_u64(exponent as u64)
}

/// The polynomial whose revdot with one holding `weights` as its low
/// coefficients, in order, is their weighted sum.
fn mirrored<F: Field, R: Rank>(weights: impl Iterator<Item = F>) -> sparse::Polynomial<F, R> {
    let n = R::num_coeffs();
    let mut coeffs = vec![F::ZERO; n];
    for (k, weight) in weights.enumerate() {
        coeffs[n - 1 - k] = weight;
    }
    sparse::Polynomial::from_coeffs(coeffs)
}

/// The commitments to the [`Derived`] polynomials, in order, from the
/// claims' `shapes`, each component's `commitment` and the fold's
/// messages: $\[A\]$ sums every claim's $a$ under its $A$ weight, the dilated
/// polynomial the circuit claims' $a$ under their $B$ weights, and the raw
/// polynomial the raw claims' $b$ likewise.
pub(crate) fn commitments<C: Affine, B: Backend, Id: Copy>(
    shapes: &[Shape<Id, C::Scalar>],
    weights: &Weights<C::Scalar>,
    commitment: impl Fn(Id) -> C,
    fold: &Fold<C>,
) -> Vec<C> {
    let derive = |terms: Vec<(C::Scalar, Id)>| -> C {
        let (scalars, points): (Vec<_>, Vec<_>) = terms
            .into_iter()
            .map(|(weight, id)| (weight, commitment(id)))
            .unzip();
        B::msm(&scalars, &points).into()
    };
    let weighted = |side: fn(&Shape<Id, C::Scalar>) -> &[(C::Scalar, Id)],
                    weight: fn(&Weights<C::Scalar>, usize) -> C::Scalar,
                    kinds: fn(Kind) -> bool| {
        shapes
            .iter()
            .enumerate()
            .filter(|(_, shape)| kinds(shape.kind))
            .flat_map(|(i, shape)| {
                side(shape)
                    .iter()
                    .map(move |&(w, id)| (weight(weights, i) * w, id))
            })
            .collect::<Vec<_>>()
    };
    vec![
        derive(weighted(|shape| &shape.a, Weights::a, |_| true)),
        derive(weighted(
            |shape| &shape.a,
            Weights::b,
            |kind| matches!(kind, Kind::Circuit(_)),
        )),
        derive(weighted(
            |shape| &shape.b,
            Weights::b,
            |kind| matches!(kind, Kind::Raw),
        )),
        fold.inner,
        fold.outer,
    ]
}
