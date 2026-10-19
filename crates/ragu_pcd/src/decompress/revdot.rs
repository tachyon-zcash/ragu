//! The revdot reduction's verifier as a gadget: the fold's weights, the
//! public parts of the folded claims and the split identity over circuit
//! elements, leaving the opening claims for the batch.
//!
//! This is the [`compress::revdot`](crate::compress::revdot) verifier over
//! [`Element`]s. The challenges and the prover's scalar messages arrive
//! allocated, the registry restrictions as wires the decider will check,
//! and the identity $\sum_i \rho^i a_i(r) b_i(r) = r^{n-1} p(1/r) + r^n
//! q(r)$ is enforced rather than compared. What the native verifier
//! derives by multi-scalar multiplication, the commitments the openings
//! are of, is not this gadget's concern: it leaves opening claims by
//! polynomial index, as the native verifier does.

use alloc::vec::Vec;

use ragu_circuits::{
    polynomials::{Rank, txz},
    registry::CircuitIndex,
};
use ragu_core::{Result, drivers::Driver};
use ragu_primitives::Element;

use super::{Powers, consecutive_powers};
use crate::compress::revdot::{
    OpeningClaim,
    claims::Kind,
    fold::{Derived, GROUP, Layout, Weights},
};

/// The prover's scalar messages of the reduction on one curve, allocated:
/// what [`Reduction`](crate::compress::revdot::Reduction) carries besides
/// its commitments.
pub(crate) struct Messages<'dr, D: Driver<'dr>> {
    /// The first layer's weighted error terms, $\varepsilon$.
    pub inner_epsilon: Element<'dr, D>,
    /// The second layer's.
    pub outer_epsilon: Element<'dr, D>,
    /// Each [`Derived`] polynomial's claimed opening at its point, in
    /// order.
    pub openings: Vec<Element<'dr, D>>,
    /// The claimed $p(1/r)$.
    pub p_at_inverse_r: Element<'dr, D>,
    /// The claimed $q(r)$.
    pub q_at_r: Element<'dr, D>,
}

/// The verifier's challenges the reduction on one curve uses: $z$ from the
/// statement, the fold's weights, $\rho$ and $r$.
pub(crate) struct Challenges<'dr, D: Driver<'dr>> {
    pub z: Element<'dr, D>,
    pub weights: Weights<Element<'dr, D>>,
    pub rho: Element<'dr, D>,
    pub r: Element<'dr, D>,
}

/// A wire binding's public data: the coefficient degrees it pins and the
/// value expected at each, as [`Masked`](crate::compress::revdot::claims::Masked)
/// holds them.
pub(crate) struct Binding<'dr, D: Driver<'dr>> {
    pub degrees: Vec<usize>,
    pub expected: Vec<Element<'dr, D>>,
}

impl<'dr, D: Driver<'dr>> Binding<'dr, D> {
    /// $E(r) = \sum_j e_j r^{d_j}$.
    fn expected_at(&self, dr: &mut D, powers: &Powers<'dr, D>) -> Result<Element<'dr, D>> {
        let mut terms = Vec::with_capacity(self.degrees.len());
        for (&degree, expected) in self.degrees.iter().zip(&self.expected) {
            let power = powers.pow(dr, degree)?;
            terms.push(expected.mul(dr, &power)?);
        }
        Ok(Element::sum(dr, &terms))
    }

    /// $M(r) = \sum_j \sigma^j r^{N - 1 - d_j}$, with `sigma` holding the
    /// powers of $\sigma$.
    fn mask_at<R: Rank>(
        &self,
        dr: &mut D,
        powers: &Powers<'dr, D>,
        sigma: &[Element<'dr, D>],
    ) -> Result<Element<'dr, D>> {
        let mut terms = Vec::with_capacity(self.degrees.len());
        for (j, &degree) in self.degrees.iter().enumerate() {
            let power = powers.pow(dr, R::num_coeffs() - 1 - degree)?;
            terms.push(sigma[j].mul(dr, &power)?);
        }
        Ok(Element::sum(dr, &terms))
    }
}

/// The public parts of the claims on one curve: what the native verifier
/// evaluates itself.
pub(crate) struct Public<'dr, D: Driver<'dr>> {
    /// Each claim's kind, in claim order.
    pub kinds: Vec<Kind>,
    /// Each claim's target $k(y)$, in claim order.
    pub targets: Vec<Element<'dr, D>>,
    /// The wiring restriction at $(r, y)$ of each circuit the kinds name:
    /// $m(\omega_c, r, y)$.
    pub restrictions: Vec<(CircuitIndex, Element<'dr, D>)>,
    /// The wire bindings, in the order the masked kinds index them.
    pub bindings: Vec<Binding<'dr, D>>,
    /// The challenge weighting the bindings' wires.
    pub sigma: Element<'dr, D>,
}

impl<'dr, D: Driver<'dr>> Public<'dr, D> {
    /// The restriction of `circuit`.
    ///
    /// # Panics
    ///
    /// Panics if the circuit's restriction was not supplied: the kinds and
    /// the restrictions both come from the verifier's own code.
    fn restriction(&self, circuit: CircuitIndex) -> &Element<'dr, D> {
        &self
            .restrictions
            .iter()
            .find(|(listed, _)| *listed == circuit)
            .expect("every circuit the claims name has its restriction")
            .1
    }
}

/// The fold's per-claim weights as elements over `layout`, and the powers
/// of the challenges they are built from.
struct Folded<'dr, D: Driver<'dr>> {
    /// Claim `i`'s weight in $A$.
    a: Vec<Element<'dr, D>>,
    /// Claim `i`'s weight in $B$.
    b: Vec<Element<'dr, D>>,
    mu: Vec<Element<'dr, D>>,
    nu: Vec<Element<'dr, D>>,
    mu_prime: Vec<Element<'dr, D>>,
    nu_prime: Vec<Element<'dr, D>>,
}

impl<'dr, D: Driver<'dr>> Folded<'dr, D> {
    /// The weights [`Weights`] defines, over the claims `layout` groups.
    fn new(dr: &mut D, weights: &Weights<Element<'dr, D>>, layout: &Layout) -> Result<Self> {
        let groups = layout.groups();
        let mu = consecutive_powers(dr, &weights.mu, GROUP)?;
        let nu = consecutive_powers(dr, &weights.nu, GROUP)?;
        let mu_prime = consecutive_powers(dr, &weights.mu_prime, groups)?;
        let nu_prime = consecutive_powers(dr, &weights.nu_prime, groups)?;
        let claims = (0..groups).flat_map(|g| layout.members(g));
        let (mut a, mut b) = (Vec::new(), Vec::new());
        for i in claims {
            a.push(mu_prime[i / GROUP].mul(dr, &mu[i % GROUP])?);
            b.push(nu_prime[i / GROUP].mul(dr, &nu[i % GROUP])?);
        }
        Ok(Folded {
            a,
            b,
            mu,
            nu,
            mu_prime,
            nu_prime,
        })
    }

    /// Each layer's $W(r)$, formed as $r^{N - K}$ times the Horner sum of
    /// the $K$ weights at $r$, since the mirrored polynomial holds weight
    /// $k$ at degree $N - 1 - k$: the first layer's, then the second's.
    fn at_r<R: Rank>(
        &self,
        dr: &mut D,
        weights: &Weights<Element<'dr, D>>,
        layout: &Layout,
        r: &Element<'dr, D>,
        powers: &Powers<'dr, D>,
    ) -> Result<(Element<'dr, D>, Element<'dr, D>)> {
        let both_primes = weights.mu_prime.mul(dr, &weights.nu_prime)?;
        let both_primes = consecutive_powers(dr, &both_primes, layout.groups())?;
        let mut inner = Vec::new();
        for (g, i, j) in layout.inner() {
            let pair = self.mu[i].mul(dr, &self.nu[j])?;
            inner.push(both_primes[g].mul(dr, &pair)?);
        }
        let mut outer = Vec::new();
        for (g, h) in layout.outer() {
            outer.push(self.mu_prime[g].mul(dr, &self.nu_prime[h])?);
        }
        let mirrored = |dr: &mut D, weights: Vec<Element<'dr, D>>| -> Result<Element<'dr, D>> {
            let shift = powers.pow(dr, R::num_coeffs() - weights.len())?;
            Element::fold(dr, &weights, r)?.mul(dr, &shift)
        };
        Ok((mirrored(dr, inner)?, mirrored(dr, outer)?))
    }
}

/// What the weights phase leaves for the public phase: each layer's
/// $W(r)$, $t(r, z)$ and $1/r$.
pub(crate) struct AtR<'dr, D: Driver<'dr>> {
    pub inner_at_r: Element<'dr, D>,
    pub outer_at_r: Element<'dr, D>,
    pub tz_at_r: Element<'dr, D>,
    pub inverse_r: Element<'dr, D>,
}

/// The weights phase of the reduction: each layer's $W(r)$ from the
/// fold's weights, $t(r, z)$, and $1/r$, over `claims` claims.
pub(crate) fn weights<'dr, D: Driver<'dr>, R: Rank>(
    dr: &mut D,
    claims: usize,
    challenges: &Challenges<'dr, D>,
) -> Result<AtR<'dr, D>> {
    let layout = Layout::new(claims);
    let r = &challenges.r;
    let powers = Powers::new(dr, r, R::RANK + 1)?;
    let r_invertible = r.enforce_invertible(dr)?;
    let z_invertible = challenges.z.enforce_invertible(dr)?;
    let tz_at_r = dr.routine(
        txz::Evaluate::<R>::new(),
        (r_invertible.clone(), z_invertible),
    )?;
    let folded = Folded::new(dr, &challenges.weights, &layout)?;
    let (inner_at_r, outer_at_r) =
        folded.at_r::<R>(dr, &challenges.weights, &layout, r, &powers)?;
    Ok(AtR {
        inner_at_r,
        outer_at_r,
        tz_at_r,
        inverse_r: r_invertible.into_inverse().into_inner(),
    })
}

/// A wire binding at the reduction's challenges: its expected value
/// $E(r)$ and its mask $M(r)$.
pub(crate) struct BindingAt<'dr, D: Driver<'dr>> {
    pub expected: Element<'dr, D>,
    pub mask: Element<'dr, D>,
}

/// The bindings phase of the reduction: each binding's expected value and
/// mask at $r$, the wires weighted by the powers of `sigma`.
pub(crate) fn bindings_at<'dr, D: Driver<'dr>, R: Rank>(
    dr: &mut D,
    bindings: &[Binding<'dr, D>],
    sigma: &Element<'dr, D>,
    r: &Element<'dr, D>,
) -> Result<Vec<BindingAt<'dr, D>>> {
    let powers = Powers::new(dr, r, R::RANK + 1)?;
    let wires = bindings
        .iter()
        .map(|binding| binding.degrees.len())
        .max()
        .unwrap_or(0);
    let sigma = consecutive_powers(dr, sigma, wires)?;
    bindings
        .iter()
        .map(|binding| {
            Ok(BindingAt {
                expected: binding.expected_at(dr, &powers)?,
                mask: binding.mask_at::<R>(dr, &powers, &sigma)?,
            })
        })
        .collect()
}

/// The public phase of the reduction: the folded claim's public parts and
/// target from the weights and the bindings, the split identity enforced,
/// and the folded target $p(0)$ must take returned.
///
/// # Panics
///
/// Panics unless `public` holds one kind and one target per claim,
/// `bindings_at` one entry per binding, and `messages` one opening per
/// derived polynomial: the shapes are fixed by the protocol and the
/// messages' shape is checked before allocation.
pub(crate) fn public<'dr, D: Driver<'dr>, R: Rank>(
    dr: &mut D,
    public: &Public<'dr, D>,
    challenges: &Challenges<'dr, D>,
    messages: &Messages<'dr, D>,
    at_r: &AtR<'dr, D>,
    bindings_at: &[BindingAt<'dr, D>],
) -> Result<Element<'dr, D>> {
    let n = R::num_coeffs();
    let claims = public.kinds.len();
    assert_eq!(public.targets.len(), claims, "one target per claim");
    assert_eq!(
        bindings_at.len(),
        public.bindings.len(),
        "one evaluation per binding"
    );
    assert_eq!(
        messages.openings.len(),
        Derived::ALL.len(),
        "one opening per derived polynomial"
    );
    let layout = Layout::new(claims);
    let r = &challenges.r;
    let powers = Powers::new(dr, r, R::RANK + 1)?;
    let folded = Folded::new(dr, &challenges.weights, &layout)?;

    // The public parts of the folded claim's a and b, and its target.
    let (mut a_terms, mut b_terms, mut k_terms) = (Vec::new(), Vec::new(), Vec::new());
    for (i, &kind) in public.kinds.iter().enumerate() {
        let (a_i, b_i) = (&folded.a[i], &folded.b[i]);
        let a_i_b_i = a_i.mul(dr, b_i)?;
        k_terms.push(a_i_b_i.mul(dr, &public.targets[i])?);
        match kind {
            Kind::Raw => {}
            Kind::Circuit(circuit) => {
                let b = public.restriction(circuit).add(dr, &at_r.tz_at_r);
                b_terms.push(b_i.mul(dr, &b)?);
            }
            Kind::Bonding(circuit) => {
                b_terms.push(b_i.mul(dr, public.restriction(circuit))?);
            }
            Kind::Masked(m) => {
                let at = &bindings_at[m];
                a_terms.push(a_i.mul(dr, &at.expected)?.negate(dr));
                b_terms.push(b_i.mul(dr, &at.mask)?);
            }
        }
    }
    let a_public = Element::sum(dr, &a_terms);
    let b_public = Element::sum(dr, &b_terms);
    let target = Element::sum(dr, &k_terms);

    // The three folded claims at r, each as (a, b, k).
    let opened = |which: Derived| &messages.openings[which as usize];
    let epsilons = messages.inner_epsilon.add(dr, &messages.outer_epsilon);
    let evaluated = [
        (
            opened(Derived::A).add(dr, &a_public),
            opened(Derived::B)
                .add(dr, opened(Derived::Dilated))
                .add(dr, &b_public),
            target.add(dr, &epsilons),
        ),
        (
            opened(Derived::Inner).clone(),
            at_r.inner_at_r.clone(),
            messages.inner_epsilon.clone(),
        ),
        (
            opened(Derived::Outer).clone(),
            at_r.outer_at_r.clone(),
            messages.outer_epsilon.clone(),
        ),
    ];

    // \sum_i \rho^i a_i(r) b_i(r) against the split, with the first claim
    // weighted lowest, and the target p(0) must take.
    let mut products = Vec::with_capacity(evaluated.len());
    let mut targets = Vec::with_capacity(evaluated.len());
    for (a, b, k) in evaluated.iter().rev() {
        products.push(a.mul(dr, b)?);
        targets.push(k.clone());
    }
    let combined = Element::fold(dr, &products, &challenges.rho)?;
    let target = Element::fold(dr, &targets, &challenges.rho)?;
    let r_to_n_minus_1 = powers.pow(dr, n - 1)?;
    let r_to_n = powers.pow(dr, n)?;
    let p_term = r_to_n_minus_1.mul(dr, &messages.p_at_inverse_r)?;
    let q_term = r_to_n.mul(dr, &messages.q_at_r)?;
    let split = p_term.add(dr, &q_term);
    combined.sub(dr, &split).enforce_zero(dr)?;
    Ok(target)
}

/// The opening claims the reduction leaves for the batch, as the native
/// verifier lists them: each [`Derived`] polynomial at its point, $p$ at
/// $1/r$, $q$ at $r$, and $p$ at $0$, where it must equal `target`.
pub(crate) fn openings<'dr, D: Driver<'dr>>(
    dr: &mut D,
    challenges: &Challenges<'dr, D>,
    messages: &Messages<'dr, D>,
    inverse_r: &Element<'dr, D>,
    target: Element<'dr, D>,
) -> Result<Vec<OpeningClaim<Element<'dr, D>>>> {
    let r = &challenges.r;
    let dilated = r.mul(dr, &challenges.z)?;
    let mut openings = Vec::with_capacity(Derived::ALL.len() + 3);
    for (poly, (derived, value)) in Derived::ALL.iter().zip(&messages.openings).enumerate() {
        let point = match derived {
            Derived::Dilated => dilated.clone(),
            _ => r.clone(),
        };
        openings.push(OpeningClaim {
            poly,
            point,
            value: value.clone(),
        });
    }
    let (p, q) = (Derived::ALL.len(), Derived::ALL.len() + 1);
    openings.push(OpeningClaim {
        poly: p,
        point: inverse_r.clone(),
        value: messages.p_at_inverse_r.clone(),
    });
    openings.push(OpeningClaim {
        poly: q,
        point: r.clone(),
        value: messages.q_at_r.clone(),
    });
    openings.push(OpeningClaim {
        poly: p,
        point: Element::zero(dr),
        value: target,
    });
    Ok(openings)
}

/// Enforces the reduction on one curve and returns the opening claims it
/// leaves for the batch: the weights, bindings and public phases and the
/// openings, as one circuit.
pub(crate) fn verify<'dr, D: Driver<'dr>, R: Rank>(
    dr: &mut D,
    public_parts: &Public<'dr, D>,
    challenges: &Challenges<'dr, D>,
    messages: &Messages<'dr, D>,
) -> Result<Vec<OpeningClaim<Element<'dr, D>>>> {
    let at_r = weights::<_, R>(dr, public_parts.kinds.len(), challenges)?;
    let bound = bindings_at::<_, R>(
        dr,
        &public_parts.bindings,
        &public_parts.sigma,
        &challenges.r,
    )?;
    let target = public::<_, R>(dr, public_parts, challenges, messages, &at_r, &bound)?;
    openings(dr, challenges, messages, &at_r.inverse_r, target)
}

#[cfg(test)]
#[path = "../../tests/decompress_revdot.rs"]
mod tests;
