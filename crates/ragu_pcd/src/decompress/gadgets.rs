//! The compressed verifier's checks as gadgets over circuit values, one
//! module per part of
//! [`verify_compressed`](crate::Application::verify_compressed): [`revdot`],
//! [`batch`] and [`ipa`] its field identities over [`Element`]s, and
//! [`derive`](mod@derive) the commitments it derives, as endoscalar chains over the
//! other curve's points. The chunk circuits run them over the stages they
//! load ([`execute`](super::circuits::execute)).

use alloc::vec::Vec;

use ragu_core::{Result, drivers::Driver};
use ragu_primitives::Element;

pub(crate) mod revdot {
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
        fn mask_at<K: Rank>(
            &self,
            dr: &mut D,
            powers: &Powers<'dr, D>,
            sigma: &[Element<'dr, D>],
        ) -> Result<Element<'dr, D>> {
            let mut terms = Vec::with_capacity(self.degrees.len());
            for (j, &degree) in self.degrees.iter().enumerate() {
                let power = powers.pow(dr, K::num_coeffs() - 1 - degree)?;
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
        #[cfg(test)]
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
        fn at_r<K: Rank>(
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
                let shift = powers.pow(dr, K::num_coeffs() - weights.len())?;
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
    pub(crate) fn weights<'dr, D: Driver<'dr>, K: Rank>(
        dr: &mut D,
        claims: usize,
        challenges: &Challenges<'dr, D>,
    ) -> Result<AtR<'dr, D>> {
        let layout = Layout::new(claims);
        let r = &challenges.r;
        let powers = Powers::new(dr, r, K::RANK + 1)?;
        let r_invertible = r.enforce_invertible(dr)?;
        let z_invertible = challenges.z.enforce_invertible(dr)?;
        let tz_at_r = dr.routine(
            txz::Evaluate::<K>::new(),
            (r_invertible.clone(), z_invertible),
        )?;
        let folded = Folded::new(dr, &challenges.weights, &layout)?;
        let (inner_at_r, outer_at_r) =
            folded.at_r::<K>(dr, &challenges.weights, &layout, r, &powers)?;
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
    pub(crate) fn bindings_at<'dr, D: Driver<'dr>, K: Rank>(
        dr: &mut D,
        bindings: &[Binding<'dr, D>],
        sigma: &Element<'dr, D>,
        r: &Element<'dr, D>,
    ) -> Result<Vec<BindingAt<'dr, D>>> {
        let powers = Powers::new(dr, r, K::RANK + 1)?;
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
                    mask: binding.mask_at::<K>(dr, &powers, &sigma)?,
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
    pub(crate) fn public<'dr, D: Driver<'dr>, K: Rank>(
        dr: &mut D,
        public: &Public<'dr, D>,
        challenges: &Challenges<'dr, D>,
        messages: &Messages<'dr, D>,
        at_r: &AtR<'dr, D>,
        bindings_at: &[BindingAt<'dr, D>],
    ) -> Result<Element<'dr, D>> {
        let n = K::num_coeffs();
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
        let powers = Powers::new(dr, r, K::RANK + 1)?;
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
    #[cfg(test)]
    pub(crate) fn verify<'dr, D: Driver<'dr>, K: Rank>(
        dr: &mut D,
        public_parts: &Public<'dr, D>,
        challenges: &Challenges<'dr, D>,
        messages: &Messages<'dr, D>,
    ) -> Result<Vec<OpeningClaim<Element<'dr, D>>>> {
        let at_r = weights::<_, K>(dr, public_parts.kinds.len(), challenges)?;
        let bound = bindings_at::<_, K>(
            dr,
            &public_parts.bindings,
            &public_parts.sigma,
            &challenges.r,
        )?;
        let target = public::<_, K>(dr, public_parts, challenges, messages, &at_r, &bound)?;
        openings(dr, challenges, messages, &at_r.inverse_r, target)
    }
}

pub(crate) mod batch {
    //! The batch's verifier as a gadget: $f(u)$ from the quotient relation,
    //! the batched value $v$ and the weights of the batched commitment, over
    //! circuit elements.
    //!
    //! This is the [`compress::batch`](crate::compress::batch) verifier over
    //! [`Element`]s, given the opening claims the reduction left and the
    //! instance's, the prover's values at $u$ and the challenges. The claims'
    //! points and values are elements, their polynomial indices constants: the
    //! batched commitment is the weighted sum of $\[f\]$ and the polynomials'
    //! commitments under the returned weights, which a circuit over the other
    //! field forms. The native verifier rejects two claims on one polynomial
    //! and point with different values; the protocol's claim lists never
    //! repeat a pair, so the gadget takes the lists as they are.

    use alloc::vec::Vec;
    use core::iter::once;

    use ragu_core::{Result, drivers::Driver};
    use ragu_primitives::Element;

    use super::consecutive_powers;
    use crate::compress::revdot::OpeningClaim;

    /// The prover's scalar messages of the batch on one curve: each
    /// polynomial's value at $u$, in the polynomials' order.
    pub(crate) struct Messages<'dr, D: Driver<'dr>> {
        pub evaluations: Vec<Element<'dr, D>>,
    }

    /// The verifier's challenges of the batch: $\alpha$ weighting the
    /// quotients, $u$ the point, $\beta$ weighting the polynomials.
    pub(crate) struct Challenges<'dr, D: Driver<'dr>> {
        pub alpha: Element<'dr, D>,
        pub u: Element<'dr, D>,
        pub beta: Element<'dr, D>,
    }

    /// The one opening claim the batch leaves for the IPA, less its
    /// commitment: the point $u$, the value $v$, and the weights of $\[f\]$ and
    /// the polynomials' commitments in the batched commitment, $\[f\]$'s first
    /// and highest.
    pub(crate) struct Batched<'dr, D: Driver<'dr>> {
        pub point: Element<'dr, D>,
        pub value: Element<'dr, D>,
        /// The chunks form $\[H\]$ by a Horner chain under $\beta$'s
        /// endoscalar instead; the tests read the weights.
        #[cfg_attr(not(test), allow(dead_code))]
        pub weights: Vec<Element<'dr, D>>,
    }

    /// The batch on one curve over `claims`, whose polynomial indices lie
    /// below `polys`, the number of committed polynomials. Witness generation
    /// fails if $u$ lands on a claim's point, which the native verifier
    /// rejects too.
    ///
    /// # Panics
    ///
    /// Panics unless `messages` holds one value per polynomial, which is
    /// checked before allocation, or if a claim names a polynomial beyond
    /// `polys`.
    pub(crate) fn verify<'dr, D: Driver<'dr>>(
        dr: &mut D,
        claims: &[OpeningClaim<Element<'dr, D>>],
        polys: usize,
        challenges: &Challenges<'dr, D>,
        messages: &Messages<'dr, D>,
    ) -> Result<Batched<'dr, D>> {
        assert_eq!(
            messages.evaluations.len(),
            polys,
            "one value per batched polynomial"
        );
        let u = &challenges.u;

        // f(u) from the quotient relation, the first claim weighted highest.
        let mut quotients = Vec::with_capacity(claims.len());
        for claim in claims {
            let evaluation = &messages.evaluations[claim.poly];
            let numerator = evaluation.sub(dr, &claim.value);
            let denominator = u.sub(dr, &claim.point).invert(dr)?;
            quotients.push(numerator.mul(dr, &denominator)?);
        }
        let f_at_u = Element::fold(dr, &quotients, &challenges.alpha)?;

        // v: f and every polynomial under beta, f weighted highest; and the
        // same weights for the commitments.
        let value = Element::fold(
            dr,
            once(&f_at_u).chain(&messages.evaluations),
            &challenges.beta,
        )?;
        let mut weights = consecutive_powers(dr, &challenges.beta, polys + 1)?;
        weights.reverse();

        Ok(Batched {
            point: u.clone(),
            value,
            weights,
        })
    }
}

pub(crate) mod ipa {
    //! The IPA verifier's scalar side as a gadget: the round challenges'
    //! inverses, $b = s(x)$ and the scalar each point of the final check
    //! carries, over circuit elements.
    //!
    //! This is the scalar part of [`verify_proof`](crate::ipa::verify_proof).
    //! The batched claim's point $x$ and value $v$, the prover's $c$ and the
    //! challenges $\xi$, $z$ and $u_j$ arrive as elements, and the gadget
    //! returns the scalars of the final check's multi-scalar multiplication.
    //! Its points, the prover's $\[S\]$, $L_j$ and $R_j$, the generators and
    //! $G' = \langle s, G \rangle$, live on the other curve, so the circuit
    //! over their base field forms the multi-scalar multiplication and checks
    //! that it is the identity.
    //!
    //! With $k$ rounds, $s(X) = \prod\_{i < k} (1 + u\_{k-1-i} X^{2^i})$: $G'$
    //! is the commitment to $s$ over the same generators and $b = s(x)$.
    //! [`s_at`] evaluates $s$ wherever a circuit needs it, in $2k - 1$ gates,
    //! which is how the polynomial a decompression step commits for $s$ is
    //! checked against the round challenges (see the module's *The step
    //! binding*).

    use alloc::vec::Vec;

    use ragu_core::{Result, drivers::Driver};
    use ragu_primitives::Element;

    use super::Powers;

    /// The prover's scalar message of the IPA: $c$, the final folded
    /// coefficient.
    pub(crate) struct Messages<'dr, D: Driver<'dr>> {
        pub c: Element<'dr, D>,
    }

    /// The verifier's challenges of the IPA: $\xi$ folding $\[S\]$ in, $z$
    /// weighting $U$, and the round challenges $u_j$ in order.
    pub(crate) struct Challenges<'dr, D: Driver<'dr>> {
        pub xi: Element<'dr, D>,
        pub z: Element<'dr, D>,
        pub rounds: Vec<Element<'dr, D>>,
    }

    /// The scalars of the final check: with the batched commitment weighted
    /// by one, the sum of every point under its scalar must be the identity.
    /// The chunks read $c b z$ alone, the other side scaling the rest's points
    /// by digits; the tests read every scalar.
    #[cfg_attr(not(test), allow(dead_code))]
    pub(crate) struct Scalars<'dr, D: Driver<'dr>> {
        /// The scalar of $G_0$: $-v$.
        pub g_0: Element<'dr, D>,
        /// The scalar of $\[S\]$: $\xi$.
        pub s_commitment: Element<'dr, D>,
        /// Each round's scalars of $L_j$ and $R_j$: $u_j^{-1}$ and $u_j$.
        pub rounds: Vec<(Element<'dr, D>, Element<'dr, D>)>,
        /// The scalar of $U$: $-c b z$.
        pub u: Element<'dr, D>,
        /// The scalar of $G'$: $-c$.
        pub g_prime: Element<'dr, D>,
    }

    /// $s(\text{point}) = \prod\_{i < k} (1 + u\_{k-1-i} \cdot \text{point}^{2^i})$
    /// over the `rounds`' challenges $u_j$.
    pub(crate) fn s_at<'dr, D: Driver<'dr>>(
        dr: &mut D,
        rounds: &[Element<'dr, D>],
        point: &Element<'dr, D>,
    ) -> Result<Element<'dr, D>> {
        let powers = Powers::new(dr, point, rounds.len() as u32)?;
        let mut product: Option<Element<'dr, D>> = None;
        for (u_j, power) in rounds.iter().rev().zip(powers.squares()) {
            let factor = u_j.mul(dr, power)?.add(dr, &Element::one());
            product = Some(match product {
                None => factor,
                Some(acc) => acc.mul(dr, &factor)?,
            });
        }
        Ok(product.unwrap_or_else(Element::one))
    }

    /// The scalars of the final check for the claim that the batched
    /// polynomial takes `value` at `point`. Witness generation fails on a zero
    /// round challenge, which the native verifier rejects too.
    pub(crate) fn verify<'dr, D: Driver<'dr>>(
        dr: &mut D,
        point: &Element<'dr, D>,
        value: &Element<'dr, D>,
        challenges: &Challenges<'dr, D>,
        messages: &Messages<'dr, D>,
    ) -> Result<Scalars<'dr, D>> {
        let mut rounds = Vec::with_capacity(challenges.rounds.len());
        for u_j in &challenges.rounds {
            rounds.push((u_j.invert(dr)?, u_j.clone()));
        }
        let b = s_at(dr, &challenges.rounds, point)?;
        let neg_c = messages.c.negate(dr);
        let u = neg_c.mul(dr, &b)?.mul(dr, &challenges.z)?;
        Ok(Scalars {
            g_0: value.negate(dr),
            s_commitment: challenges.xi.clone(),
            rounds,
            u,
            g_prime: neg_c,
        })
    }
}

pub(crate) mod derive {
    //! The commitments the compressed verifier derives, as endoscalar chains
    //! over the other curve's points: the fold's $\[A\]$, dilated and raw
    //! polynomials, the batch's $\[H\]$, and the IPA's final check.
    //!
    //! Every challenge that multiplies a point here is one the compression
    //! squeezed as an endoscalar, so each weighted sum is a Horner chain of
    //! [`group_scale`](ragu_primitives::Endoscalar::group_scale) steps, as the fuse's
    //! endoscaling steps form their sums. The claims' points come from the
    //! same [`build`](crate::internal::native::claims::build) the decider and
    //! the compressed verifier enumerate the claims through, run over the
    //! components' commitments. The IPA's $u_j^{-1} L_j$ comes as a witness
    //! point that $u_j$ scales back to $L_j$, and the final check's three
    //! full-width scalars, $v$, $c$ and $c b z$, scale their points by a
    //! signed-digit chain over witness bits, which the circuit over the scalar
    //! field binds to the scalars it computes and holds as a digits stage the
    //! chain's circuit recomputes (see [`stages`](crate::decompress::stages)).

    use alloc::vec::Vec;
    #[cfg(test)]
    use core::iter::once;
    use core::ops::Range;

    #[cfg(test)]
    use ragu_circuits::registry::CircuitIndex;
    use ragu_core::{
        Coeff, Error, Result,
        drivers::{Driver, DriverValue},
        maybe::Maybe,
    };
    use ragu_primitives::{Boolean, Element, NonzeroBank, Point};
    #[cfg(test)]
    use ragu_primitives::{Endoscalar, GadgetExt};
    use udon::{
        curve::{EndomorphismAffine as Affine, Projective},
        field::Field,
    };

    #[cfg(test)]
    use crate::{
        compress::revdot::{
            claims::Kind,
            fold::{Layout, Weights},
            native_position, nested_position,
        },
        internal::{
            native::{self, claims::Processor as NativeProcessor},
            nested::{self, claims::Processor as NestedProcessor},
            revdot::Source,
        },
        profile::Standard,
    };

    /// A claim's points: its $a$, a raw claim's $b$, and its kind.
    #[cfg(test)]
    pub(crate) struct Claim<'dr, D: Driver<'dr>, C: Affine<Base = D::F>> {
        pub kind: Kind,
        pub a: Point<'dr, D, C>,
        pub b: Option<Point<'dr, D, C>>,
    }

    /// $\sum_i e^{n-1-i} P_i$ over the present points of `points`, the first
    /// present point weighted highest, as the Horner chain
    /// $\text{acc} = e \cdot \text{acc} + P_i$ that scales alone past an
    /// absent point. `None` if no point is present.
    #[cfg(test)]
    fn horner<'dr, D: Driver<'dr>, C: Affine<Base = D::F>>(
        dr: &mut D,
        points: impl IntoIterator<Item = Option<Point<'dr, D, C>>>,
        e: &Endoscalar<'dr, D>,
        bank: &mut NonzeroBank<'dr, D>,
    ) -> Result<Option<Point<'dr, D, C>>> {
        let mut acc: Option<Point<'dr, D, C>> = None;
        for point in points {
            acc = match (acc, point) {
                (None, point) => point,
                (Some(acc), None) => Some(e.group_scale(dr, &acc)?),
                (Some(acc), Some(point)) => {
                    Some(e.group_scale(dr, &acc)?.add_incomplete(dr, &point, bank)?)
                }
            };
        }
        Ok(acc)
    }

    /// The sum of `points`, which must not be empty.
    #[cfg(test)]
    fn sum<'dr, D: Driver<'dr>, C: Affine<Base = D::F>>(
        dr: &mut D,
        mut points: impl Iterator<Item = Point<'dr, D, C>>,
        bank: &mut NonzeroBank<'dr, D>,
    ) -> Result<Point<'dr, D, C>> {
        let first = points
            .next()
            .ok_or_else(|| Error::InvalidWitness("a claim sums at least one component".into()))?;
        points.try_fold(first, |acc, point| acc.add_incomplete(dr, &point, bank))
    }

    /// The processor that builds the claims' points, the counterpart of the
    /// compressed verifier's shaper over points: a circuit claim sums its
    /// components, a bonding claim Horner-folds its components under $z$.
    /// The processor's methods cannot fail, so the first error waits in
    /// `error` and stops the rest.
    #[cfg(test)]
    struct Deriver<'a, 'dr, D: Driver<'dr>, C: Affine<Base = D::F>> {
        dr: &'a mut D,
        bank: &'a mut NonzeroBank<'dr, D>,
        z: &'a Endoscalar<'dr, D>,
        claims: Vec<Claim<'dr, D, C>>,
        error: Option<Error>,
    }

    #[cfg(test)]
    impl<'a, 'dr, D: Driver<'dr>, C: Affine<Base = D::F>> Deriver<'a, 'dr, D, C> {
        fn push(&mut self, kind: Kind, a: Result<Point<'dr, D, C>>, b: Option<Point<'dr, D, C>>) {
            if self.error.is_some() {
                return;
            }
            match a {
                Ok(a) => self.claims.push(Claim { kind, a, b }),
                Err(error) => self.error = Some(error),
            }
        }

        fn circuit(&mut self, circuit: CircuitIndex, rxs: impl Iterator<Item = Point<'dr, D, C>>) {
            let a = sum(self.dr, rxs, self.bank);
            self.push(Kind::Circuit(circuit), a, None);
        }

        fn bonding(
            &mut self,
            circuit: CircuitIndex,
            rxs: impl Iterator<Item = Point<'dr, D, C>>,
        ) -> Result<()> {
            let rxs: Vec<_> = rxs.map(Some).collect();
            let a = horner(self.dr, rxs, self.z, self.bank)?
                .ok_or_else(|| Error::InvalidWitness("a bonding claim has a component".into()));
            self.push(Kind::Bonding(circuit), a, None);
            Ok(())
        }

        fn finish(
            self,
            masked: impl Iterator<Item = Point<'dr, D, C>>,
        ) -> Result<Vec<Claim<'dr, D, C>>> {
            if let Some(error) = self.error {
                return Err(error);
            }
            let mut claims = self.claims;
            claims.extend(masked.enumerate().map(|(m, poly)| Claim {
                kind: Kind::Masked(m),
                a: poly,
                b: None,
            }));
            Ok(claims)
        }
    }

    #[cfg(test)]
    impl<'dr, D: Driver<'dr>, C: Affine<Base = D::F>>
        NativeProcessor<Standard, Point<'dr, D, C>, CircuitIndex> for Deriver<'_, 'dr, D, C>
    {
        fn raw_claim(&mut self, a: Point<'dr, D, C>, b: Point<'dr, D, C>) {
            self.push(Kind::Raw, Ok(a), Some(b));
        }

        fn circuit_claim(
            &mut self,
            circuit_id: CircuitIndex,
            rxs: impl Iterator<Item = Point<'dr, D, C>>,
        ) {
            self.circuit(circuit_id, rxs);
        }

        fn internal_circuit_claim(
            &mut self,
            id: native::InternalCircuitIndex,
            rxs: impl Iterator<Item = Point<'dr, D, C>>,
        ) {
            self.circuit(id.circuit_index::<Standard>(), rxs);
        }

        fn bonding_claim(
            &mut self,
            id: native::InternalCircuitIndex,
            rxs: impl Iterator<Item = Point<'dr, D, C>>,
        ) -> Result<()> {
            self.bonding(id.circuit_index::<Standard>(), rxs)
        }
    }

    #[cfg(test)]
    impl<'dr, D: Driver<'dr>, C: Affine<Base = D::F>> NestedProcessor<Standard, Point<'dr, D, C>>
        for Deriver<'_, 'dr, D, C>
    {
        fn raw_claim(&mut self, a: Point<'dr, D, C>, b: Point<'dr, D, C>) {
            self.push(Kind::Raw, Ok(a), Some(b));
        }

        fn internal_circuit_claim(
            &mut self,
            id: nested::InternalCircuitIndex,
            rxs: impl Iterator<Item = Point<'dr, D, C>>,
        ) {
            self.circuit(id.circuit_index::<Standard>(), rxs);
        }

        fn bonding_claim(
            &mut self,
            id: nested::InternalCircuitIndex,
            rxs: impl Iterator<Item = Point<'dr, D, C>>,
        ) -> Result<()> {
            self.bonding(id.circuit_index::<Standard>(), rxs)
        }
    }

    /// A [`Source`] over one curve's commitments, in the instance's order.
    #[cfg(test)]
    struct Commitments<'p, 'dr, D: Driver<'dr>, C: Affine<Base = D::F>> {
        points: &'p [Point<'dr, D, C>],
    }

    #[cfg(test)]
    impl<'dr, D: Driver<'dr>, C: Affine<Base = D::F>> Commitments<'_, 'dr, D, C> {
        fn point(&self, position: usize) -> Point<'dr, D, C> {
            self.points[position].clone()
        }
    }

    #[cfg(test)]
    impl<'dr, D: Driver<'dr>, C: Affine<Base = D::F>> Source for Commitments<'_, 'dr, D, C> {
        type RxComponent = native::RxComponent;
        type Rx = Point<'dr, D, C>;
        type AppCircuitId = CircuitIndex;

        fn rx(&self, component: native::RxComponent) -> impl Iterator<Item = Self::Rx> {
            once(self.point(native_position::<Standard>(component)))
        }

        /// A proof folds its own application claim, so its verifier has none.
        fn applications(&self) -> impl Iterator<Item = (CircuitIndex, [Self::Rx; 2])> {
            core::iter::empty()
        }
    }

    /// The nested counterpart of [`Commitments`].
    #[cfg(test)]
    struct NestedCommitments<'p, 'dr, D: Driver<'dr>, C: Affine<Base = D::F>> {
        points: &'p [Point<'dr, D, C>],
    }

    #[cfg(test)]
    impl<'dr, D: Driver<'dr>, C: Affine<Base = D::F>> Source for NestedCommitments<'_, 'dr, D, C> {
        type RxComponent = nested::RxComponent;
        type Rx = Point<'dr, D, C>;
        type AppCircuitId = ();

        fn rx(&self, component: nested::RxComponent) -> impl Iterator<Item = Self::Rx> {
            once(self.points[nested_position::<Standard>(component)].clone())
        }

        fn applications(&self) -> impl Iterator<Item = ((), [Self::Rx; 2])> {
            core::iter::empty()
        }
    }

    /// The native claims' points over `commitments`, the native components'
    /// in the instance's order, then the wire bindings over the stage
    /// polynomials `masked` names, in the compressed verifier's order.
    #[cfg(test)]
    pub(crate) fn native_claims<'dr, D: Driver<'dr>, C: Affine<Base = D::F>>(
        dr: &mut D,
        commitments: &[Point<'dr, D, C>],
        z: &Endoscalar<'dr, D>,
        masked: impl Iterator<Item = native::RxComponent>,
        bank: &mut NonzeroBank<'dr, D>,
    ) -> Result<Vec<Claim<'dr, D, C>>> {
        let mut deriver = Deriver {
            dr,
            bank,
            z,
            claims: Vec::new(),
            error: None,
        };
        let source = Commitments {
            points: commitments,
        };
        native::claims::build::<Standard, _, _>(&source, &mut deriver)?;
        deriver.finish(masked.map(|component| source.point(native_position::<Standard>(component))))
    }

    /// The nested claims' points, as [`native_claims`] lists them.
    #[cfg(test)]
    pub(crate) fn nested_claims<'dr, D: Driver<'dr>, C: Affine<Base = D::F>>(
        dr: &mut D,
        commitments: &[Point<'dr, D, C>],
        z: &Endoscalar<'dr, D>,
        masked: impl Iterator<Item = nested::RxComponent>,
        bank: &mut NonzeroBank<'dr, D>,
    ) -> Result<Vec<Claim<'dr, D, C>>> {
        let mut deriver = Deriver {
            dr,
            bank,
            z,
            claims: Vec::new(),
            error: None,
        };
        let source = NestedCommitments {
            points: commitments,
        };
        nested::claims::build::<Standard, _, _>(&source, &mut deriver)?;
        deriver.finish(
            masked.map(|component| commitments[nested_position::<Standard>(component)].clone()),
        )
    }

    /// $\sum_i w_i P_i$ over the present points, claim `i` weighted
    /// $\text{outer}^{g} \text{inner}^{s}$ for its group $g$ and slot $s$, as
    /// [`Weights`] weights the claims: each group's chain under `inner`, then
    /// the groups' under `outer`, both run from the last so that the first
    /// claim's weight is one.
    #[cfg(test)]
    fn weighted<'dr, D: Driver<'dr>, C: Affine<Base = D::F>>(
        dr: &mut D,
        points: Vec<Option<Point<'dr, D, C>>>,
        inner: &Endoscalar<'dr, D>,
        outer: &Endoscalar<'dr, D>,
        bank: &mut NonzeroBank<'dr, D>,
    ) -> Result<Point<'dr, D, C>> {
        let layout = Layout::new(points.len());
        let mut groups = Vec::with_capacity(layout.groups());
        for g in 0..layout.groups() {
            let members = points[layout.members(g)].iter().rev().cloned();
            groups.push(horner(dr, members, inner, bank)?);
        }
        horner(dr, groups.into_iter().rev(), outer, bank)?
            .ok_or_else(|| Error::InvalidWitness("a derived polynomial has a term".into()))
    }

    /// The fold's derived commitments the split opens, in
    /// [`Derived`](crate::compress::revdot::fold::Derived) order before the
    /// error terms: $\[A\]$ over every claim's $a$ under the $A$ weights, the
    /// dilated polynomial's over the circuit claims' $a$ under the $B$
    /// weights, and the raw polynomial's over the raw claims' $b$ likewise.
    #[cfg(test)]
    pub(crate) fn fold<'dr, D: Driver<'dr>, C: Affine<Base = D::F>>(
        dr: &mut D,
        claims: &[Claim<'dr, D, C>],
        weights: &Weights<Endoscalar<'dr, D>>,
        bank: &mut NonzeroBank<'dr, D>,
    ) -> Result<[Point<'dr, D, C>; 3]> {
        let select = |pick: fn(&Claim<'dr, D, C>) -> Option<Point<'dr, D, C>>| {
            claims.iter().map(pick).collect::<Vec<_>>()
        };
        let a = weighted(
            dr,
            select(|claim| Some(claim.a.clone())),
            &weights.mu,
            &weights.mu_prime,
            bank,
        )?;
        let dilated = weighted(
            dr,
            select(|claim| matches!(claim.kind, Kind::Circuit(_)).then(|| claim.a.clone())),
            &weights.nu,
            &weights.nu_prime,
            bank,
        )?;
        let raw = weighted(
            dr,
            select(|claim| {
                matches!(claim.kind, Kind::Raw)
                    .then(|| claim.b.clone())
                    .flatten()
            }),
            &weights.nu,
            &weights.nu_prime,
            bank,
        )?;
        Ok([a, dilated, raw])
    }

    /// The batched commitment $\[H\]$: $\[f\]$ and the `commitments` under
    /// $\beta$, $\[f\]$ weighted highest, as the batch weights them.
    #[cfg(test)]
    pub(crate) fn batched<'dr, D: Driver<'dr>, C: Affine<Base = D::F>>(
        dr: &mut D,
        f: &Point<'dr, D, C>,
        commitments: &[Point<'dr, D, C>],
        beta: &Endoscalar<'dr, D>,
        bank: &mut NonzeroBank<'dr, D>,
    ) -> Result<Point<'dr, D, C>> {
        horner(
            dr,
            once(f).chain(commitments).map(|point| Some(point.clone())),
            beta,
            bank,
        )?
        .ok_or_else(|| Error::InvalidWitness("the batch has a polynomial".into()))
    }

    /// A full-width scalar $k$ of the other field as signed digits: the bits
    /// $b_i$ of $B = (k + 2^n - 1) / 2$ in that field, $n$ one more than its
    /// capacity, so that $\sum\_{i < n} (2 b_i - 1) 2^i = k$ there. The circuit
    /// over that field binds $B$'s bits to $k$ by that linear relation; here
    /// they are witnesses.
    pub(crate) struct Digits<'dr, D: Driver<'dr>> {
        bits: Vec<Boolean<'dr, D>>,
    }

    /// The digit count of a scalar of the field `S`: one more than its
    /// capacity, so that every scalar is a signed-digit sum
    /// $\sum\_{i < n} (2 b_i - 1) 2^i$ of that many bits.
    pub(crate) fn digit_width<S: Field>() -> usize {
        S::CAPACITY as usize + 1
    }

    impl<'dr, D: Driver<'dr>> Digits<'dr, D> {
        /// The digit count of a scalar of the field `S`: [`digit_width`].
        pub(crate) fn width<S: Field>() -> usize {
            digit_width::<S>()
        }

        /// The digits' bits, in order: $b_i$ for the digit $2 b_i - 1$.
        pub(crate) fn bits(&self) -> &[Boolean<'dr, D>] {
            &self.bits
        }

        /// The digits of `scalar`, a value of the field `S`.
        pub(crate) fn alloc<S: Field>(dr: &mut D, scalar: DriverValue<D, S>) -> Result<Self> {
            Self::alloc_range(dr, scalar, 0..Self::width::<S>())
        }

        /// The digits of `scalar` at the positions `range`, for a scaling cut
        /// across circuits.
        pub(crate) fn alloc_range<S: Field>(
            dr: &mut D,
            scalar: DriverValue<D, S>,
            range: Range<usize>,
        ) -> Result<Self> {
            let bits = scalar.map(Self::bits_of);
            range
                .map(|i| Boolean::alloc(dr, &mut (), bits.as_ref().map(|bits| bits[i])))
                .collect::<Result<Vec<_>>>()
                .map(|bits| Digits { bits })
        }

        /// A flag's digit: its bit, for the digit $2 b - 1$.
        pub(crate) fn of_flag(bit: Boolean<'dr, D>) -> Self {
            Digits {
                bits: alloc::vec![bit],
            }
        }

        /// The number of digits held.
        pub(crate) fn len(&self) -> usize {
            self.bits.len()
        }

        /// Binds the digits of the element `k` of this circuit's own field to it
        /// and keeps none of them: the other side allocates the same bits from
        /// the value and scales by them, so here only the binding matters.
        #[cfg(test)]
        pub(crate) fn bind(dr: &mut D, k: &Element<'dr, D>) -> Result<()> {
            Self::alloc_bound(dr, k).map(|_| ())
        }

        /// The digits of the element `k` of this circuit's own field, bound to
        /// it: $2 B - (2^n - 1) = k$ over the packed bits. The other side
        /// allocates the same bits from the value and scales by them.
        pub(crate) fn alloc_bound(dr: &mut D, k: &Element<'dr, D>) -> Result<Self> {
            let digits = Self::alloc(dr, k.value().map(|k| *k))?;
            let mut power = D::F::ONE;
            let mut packed = Element::zero(dr);
            for bit in &digits.bits {
                packed = packed.add_coeff(dr, &bit.element(), Coeff::Arbitrary(power));
                power = power.double();
            }
            // 2 B - (2^n - 1) - k = 0, with 2^n the power left after the last
            // doubling.
            let shift = power - D::F::ONE;
            packed
                .scale(dr, Coeff::Two)
                .add_coeff(dr, &Element::one(), Coeff::NegativeArbitrary(shift))
                .sub(dr, k)
                .enforce_zero(dr)?;
            Ok(digits)
        }

        /// The bits of $B = (k + 2^n - 1) / 2$ for the scalar $k$.
        pub(crate) fn bits_of<S: Field>(scalar: S) -> Vec<bool> {
            let n = S::CAPACITY as usize + 1;
            let two = S::ONE.double();
            let b = (scalar + two.pow_u64(n as u64) - S::ONE)
                * two.invert().expect("two is invertible");
            b.to_le_bits().as_ref()[..n].to_vec()
        }
    }

    /// The signed-digit chain $\text{acc} = 2 \text{acc} \pm P$ over `digits`
    /// from the top digit down, continuing from `init`, or starting from the
    /// fixed point `offset` plus the top digit's term when there is none. The
    /// offset is independent of $P$, so that no partial sum is $\pm P$, which
    /// the incomplete additions cannot take. A full-width scalar's chain may
    /// be cut across circuits: each part continues from the last part's
    /// accumulator, and [`scale_shift`] ends it.
    pub(crate) fn scale_chain<'dr, D: Driver<'dr>, C: Affine<Base = D::F>>(
        dr: &mut D,
        point: &Point<'dr, D, C>,
        digits: &Digits<'dr, D>,
        init: Option<Point<'dr, D, C>>,
        offset: C,
        bank: &mut NonzeroBank<'dr, D>,
    ) -> Result<Point<'dr, D, C>> {
        let mut bits = digits.bits.iter().rev();
        let mut acc = match init {
            Some(acc) => acc,
            None => {
                let top = bits
                    .next()
                    .ok_or_else(|| Error::InvalidWitness("a scalar has a digit".into()))?;
                let negate = top.not(dr);
                let term = point.conditional_negate(dr, &negate)?;
                Point::constant(dr, offset)?.add_incomplete(dr, &term, bank)?
            }
        };
        for bit in bits {
            let negate = bit.not(dr);
            let term = point.conditional_negate(dr, &negate)?;
            acc = acc.double_and_add_incomplete(dr, &term, bank)?;
        }
        Ok(acc)
    }

    /// The offset accumulated by an `n`-digit signed-digit chain.
    pub(crate) fn scale_offset<C: Affine>(offset: C, n: usize) -> C {
        let doubled = C::Scalar::ONE.double().pow_u64((n - 1) as u64);
        (offset * doubled).to_affine()
    }

    /// Ends a signed-digit chain of `n` digits: removes the offset's $2^{n-1}$
    /// multiple from `acc`.
    pub(crate) fn scale_shift<'dr, D: Driver<'dr>, C: Affine<Base = D::F>>(
        dr: &mut D,
        acc: Point<'dr, D, C>,
        offset: C,
        n: usize,
        bank: &mut NonzeroBank<'dr, D>,
    ) -> Result<Point<'dr, D, C>> {
        let shift = Point::constant(dr, scale_offset(offset, n))?.negate(dr);
        acc.add_incomplete(dr, &shift, bank)
    }

    /// $k P$ for the full-width scalar `digits` represent: the whole
    /// signed-digit chain from `offset`, ended.
    #[cfg(test)]
    pub(crate) fn scale<'dr, D: Driver<'dr>, C: Affine<Base = D::F>>(
        dr: &mut D,
        point: &Point<'dr, D, C>,
        digits: &Digits<'dr, D>,
        offset: C,
        bank: &mut NonzeroBank<'dr, D>,
    ) -> Result<Point<'dr, D, C>> {
        let acc = scale_chain(dr, point, digits, None, offset, bank)?;
        scale_shift(dr, acc, offset, digits.len(), bank)
    }

    /// The fixed points of the IPA's final check: the generators $G_0$ and $U$
    /// the parameters fix, and the point the signed-digit chains start from,
    /// independent of every point they scale.
    #[derive(Clone, Copy)]
    #[cfg(test)]
    pub(crate) struct Fixed<C> {
        pub g_0: C,
        pub u: C,
        pub offset: C,
    }

    /// The IPA's points on one curve: the prover's $\[S\]$, its rounds' $L_j$
    /// and $R_j$, the witness points $u_j^{-1} L_j$, and $G'$. The circuit
    /// binds each $u_j^{-1} L_j$ to its $L_j$; $G'$ it does not bind, which is
    /// the chunk circuits' step binding's to do (see the module's *The step
    /// binding*).
    #[cfg(test)]
    pub(crate) struct Opening<'dr, D: Driver<'dr>, C: Affine<Base = D::F>> {
        pub s_commitment: Point<'dr, D, C>,
        pub rounds: Vec<(Point<'dr, D, C>, Point<'dr, D, C>)>,
        pub inverse_scaled: Vec<Point<'dr, D, C>>,
        pub g_prime: Point<'dr, D, C>,
    }

    /// The final check's full-width scalars as digits: $v$, $c$ and $c b z$.
    #[cfg(test)]
    pub(crate) struct Scalars<'dr, D: Driver<'dr>> {
        pub v: Digits<'dr, D>,
        pub c: Digits<'dr, D>,
        pub cbz: Digits<'dr, D>,
    }

    /// Enforces the IPA's final check for the batched commitment `h` opened at
    /// the batch's point with value $v$: $\[H\] + \xi \[S\] + \sum_j (u_j^{-1}
    /// L_j + u_j R_j) = v G_0 + c G' + c b z U$, with each $u_j^{-1} L_j$ the
    /// witness point $u_j$ scales back to $L_j$, and $G_0$ and $U$ the
    /// generators `fixed` holds.
    #[cfg(test)]
    pub(crate) fn enforce_opening<'dr, D: Driver<'dr>, C: Affine<Base = D::F>>(
        dr: &mut D,
        h: &Point<'dr, D, C>,
        opening: &Opening<'dr, D, C>,
        xi: &Endoscalar<'dr, D>,
        u: &[Endoscalar<'dr, D>],
        scalars: &Scalars<'dr, D>,
        fixed: Fixed<C>,
        bank: &mut NonzeroBank<'dr, D>,
    ) -> Result<()> {
        assert_eq!(opening.rounds.len(), u.len(), "one challenge per round");
        assert_eq!(
            opening.inverse_scaled.len(),
            u.len(),
            "one inverse-scaled point per round"
        );

        let scaled_s = xi.group_scale(dr, &opening.s_commitment)?;
        let mut left = h.add_incomplete(dr, &scaled_s, bank)?;
        for ((l, r), (u_j, scaled)) in opening
            .rounds
            .iter()
            .zip(u.iter().zip(&opening.inverse_scaled))
        {
            u_j.group_scale(dr, scaled)?.enforce_equal(dr, l)?;
            left = left.add_incomplete(dr, scaled, bank)?;
            let scaled_r = u_j.group_scale(dr, r)?;
            left = left.add_incomplete(dr, &scaled_r, bank)?;
        }

        let g_0 = Point::constant(dr, fixed.g_0)?;
        let u_point = Point::constant(dr, fixed.u)?;
        let shifted = |dr: &mut D,
                       point: &Point<'dr, D, C>,
                       digits: &Digits<'dr, D>,
                       multiple: u64,
                       bank: &mut NonzeroBank<'dr, D>| {
            let offset = (fixed.offset * C::Scalar::from(multiple)).to_affine();
            scale_chain(dr, point, digits, None, offset, bank)
        };
        let mut right = shifted(dr, &g_0, &scalars.v, 1, bank)?;
        let scaled_g_prime = shifted(dr, &opening.g_prime, &scalars.c, 2, bank)?;
        right = right.add_incomplete(dr, &scaled_g_prime, bank)?;
        let scaled_u = shifted(dr, &u_point, &scalars.cbz, 4, bank)?;
        right = right.add_incomplete(dr, &scaled_u, bank)?;
        let correction =
            (scale_offset(fixed.offset, scalars.v.len()) * C::Scalar::from(7)).to_affine();
        let correction = Point::constant(dr, correction)?.negate(dr);
        right = right.add_incomplete(dr, &correction, bank)?;
        left.enforce_equal(dr, &right)
    }
}

/// An element's powers $x^{2^i}$, for raising it to constant exponents by
/// square-and-multiply.
pub(crate) struct Powers<'dr, D: Driver<'dr>> {
    squares: Vec<Element<'dr, D>>,
}

impl<'dr, D: Driver<'dr>> Powers<'dr, D> {
    /// The squares of `base` up to $x^{2^{\text{bits} - 1}}$, so that every
    /// exponent below $2^\text{bits}$ can be formed. Costs `bits - 1`
    /// gates.
    pub(crate) fn new(dr: &mut D, base: &Element<'dr, D>, bits: u32) -> Result<Self> {
        let mut squares = Vec::with_capacity(bits as usize);
        let mut current = base.clone();
        for i in 0..bits {
            if i > 0 {
                current = current.square(dr)?;
            }
            squares.push(current.clone());
        }
        Ok(Powers { squares })
    }

    /// $x^{2^i}$ for each $i$ below the prepared bits, in order.
    pub(crate) fn squares(&self) -> &[Element<'dr, D>] {
        &self.squares
    }

    /// $x^e$ for the constant `exponent`: one gate per set bit beyond the
    /// first.
    ///
    /// # Panics
    ///
    /// Panics if the exponent needs more bits than [`new`](Self::new)
    /// prepared.
    pub(crate) fn pow(&self, dr: &mut D, exponent: usize) -> Result<Element<'dr, D>> {
        assert!(
            exponent >> self.squares.len() == 0,
            "exponent {exponent} exceeds the prepared {} bits",
            self.squares.len()
        );
        let mut result: Option<Element<'dr, D>> = None;
        for (i, square) in self.squares.iter().enumerate() {
            if (exponent >> i) & 1 == 1 {
                result = Some(match result {
                    None => square.clone(),
                    Some(acc) => acc.mul(dr, square)?,
                });
            }
        }
        Ok(result.unwrap_or_else(Element::one))
    }
}

/// $1, x, x^2, \ldots, x^{\text{count} - 1}$: `count - 2` gates.
pub(crate) fn consecutive_powers<'dr, D: Driver<'dr>>(
    dr: &mut D,
    base: &Element<'dr, D>,
    count: usize,
) -> Result<Vec<Element<'dr, D>>> {
    let mut powers: Vec<Element<'dr, D>> = Vec::with_capacity(count);
    for i in 0..count {
        let next = match i {
            0 => Element::one(),
            1 => base.clone(),
            _ => powers[i - 1].mul(dr, base)?,
        };
        powers.push(next);
    }
    Ok(powers)
}

#[cfg(test)]
#[path = "../../tests/decompression/gadgets.rs"]
mod tests;
