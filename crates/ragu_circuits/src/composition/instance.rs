//! Recursion circuits share a unified public input structure. This optimization
//! reduces the number of instance polynomials evaluated within the circuits,
//! thereby lowering the overall constraint count.
//!
//! All staged circuits use the same public inputs, meaning their k(y) evaluations
//! are identical. This is possible because staged circuit commitments are selected
//! after the staging polynomials, which define verifier challenges, so there’s
//! no data dependency between them.
//!
//! Having unused public inputs in some circuits isn't wasteful; the prover simply
//! needs to witness those values. Overall, this approach reduces the constraint
//! cost for `compute_c` (the revdot claim) in proportion to the number of recursion circuits.
use arithmetic::CurveAffine;
use ragu_core::{drivers::Driver, gadgets::Gadget};
use ragu_primitives::{Element, Point, io::Write};

/// Unified instance for all recursion circuits.
pub struct UnifiedRecursionInstance<C: CurveAffine> {
    // All challenges needed by any recursion circuit.
    pub w_challenge: C::Base,
    pub y_challenge: C::Base,
    pub z_challenge: C::Base,
    pub mu_challenge: C::Base,
    pub nu_challenge: C::Base,
    pub x_challenge: C::Base,
    pub alpha_challenge: C::Base,
    pub u_challenge: C::Base,
    pub b_challenge: C::Base,

    // All nested commitments needed by any recursion circuit.
    pub b_staging_nested_commitment: C,
    pub d1_nested_commitment: C,
    pub d2_nested_commitment: C,
    pub d_staging_nested_commitment: C,
    pub e1_nested_commitment: C,
    pub e2_nested_commitment: C,
    pub e_staging_nested_commitment: C,
    pub g1_nested_commitment: C,
    pub g_staging_nested_commitment: C,
    pub p_nested_commitment: C,

    // All computed values inside the circuit.
    pub c: C::Base,
    pub v: C::Base,
}

/// Unified output gadget for all recursion circuits.
#[derive(Gadget, Write)]
pub struct UnifiedRecursionOutput<'dr, D: Driver<'dr>, C: CurveAffine<Base = D::F>> {
    // All challenges needed by any recursion circuit.
    #[ragu(gadget)]
    pub w_challenge: Element<'dr, D>,
    #[ragu(gadget)]
    pub y_challenge: Element<'dr, D>,
    #[ragu(gadget)]
    pub z_challenge: Element<'dr, D>,
    #[ragu(gadget)]
    pub mu_challenge: Element<'dr, D>,
    #[ragu(gadget)]
    pub nu_challenge: Element<'dr, D>,
    #[ragu(gadget)]
    pub x_challenge: Element<'dr, D>,
    #[ragu(gadget)]
    pub alpha_challenge: Element<'dr, D>,
    #[ragu(gadget)]
    pub u_challenge: Element<'dr, D>,
    #[ragu(gadget)]
    pub b_challenge: Element<'dr, D>,

    // All nested commitments needed by any recursion circuit.
    #[ragu(gadget)]
    pub b_staging_nested_commitment: Point<'dr, D, C>,
    #[ragu(gadget)]
    pub d1_nested_commitment: Point<'dr, D, C>,
    #[ragu(gadget)]
    pub d2_nested_commitment: Point<'dr, D, C>,
    #[ragu(gadget)]
    pub d_staging_nested_commitment: Point<'dr, D, C>,
    #[ragu(gadget)]
    pub e1_nested_commitment: Point<'dr, D, C>,
    #[ragu(gadget)]
    pub e2_nested_commitment: Point<'dr, D, C>,
    #[ragu(gadget)]
    pub e_staging_nested_commitment: Point<'dr, D, C>,
    #[ragu(gadget)]
    pub g1_nested_commitment: Point<'dr, D, C>,
    #[ragu(gadget)]
    pub g_staging_nested_commitment: Point<'dr, D, C>,
    #[ragu(gadget)]
    pub p_nested_commitment: Point<'dr, D, C>,

    // All computed values inside the circuit.
    #[ragu(gadget)]
    pub c: Element<'dr, D>,
    #[ragu(gadget)]
    pub v: Element<'dr, D>,
}
