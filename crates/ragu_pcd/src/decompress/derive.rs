//! The commitments the compressed verifier derives, as endoscalar chains
//! over the other curve's points: the fold's $\[A\]$, dilated and raw
//! polynomials, the batch's $\[H\]$, and the IPA's final check.
//!
//! Every challenge that multiplies a point here is one the compression
//! squeezed as an endoscalar, so each weighted sum is a Horner chain of
//! [`group_scale`](Endoscalar::group_scale) steps, as the fuse's
//! endoscaling steps form their sums. The claims' points come from the
//! same [`build`](crate::internal::native::claims::build) the decider and
//! the compressed verifier enumerate the claims through, run over the
//! components' commitments. The IPA's $u_j^{-1} L_j$ comes as a witness
//! point that $u_j$ scales back to $L_j$, and the final check's three
//! full-width scalars, $v$, $c$ and $c b z$, scale their points by a
//! signed-digit chain over witness bits, which the circuit over the scalar
//! field binds to the scalars it computes.

use alloc::vec::Vec;
use core::iter::once;

use ragu_circuits::registry::CircuitIndex;
use ragu_core::{
    Coeff, Error, Result,
    drivers::{Driver, DriverValue},
    maybe::Maybe,
};
use ragu_primitives::{Boolean, Element, Endoscalar, GadgetExt, NonzeroBank, Point};
use udon::{
    curve::{EndomorphismAffine as Affine, Projective},
    field::Field,
};

use crate::{
    compress::revdot::{
        claims::Kind,
        fold::{Layout, Weights},
        native_position, nested_position,
    },
    internal::{
        claims::Source,
        native::{self, claims::Processor as NativeProcessor},
        nested::{self, claims::Processor as NestedProcessor},
    },
};

/// A claim's points: its $a$, a raw claim's $b$, and its kind.
pub(crate) struct Claim<'dr, D: Driver<'dr>, C: Affine<Base = D::F>> {
    pub kind: Kind,
    pub a: Point<'dr, D, C>,
    pub b: Option<Point<'dr, D, C>>,
}

/// $\sum_i e^{n-1-i} P_i$ over the present points of `points`, the first
/// present point weighted highest, as the Horner chain
/// $\text{acc} = e \cdot \text{acc} + P_i$ that scales alone past an
/// absent point. `None` if no point is present.
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
/// components, a bonding claim Horner-folds its groups' sums under $z$.
/// The processor's methods cannot fail, so the first error waits in
/// `error` and stops the rest.
struct Deriver<'a, 'dr, D: Driver<'dr>, C: Affine<Base = D::F>> {
    dr: &'a mut D,
    bank: &'a mut NonzeroBank<'dr, D>,
    z: &'a Endoscalar<'dr, D>,
    claims: Vec<Claim<'dr, D, C>>,
    error: Option<Error>,
}

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
        groups: impl Iterator<Item = impl Iterator<Item = Point<'dr, D, C>>>,
    ) -> Result<()> {
        let mut sums = Vec::new();
        for group in groups {
            sums.push(Some(sum(self.dr, group, self.bank)?));
        }
        let a = horner(self.dr, sums, self.z, self.bank)?
            .ok_or_else(|| Error::InvalidWitness("a bonding claim has a group".into()));
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

impl<'dr, D: Driver<'dr>, C: Affine<Base = D::F>> NativeProcessor<Point<'dr, D, C>, CircuitIndex>
    for Deriver<'_, 'dr, D, C>
{
    fn raw_claim(&mut self, a: Point<'dr, D, C>, b: Point<'dr, D, C>) {
        self.push(Kind::Raw, Ok(a), Some(b));
    }

    fn circuit_claim(&mut self, circuit_id: CircuitIndex, rx: Point<'dr, D, C>) {
        self.circuit(circuit_id, once(rx));
    }

    fn internal_circuit_claim(
        &mut self,
        id: native::InternalCircuitIndex,
        rxs: impl Iterator<Item = Point<'dr, D, C>>,
    ) {
        self.circuit(id.circuit_index(), rxs);
    }

    fn grouped_bonding_claim(
        &mut self,
        id: native::InternalCircuitIndex,
        groups: impl Iterator<Item = impl Iterator<Item = Point<'dr, D, C>>>,
    ) -> Result<()> {
        self.bonding(id.circuit_index(), groups)
    }
}

impl<'dr, D: Driver<'dr>, C: Affine<Base = D::F>> NestedProcessor<Point<'dr, D, C>>
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
        self.circuit(id.circuit_index(), rxs);
    }

    fn grouped_bonding_claim(
        &mut self,
        id: nested::InternalCircuitIndex,
        groups: impl Iterator<Item = impl Iterator<Item = Point<'dr, D, C>>>,
    ) -> Result<()> {
        self.bonding(id.circuit_index(), groups)
    }
}

/// A [`Source`] over one curve's commitments, in the instance's order.
struct Commitments<'p, 'dr, D: Driver<'dr>, C: Affine<Base = D::F>> {
    points: &'p [Point<'dr, D, C>],
    circuit_id: Option<CircuitIndex>,
}

impl<'dr, D: Driver<'dr>, C: Affine<Base = D::F>> Commitments<'_, 'dr, D, C> {
    fn point(&self, position: usize) -> Point<'dr, D, C> {
        self.points[position].clone()
    }
}

impl<'dr, D: Driver<'dr>, C: Affine<Base = D::F>> Source for Commitments<'_, 'dr, D, C> {
    type RxComponent = native::RxComponent;
    type Rx = Point<'dr, D, C>;
    type AppCircuitId = CircuitIndex;

    fn rx(&self, component: native::RxComponent) -> impl Iterator<Item = Self::Rx> {
        once(self.point(native_position(component)))
    }

    fn app_circuits(&self) -> impl Iterator<Item = CircuitIndex> {
        self.circuit_id.into_iter()
    }
}

/// The nested counterpart of [`Commitments`].
struct NestedCommitments<'p, 'dr, D: Driver<'dr>, C: Affine<Base = D::F>> {
    points: &'p [Point<'dr, D, C>],
}

impl<'dr, D: Driver<'dr>, C: Affine<Base = D::F>> Source for NestedCommitments<'_, 'dr, D, C> {
    type RxComponent = nested::RxComponent;
    type Rx = Point<'dr, D, C>;
    type AppCircuitId = ();

    fn rx(&self, component: nested::RxComponent) -> impl Iterator<Item = Self::Rx> {
        once(self.points[nested_position(component)].clone())
    }

    fn app_circuits(&self) -> impl Iterator<Item = ()> {
        core::iter::empty()
    }
}

/// The native claims' points over `commitments`, the native components'
/// in the instance's order, for the application circuit `circuit_id`, then
/// the wire bindings over the stage polynomials `masked` names, in the
/// compressed verifier's order.
pub(crate) fn native_claims<'dr, D: Driver<'dr>, C: Affine<Base = D::F>>(
    dr: &mut D,
    commitments: &[Point<'dr, D, C>],
    circuit_id: CircuitIndex,
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
        circuit_id: Some(circuit_id),
    };
    native::claims::build(&source, &mut deriver)?;
    deriver.finish(masked.map(|component| source.point(native_position(component))))
}

/// The nested claims' points, as [`native_claims`] lists them.
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
    nested::claims::build(&source, &mut deriver)?;
    deriver.finish(masked.map(|component| commitments[nested_position(component)].clone()))
}

/// $\sum_i w_i P_i$ over the present points, claim `i` weighted
/// $\text{outer}^{g} \text{inner}^{s}$ for its group $g$ and slot $s$, as
/// [`Weights`] weights the claims: each group's chain under `inner`, then
/// the groups' under `outer`, both run from the last so that the first
/// claim's weight is one.
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
/// capacity, so that $\sum_{i < n} (2 b_i - 1) 2^i = k$ there. The circuit
/// over that field binds $B$'s bits to $k$ by that linear relation; here
/// they are witnesses.
pub(crate) struct Digits<'dr, D: Driver<'dr>> {
    bits: Vec<Boolean<'dr, D>>,
}

impl<'dr, D: Driver<'dr>> Digits<'dr, D> {
    /// The digits of `scalar`, a value of the field `S`.
    pub(crate) fn alloc<S: Field>(dr: &mut D, scalar: DriverValue<D, S>) -> Result<Self> {
        let n = S::CAPACITY as usize + 1;
        let bits = scalar.map(Self::bits);
        (0..n)
            .map(|i| Boolean::alloc(dr, &mut (), bits.as_ref().map(|bits| bits[i])))
            .collect::<Result<Vec<_>>>()
            .map(|bits| Digits { bits })
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
    fn bits<S: Field>(scalar: S) -> Vec<bool> {
        let n = S::CAPACITY as usize + 1;
        let two = S::ONE.double();
        let b =
            (scalar + two.pow_u64(n as u64) - S::ONE) * two.invert().expect("two is invertible");
        b.to_le_bits().as_ref()[..n].to_vec()
    }
}

/// $k P$ for the full-width scalar `digits` represent: the signed-digit
/// chain $\text{acc} = 2 \text{acc} \pm P$ from the top digit down. The
/// chain starts from the fixed point `offset`, independent of $P$, so
/// that no partial sum is $\pm P$, which the incomplete additions cannot
/// take, and ends by removing the offset's $2^{n-1}$ multiple.
pub(crate) fn scale<'dr, D: Driver<'dr>, C: Affine<Base = D::F>>(
    dr: &mut D,
    point: &Point<'dr, D, C>,
    digits: &Digits<'dr, D>,
    offset: C,
    bank: &mut NonzeroBank<'dr, D>,
) -> Result<Point<'dr, D, C>> {
    let n = digits.bits.len();
    let mut bits = digits.bits.iter().rev();
    let top = bits
        .next()
        .ok_or_else(|| Error::InvalidWitness("a scalar has a digit".into()))?;
    let negate = top.not(dr);
    let term = point.conditional_negate(dr, &negate)?;
    let start = Point::constant(dr, offset)?;
    let mut acc = start.add_incomplete(dr, &term, bank)?;
    for bit in bits {
        let negate = bit.not(dr);
        let term = point.conditional_negate(dr, &negate)?;
        acc = acc.double_and_add_incomplete(dr, &term, bank)?;
    }
    let doubled = C::Scalar::ONE.double().pow_u64((n - 1) as u64);
    let shift = Point::constant(dr, (offset * doubled).to_affine())?.negate(dr);
    acc.add_incomplete(dr, &shift, bank)
}

/// The fixed points of the IPA's final check: the generators $G_0$ and $U$
/// the parameters fix, and the point the signed-digit chains start from,
/// independent of every point they scale.
#[derive(Clone, Copy)]
pub(crate) struct Fixed<C> {
    pub g_0: C,
    pub u: C,
    pub offset: C,
}

/// The IPA's points on one curve: the prover's $\[S\]$, its rounds' $L_j$
/// and $R_j$, the witness points $u_j^{-1} L_j$, and $G'$. The circuit
/// binds each $u_j^{-1} L_j$ to its $L_j$; $G'$ it does not bind yet, see
/// the module's integration notes.
pub(crate) struct Opening<'dr, D: Driver<'dr>, C: Affine<Base = D::F>> {
    pub s_commitment: Point<'dr, D, C>,
    pub rounds: Vec<(Point<'dr, D, C>, Point<'dr, D, C>)>,
    pub inverse_scaled: Vec<Point<'dr, D, C>>,
    pub g_prime: Point<'dr, D, C>,
}

/// The final check's full-width scalars as digits: $v$, $c$ and $c b z$.
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
    let right = scale(dr, &g_0, &scalars.v, fixed.offset, bank)?;
    let scaled_g_prime = scale(dr, &opening.g_prime, &scalars.c, fixed.offset, bank)?;
    let right = right.add_incomplete(dr, &scaled_g_prime, bank)?;
    let scaled_u = scale(dr, &u_point, &scalars.cbz, fixed.offset, bank)?;
    let right = right.add_incomplete(dr, &scaled_u, bank)?;
    left.enforce_equal(dr, &right)
}

#[cfg(test)]
#[path = "../../tests/decompress_derive.rs"]
mod tests;
