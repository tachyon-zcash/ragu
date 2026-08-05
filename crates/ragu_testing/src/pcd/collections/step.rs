//! The four steps of the collections application: singleton seeds and
//! handle-binding fuses. A child's header carries its output's handle, and the
//! parent re-witnesses the polynomial and enforces the handle it gets back
//! equal to the child's header wires. Multisets ([`SeedSet`], [`MergeSets`])
//! are monic root polynomials merged by multiplication; sequences
//! ([`SeedSequence`], [`ConcatSequences`]) are coefficient-list polynomials
//! with a monic sentinel, concatenated by shifted addition.

#![allow(clippy::type_complexity)]

use core::{array, marker::PhantomData};

use ff::{Field, PrimeField};
use ragu_arithmetic::Cycle;
use ragu_circuits::polynomials::{Rank, sparse};
use ragu_core::{
    Result,
    drivers::{Driver, DriverValue},
    gadgets::{Bound, Kind},
    maybe::Maybe,
};
use ragu_pcd::{
    HANDLE_WIRES, PolyHandle,
    header::{Header, Suffix},
    step::{Encoded, Index, Step, StepCtx},
};
use ragu_primitives::{
    Boolean, Element, GadgetExt,
    allocator::{Allocator, Standard},
    multipack,
    vec::{CollectFixed, ConstLen, FixedVec, Len},
};

/// A sequence's header is its handle, then its length. The wider of the two
/// headers, so it is what [`HEADER_SIZE`](super::HEADER_SIZE) is sized from.
pub const SEQ_HEADER: usize = HANDLE_WIRES + 1;

/// A handle's wires, which is all of it a step can see: what it writes. The
/// framework offers no accessor.
fn handle_wires<'dr, D: Driver<'dr>, C: Cycle<CircuitField = D::F>>(
    dr: &mut D,
    handle: &PolyHandle<'dr, D, C>,
) -> Result<[Element<'dr, D>; HANDLE_WIRES]> {
    let mut wires = Vec::new();
    handle.write(dr, &mut wires)?;
    Ok(wires
        .try_into()
        .unwrap_or_else(|_| unreachable!("a handle writes HANDLE_WIRES wires")))
}

/// Data carried by a [`SetHeader`]: the set's handle and its polynomial as
/// unstructured PCD data (the circuit never sees the polynomial).
pub struct SetData<F: Field, R: Rank> {
    pub handle: [F; HANDLE_WIRES],
    pub polynomial: sparse::Polynomial<F, R>,
}

impl<F: Field, R: Rank> Clone for SetData<F, R> {
    fn clone(&self) -> Self {
        Self {
            handle: self.handle,
            polynomial: self.polynomial.clone(),
        }
    }
}

impl<F: Field, R: Rank> SetData<F, R> {
    /// Assembles the carried value from a handle's wires and the polynomial.
    fn from_handle<'dr, D: Driver<'dr, F = F>>(
        wires: [Element<'dr, D>; HANDLE_WIRES],
        polynomial: DriverValue<D, sparse::Polynomial<F, R>>,
    ) -> DriverValue<D, Self> {
        let handle: [_; HANDLE_WIRES] = array::from_fn(|i| wires[i].value().map(|v| *v));
        polynomial.map(move |polynomial| SetData {
            handle: handle.map(Maybe::take),
            polynomial,
        })
    }
}

/// Header carrying a set's handle, and nothing else.
pub struct SetHeader<R>(PhantomData<R>);

impl<F: Field, R: Rank> Header<F> for SetHeader<R> {
    const SUFFIX: Suffix = Suffix::new(0);
    type Data = SetData<F, R>;
    type Output = Kind![F; FixedVec<Element<'_, _>, ConstLen<HANDLE_WIRES>>];

    fn encode<'dr, D: Driver<'dr, F = F>, A: Allocator<'dr, D>>(
        dr: &mut D,
        allocator: &mut A,
        witness: DriverValue<D, Self::Data>,
    ) -> Result<Bound<'dr, D, Self::Output>> {
        ConstLen::<HANDLE_WIRES>::range()
            .map(|i| Element::alloc(dr, allocator, witness.as_ref().map(|d| d.handle[i])))
            .try_collect_fixed()
    }
}

/// Witness for [`SeedSet`]: the one-member set as a polynomial.
pub struct SeedSetWitness<C: Cycle, R: Rank> {
    pub polynomial: sparse::Polynomial<C::CircuitField, R>,
}

/// A leaf establishing a one-member set: witnesses its committed polynomial
/// and outputs the handle in the header.
pub struct SeedSet<C, R> {
    _marker: PhantomData<(C, R)>,
}

impl<C, R> SeedSet<C, R> {
    pub fn new() -> Self {
        Self {
            _marker: PhantomData,
        }
    }
}

impl<C, R> Default for SeedSet<C, R> {
    fn default() -> Self {
        Self::new()
    }
}

impl<C: Cycle, R: Rank> Step<C> for SeedSet<C, R> {
    const INDEX: Index = Index::new(0);
    type Witness<'source> = SeedSetWitness<C, R>;
    type Aux<'source> = ();
    type Left = ();
    type Right = ();
    type Output = SetHeader<R>;

    fn witness<'dr, 'source: 'dr, D: Driver<'dr, F = C::CircuitField>, const HEADER_SIZE: usize>(
        &self,
        ctx: &mut StepCtx<'_, 'dr, D, C>,
        witness: DriverValue<D, Self::Witness<'source>>,
        _left: DriverValue<D, ()>,
        _right: DriverValue<D, ()>,
    ) -> Result<(
        (
            Encoded<'dr, D, Self::Left, HEADER_SIZE>,
            Encoded<'dr, D, Self::Right, HEADER_SIZE>,
            Encoded<'dr, D, Self::Output, HEADER_SIZE>,
        ),
        DriverValue<D, <Self::Output as Header<C::CircuitField>>::Data>,
        DriverValue<D, Self::Aux<'source>>,
    )>
    where
        Self: 'dr,
    {
        let polynomial = witness.map(|w| w.polynomial);
        let handle = ctx.witness_polynomial(polynomial.as_ref().map(|p| p.clone()))?;

        let wires = handle_wires(ctx.dr, &handle)?;
        let output_data = SetData::from_handle(wires.clone(), polynomial);
        let header: FixedVec<_, ConstLen<HANDLE_WIRES>> = wires.into_iter().collect_fixed()?;

        Ok((
            (
                Encoded::from_gadget(()),
                Encoded::from_gadget(()),
                Encoded::from_gadget(header),
            ),
            output_data,
            D::unit(),
        ))
    }
}

/// Witness for the [`MergeSets`] fuse: the two contributing sets and the
/// claimed merged set.
pub struct MergeSetsWitness<C: Cycle, R: Rank> {
    pub a: sparse::Polynomial<C::CircuitField, R>,
    pub b: sparse::Polynomial<C::CircuitField, R>,
    pub product: sparse::Polynomial<C::CircuitField, R>,
}

/// The merging fuse: binds its witnessed inputs to the children's handles,
/// proves `c(z) = a(z)·b(z)` at a challenge derived from all three handles,
/// and outputs the merged set's handle alone.
pub struct MergeSets<C, R> {
    _marker: PhantomData<(C, R)>,
}

impl<C, R> MergeSets<C, R> {
    pub fn new() -> Self {
        Self {
            _marker: PhantomData,
        }
    }
}

impl<C, R> Default for MergeSets<C, R> {
    fn default() -> Self {
        Self::new()
    }
}

impl<C: Cycle, R: Rank> Step<C> for MergeSets<C, R> {
    const INDEX: Index = Index::new(2);
    type Witness<'source> = MergeSetsWitness<C, R>;
    type Aux<'source> = ();
    type Left = SetHeader<R>;
    type Right = SetHeader<R>;
    type Output = SetHeader<R>;

    fn witness<'dr, 'source: 'dr, D: Driver<'dr, F = C::CircuitField>, const HEADER_SIZE: usize>(
        &self,
        ctx: &mut StepCtx<'_, 'dr, D, C>,
        witness: DriverValue<D, Self::Witness<'source>>,
        left: DriverValue<D, SetData<C::CircuitField, R>>,
        right: DriverValue<D, SetData<C::CircuitField, R>>,
    ) -> Result<(
        (
            Encoded<'dr, D, Self::Left, HEADER_SIZE>,
            Encoded<'dr, D, Self::Right, HEADER_SIZE>,
            Encoded<'dr, D, Self::Output, HEADER_SIZE>,
        ),
        DriverValue<D, <Self::Output as Header<C::CircuitField>>::Data>,
        DriverValue<D, Self::Aux<'source>>,
    )>
    where
        Self: 'dr,
    {
        let allocator = &mut Standard::new();

        let left_encoded = Encoded::new(ctx.dr, allocator, left)?;
        let right_encoded = Encoded::new(ctx.dr, allocator, right)?;

        let a_poly = witness.as_ref().map(|w| w.a.clone());
        let b_poly = witness.as_ref().map(|w| w.b.clone());
        let product_polynomial = witness.map(|w| w.product);
        let handles = [
            ctx.witness_polynomial(a_poly)?,
            ctx.witness_polynomial(b_poly)?,
            ctx.witness_polynomial(product_polynomial.as_ref().map(|p| p.clone()))?,
        ];
        // Each contributor's handle is bound to its child's header-carried one
        // before `z` is derived, so `z` cannot be steered by a swap.
        let left_header: &FixedVec<Element<'dr, D>, ConstLen<HANDLE_WIRES>> =
            left_encoded.as_gadget();
        let right_header: &FixedVec<Element<'dr, D>, ConstLen<HANDLE_WIRES>> =
            right_encoded.as_gadget();
        for (handle, header) in [(&handles[0], left_header), (&handles[1], right_header)] {
            for (wire, carried) in handle_wires(ctx.dr, handle)?.iter().zip(header.iter()) {
                wire.enforce_equal(ctx.dr, carried)?;
            }
        }
        let z = ctx.derive_challenge(&handles)?;
        let [a, b, c] = handles;

        let y_a = open_at(ctx, allocator, &a, &z)?;
        let y_b = open_at(ctx, allocator, &b, &z)?;
        let y_c = y_a.mul(ctx.dr, &y_b)?;
        ctx.enforce_poly_query(&c, z, y_c)?;

        let wires = handle_wires(ctx.dr, &c)?;
        let output_data = SetData::from_handle(wires.clone(), product_polynomial);
        let header: FixedVec<_, ConstLen<HANDLE_WIRES>> = wires.into_iter().collect_fixed()?;

        Ok((
            (left_encoded, right_encoded, Encoded::from_gadget(header)),
            output_data,
            D::unit(),
        ))
    }
}

/// Data carried by a [`SeqHeader`]: the sequence's handle and its member list
/// as unstructured PCD data.
pub struct SeqData<F: Field> {
    pub handle: [F; HANDLE_WIRES],
    pub members: Vec<F>,
}

impl<F: Field> Clone for SeqData<F> {
    fn clone(&self) -> Self {
        Self {
            handle: self.handle,
            members: self.members.clone(),
        }
    }
}

impl<F: Field> SeqData<F> {
    /// Assembles the carried value from a handle's wires and the member
    /// list.
    fn from_handle<'dr, D: Driver<'dr, F = F>>(
        wires: [Element<'dr, D>; HANDLE_WIRES],
        members: DriverValue<D, Vec<F>>,
    ) -> DriverValue<D, Self> {
        let handle: [_; HANDLE_WIRES] = array::from_fn(|i| wires[i].value().map(|v| *v));
        members.map(move |members| SeqData {
            handle: handle.map(Maybe::take),
            members,
        })
    }
}

impl<F: PrimeField> SeqData<F> {
    /// The header elements in layout order: the handle, then the length.
    fn header_element(&self, i: usize) -> F {
        match self.handle.get(i) {
            Some(limb) => *limb,
            None => F::from(self.members.len() as u64),
        }
    }
}

/// Header carrying a sequence's handle and its length.
pub struct SeqHeader;

impl<F: PrimeField> Header<F> for SeqHeader {
    const SUFFIX: Suffix = Suffix::new(1);
    type Data = SeqData<F>;
    type Output = Kind![F; FixedVec<Element<'_, _>, ConstLen<SEQ_HEADER>>];

    fn encode<'dr, D: Driver<'dr, F = F>, A: Allocator<'dr, D>>(
        dr: &mut D,
        allocator: &mut A,
        witness: DriverValue<D, Self::Data>,
    ) -> Result<Bound<'dr, D, Self::Output>> {
        ConstLen::<SEQ_HEADER>::range()
            .map(|i| Element::alloc(dr, allocator, witness.as_ref().map(|d| d.header_element(i))))
            .try_collect_fixed()
    }
}

/// Witness for [`SeedSequence`]: the literal member and its committed
/// one-member sequence `[member, 1]`.
pub struct SeedSequenceWitness<C: Cycle, R: Rank> {
    pub sequence: sparse::Polynomial<C::CircuitField, R>,
    pub member: C::CircuitField,
}

/// A leaf establishing a one-member sequence: witnesses the committed
/// polynomial `[member, 1]` and outputs its handle, with the header length
/// pinned to the constant `1`.
pub struct SeedSequence<C, R> {
    _marker: PhantomData<(C, R)>,
}

impl<C, R> SeedSequence<C, R> {
    pub fn new() -> Self {
        Self {
            _marker: PhantomData,
        }
    }
}

impl<C, R> Default for SeedSequence<C, R> {
    fn default() -> Self {
        Self::new()
    }
}

impl<C: Cycle, R: Rank> Step<C> for SeedSequence<C, R> {
    const INDEX: Index = Index::new(1);
    type Witness<'source> = SeedSequenceWitness<C, R>;
    type Aux<'source> = ();
    type Left = ();
    type Right = ();
    type Output = SeqHeader;

    fn witness<'dr, 'source: 'dr, D: Driver<'dr, F = C::CircuitField>, const HEADER_SIZE: usize>(
        &self,
        ctx: &mut StepCtx<'_, 'dr, D, C>,
        witness: DriverValue<D, Self::Witness<'source>>,
        _left: DriverValue<D, ()>,
        _right: DriverValue<D, ()>,
    ) -> Result<(
        (
            Encoded<'dr, D, Self::Left, HEADER_SIZE>,
            Encoded<'dr, D, Self::Right, HEADER_SIZE>,
            Encoded<'dr, D, Self::Output, HEADER_SIZE>,
        ),
        DriverValue<D, <Self::Output as Header<C::CircuitField>>::Data>,
        DriverValue<D, Self::Aux<'source>>,
    )>
    where
        Self: 'dr,
    {
        let member = witness.as_ref().map(|w| w.member);
        let sequence = witness.map(|w| w.sequence);
        let handle = ctx.witness_polynomial(sequence)?;

        let wires = handle_wires(ctx.dr, &handle)?;
        let output_data = SeqData::from_handle(wires.clone(), member.map(|m| vec![m]));
        let header: FixedVec<Element<'dr, D>, ConstLen<SEQ_HEADER>> =
            wires.into_iter().chain([Element::one()]).collect_fixed()?;

        Ok((
            (
                Encoded::from_gadget(()),
                Encoded::from_gadget(()),
                Encoded::from_gadget(header),
            ),
            output_data,
            D::unit(),
        ))
    }
}

/// Witness for the [`ConcatSequences`] fuse: the contributing sequences and
/// the claimed concatenation.
pub struct ConcatSequencesWitness<C: Cycle, R: Rank> {
    pub a: sparse::Polynomial<C::CircuitField, R>,
    pub b: sparse::Polynomial<C::CircuitField, R>,
    pub output: sparse::Polynomial<C::CircuitField, R>,
}

/// The concatenation fuse: binds its witnessed inputs to the children's
/// handles and proves the shifted addition `C = A + X^{ℓa}·(B − 1)` — the
/// `− 1` removes `A`'s sentinel, which `B`'s lowest member overwrites —
/// outputting `C`'s handle with length `ℓc = ℓa + ℓb`.
pub struct ConcatSequences<C, R> {
    _marker: PhantomData<(C, R)>,
}

impl<C, R> ConcatSequences<C, R> {
    pub fn new() -> Self {
        Self {
            _marker: PhantomData,
        }
    }
}

impl<C, R> Default for ConcatSequences<C, R> {
    fn default() -> Self {
        Self::new()
    }
}

impl<C: Cycle, R: Rank> Step<C> for ConcatSequences<C, R> {
    const INDEX: Index = Index::new(3);
    type Witness<'source> = ConcatSequencesWitness<C, R>;
    type Aux<'source> = ();
    type Left = SeqHeader;
    type Right = SeqHeader;
    type Output = SeqHeader;

    fn witness<'dr, 'source: 'dr, D: Driver<'dr, F = C::CircuitField>, const HEADER_SIZE: usize>(
        &self,
        ctx: &mut StepCtx<'_, 'dr, D, C>,
        witness: DriverValue<D, Self::Witness<'source>>,
        left: DriverValue<D, SeqData<C::CircuitField>>,
        right: DriverValue<D, SeqData<C::CircuitField>>,
    ) -> Result<(
        (
            Encoded<'dr, D, Self::Left, HEADER_SIZE>,
            Encoded<'dr, D, Self::Right, HEADER_SIZE>,
            Encoded<'dr, D, Self::Output, HEADER_SIZE>,
        ),
        DriverValue<D, <Self::Output as Header<C::CircuitField>>::Data>,
        DriverValue<D, Self::Aux<'source>>,
    )>
    where
        Self: 'dr,
    {
        let allocator = &mut Standard::new();

        let la = left.as_ref().map(|d| d.members.len());
        let lb = right.as_ref().map(|d| d.members.len());
        let members = D::try_just(|| {
            let mut members = left.as_ref().take().members.clone();
            members.extend(right.as_ref().take().members.iter().copied());
            Ok(members)
        })?;
        let left_encoded = Encoded::new(ctx.dr, allocator, left)?;
        let right_encoded = Encoded::new(ctx.dr, allocator, right)?;

        let a_poly = witness.as_ref().map(|w| w.a.clone());
        let b_poly = witness.as_ref().map(|w| w.b.clone());
        let c_poly = witness.map(|w| w.output);
        let handles = [
            ctx.witness_polynomial(a_poly)?,
            ctx.witness_polynomial(b_poly)?,
            ctx.witness_polynomial(c_poly)?,
        ];
        // Each contributor's handle is bound to its child's header-carried one
        // before `z` is derived, so `z` cannot be steered by a swap.
        {
            let left_header: &FixedVec<Element<'dr, D>, ConstLen<SEQ_HEADER>> =
                left_encoded.as_gadget();
            let right_header: &FixedVec<Element<'dr, D>, ConstLen<SEQ_HEADER>> =
                right_encoded.as_gadget();
            for (handle, header) in [(&handles[0], left_header), (&handles[1], right_header)] {
                for (wire, carried) in handle_wires(ctx.dr, handle)?.iter().zip(header.iter()) {
                    wire.enforce_equal(ctx.dr, carried)?;
                }
            }
        }
        let z = ctx.derive_challenge(&handles)?;
        let [a, b, c] = handles;

        // The offset factor z^{ℓa} must not be a free witness (it could be
        // chosen after z is known): pack ℓa's bits against the header length
        // — which also proves ℓa < num_coeffs — and square-and-multiply.
        let log_coeffs = R::num_coeffs().trailing_zeros() as usize;
        let la_bits = (0..log_coeffs)
            .map(|i| Boolean::alloc(ctx.dr, allocator, la.as_ref().map(|l| (*l >> i) & 1 == 1)))
            .collect::<Result<Vec<_>>>()?;
        {
            let left_header: &FixedVec<Element<'dr, D>, ConstLen<SEQ_HEADER>> =
                left_encoded.as_gadget();
            multipack(ctx.dr, &la_bits)?[0].enforce_equal(ctx.dr, &left_header[HANDLE_WIRES])?;
        }
        let one = Element::one();
        let mut t = Element::one();
        let mut z_pow = z.clone();
        for bit in &la_bits {
            let factor = bit.conditional_select(ctx.dr, &one, &z_pow)?;
            t = t.mul(ctx.dr, &factor)?;
            z_pow = z_pow.square(ctx.dr)?;
        }

        let y_a = open_at(ctx, allocator, &a, &z)?;
        let y_b = open_at(ctx, allocator, &b, &z)?;
        let y_b_less_sentinel = y_b.sub(ctx.dr, &one);
        let shifted = t.mul(ctx.dr, &y_b_less_sentinel)?;
        let y_c = y_a.add(ctx.dr, &shifted);
        ctx.enforce_poly_query(&c, z, y_c)?;

        // ℓc = ℓa + ℓb, packed from fresh bits so the sum is proven below
        // the rank's capacity and cannot wrap.
        let lc_value = la.as_ref().and_then(|l| lb.as_ref().map(|r| *l + *r));
        let lc_bits = (0..log_coeffs)
            .map(|i| {
                let value = lc_value.as_ref().map(|l| (*l >> i) & 1 == 1);
                Boolean::alloc(ctx.dr, allocator, value)
            })
            .collect::<Result<Vec<_>>>()?;
        let lc = multipack(ctx.dr, &lc_bits)?.remove(0);
        {
            let left_header: &FixedVec<Element<'dr, D>, ConstLen<SEQ_HEADER>> =
                left_encoded.as_gadget();
            let right_header: &FixedVec<Element<'dr, D>, ConstLen<SEQ_HEADER>> =
                right_encoded.as_gadget();
            let sum = left_header[HANDLE_WIRES].add(ctx.dr, &right_header[HANDLE_WIRES]);
            lc.enforce_equal(ctx.dr, &sum)?;
        }

        let wires = handle_wires(ctx.dr, &c)?;
        let output_data = SeqData::from_handle(wires.clone(), members);
        let header: FixedVec<Element<'dr, D>, ConstLen<SEQ_HEADER>> =
            wires.into_iter().chain([lc]).collect_fixed()?;

        Ok((
            (left_encoded, right_encoded, Encoded::from_gadget(header)),
            output_data,
            D::unit(),
        ))
    }
}

/// Opens `handle` at `z` via a poly-query.
fn open_at<'dr, D: Driver<'dr, F = C::CircuitField>, C: Cycle>(
    ctx: &mut StepCtx<'_, 'dr, D, C>,
    allocator: &mut impl Allocator<'dr, D>,
    handle: &PolyHandle<'dr, D, C>,
    z: &Element<'dr, D>,
) -> Result<Element<'dr, D>> {
    let y_value = ctx.evaluate(handle, z.value().map(|z| *z))?;
    let y = Element::alloc(ctx.dr, allocator, y_value)?;
    ctx.enforce_poly_query(handle, z.clone(), y.clone())?;
    Ok(y)
}
