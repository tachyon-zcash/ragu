//! Preamble stage for native fuse operations.
//!
//! Verifies child proof headers and computes the Ky term.

use alloc::vec::Vec;
use core::marker::PhantomData;

use ragu_arithmetic::Cycle;
use ragu_circuits::{horner::Horner, polynomials::Rank, staging};
use ragu_core::{
    Error, Result,
    drivers::{Driver, DriverValue},
    gadgets::{Bound, Gadget, Kind},
    maybe::Maybe,
};
use ragu_primitives::{
    Boolean, Element, GadgetExt,
    allocator::Allocator,
    consistent::Consistent,
    vec::{CollectFixed, ConstLen, FixedVec, Len},
};

use crate::{
    Proof,
    framework_hooks::HookConfig,
    header::Header,
    internal::native::unified,
    poly_commitment::{self, PolyHandle},
    step::internal::padded,
};

type HeaderVec<'dr, D, const HEADER_SIZE: usize> = FixedVec<Element<'dr, D>, ConstLen<HEADER_SIZE>>;

/// Witness data for a single child proof in the preamble stage.
pub struct ChildWitness<'a, C: Cycle, R: Rank, const HEADER_SIZE: usize> {
    /// Output header for this child proof.
    pub output_header: FixedVec<C::CircuitField, ConstLen<HEADER_SIZE>>,
    /// Reference to the child proof.
    pub proof: &'a Proof<C, R>,
}

/// Witness for the native preamble stage.
///
/// Contains references to the left and right proofs, plus output headers
/// computed outside the circuit.
pub struct Witness<'a, C: Cycle, R: Rank, const HEADER_SIZE: usize> {
    /// Left child proof witness.
    pub left: ChildWitness<'a, C, R, HEADER_SIZE>,
    /// Right child proof witness.
    pub right: ChildWitness<'a, C, R, HEADER_SIZE>,
}

impl<'a, C: Cycle, R: Rank, const HEADER_SIZE: usize> Witness<'a, C, R, HEADER_SIZE> {
    /// Create a witness from child proof references and pre-computed output headers.
    pub fn new(
        left: &'a Proof<C, R>,
        right: &'a Proof<C, R>,
        left_output_header: &[C::CircuitField],
        right_output_header: &[C::CircuitField],
    ) -> Result<Self> {
        Ok(Witness {
            left: ChildWitness {
                output_header: FixedVec::try_from(left_output_header.to_vec())?,
                proof: left,
            },
            right: ChildWitness {
                output_header: FixedVec::try_from(right_output_header.to_vec())?,
                proof: right,
            },
        })
    }
}

/// Headers claimed by a child proof for its own left and right children.
#[derive(Gadget, Consistent)]
pub struct ChildHeaders<'dr, D: Driver<'dr>, const HEADER_SIZE: usize> {
    /// Left child header (grandchild from current perspective).
    #[ragu(gadget)]
    pub left: HeaderVec<'dr, D, HEADER_SIZE>,
    /// Right child header (grandchild from current perspective).
    #[ragu(gadget)]
    pub right: HeaderVec<'dr, D, HEADER_SIZE>,
}

/// Processed inputs from a single child proof in the preamble stage.
#[derive(Gadget, Consistent)]
pub struct ProofInputs<
    'dr,
    D: Driver<'dr>,
    C: Cycle<CircuitField = D::F>,
    const HEADER_SIZE: usize,
    J: HookConfig,
> {
    /// Headers this child proof claimed for its own children.
    #[ragu(gadget)]
    pub children: ChildHeaders<'dr, D, HEADER_SIZE>,
    /// Output header of this child proof.
    #[ragu(gadget)]
    pub output_header: HeaderVec<'dr, D, HEADER_SIZE>,
    /// The child's witnessed polynomials; positions it left unused hold the
    /// canonical padding polynomial.
    #[ragu(gadget)]
    pub witness_polys: FixedVec<PolyHandle<'dr, D, C>, J::PolyWitnesses>,
    #[ragu(gadget)]
    pub circuit_id: Element<'dr, D>,
    #[ragu(gadget)]
    pub unified: unified::Output<'dr, D, C>,
}

impl<'dr, D: Driver<'dr, F = C::CircuitField>, C: Cycle, const HEADER_SIZE: usize, J: HookConfig>
    ProofInputs<'dr, D, C, HEADER_SIZE, J>
{
    /// Compute unified k(y) and unified+bridged k(y) values simultaneously,
    /// sharing computation.
    ///
    /// Returns `(unified_ky, unified_bridge_ky)` where:
    /// - `unified_ky` = k(y) for `(unified, 0)`
    /// - `unified_bridge_ky` = k(y) for `(unified, children.left, children.right, 0)`
    ///
    /// The Horner evaluation order and trailing zero here define the numerical
    /// values that [`ky_values`](super::super::claims::ky_values) must produce
    /// in matching positions.
    pub fn unified_ky_values(
        &self,
        dr: &mut D,
        y: &Element<'dr, D>,
    ) -> Result<(Element<'dr, D>, Element<'dr, D>)> {
        let mut ky = Horner::new(y);
        self.unified.write(dr, &mut ky)?;

        Ok((
            ({
                let mut ky = ky.clone();
                Element::zero(dr).write(dr, &mut ky)?;
                ky.finish_ky(dr)?
            }),
            ({
                self.children.left.write(dr, &mut ky)?;
                self.children.right.write(dr, &mut ky)?;
                Element::zero(dr).write(dr, &mut ky)?;
                ky.finish_ky(dr)?
            }),
        ))
    }

    /// Binds the child's hook wires to its committed application rx. The
    /// adapter writes these same types into the instance, so the layout below
    /// is the layout it wrote.
    pub fn application_ky(&self, dr: &mut D, y: &Element<'dr, D>) -> Result<Element<'dr, D>> {
        let mut ky = Horner::new(y);
        self.children.left.write(dr, &mut ky)?;
        self.children.right.write(dr, &mut ky)?;
        self.output_header.write(dr, &mut ky)?;
        self.witness_polys.write(dr, &mut ky)?;
        ky.finish_ky(dr)
    }

    /// Returns true if this child proof is a trivial proof (output header suffix == 1).
    pub fn is_trivial(
        &self,
        dr: &mut D,
        allocator: &mut impl Allocator<'dr, D>,
    ) -> Result<Boolean<'dr, D>> {
        let suffix = &self.output_header[HEADER_SIZE - 1];
        suffix.is_equal(dr, allocator, &Element::one())
    }
}

impl<'dr, D: Driver<'dr, F = C::CircuitField>, C: Cycle, const HEADER_SIZE: usize, J: HookConfig>
    ProofInputs<'dr, D, C, HEADER_SIZE, J>
{
    /// Allocate ProofInputs from a proof reference and pre-computed output
    /// header; the proof's hook lists are checked against the configured counts.
    pub fn alloc<R: Rank>(
        dr: &mut D,
        proof: DriverValue<D, &Proof<C, R>>,
        output_header: DriverValue<D, &FixedVec<D::F, ConstLen<HEADER_SIZE>>>,
    ) -> Result<Self> {
        let num_polys = J::PolyWitnesses::len();

        // A child proof reaching the fuse has not passed through `verify`, so
        // this is its own boundary. `alloc` has no verdict to return, hence
        // `Err`: a carried artifact whose encoding does not fit its declared
        // size, not a witness the prover authored in-circuit.
        D::try_just(|| {
            if proof.as_ref().take().has_shape(&J::layout()) {
                Ok(())
            } else {
                Err(Error::MalformedEncoding(
                    "proof does not carry exactly the configured hook lists".into(),
                ))
            }
        })?;

        fn alloc_header<'dr, D: Driver<'dr>, const N: usize>(
            dr: &mut D,
            allocator: &mut (),
            data: DriverValue<D, &[D::F]>,
        ) -> Result<FixedVec<Element<'dr, D>, ConstLen<N>>> {
            D::try_just(|| {
                if data.as_ref().take().len() != N {
                    return Err(Error::MalformedEncoding(
                        "Header data length does not match HEADER_SIZE".into(),
                    ));
                }

                Ok(())
            })?;

            (0..N)
                .map(|i| Element::alloc(dr, allocator, data.as_ref().map(|d| d[i])))
                .try_collect_fixed()
        }

        let allocator = &mut ();
        Ok(ProofInputs {
            children: ChildHeaders {
                left: alloc_header(dr, allocator, proof.as_ref().map(|p| p.left_header()))?,
                right: alloc_header(dr, allocator, proof.as_ref().map(|p| p.right_header()))?,
            },
            output_header: alloc_header(dr, allocator, output_header.as_ref().map(|h| &h[..]))?,
            witness_polys: (0..num_polys)
                .map(|i| {
                    PolyHandle::alloc(
                        dr,
                        D::try_just(|| {
                            poly_commitment::handle::<C>(
                                proof.as_ref().take().witness_poly_commitment(i),
                            )
                        })?,
                    )
                })
                .try_collect_fixed()?,
            circuit_id: Element::alloc(
                dr,
                allocator,
                proof.as_ref().map(|p| p.circuit_id().omega_j()),
            )?,
            unified: unified::Output::alloc_from_proof(dr, allocator, proof)?,
        })
    }

    /// Allocate ProofInputs from a proof reference and some unprocessed header
    /// data. Shape as in [`alloc`](Self::alloc).
    pub fn alloc_for_verify<R: Rank, H: Header<C::CircuitField>>(
        dr: &mut D,
        proof: DriverValue<D, &Proof<C, R>>,
        header_data: DriverValue<D, H::Data>,
    ) -> Result<Self> {
        let header_data = D::try_just(|| {
            use ragu_core::drivers::emulator::{Emulator, Wireless};
            let emulator = &mut Emulator::<Wireless<D::MaybeKind, D::F>>::wireless();

            let output = H::encode(emulator, &mut (), header_data)?;
            let output = padded::for_header::<H, HEADER_SIZE, _>(emulator, output)?;

            let mut header_data = Vec::with_capacity(HEADER_SIZE);
            output.write(emulator, &mut header_data)?;

            header_data
                .into_iter()
                .map(|e| *e.value().take())
                .collect_fixed()
        })?;

        Self::alloc(dr, proof, header_data.as_ref())
    }
}

/// Prover-internal output of the native preamble stage.
///
/// This is stage communication data, not part of the circuit's public instance.
/// The verifier never sees these values directly.
#[derive(Gadget, Consistent)]
pub struct Output<
    'dr,
    D: Driver<'dr>,
    C: Cycle<CircuitField = D::F>,
    const HEADER_SIZE: usize,
    J: HookConfig,
> {
    #[ragu(gadget)]
    pub left: ProofInputs<'dr, D, C, HEADER_SIZE, J>,
    #[ragu(gadget)]
    pub right: ProofInputs<'dr, D, C, HEADER_SIZE, J>,
}

impl<'dr, D: Driver<'dr>, C: Cycle<CircuitField = D::F>, const HEADER_SIZE: usize, J: HookConfig>
    Output<'dr, D, C, HEADER_SIZE, J>
{
    /// Returns true if both child proofs are trivial proofs.
    pub fn is_base_case(
        &self,
        dr: &mut D,
        allocator: &mut impl Allocator<'dr, D>,
    ) -> Result<Boolean<'dr, D>> {
        let left_is_trivial = self.left.is_trivial(dr, allocator)?;
        let right_is_trivial = self.right.is_trivial(dr, allocator)?;
        left_is_trivial.and(dr, &right_is_trivial)
    }
}

/// The root of the native stage chain. Per child: three headers, the
/// polynomial region, the circuit id, and the unified wires.
pub struct Stage<C: Cycle, R, const HEADER_SIZE: usize, J: HookConfig> {
    _marker: PhantomData<(C, R, J)>,
}

impl<C: Cycle, R, const HEADER_SIZE: usize, J: HookConfig> Default for Stage<C, R, HEADER_SIZE, J> {
    fn default() -> Self {
        Stage {
            _marker: PhantomData,
        }
    }
}

impl<C: Cycle, R: Rank, const HEADER_SIZE: usize, J: HookConfig> staging::Stage<C::CircuitField, R>
    for Stage<C, R, HEADER_SIZE, J>
{
    type Parent = ();
    type Witness<'source> = &'source Witness<'source, C, R, HEADER_SIZE>;
    type OutputKind = Kind![
        C::CircuitField;
        Output<'_, _, C, HEADER_SIZE, J>
    ];

    fn values() -> usize {
        2 * (3 * HEADER_SIZE + J::layout().poly_query_instance_len() + 1 + unified::NUM_WIRES)
    }

    fn witness<'dr, 'source: 'dr, D: Driver<'dr, F = C::CircuitField>>(
        &self,
        dr: &mut D,
        witness: DriverValue<D, Self::Witness<'source>>,
    ) -> Result<Bound<'dr, D, Self::OutputKind>>
    where
        Self: 'dr,
    {
        let left = ProofInputs::alloc(
            dr,
            witness.as_ref().map(|w| w.left.proof),
            witness.as_ref().map(|w| &w.left.output_header),
        )?;

        let right = ProofInputs::alloc(
            dr,
            witness.as_ref().map(|w| w.right.proof),
            witness.as_ref().map(|w| &w.right.output_header),
        )?;

        Ok(Output { left, right })
    }
}

#[cfg(test)]
mod tests {
    use ragu_pasta::Pasta;

    use super::*;
    use crate::{
        AppHooks,
        internal::tests::{HEADER_SIZE, R, assert_stage_values},
    };

    #[test]
    fn stage_values_matches_wire_count() {
        fn check<const POLYS: usize>() {
            assert_stage_values(&Stage::<Pasta, R, { HEADER_SIZE }, AppHooks<POLYS>>::default());
        }
        check::<0>();
        check::<1>();
        check::<4>();
        check::<8>();
    }
}
