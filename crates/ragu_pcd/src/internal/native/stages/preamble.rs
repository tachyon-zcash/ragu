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
    vec::{CollectFixed, ConstLen, FixedVec},
};

use crate::{Proof, header::Header, internal::native::unified, step::internal::padded};

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
pub struct ProofInputs<'dr, D: Driver<'dr>, C: Cycle<CircuitField = D::F>, const HEADER_SIZE: usize>
{
    /// Headers this child proof claimed for its own children.
    #[ragu(gadget)]
    pub children: ChildHeaders<'dr, D, HEADER_SIZE>,
    /// Output header of this child proof.
    #[ragu(gadget)]
    pub output_header: HeaderVec<'dr, D, HEADER_SIZE>,
    #[ragu(gadget)]
    pub circuit_id: Element<'dr, D>,
    #[ragu(gadget)]
    pub unified: unified::Output<'dr, D, C>,
}

impl<'dr, D: Driver<'dr, F = C::CircuitField>, C: Cycle, const HEADER_SIZE: usize>
    ProofInputs<'dr, D, C, HEADER_SIZE>
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

    /// Compute k(y) for the application circuit instance.
    ///
    /// Returns `application_ky` = k(y) for `(children.left, children.right, output_header)`.
    pub fn application_ky(&self, dr: &mut D, y: &Element<'dr, D>) -> Result<Element<'dr, D>> {
        let mut ky = Horner::new(y);
        self.children.left.write(dr, &mut ky)?;
        self.children.right.write(dr, &mut ky)?;
        self.output_header.write(dr, &mut ky)?;
        ky.finish_ky(dr)
    }
}

impl<'dr, D: Driver<'dr, F = C::CircuitField>, C: Cycle, const HEADER_SIZE: usize>
    ProofInputs<'dr, D, C, HEADER_SIZE>
{
    /// Allocate ProofInputs from a proof reference and pre-computed output header.
    pub fn alloc<R: Rank>(
        dr: &mut D,
        proof: DriverValue<D, &Proof<C, R>>,
        output_header: DriverValue<D, &FixedVec<D::F, ConstLen<HEADER_SIZE>>>,
    ) -> Result<Self> {
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
            circuit_id: Element::alloc(
                dr,
                allocator,
                proof.as_ref().map(|p| p.circuit_id().omega_j()),
            )?,
            unified: unified::Output::alloc_from_proof(dr, allocator, proof)?,
        })
    }

    /// Allocate [`ProofInputs`] reusing core wires from the preamble [`Stage`].
    ///
    /// Only the headers (grandchild headers and output header prefix) are newly
    /// allocated via `allocator`; `circuit_id`, `unified`, and the output
    /// header's last element (suffix) come from `core`. This avoids duplicating
    /// the core allocations done by the stage.
    ///
    /// Pass a pairing allocator (e.g. [`Standard`]) to keep the header
    /// allocation cost at one gate per two wires.
    ///
    /// [`Standard`]: ragu_primitives::allocator::Standard
    pub fn alloc_reusing_core<R: Rank, A: Allocator<'dr, D>>(
        dr: &mut D,
        allocator: &mut A,
        proof: DriverValue<D, &Proof<C, R>>,
        output_header: DriverValue<D, &FixedVec<D::F, ConstLen<HEADER_SIZE>>>,
        core: &CoreInputs<'dr, D, C>,
    ) -> Result<Self> {
        fn alloc_header<'dr, D: Driver<'dr>, A: Allocator<'dr, D>, const N: usize>(
            dr: &mut D,
            allocator: &mut A,
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

        let children = ChildHeaders {
            left: alloc_header(dr, allocator, proof.as_ref().map(|p| p.left_header()))?,
            right: alloc_header(dr, allocator, proof.as_ref().map(|p| p.right_header()))?,
        };

        // Allocate the first HEADER_SIZE - 1 elements of the output header.
        // The last element reuses `core.output_suffix` so that the shared-stage
        // wire is the same wire hashes_1's public instance serialization
        // exposes — no extra enforce_equal needed.
        let mut elems: Vec<Element<'dr, D>> = Vec::with_capacity(HEADER_SIZE);
        for i in 0..HEADER_SIZE - 1 {
            elems.push(Element::alloc(
                dr,
                allocator,
                output_header.as_ref().map(|h| h[i]),
            )?);
        }
        elems.push(core.output_suffix.clone());
        let output_header: HeaderVec<'dr, D, HEADER_SIZE> = FixedVec::try_from(elems)?;

        Ok(ProofInputs {
            children,
            output_header,
            circuit_id: core.circuit_id.clone(),
            unified: core.unified.clone(),
        })
    }

    /// Allocate ProofInputs from a proof reference and some unprocessed header
    /// data.
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

/// Core inputs from a single child proof allocated by the preamble [`Stage`].
///
/// Holds the data shared across multiple circuits: the child's circuit ID, its
/// unified instance, and the output header's last element (the trivial-proof
/// indicator). The full output header and grandchild headers are allocated
/// on-demand by [`hashes_1`] only, since no other circuit reads them.
///
/// [`hashes_1`]: super::super::circuits::hashes_1
#[derive(Gadget, Consistent)]
pub struct CoreInputs<'dr, D: Driver<'dr>, C: Cycle<CircuitField = D::F>> {
    #[ragu(gadget)]
    pub circuit_id: Element<'dr, D>,
    #[ragu(gadget)]
    pub unified: unified::Output<'dr, D, C>,
    /// Last element of the child's output header. Used by [`outer_collapse`] to
    /// detect the base case (trivial proof). Kept in the shared stage so
    /// [`hashes_1`] and [`outer_collapse`] see the same wire.
    ///
    /// [`outer_collapse`]: super::super::circuits::outer_collapse
    /// [`hashes_1`]: super::super::circuits::hashes_1
    #[ragu(gadget)]
    pub output_suffix: Element<'dr, D>,
}

impl<'dr, D: Driver<'dr, F = C::CircuitField>, C: Cycle> CoreInputs<'dr, D, C> {
    /// Returns true if this child proof is a trivial proof (output header suffix == 1).
    pub fn is_trivial(&self, dr: &mut D) -> Result<Boolean<'dr, D>> {
        self.output_suffix.is_equal(dr, &Element::one())
    }

    /// Allocate [`CoreInputs`] from a proof reference and the suffix element.
    fn alloc<R: Rank>(
        dr: &mut D,
        proof: DriverValue<D, &Proof<C, R>>,
        output_suffix: DriverValue<D, C::CircuitField>,
    ) -> Result<Self> {
        let allocator = &mut ();
        Ok(CoreInputs {
            circuit_id: Element::alloc(
                dr,
                allocator,
                proof.as_ref().map(|p| p.circuit_id().omega_j()),
            )?,
            unified: unified::Output::alloc_from_proof(dr, allocator, proof)?,
            output_suffix: Element::alloc(dr, allocator, output_suffix)?,
        })
    }
}

/// Prover-internal output of the native preamble stage.
///
/// This is stage communication data, not part of the circuit's public instance.
/// The verifier never sees these values directly.
#[derive(Gadget, Consistent)]
pub struct Output<'dr, D: Driver<'dr>, C: Cycle<CircuitField = D::F>> {
    #[ragu(gadget)]
    pub left: CoreInputs<'dr, D, C>,
    #[ragu(gadget)]
    pub right: CoreInputs<'dr, D, C>,
}

impl<'dr, D: Driver<'dr>, C: Cycle<CircuitField = D::F>> Output<'dr, D, C> {
    /// Returns true if both child proofs are trivial proofs.
    pub fn is_base_case(&self, dr: &mut D) -> Result<Boolean<'dr, D>> {
        let left_is_trivial = self.left.is_trivial(dr)?;
        let right_is_trivial = self.right.is_trivial(dr)?;
        left_is_trivial.and(dr, &right_is_trivial)
    }
}

#[derive(Default)]
pub struct Stage<C: Cycle, R, const HEADER_SIZE: usize> {
    _marker: PhantomData<(C, R)>,
}

impl<C: Cycle, R: Rank, const HEADER_SIZE: usize> staging::Stage<C::CircuitField, R>
    for Stage<C, R, HEADER_SIZE>
{
    type Parent = ();
    type Witness<'source> = &'source Witness<'source, C, R, HEADER_SIZE>;
    type OutputKind = Kind![C::CircuitField; Output<'_, _, C>];

    fn values() -> usize {
        // 2 proofs * (1 circuit_id + unified instance wires + 1 output_suffix)
        2 * (1 + unified::NUM_WIRES + 1)
    }

    fn witness<'dr, 'source: 'dr, D: Driver<'dr, F = C::CircuitField>>(
        &self,
        dr: &mut D,
        witness: DriverValue<D, Self::Witness<'source>>,
    ) -> Result<Bound<'dr, D, Self::OutputKind>>
    where
        Self: 'dr,
    {
        let left = CoreInputs::alloc(
            dr,
            witness.as_ref().map(|w| w.left.proof),
            witness.as_ref().map(|w| w.left.output_header[HEADER_SIZE - 1]),
        )?;

        let right = CoreInputs::alloc(
            dr,
            witness.as_ref().map(|w| w.right.proof),
            witness.as_ref().map(|w| w.right.output_header[HEADER_SIZE - 1]),
        )?;

        Ok(Output { left, right })
    }
}

#[cfg(test)]
mod tests {
    use ragu_pasta::Pasta;

    use super::*;
    use crate::internal::tests::{HEADER_SIZE, R, assert_stage_values};

    #[test]
    fn stage_values_matches_wire_count() {
        assert_stage_values(&Stage::<Pasta, R, { HEADER_SIZE }>::default());
    }
}
