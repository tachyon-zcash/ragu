use arithmetic::Cycle;
use ragu_circuits::{polynomials::Rank, staging};
use ragu_core::{
    Error, Result,
    drivers::{Driver, DriverValue},
    gadgets::{Gadget, GadgetKind, Kind},
    maybe::Maybe,
};
use ragu_primitives::{
    Boolean, Element, GadgetExt,
    vec::{CollectFixed, ConstLen, FixedVec},
};

use alloc::vec::Vec;
use core::marker::PhantomData;

use crate::{Proof, components::ky::Ky, header::Header, internal_circuits::unified, step::padded};

pub use crate::internal_circuits::InternalCircuitIndex::PreambleStage as STAGING_ID;

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
    /// Create a witness from proof references and pre-computed output headers.
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
#[derive(Gadget)]
pub struct ChildHeaders<'dr, D: Driver<'dr>, const HEADER_SIZE: usize> {
    /// Left child header (grandchild from current perspective).
    #[ragu(gadget)]
    pub left: HeaderVec<'dr, D, HEADER_SIZE>,
    /// Right child header (grandchild from current perspective).
    #[ragu(gadget)]
    pub right: HeaderVec<'dr, D, HEADER_SIZE>,
}

/// Processed inputs from a single child proof in the preamble stage.
#[derive(Gadget)]
pub struct ProofInputs<'dr, D: Driver<'dr>, C: Cycle, const HEADER_SIZE: usize> {
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

impl<'dr, D: Driver<'dr>, C: Cycle, const HEADER_SIZE: usize> ProofInputs<'dr, D, C, HEADER_SIZE> {
    /// Compute unified k(y) and unified+bridged k(y) values simultaneously,
    /// sharing computation.
    ///
    /// Returns `(unified_ky, unified_bridge_ky)` where:
    /// - `unified_ky` = k(y) for `(unified, 0)`
    /// - `unified_bridge_ky` = k(y) for `(unified, children.left, children.right, 0)`
    pub fn unified_ky_values(
        &self,
        dr: &mut D,
        y: &Element<'dr, D>,
    ) -> Result<(Element<'dr, D>, Element<'dr, D>)> {
        let mut ky = Ky::new(y);
        self.unified.write(dr, &mut ky)?;

        Ok((
            ({
                let mut ky = ky.clone();
                Element::zero(dr).write(dr, &mut ky)?;
                ky.finish(dr)?
            }),
            ({
                self.children.left.write(dr, &mut ky)?;
                self.children.right.write(dr, &mut ky)?;
                Element::zero(dr).write(dr, &mut ky)?;
                ky.finish(dr)?
            }),
        ))
    }

    /// Compute k(y) for the application circuit instance.
    ///
    /// Returns `application_ky` = k(y) for `(children.left, children.right, output_header)`.
    pub fn application_ky(&self, dr: &mut D, y: &Element<'dr, D>) -> Result<Element<'dr, D>> {
        let mut ky = Ky::new(y);
        self.children.left.write(dr, &mut ky)?;
        self.children.right.write(dr, &mut ky)?;
        self.output_header.write(dr, &mut ky)?;
        ky.finish(dr)
    }

    /// Returns true if this child proof is a trivial proof (output header suffix == 1).
    pub fn is_trivial(&self, dr: &mut D) -> Result<Boolean<'dr, D>> {
        let suffix = &self.output_header[HEADER_SIZE - 1];
        suffix.is_equal(dr, &Element::one())
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
            data: DriverValue<D, &[D::F]>,
        ) -> Result<FixedVec<Element<'dr, D>, ConstLen<N>>> {
            D::with(|| {
                if data.view().take().len() != N {
                    return Err(Error::MalformedEncoding(
                        "Header data length does not match HEADER_SIZE".into(),
                    ));
                }

                Ok(())
            })?;

            (0..N)
                .map(|i| Element::alloc(dr, data.view().map(|d| d[i])))
                .try_collect_fixed()
        }

        Ok(ProofInputs {
            children: ChildHeaders {
                left: alloc_header(
                    dr,
                    proof.view().map(|p| p.application.left_header.as_slice()),
                )?,
                right: alloc_header(
                    dr,
                    proof.view().map(|p| p.application.right_header.as_slice()),
                )?,
            },
            output_header: alloc_header(dr, output_header.view().map(|h| &h[..]))?,
            circuit_id: Element::alloc(
                dr,
                proof.view().map(|p| p.application.circuit_id.omega_j()),
            )?,
            unified: unified::Output::alloc_from_proof(dr, proof)?,
        })
    }

    /// Allocate ProofInputs from a proof reference and some unprocessed header
    /// data.
    pub fn alloc_for_verify<'source, R: Rank, H: Header<C::CircuitField>>(
        dr: &mut D,
        proof: DriverValue<D, &Proof<C, R>>,
        header_data: DriverValue<D, H::Data<'source>>,
    ) -> Result<Self>
    where
        'source: 'dr,
    {
        let header_data = D::with(|| {
            use ragu_core::drivers::emulator::{Emulator, Wireless};
            let emulator = &mut Emulator::<Wireless<D::MaybeKind, D::F>>::wireless();

            let output = H::encode(emulator, header_data)?;
            let output = padded::for_header::<H, HEADER_SIZE, _>(emulator, output)?;

            let mut header_data = Vec::with_capacity(HEADER_SIZE);
            output.write(emulator, &mut header_data)?;

            header_data
                .into_iter()
                .map(|e| *e.value().take())
                .collect_fixed()
        })?;

        Self::alloc(dr, proof, header_data.view())
    }
}

/// Output of the native preamble stage.
#[derive(Gadget)]
pub struct Output<'dr, D: Driver<'dr>, C: Cycle, const HEADER_SIZE: usize> {
    #[ragu(gadget)]
    pub left: ProofInputs<'dr, D, C, HEADER_SIZE>,
    #[ragu(gadget)]
    pub right: ProofInputs<'dr, D, C, HEADER_SIZE>,
}

impl<'dr, D: Driver<'dr>, C: Cycle, const HEADER_SIZE: usize> Output<'dr, D, C, HEADER_SIZE> {
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
    type OutputKind = Kind![C::CircuitField; Output<'_, _, C, HEADER_SIZE>];

    fn values() -> usize {
        // 2 proofs * (3 headers * HEADER_SIZE + 1 circuit_id + unified instance wires)
        2 * (3 * HEADER_SIZE + 1 + unified::NUM_WIRES)
    }

    fn witness<'dr, 'source: 'dr, D: Driver<'dr, F = C::CircuitField>>(
        &self,
        dr: &mut D,
        witness: DriverValue<D, Self::Witness<'source>>,
    ) -> Result<<Self::OutputKind as GadgetKind<C::CircuitField>>::Rebind<'dr, D>>
    where
        Self: 'dr,
    {
        let left = ProofInputs::alloc(
            dr,
            witness.view().map(|w| w.left.proof),
            witness.view().map(|w| &w.left.output_header),
        )?;

        let right = ProofInputs::alloc(
            dr,
            witness.view().map(|w| w.right.proof),
            witness.view().map(|w| &w.right.output_header),
        )?;

        Ok(Output { left, right })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::internal_circuits::stages::native::tests::{
        TEST_HEADER_SIZE, TestR, assert_stage_values,
    };
    use ragu_pasta::Pasta;

    #[test]
    fn stage_values_matches_wire_count() {
        assert_stage_values(&Stage::<Pasta, TestR, { TEST_HEADER_SIZE }>::default());
    }
}
