use arithmetic::Cycle;
use ragu_circuits::{polynomials::Rank, staging};
use ragu_core::{
    Error, Result,
    drivers::{Driver, DriverValue},
    gadgets::{Gadget, GadgetKind, Kind},
    maybe::Maybe,
};
use ragu_primitives::{
    Element, GadgetExt,
    vec::{CollectFixed, ConstLen, FixedVec},
};

use core::marker::PhantomData;

use crate::{components::ky::Ky, internal_circuits::unified, proof::Proof};

pub use crate::internal_circuits::InternalCircuitIndex::PreambleStage as STAGING_ID;

type HeaderVec<'dr, D, const HEADER_SIZE: usize> = FixedVec<Element<'dr, D>, ConstLen<HEADER_SIZE>>;

/// Witness for the native preamble stage.
///
/// Contains references to the left and right proofs, plus output headers
/// computed outside the circuit.
pub struct Witness<'a, C: Cycle, R: Rank, const HEADER_SIZE: usize> {
    /// Output header for left proof.
    pub left_output_header: [C::CircuitField; HEADER_SIZE],
    /// Output header for right proof.
    pub right_output_header: [C::CircuitField; HEADER_SIZE],
    /// Left proof.
    pub left: &'a Proof<C, R>,
    /// Right proof.
    pub right: &'a Proof<C, R>,
}

impl<'a, C: Cycle, R: Rank, const HEADER_SIZE: usize> Witness<'a, C, R, HEADER_SIZE> {
    /// Create a witness from proof references and pre-computed output headers.
    pub fn new(
        left: &'a Proof<C, R>,
        right: &'a Proof<C, R>,
        left_output_header: &[C::CircuitField],
        right_output_header: &[C::CircuitField],
    ) -> Result<Self> {
        fn slice_to_array<T: Copy, const N: usize>(slice: &[T]) -> Result<[T; N]> {
            slice.try_into().map_err(|_| Error::VectorLengthMismatch {
                expected: N,
                actual: slice.len(),
            })
        }

        Ok(Witness {
            left_output_header: slice_to_array(left_output_header)?,
            right_output_header: slice_to_array(right_output_header)?,
            left,
            right,
        })
    }
}

#[derive(Gadget)]
pub struct ProofInputs<'dr, D: Driver<'dr>, C: Cycle, const HEADER_SIZE: usize> {
    #[ragu(gadget)]
    pub right_header: HeaderVec<'dr, D, HEADER_SIZE>,
    #[ragu(gadget)]
    pub left_header: HeaderVec<'dr, D, HEADER_SIZE>,
    #[ragu(gadget)]
    pub output_header: HeaderVec<'dr, D, HEADER_SIZE>,
    #[ragu(gadget)]
    pub circuit_id: Element<'dr, D>,
    #[ragu(gadget)]
    pub unified: unified::Output<'dr, D, C>,
}

impl<'dr, D: Driver<'dr>, C: Cycle, const HEADER_SIZE: usize> ProofInputs<'dr, D, C, HEADER_SIZE> {
    /// Compute k(y) for application circuit headers.
    pub fn application_ky(&self, dr: &mut D, y: &Element<'dr, D>) -> Result<Element<'dr, D>> {
        let mut ky = Ky::new(dr, y);
        self.left_header.write(dr, &mut ky)?;
        self.right_header.write(dr, &mut ky)?;
        self.output_header.write(dr, &mut ky)?;
        ky.finish(dr)
    }

    /// Compute k(y) for unified circuit instance.
    pub fn unified_ky(&self, dr: &mut D, y: &Element<'dr, D>) -> Result<Element<'dr, D>> {
        let mut ky = Ky::new(dr, y);
        self.unified.write(dr, &mut ky)?;
        Element::zero(dr).write(dr, &mut ky)?;
        ky.finish(dr)
    }
}

impl<'dr, D: Driver<'dr, F = C::CircuitField>, C: Cycle, const HEADER_SIZE: usize>
    ProofInputs<'dr, D, C, HEADER_SIZE>
{
    /// Allocate ProofInputs from a proof reference and pre-computed output header.
    pub fn alloc<R: Rank>(
        dr: &mut D,
        proof: DriverValue<D, &Proof<C, R>>,
        output_header: DriverValue<D, &[D::F; HEADER_SIZE]>,
    ) -> Result<Self> {
        fn alloc_header<'dr, D: Driver<'dr>, const N: usize>(
            dr: &mut D,
            data: DriverValue<D, &[D::F]>,
        ) -> Result<FixedVec<Element<'dr, D>, ConstLen<N>>> {
            (0..N)
                .map(|i| Element::alloc(dr, data.view().map(|d| d[i])))
                .try_collect_fixed()
        }

        Ok(ProofInputs {
            right_header: alloc_header(
                dr,
                proof.view().map(|p| p.application.right_header.as_slice()),
            )?,
            left_header: alloc_header(
                dr,
                proof.view().map(|p| p.application.left_header.as_slice()),
            )?,
            output_header: alloc_header(dr, output_header.view().map(|h| h.as_slice()))?,
            circuit_id: Element::alloc(
                dr,
                proof.view().map(|p| p.application.circuit_id.omega_j()),
            )?,
            unified: unified::Output::alloc_from_proof(dr, proof)?,
        })
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
            witness.view().map(|w| w.left),
            witness.view().map(|w| &w.left_output_header),
        )?;

        let right = ProofInputs::alloc(
            dr,
            witness.view().map(|w| w.right),
            witness.view().map(|w| &w.right_output_header),
        )?;

        Ok(Output { left, right })
    }
}
