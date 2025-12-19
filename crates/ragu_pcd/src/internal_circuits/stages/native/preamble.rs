use arithmetic::Cycle;
use ff::PrimeField;
use ragu_circuits::{polynomials::Rank, staging};
use ragu_core::{
    Error, Result,
    drivers::{Driver, DriverValue, emulator::Emulator},
    gadgets::{Gadget, GadgetKind, Kind},
    maybe::{Always, Maybe, MaybeKind},
};
use ragu_primitives::{
    Element, GadgetExt,
    vec::{CollectFixed, ConstLen, FixedVec},
};

use alloc::vec::Vec;
use core::marker::PhantomData;

use crate::{
    header::Header,
    internal_circuits::unified,
    proof::{Pcd, Proof},
    step::padded,
};

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

impl<'a, C: Cycle, R: Rank, const HEADER_SIZE: usize> Witness<'a, C, R, HEADER_SIZE> {
    /// Create a witness from proof references and pre-computed output headers.
    pub fn new(
        left: &'a Proof<C, R>,
        right: &'a Proof<C, R>,
        left_output_header: [C::CircuitField; HEADER_SIZE],
        right_output_header: [C::CircuitField; HEADER_SIZE],
    ) -> Self {
        Witness {
            left_output_header,
            right_output_header,
            left,
            right,
        }
    }

    /// Create a witness from two PCDs.
    ///
    /// Output headers are computed outside the circuit using the encoder pattern.
    /// Other data (input headers, circuit IDs, unified instance) is accessed
    /// directly from the proof references during circuit synthesis.
    pub fn from_pcds<HL, HR>(
        left: &'a Pcd<'_, C, R, HL>,
        right: &'a Pcd<'_, C, R, HR>,
    ) -> Result<Self>
    where
        HL: Header<C::CircuitField>,
        HR: Header<C::CircuitField>,
    {
        // TODO: Implement Buffer for arrays/slices to avoid Vec allocation here.
        /// Encode header data into a fixed-size field element array.
        fn encode_output_header<F: PrimeField, H: Header<F>, const HEADER_SIZE: usize>(
            data: H::Data<'_>,
        ) -> Result<[F; HEADER_SIZE]> {
            fn vec_to_array<F: Copy, const N: usize>(v: &[F]) -> Result<[F; N]> {
                v.try_into().map_err(|_| Error::VectorLengthMismatch {
                    expected: N,
                    actual: v.len(),
                })
            }

            let mut emulator = Emulator::execute();
            let gadget = H::encode(&mut emulator, Always::maybe_just(|| data))?;
            let padded = padded::for_header::<H, HEADER_SIZE, _>(&mut emulator, gadget)?;

            let mut elements = Vec::with_capacity(HEADER_SIZE);
            padded.write(&mut emulator, &mut elements)?;

            let values: Vec<_> = elements.into_iter().map(|e| *e.value().take()).collect();
            vec_to_array(&values)
        }

        Ok(Witness::new(
            &left.proof,
            &right.proof,
            encode_output_header::<C::CircuitField, HL, HEADER_SIZE>(left.data.clone())?,
            encode_output_header::<C::CircuitField, HR, HEADER_SIZE>(right.data.clone())?,
        ))
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
