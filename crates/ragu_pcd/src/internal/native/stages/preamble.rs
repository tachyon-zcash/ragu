//! Preamble stage for native fuse operations.
//!
//! Witnesses what each child proof exposes to the step that consumes it
//! (its output header, its circuit id and its unified instance), and the
//! step's own output header, circuit id and online openings, from which the
//! step's own application $k(y)$ is computed.
//!
//! The stage is committed after the step's circuit ran, in the fuse's
//! `s_prime` phase, because the output header and the openings are what the
//! circuit fixes at $\zeta = w$ (see [`online`]). Nothing here must be fixed
//! earlier: every value is held to a claim folded at $y$, the children's to
//! their exported instances and the step's own to its application claim,
//! and the `s_prime` bridge carries the commitment before $y$ is squeezed.

use alloc::vec::Vec;
use core::marker::PhantomData;

use ragu_circuits::{horner::Horner, polynomials::Rank, registry::CircuitIndex, staging};
use ragu_core::{
    Cycle, Error, Result,
    drivers::{Driver, DriverValue},
    gadgets::{Bound, Gadget, Kind},
    maybe::Maybe,
};
use ragu_primitives::{
    Boolean, Element, GadgetExt, Point,
    allocator::Allocator,
    consistent::Consistent,
    vec::{CollectFixed, ConstLen, FixedVec},
};

use crate::{
    Proof,
    header::{Header, Suffix},
    internal::{ky, native::unified, online},
    profile::{Profile, ProfiledCycle},
    step::{InternalStepIndex, internal::padded},
};

type HeaderVec<'dr, D, const HEADER_SIZE: usize> = FixedVec<Element<'dr, D>, ConstLen<HEADER_SIZE>>;

/// Witness data for a single child proof in the preamble stage.
pub struct ChildWitness<'a, C: Cycle, R: Rank, const HEADER_SIZE: usize> {
    /// Output header for this child proof.
    pub output_header: FixedVec<C::CircuitField, ConstLen<HEADER_SIZE>>,
    /// Reference to the child proof.
    pub proof: &'a Proof<C, R>,
}

/// The step's own application data: its encoded output header, its circuit
/// id and its online openings.
pub struct OwnWitness<F, const HEADER_SIZE: usize> {
    /// The step's output header, as its application circuit encodes it.
    pub output_header: FixedVec<F, ConstLen<HEADER_SIZE>>,
    /// The step's application circuit.
    pub circuit_id: CircuitIndex,
    /// The step's online openings, one per slot (see [`online`]).
    pub online: online::Queries<F>,
}

/// Witness for the native preamble stage.
///
/// Contains references to the left and right proofs, their output headers
/// computed outside the circuit, and the step's own output header, circuit
/// id and online openings.
pub struct Witness<'a, C: Cycle, R: Rank, const HEADER_SIZE: usize> {
    /// Left child proof witness.
    pub left: ChildWitness<'a, C, R, HEADER_SIZE>,
    /// Right child proof witness.
    pub right: ChildWitness<'a, C, R, HEADER_SIZE>,
    /// The step's own application data.
    pub own: OwnWitness<C::CircuitField, HEADER_SIZE>,
}

impl<'a, C: Cycle, R: Rank, const HEADER_SIZE: usize> Witness<'a, C, R, HEADER_SIZE> {
    /// Create a witness from child proof references, the children's
    /// pre-computed output headers and the step's own output header,
    /// circuit id and online openings.
    pub fn new(
        left: &'a Proof<C, R>,
        right: &'a Proof<C, R>,
        left_output_header: &[C::CircuitField],
        right_output_header: &[C::CircuitField],
        output_header: &[C::CircuitField],
        circuit_id: CircuitIndex,
        online: online::Queries<C::CircuitField>,
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
            own: OwnWitness {
                output_header: FixedVec::try_from(output_header.to_vec())?,
                circuit_id,
                online,
            },
        })
    }
}

/// What a proof exposes to the step that consumes it: its output header,
/// its circuit id and its unified instance.
///
/// The preamble holds one per child. A verifier of a proof with no parent
/// allocates one for that proof, from its own output header and circuit id.
#[derive(Gadget, Consistent)]
pub struct ProofInputs<'dr, D: Driver<'dr>, C: Cycle<CircuitField = D::F>, const HEADER_SIZE: usize>
{
    /// Output header of this child proof.
    #[ragu(gadget)]
    pub output_header: HeaderVec<'dr, D, HEADER_SIZE>,
    #[ragu(gadget)]
    pub circuit_id: Element<'dr, D>,
    #[ragu(gadget)]
    pub unified: unified::Output<'dr, D, C>,
}

/// The step's own output header, circuit id and online openings: the
/// output header and circuit id are the application slots the step's
/// `hashes_1` exports for its parent, and all three enter the step's own
/// application claim.
#[derive(Gadget, Consistent)]
pub struct OwnInputs<'dr, D: Driver<'dr>, const HEADER_SIZE: usize> {
    /// The step's own output header.
    #[ragu(gadget)]
    pub output_header: HeaderVec<'dr, D, HEADER_SIZE>,
    /// The step's own application circuit id, as its domain point.
    #[ragu(gadget)]
    pub circuit_id: Element<'dr, D>,
    /// The step's online openings, in slot order: the point each slot's
    /// polynomial is opened at and the claimed evaluation. `collapse` folds
    /// the application claim over them and `compute_v` folds them into the
    /// batch, which is what holds the application's queries to the proved
    /// openings.
    #[ragu(gadget)]
    pub online: online::QueriesOutput<'dr, D>,
}

impl<'dr, D: Driver<'dr, F = C::CircuitField>, C: Cycle, const HEADER_SIZE: usize>
    ProofInputs<'dr, D, C, HEADER_SIZE>
{
    /// Compute unified k(y) and unified+bridged k(y) values simultaneously,
    /// sharing computation.
    ///
    /// Returns `(unified_ky, unified_bridge_ky)` where:
    /// - `unified_ky` = k(y) for `(unified, 0)`
    /// - `unified_bridge_ky` = k(y) for `(unified, output_header, circuit_id, 0)`,
    ///   the instance this proof's `hashes_1` exported
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
                self.output_header.write(dr, &mut ky)?;
                self.circuit_id.write(dr, &mut ky)?;
                Element::zero(dr).write(dr, &mut ky)?;
                ky.finish_ky(dr)?
            }),
        ))
    }

    /// The statement circuit's $k(y)$ for this child, when profile `P`'s
    /// native extension has one: the $k(y)$ of the header the extension
    /// verified, followed by the zero the circuit's slot appends to its
    /// output. The header is the child's own output header for a proof of
    /// the decompression step and the unit header for a proof of any other
    /// step, so a profile's prover verifies a proof with the unit header,
    /// such as an application's bootstrap, outside that step. `None` for a
    /// profile without a statement circuit, which computes nothing and
    /// which [`ky_values`] never asks for.
    ///
    /// The decompression step's output header is a witness wire set, so
    /// this is what binds it: a proof of that step whose output header is
    /// not the decompressed statement's has a false claim on the statement
    /// circuit.
    ///
    /// [`ky_values`]: crate::internal::native::claims::ky_values
    pub fn statement_ky<P: Profile>(
        &self,
        dr: &mut D,
        y: &Element<'dr, D>,
    ) -> Result<Option<Element<'dr, D>>> {
        if P::native_extension().statement.is_none() {
            return Ok(None);
        }
        let decompress = InternalStepIndex::Decompress.circuit_index::<P>()?;
        let decompress = Element::constant(dr, decompress.omega_j());
        let is_decompress = self.circuit_id.is_equal(dr, &mut (), &decompress)?;
        let own = {
            let mut ky = Horner::new(y);
            self.output_header.write(dr, &mut ky)?;
            ky::finish_extension_ky(ky, dr)?
        };
        let canonical = {
            let mut ky = Horner::new(y);
            for value in ky::output_header::<C, (), HEADER_SIZE>(())? {
                Element::constant(dr, value).write(dr, &mut ky)?;
            }
            ky::finish_extension_ky(ky, dr)?
        };
        is_decompress
            .conditional_select(dr, &canonical, &own)
            .map(Some)
    }

    /// Returns true when the current step declared a [`Dummy`] input for
    /// this child — which only the internal [`Bootstrap`] step can, so this is
    /// exactly the base case. See [`Bootstrap`] for why that holds.
    ///
    /// [`Dummy`]: crate::header::Dummy
    /// [`Bootstrap`]: crate::step::internal::bootstrap
    pub fn is_dummy_input(
        &self,
        dr: &mut D,
        allocator: &mut impl Allocator<'dr, D>,
    ) -> Result<Boolean<'dr, D>> {
        let bootstrap = Element::constant(dr, D::F::from(Suffix::internal(2).get()));
        self.output_header[HEADER_SIZE - 1].is_equal(dr, allocator, &bootstrap)
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
            output_header: alloc_header(dr, allocator, output_header.as_ref().map(|h| &h[..]))?,
            circuit_id: Element::alloc(
                dr,
                allocator,
                proof.as_ref().map(|p| p.circuit_id().omega_j()),
            )?,
            unified: unified::Output::alloc_from_proof(dr, allocator, proof.as_ref().map(|p| *p))?,
        })
    }

    /// Allocate ProofInputs from the parts a proof's instance carries: the
    /// encoded output header, the circuit id as its domain point, and the
    /// unified instance's values.
    pub fn alloc_from_parts(
        dr: &mut D,
        output_header: DriverValue<D, &[D::F]>,
        circuit_id: DriverValue<D, D::F>,
        unified: DriverValue<D, &unified::Instance<C>>,
    ) -> Result<Self> {
        fn alloc_header<'dr, D: Driver<'dr>, const N: usize>(
            dr: &mut D,
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
                .map(|i| Element::alloc(dr, &mut (), data.as_ref().map(|d| d[i])))
                .try_collect_fixed()
        }

        Ok(ProofInputs {
            output_header: alloc_header(dr, output_header)?,
            circuit_id: Element::alloc(dr, &mut (), circuit_id)?,
            unified: unified::Output::alloc_from_instance(dr, &mut (), unified)?,
        })
    }
}

/// Encodes a header's data as the step's padded output header: the
/// `HEADER_SIZE` field elements the application circuit's instance carries.
pub fn encode_output_header<'dr, D: Driver<'dr>, H: Header<D::F>, const HEADER_SIZE: usize>(
    header_data: DriverValue<D, H::Data>,
) -> Result<DriverValue<D, FixedVec<D::F, ConstLen<HEADER_SIZE>>>> {
    D::try_just(|| {
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
    })
}

/// Prover-internal output of the native preamble stage.
///
/// This is stage communication data, not part of the circuit's public instance.
/// The verifier never sees these values directly.
#[derive(Gadget, Consistent)]
pub struct Output<'dr, D: Driver<'dr>, C: Cycle<CircuitField = D::F>, const HEADER_SIZE: usize> {
    #[ragu(gadget)]
    pub left: ProofInputs<'dr, D, C, HEADER_SIZE>,
    #[ragu(gadget)]
    pub right: ProofInputs<'dr, D, C, HEADER_SIZE>,
    #[ragu(gadget)]
    pub own: OwnInputs<'dr, D, HEADER_SIZE>,
}

impl<'dr, D: Driver<'dr>, C: Cycle<CircuitField = D::F>, const HEADER_SIZE: usize>
    Output<'dr, D, C, HEADER_SIZE>
{
    /// Returns true when the current step declared [`Dummy`] for both of its
    /// inputs, i.e. this fuse is the base case that bootstraps the recursion.
    ///
    /// [`Dummy`]: crate::header::Dummy
    pub fn is_base_case(
        &self,
        dr: &mut D,
        allocator: &mut impl Allocator<'dr, D>,
    ) -> Result<Boolean<'dr, D>> {
        let left_is_dummy = self.left.is_dummy_input(dr, allocator)?;
        let right_is_dummy = self.right.is_dummy_input(dr, allocator)?;
        left_is_dummy.and(dr, &right_is_dummy)
    }

    /// Compute k(y) for the step's own application circuit instance: k(y)
    /// for `(zeta, online, bridge_hash, left.output_header,
    /// right.output_header, own.output_header)`, the instance the step's
    /// circuit satisfied (see [`Adapter`]).
    ///
    /// `zeta` is the step's $w$ and `bridge_hash` the commitment of its
    /// bridge-hash stage, both from the unified instance. The openings are
    /// the ones `compute_v` folds into the batch, so the instance the
    /// circuit satisfied is held to the openings the batch proves by
    /// construction. The step's inputs are its children's output headers,
    /// read from the same wires their `unified_bridge_ky` values bind to
    /// the children's exports.
    ///
    /// [`Adapter`]: crate::step::internal::adapter::Adapter
    pub fn application_ky(
        &self,
        dr: &mut D,
        y: &Element<'dr, D>,
        zeta: &Element<'dr, D>,
        bridge_hash: &Point<'dr, D, C::NestedCurve>,
    ) -> Result<Element<'dr, D>> {
        let mut ky = Horner::new(y);
        zeta.write(dr, &mut ky)?;
        self.own.online.write(dr, &mut ky)?;
        bridge_hash.write(dr, &mut ky)?;
        self.left.output_header.write(dr, &mut ky)?;
        self.right.output_header.write(dr, &mut ky)?;
        self.own.output_header.write(dr, &mut ky)?;
        ky.finish_ky(dr)
    }

    /// Enforces that a step taking the base case is the bootstrap step with
    /// the unit output header and padding output slots: when `is_base_case`
    /// holds, the own circuit id must be [`Bootstrap`]'s, the own output
    /// header the unit header's encoding, and each output slot opened at
    /// `zeta`, the step's $w$, to the value one.
    ///
    /// The base case leaves the step's folded claim unconstrained, and that
    /// claim includes the step's own application claim. Without this, a
    /// step could witness [`Dummy`] inputs and export any output header,
    /// circuit id and online polynomials. The constraint lives in the
    /// calling circuit, whose own claim the parent (or the decider)
    /// enforces, so it holds whatever the step's folded claim is.
    ///
    /// The slot pin repeats, outside the free claim, what the bootstrap
    /// step's circuit enforces inside it (see
    /// [`pin_output_slots`](crate::step::internal::pin_output_slots)). The
    /// output commitments are absorbed before $w$, and `compute_v`, whose
    /// claim is enforced like this circuit's, proves the openings over
    /// these same wires. So each output polynomial takes the value one at
    /// a point chosen after it, and is the constant one except with
    /// probability at most its degree over the field size.
    ///
    /// [`Bootstrap`]: crate::step::internal::bootstrap
    /// [`Dummy`]: crate::header::Dummy
    pub fn enforce_base_case_is_bootstrap<P: Profile>(
        &self,
        dr: &mut D,
        allocator: &mut impl Allocator<'dr, D>,
        is_base_case: &Boolean<'dr, D>,
        zeta: &Element<'dr, D>,
    ) -> Result<()> {
        let bootstrap = InternalStepIndex::Bootstrap.circuit_index::<P>()?;
        let bootstrap = Element::constant(dr, bootstrap.omega_j());
        is_base_case.conditional_enforce_equal(dr, allocator, &self.own.circuit_id, &bootstrap)?;
        let unit = ky::output_header::<C, (), HEADER_SIZE>(())?;
        for (wire, value) in self.own.output_header.iter().zip(unit) {
            let value = Element::constant(dr, value);
            is_base_case.conditional_enforce_equal(dr, allocator, wire, &value)?;
        }
        let one = Element::one();
        for index in 0..online::NUM_ONLINE_POLYNOMIALS {
            let opening = &self.own.online[online::Slot::output(index).offset()];
            is_base_case.conditional_enforce_equal(dr, allocator, &opening.x, zeta)?;
            is_base_case.conditional_enforce_equal(dr, allocator, &opening.y, &one)?;
        }
        Ok(())
    }
}

#[derive(Default)]
pub struct Stage<C: Cycle, R, const HEADER_SIZE: usize> {
    _marker: PhantomData<(C, R)>,
}

impl<C: ProfiledCycle, R: Rank, const HEADER_SIZE: usize> staging::Stage<C::CircuitField, R>
    for Stage<C, R, HEADER_SIZE>
{
    // The native stage tree is rooted at the binding stage of the
    // endoscaling walk, so the preamble chain reserves it too (see
    // `stages::points`).
    type Parent = super::points::BindingStage<C::NestedCurve, C::Profile>;
    type Witness<'source> = &'source Witness<'source, C, R, HEADER_SIZE>;
    type OutputKind = Kind![C::CircuitField; Output<'_, _, C, HEADER_SIZE>];

    fn values() -> usize {
        // 2 proofs * (output header + 1 circuit_id + unified instance
        // wires), then the own output header, circuit_id and (x, y) per
        // online slot
        2 * (HEADER_SIZE + 1 + unified::NUM_WIRES)
            + HEADER_SIZE
            + 1
            + 2 * online::NUM_ONLINE_QUERIES
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

        let own = OwnInputs {
            output_header: FixedVec::try_from_fn(|i| {
                Element::alloc(
                    dr,
                    &mut (),
                    witness.as_ref().map(|w| w.own.output_header[i]),
                )
            })?,
            circuit_id: Element::alloc(
                dr,
                &mut (),
                witness.as_ref().map(|w| w.own.circuit_id.omega_j()),
            )?,
            online: online::alloc_queries(dr, &mut (), witness.as_ref().map(|w| &w.own.online))?,
        };

        Ok(Output { left, right, own })
    }
}

#[cfg(test)]
mod tests {
    use ragu_core::pasta::Pasta;

    use super::*;
    use crate::internal::tests::{HEADER_SIZE, R, assert_stage_values};

    #[test]
    fn stage_values_matches_wire_count() {
        assert_stage_values(&Stage::<Pasta, R, { HEADER_SIZE }>::default());
    }
}
