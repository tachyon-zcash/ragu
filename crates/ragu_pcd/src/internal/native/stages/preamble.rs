//! Preamble stage for native fuse operations.
//!
//! Verifies child proof headers and computes the Ky term.

use alloc::vec::Vec;
use core::marker::PhantomData;

use ragu_circuits::{horner::Horner, polynomials::Rank, staging};
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
    internal::{
        ky,
        native::{online, unified},
    },
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
    C: ProfiledCycle<CircuitField = D::F>,
    const HEADER_SIZE: usize,
> {
    /// Headers this child proof claimed for its own children.
    #[ragu(gadget)]
    pub children: ChildHeaders<'dr, D, HEADER_SIZE>,
    /// Output header of this child proof.
    #[ragu(gadget)]
    pub output_header: HeaderVec<'dr, D, HEADER_SIZE>,
    /// Six opening claims, in [L0, L1, R0, R1, O0, O1] order.
    /// The parent uses these same values in the application and `compute_v`
    /// k(y) targets, binding the application's queries to the proved openings.
    #[ragu(gadget)]
    pub online: online::QueriesOutput<'dr, D>,
    /// Common quotient and evaluation sums for the native private helper.
    #[ragu(gadget)]
    pub mesh: FixedVec<
        Element<'dr, D>,
        crate::profile::online::stages::MeshClaimsLen<
            C::Profile,
            crate::profile::online::stages::Native,
        >,
    >,
    #[ragu(gadget)]
    pub online_fold: FixedVec<
        Element<'dr, D>,
        crate::profile::online::stages::Present<
            C::Profile,
            crate::profile::online::stages::Native,
            2,
        >,
    >,
    /// The child's common targets for its actual nested private walk points.
    #[ragu(gadget)]
    pub online_points: FixedVec<
        ragu_primitives::CompletePoint<'dr, D, C::NestedCurve>,
        crate::profile::online::stages::PolynomialsLen<
            C::Profile,
            crate::profile::online::stages::Nested,
        >,
    >,
    #[ragu(gadget)]
    pub circuit_id: Element<'dr, D>,
    #[ragu(gadget)]
    pub unified: unified::Output<'dr, D, C>,
}

impl<'dr, D: Driver<'dr, F = C::CircuitField>, C: ProfiledCycle, const HEADER_SIZE: usize>
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

    /// Compute k(y) for the application circuit instance: k(y) for
    /// `(zeta, online, children.left, children.right, output_header)`, where
    /// the child's `zeta` is its `w` and `online` its openings, both as the
    /// unified instance and the `compute_v` bridge hold them, so that the
    /// instance the child's step circuit satisfied is held to the openings
    /// its batch proved by construction (see
    /// [`Adapter`](crate::step::internal::adapter::Adapter)).
    pub fn application_ky(&self, dr: &mut D, y: &Element<'dr, D>) -> Result<Element<'dr, D>> {
        let mut ky = Horner::new(y);
        self.unified.w.write(dr, &mut ky)?;
        self.online.write(dr, &mut ky)?;
        self.unified.bridge_hash_commitment.write(dr, &mut ky)?;
        self.children.left.write(dr, &mut ky)?;
        self.children.right.write(dr, &mut ky)?;
        self.output_header.write(dr, &mut ky)?;
        ky.finish_ky(dr)
    }

    /// Compute k(y) for the child's `compute_v` circuit: k(y) for
    /// `(unified, online, 0)`, the unified instance followed by the online
    /// openings the circuit exported (see
    /// [`compute_v::Output`](crate::internal::native::circuits::compute_v::Output)).
    pub fn compute_v_bridge_ky(
        &self,
        dr: &mut D,
        y: &Element<'dr, D>,
        online_stages: &[Point<'dr, D, C::NestedCurve>],
    ) -> Result<Element<'dr, D>> {
        let mut ky = Horner::new(y);
        self.unified.write(dr, &mut ky)?;
        self.online.write(dr, &mut ky)?;
        self.online_fold.write(dr, &mut ky)?;
        for point in online_stages {
            point.write(dr, &mut ky)?;
        }
        for i in C::Profile::NESTED_ONLINE.phase_range(crate::profile::online::Phase::BeforeAlpha) {
            self.online_points[i].write(dr, &mut ky)?;
        }
        if let Some(mesh) = C::Profile::NATIVE_MESH {
            for value in mesh.inherited_values(&self.mesh) {
                value.write(dr, &mut ky)?;
            }
        }
        if let Some(mesh) = C::Profile::NESTED_MESH {
            for inherited in mesh.inherited {
                self.online_points[inherited.polynomial].write(dr, &mut ky)?;
            }
        }
        Element::zero(dr).write(dr, &mut ky)?;
        ky.finish_ky(dr)
    }

    /// The private helper shares the core's sums and the walk's point exports.
    pub fn online_helper_ky(
        &self,
        dr: &mut D,
        y: &Element<'dr, D>,
    ) -> Result<Option<Element<'dr, D>>> {
        if C::Profile::NATIVE_ONLINE.is_empty() {
            return Ok(None);
        }
        let mut target = Horner::new(y);
        for value in [
            &self.unified.w,
            &self.unified.y,
            &self.unified.x,
            &self.unified.alpha,
            &self.unified.u,
            &self.unified.pre_beta,
        ] {
            value.write(dr, &mut target)?;
        }
        self.online_fold.write(dr, &mut target)?;
        let count = C::Profile::NESTED_ONLINE
            .polynomials
            .iter()
            .take_while(|&&phase| phase == crate::profile::online::Phase::BeforeW)
            .count();
        for point in self.online_points.iter().take(count) {
            point.write(dr, &mut target)?;
        }
        self.mesh.write(dr, &mut target)?;
        ky::finish_extension_ky(target, dr).map(Some)
    }

    /// The actual nested private commitments exported by bind_endoscalar.
    pub fn bind_endoscalar_ky(
        &self,
        dr: &mut D,
        y: &Element<'dr, D>,
        unified_ky: &Element<'dr, D>,
    ) -> Result<Element<'dr, D>> {
        // Setup-fixed empty layouts preserve the existing unified target.
        if C::Profile::NESTED_ONLINE.is_empty() {
            return Ok(unified_ky.clone());
        }
        let mut ky = Horner::new(y);
        self.unified.write(dr, &mut ky)?;
        self.online_points.write(dr, &mut ky)?;
        Element::zero(dr).write(dr, &mut ky)?;
        ky.finish_ky(dr)
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
        if crate::profile::native_extension::<P>().statement.is_none() {
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

impl<'dr, D: Driver<'dr, F = C::CircuitField>, C: ProfiledCycle, const HEADER_SIZE: usize>
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
            online: online::alloc_queries(
                dr,
                allocator,
                proof.as_ref().map(|p| p.online_openings()),
            )?,
            mesh: FixedVec::try_from_fn(|i| {
                Element::alloc(dr, &mut (), proof.as_ref().map(|p| p.native_mesh_claims[i]))
            })?,
            online_fold: FixedVec::try_from_fn(|i| {
                Element::alloc(dr, &mut (), proof.as_ref().map(|p| p.native_online_fold[i]))
            })?,
            online_points: FixedVec::try_from_fn(|i| {
                ragu_primitives::CompletePoint::alloc(
                    dr,
                    proof.as_ref().map(|p| p.nested_online_commitments[i]),
                )
            })?,
            circuit_id: Element::alloc(
                dr,
                allocator,
                proof.as_ref().map(|p| p.circuit_id().omega_j()),
            )?,
            unified: unified::Output::alloc_from_proof(dr, allocator, proof.as_ref().map(|p| *p))?,
        })
    }

    /// Allocate ProofInputs from the parts a proof's instance carries: the
    /// child headers, the encoded output header, the online openings, the
    /// circuit id as its domain point, and the unified instance's values.
    #[allow(clippy::too_many_arguments)]
    pub fn alloc_from_parts(
        dr: &mut D,
        left_header: DriverValue<D, &[D::F]>,
        right_header: DriverValue<D, &[D::F]>,
        output_header: DriverValue<D, &[D::F]>,
        online: DriverValue<D, &online::Queries<D::F>>,
        circuit_id: DriverValue<D, D::F>,
        unified: DriverValue<D, &unified::Instance<C>>,
        online_points: DriverValue<D, &[C::NestedCurve]>,
        online_fold: DriverValue<D, &[D::F]>,
        mesh: DriverValue<D, &[D::F]>,
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
            children: ChildHeaders {
                left: alloc_header(dr, left_header)?,
                right: alloc_header(dr, right_header)?,
            },
            output_header: alloc_header(dr, output_header)?,
            online: online::alloc_queries(dr, &mut (), online)?,
            online_points: FixedVec::try_from_fn(|i| {
                ragu_primitives::CompletePoint::alloc(dr, online_points.as_ref().map(|p| p[i]))
            })?,
            online_fold: FixedVec::try_from_fn(|i| {
                Element::alloc(dr, &mut (), online_fold.as_ref().map(|s| s[i]))
            })?,
            mesh: FixedVec::try_from_fn(|i| {
                Element::alloc(dr, &mut (), mesh.as_ref().map(|p| p[i]))
            })?,
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
pub struct Output<
    'dr,
    D: Driver<'dr>,
    C: ProfiledCycle<CircuitField = D::F>,
    const HEADER_SIZE: usize,
> {
    #[ragu(gadget)]
    pub left: ProofInputs<'dr, D, C, HEADER_SIZE>,
    #[ragu(gadget)]
    pub right: ProofInputs<'dr, D, C, HEADER_SIZE>,
}

impl<'dr, D: Driver<'dr>, C: ProfiledCycle<CircuitField = D::F>, const HEADER_SIZE: usize>
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
        // 2 proofs * (3 headers * HEADER_SIZE + the online openings + 1
        // circuit_id + unified instance wires)
        2 * (3 * HEADER_SIZE
            + 2 * online::NUM_ONLINE_FP_QUERIES
            + 1
            + unified::NUM_WIRES
            + C::Profile::NATIVE_MESH.map_or(0, |mesh| mesh.claims_len())
            + 2 * C::Profile::NESTED_ONLINE.polynomials.len()
            + <crate::profile::online::stages::Present<
                C::Profile,
                crate::profile::online::stages::Native,
                2,
            > as ragu_primitives::vec::Len>::len())
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
    use ragu_core::pasta::Pasta;

    use super::*;
    use crate::internal::tests::{HEADER_SIZE, R, assert_stage_values};

    #[test]
    fn stage_values_matches_wire_count() {
        assert_stage_values(&Stage::<Pasta, R, { HEADER_SIZE }>::default());
    }
}
