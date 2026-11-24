//! Preamble stage for native fuse operations.
//!
//! Witnesses what each child proof exposes to the step that consumes it
//! (its output header, its circuit id, its unified instance, in a profile
//! with a statement circuit the step binding's openings and, in a profile
//! with online batches, what its batches export), and the step's own output
//! header, circuit id, online openings and bridge-hash commitment, from
//! which the step's own application $k(y)$ is computed.
//!
//! ## Commitment after $w$
//!
//! The stage is committed after the step's circuit ran, in the fuse's
//! `s_prime` phase, because the output header and the openings are what the
//! circuit fixes at $\zeta = w$ (see [`online`]). It also holds the
//! bridge-hash commitment used in the application instance. The `s_prime`
//! bridge carries this stage's commitment, fixing that point before $y$
//! is squeezed. `collapse` holds the point to the unified instance.
//!
//! The step's own values need nothing earlier: the application claim that
//! holds them is folded at $y$.
//!
//! The children's values are different. Two checks are sound only if a
//! child's value is fixed before $w$: the registry transition at $w$ reads
//! the child's $x$ and $y$, and a step circuit's check at $\zeta$ can read
//! an input header's fields. These wires are committed after $w$, but they
//! are not free after $w$:
//!
//! - The commitments of each child's circuit traces and stages are in the
//!   nested `preamble` bridge, which $w$ absorbs.
//! - A committed trace fixes its instance: $k(Y)$ is a function of the
//!   trace. The child's unified instance, output header and circuit id,
//!   and in a profile with a statement circuit the step binding's
//!   openings, are the instance of its `hashes_1` trace, and its unified
//!   instance is the instance of its other circuits' traces. In a profile
//!   with online batches, the child's helper sums, mesh claims and nested
//!   online commitments are in the instances of its `compute_v`,
//!   `bind_endoscalar` and online helper traces.
//! - This step folds those claims at $y$, with each $k(y)$ computed from
//!   the wires here, and $y$ is squeezed after this stage is committed. A
//!   wire that differs from the value the committed trace fixes makes
//!   $k(Y)$ a different polynomial, and the fold fails except with
//!   probability at most its degree over the field size.
//!
//! So each child's value here is a function of commitments that $w$
//! absorbed, provided the child's claims are enforced. In the base case
//! they are not, but then the step is pinned to the bootstrap step (see
//! [`Output::enforce_base_case_is_bootstrap`]), whose proof attests
//! nothing: no consumer relies on its children's registry polynomials or
//! on a check at $\zeta$ in it.

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
use udon::curve::Affine as _;

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
/// id, online openings and bridge-hash commitment.
pub struct Witness<'a, C: Cycle, R: Rank, const HEADER_SIZE: usize> {
    /// Left child proof witness.
    pub left: ChildWitness<'a, C, R, HEADER_SIZE>,
    /// Right child proof witness.
    pub right: ChildWitness<'a, C, R, HEADER_SIZE>,
    /// The step's own application data.
    pub own: OwnWitness<C::CircuitField, HEADER_SIZE>,
    /// Coordinates of the step's bridge-hash commitment, fixed here before $y$.
    pub bridge_hash_commitment: [C::CircuitField; 2],
}

impl<'a, C: Cycle, R: Rank, const HEADER_SIZE: usize> Witness<'a, C, R, HEADER_SIZE> {
    /// Create a witness from child proof references, the children's
    /// pre-computed output headers and the step's own output header,
    /// circuit id, online openings and bridge-hash commitment.
    pub fn new(
        left: &'a Proof<C, R>,
        right: &'a Proof<C, R>,
        left_output_header: &[C::CircuitField],
        right_output_header: &[C::CircuitField],
        output_header: &[C::CircuitField],
        circuit_id: CircuitIndex,
        online: online::Queries<C::CircuitField>,
        bridge_hash_commitment: C::NestedCurve,
    ) -> Result<Self> {
        let (bridge_hash_x, bridge_hash_y) =
            bridge_hash_commitment.coordinates().ok_or_else(|| {
                Error::InvalidWitness("bridge-hash commitment is the identity".into())
            })?;
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
            bridge_hash_commitment: [bridge_hash_x, bridge_hash_y],
        })
    }
}

/// What a proof exposes to the step that consumes it: its output header,
/// its circuit id and its unified instance.
///
/// The preamble holds one per child. A verifier of a proof with no parent
/// allocates one for that proof, from its own output header and circuit id.
#[derive(Gadget, Consistent)]
pub struct ProofInputs<
    'dr,
    D: Driver<'dr>,
    C: ProfiledCycle<CircuitField = D::F>,
    const HEADER_SIZE: usize,
> {
    /// Output header of this child proof.
    #[ragu(gadget)]
    pub output_header: HeaderVec<'dr, D, HEADER_SIZE>,
    /// Common quotient and evaluation sums for the native online helper.
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
    /// The child's common targets for its actual nested online walk points.
    #[ragu(gadget)]
    pub online_points: FixedVec<
        ragu_primitives::Point<'dr, D, C::NestedCurve>,
        crate::profile::online::stages::PolynomialsLen<
            C::Profile,
            crate::profile::online::stages::Nested,
        >,
    >,
    #[ragu(gadget)]
    pub circuit_id: Element<'dr, D>,
    /// What this proof's step exposed of its online openings for the
    /// statement claim's step binding, in a profile with a statement
    /// circuit: the point and the value at which it opened its first
    /// output slot, then the point at which it opened its left input's
    /// first slot (see [`online::step_binding`]). Empty for a profile
    /// without one.
    #[ragu(gadget)]
    pub step_binding: FixedVec<Element<'dr, D>, online::StepBindingLen<C::Profile>>,
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

impl<'dr, D: Driver<'dr, F = C::CircuitField>, C: ProfiledCycle, const HEADER_SIZE: usize>
    ProofInputs<'dr, D, C, HEADER_SIZE>
{
    /// Compute unified k(y) and unified+bridged k(y) values simultaneously,
    /// sharing computation.
    ///
    /// Returns `(unified_ky, unified_bridge_ky)` where:
    /// - `unified_ky` = k(y) for `(unified, 0)`
    /// - `unified_bridge_ky` = k(y) for
    ///   `(unified, output_header, circuit_id, step_binding, 0)`, the
    ///   instance this proof's `hashes_1` exported, whose step binding is
    ///   empty in a profile without a statement circuit
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
                self.step_binding.write(dr, &mut ky)?;
                Element::zero(dr).write(dr, &mut ky)?;
                ky.finish_ky(dr)?
            }),
        ))
    }

    /// Compute k(y) for the child's `compute_v` circuit: k(y) for the
    /// unified instance followed by what the circuit exported for the
    /// profile's online batches, then the zero suffix (see
    /// [`compute_v::Output`](crate::internal::native::circuits::compute_v::Output)).
    /// A profile without online batches exports nothing, so its target is
    /// `unified_ky`, the unified $k(y)$, and is not computed again.
    pub fn compute_v_bridge_ky(
        &self,
        dr: &mut D,
        y: &Element<'dr, D>,
        online_stages: &[Point<'dr, D, C::NestedCurve>],
        unified_ky: &Element<'dr, D>,
    ) -> Result<Element<'dr, D>> {
        // Setup-fixed empty layouts preserve the existing unified target.
        if C::Profile::NATIVE_ONLINE.is_empty()
            && C::Profile::NESTED_ONLINE.is_empty()
            && C::Profile::NATIVE_MESH.is_none()
            && C::Profile::NESTED_MESH.is_none()
        {
            return Ok(unified_ky.clone());
        }
        let mut ky = Horner::new(y);
        self.unified.write(dr, &mut ky)?;
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

    /// The online helper shares the core's sums and the walk's point exports.
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

    /// The `bind_endoscalar` circuit's $k(y)$ for this child: k(y) for
    /// `(unified, online_fq, online_points, 0)`, the unified instance
    /// followed by the commitments of the step's online Fq polynomials its
    /// native binding names, `online_fq`, then the actual nested online walk
    /// points. A profile that exports neither keeps the unified target,
    /// `unified_ky`.
    pub fn bind_endoscalar_ky(
        &self,
        dr: &mut D,
        y: &Element<'dr, D>,
        unified_ky: &Element<'dr, D>,
        online_fq: &[Point<'dr, D, C::NestedCurve>],
    ) -> Result<Element<'dr, D>> {
        // Setup-fixed empty exports preserve the existing unified target.
        if online_fq.is_empty() && C::Profile::NESTED_ONLINE.is_empty() {
            return Ok(unified_ky.clone());
        }
        let mut ky = Horner::new(y);
        self.unified.write(dr, &mut ky)?;
        for point in online_fq {
            point.write(dr, &mut ky)?;
        }
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
        // For decompression, the step binding follows the header with a
        // flag of one and the staged transcript digest. The first left
        // opening exposes that digest as its point. `unified_ky_values`
        // holds this wire to what `hashes_1` exported. Other steps use
        // the canonical unit header and two zeros.
        let own = {
            let mut ky = Horner::new(y);
            self.output_header.write(dr, &mut ky)?;
            Element::one().write(dr, &mut ky)?;
            self.step_binding.write(dr, &mut ky)?;
            ky::finish_extension_ky(ky, dr)?
        };
        let canonical = {
            let mut ky = Horner::new(y);
            for value in ky::output_header::<C, (), HEADER_SIZE>(())? {
                Element::constant(dr, value).write(dr, &mut ky)?;
            }
            for _ in 0..crate::profile::STEP_BINDING {
                Element::zero(dr).write(dr, &mut ky)?;
            }
            ky::finish_extension_ky(ky, dr)?
        };
        is_decompress
            .conditional_select(dr, &canonical, &own)
            .map(Some)
    }

    /// Returns true when this child's output header carries the [`Dummy`]
    /// suffix. The header is a wire the prover witnesses, and the step's
    /// own circuit, which declares its input suffixes, is not enforced in
    /// the base case. So this predicate alone does not confine the base
    /// case to the internal [`Bootstrap`] step:
    /// [`enforce_base_case_is_bootstrap`](Output::enforce_base_case_is_bootstrap)
    /// does.
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
            output_header: alloc_header(dr, allocator, output_header.as_ref().map(|h| &h[..]))?,
            mesh: FixedVec::try_from_fn(|i| {
                Element::alloc(dr, &mut (), proof.as_ref().map(|p| p.native_mesh_claims[i]))
            })?,
            online_fold: FixedVec::try_from_fn(|i| {
                Element::alloc(dr, &mut (), proof.as_ref().map(|p| p.native_online_fold[i]))
            })?,
            online_points: FixedVec::try_from_fn(|i| {
                ragu_primitives::Point::alloc(
                    dr,
                    proof.as_ref().map(|p| p.nested_online_commitments[i]),
                )
            })?,
            circuit_id: Element::alloc(
                dr,
                allocator,
                proof.as_ref().map(|p| p.circuit_id().omega_j()),
            )?,
            step_binding: FixedVec::try_from_fn(|i| {
                Element::alloc(dr, &mut (), proof.as_ref().map(|p| p.step_binding[i]))
            })?,
            unified: unified::Output::alloc_from_proof(dr, allocator, proof.as_ref().map(|p| *p))?,
        })
    }

    /// Allocate ProofInputs from the parts a proof's instance carries: the
    /// encoded output header, the circuit id as its domain point, the step
    /// binding's openings, the unified instance's values and the online
    /// batches' exports.
    #[allow(clippy::too_many_arguments)]
    pub fn alloc_from_parts(
        dr: &mut D,
        output_header: DriverValue<D, &[D::F]>,
        circuit_id: DriverValue<D, D::F>,
        step_binding: DriverValue<D, &[D::F]>,
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
            output_header: alloc_header(dr, output_header)?,
            online_points: FixedVec::try_from_fn(|i| {
                ragu_primitives::Point::alloc(dr, online_points.as_ref().map(|p| p[i]))
            })?,
            online_fold: FixedVec::try_from_fn(|i| {
                Element::alloc(dr, &mut (), online_fold.as_ref().map(|s| s[i]))
            })?,
            mesh: FixedVec::try_from_fn(|i| {
                Element::alloc(dr, &mut (), mesh.as_ref().map(|p| p[i]))
            })?,
            circuit_id: Element::alloc(dr, &mut (), circuit_id)?,
            step_binding: FixedVec::try_from_fn(|i| {
                Element::alloc(dr, &mut (), step_binding.as_ref().map(|s| s[i]))
            })?,
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
    #[ragu(gadget)]
    pub own: OwnInputs<'dr, D, HEADER_SIZE>,
    /// The bridge-hash commitment's coordinates. `collapse` equates these
    /// to the unified point, which supplies the curve-membership check.
    #[ragu(gadget)]
    pub bridge_hash_commitment: FixedVec<Element<'dr, D>, ConstLen<2>>,
}

impl<'dr, D: Driver<'dr>, C: ProfiledCycle<CircuitField = D::F>, const HEADER_SIZE: usize>
    Output<'dr, D, C, HEADER_SIZE>
{
    /// Returns true when both children's output headers in this stage
    /// carry the [`Dummy`] suffix, which is what takes the base case. The
    /// prover witnesses those headers, so this alone does not make the fuse
    /// the one that bootstraps the recursion (see
    /// [`is_dummy_input`](ProofInputs::is_dummy_input)).
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
    /// step's circuit enforces inside it: the step opens no output slot, so
    /// its adapter holds each to padding (see
    /// [`Adapter`](crate::step::internal::adapter::Adapter)). The
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
        for slot in online::OUTPUT_SLOTS {
            let opening = &self.own.online[slot];
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
        // 2 proofs * (output header + 1 circuit_id + the step binding's
        // openings + unified instance wires + the online batches' values),
        // then the own output header, circuit_id and (x, y) per online slot
        2 * (HEADER_SIZE
            + 1
            + <online::StepBindingLen<C::Profile> as ragu_primitives::vec::Len>::len()
            + unified::NUM_WIRES
            + C::Profile::NATIVE_MESH.map_or(0, |mesh| mesh.claims_len())
            + 2 * C::Profile::NESTED_ONLINE.polynomials.len()
            + <crate::profile::online::stages::Present<
                C::Profile,
                crate::profile::online::stages::Native,
                2,
            > as ragu_primitives::vec::Len>::len())
            + HEADER_SIZE
            + 1
            + 2 * online::NUM_ONLINE_FP_QUERIES
            + 2
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

        let bridge_hash_commitment = FixedVec::try_from_fn(|i| {
            Element::alloc(
                dr,
                &mut (),
                witness.as_ref().map(|w| w.bridge_hash_commitment[i]),
            )
        })?;

        Ok(Output {
            left,
            right,
            own,
            bridge_hash_commitment,
        })
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
