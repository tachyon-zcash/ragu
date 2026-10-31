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
    Boolean, Element, GadgetExt,
    allocator::Allocator,
    consistent::Consistent,
    vec::{CollectFixed, ConstLen, FixedVec},
};

use crate::{
    Proof,
    framework_hooks::{HookLayout, PolyQueries, WitnessPolys},
    header::{Header, Suffix},
    instance,
    internal::{ky, native::unified},
    poly_commitment::{HANDLE_WIRES, PolyHandle},
    profile::{Profile, ProfiledCycle},
    proof::{PolyQuery, hook_region},
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
    /// The child's poly-queries; positions it left unused hold the padding
    /// query.
    #[ragu(gadget)]
    pub poly_queries: FixedVec<instance::PolyQuery<'dr, D, C>, PolyQueries<C::Profile>>,
    /// The handles of the child's witnessed polynomials; positions it left
    /// unused hold the padding polynomial's.
    #[ragu(gadget)]
    pub witness_polys: FixedVec<PolyHandle<'dr, D, C>, WitnessPolys<C::Profile>>,
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

    /// The [`read_hooks`] circuit's $k(y)$ over this child's application
    /// stage: the handles, then the poly-queries, in the order the adapter
    /// staged them, so the claim holds only if these wires are the ones the
    /// child's stage holds. `None` for a profile that does not
    /// [`reads_hooks`](crate::internal::native::reads_hooks).
    ///
    /// The claim's trace is the stage polynomial alone, which has no `ONE`
    /// wire, so the constant term is zero rather than the usual one.
    ///
    /// [`read_hooks`]: super::super::circuits::read_hooks
    pub fn hooks_ky(&self, dr: &mut D, y: &Element<'dr, D>) -> Result<Option<Element<'dr, D>>> {
        if !crate::internal::native::reads_hooks::<C::Profile>() {
            return Ok(None);
        }
        let mut ky = Horner::new(y);
        self.witness_polys.write(dr, &mut ky)?;
        self.poly_queries.write(dr, &mut ky)?;
        Element::zero(dr).write(dr, &mut ky)?;
        Ok(Some(ky.finish(dr)))
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
    /// Allocates a child's hook region, padded positions included: each
    /// witnessed polynomial's handle, then each poly-query's handle, `x` and
    /// `y` (see [`hook_region`]).
    #[allow(clippy::type_complexity)]
    fn alloc_hook_region(
        dr: &mut D,
        region: DriverValue<D, Vec<C::CircuitField>>,
    ) -> Result<(
        FixedVec<PolyHandle<'dr, D, C>, WitnessPolys<C::Profile>>,
        FixedVec<instance::PolyQuery<'dr, D, C>, PolyQueries<C::Profile>>,
    )> {
        let layout = HookLayout::of::<C::Profile>();
        D::try_just(|| {
            if region.as_ref().take().len() == layout.poly_query_instance_len() {
                Ok(())
            } else {
                Err(Error::MalformedEncoding(
                    "the hook region does not fit the profile's hook layout".into(),
                ))
            }
        })?;
        let pair = |at: usize| region.as_ref().map(|r| [r[at], r[at + 1]]);
        let one = |at: usize| region.as_ref().map(|r| r[at]);
        let witness_polys =
            FixedVec::try_from_fn(|i| PolyHandle::alloc(dr, pair(HANDLE_WIRES * i)))?;
        let queries_at = HANDLE_WIRES * layout.witness_polys;
        let poly_queries = FixedVec::try_from_fn(|i| {
            let at = queries_at + (HANDLE_WIRES + 2) * i;
            Ok(instance::PolyQuery {
                com: PolyHandle::alloc(dr, pair(at))?,
                x: Element::alloc(dr, &mut (), one(at + HANDLE_WIRES))?,
                y: Element::alloc(dr, &mut (), one(at + HANDLE_WIRES + 1))?,
            })
        })?;
        Ok((witness_polys, poly_queries))
    }

    /// Allocate ProofInputs from a proof reference and pre-computed output
    /// header.
    pub fn alloc<R: Rank>(
        dr: &mut D,
        proof: DriverValue<D, &Proof<C, R>>,
        output_header: DriverValue<D, &FixedVec<D::F, ConstLen<HEADER_SIZE>>>,
    ) -> Result<Self> {
        // A child proof reaching the fuse has not passed through `verify`, so
        // this is its own boundary. `alloc` has no verdict to return, hence
        // `Err`: a carried artifact whose encoding does not fit its profile,
        // not a witness the prover authored in-circuit.
        D::try_just(|| {
            if proof.as_ref().take().has_shape() {
                Ok(())
            } else {
                Err(Error::MalformedEncoding(
                    "proof does not carry exactly the profile's hook lists".into(),
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
        let children = ChildHeaders {
            left: alloc_header(dr, allocator, proof.as_ref().map(|p| p.left_header()))?,
            right: alloc_header(dr, allocator, proof.as_ref().map(|p| p.right_header()))?,
        };
        let output_header = alloc_header(dr, allocator, output_header.as_ref().map(|h| &h[..]))?;
        // The one cast a `Proof` cannot avoid: it records commitments, and the
        // native circuit can only hold wires.
        let (witness_polys, poly_queries) = Self::alloc_hook_region(
            dr,
            D::try_just(|| proof.as_ref().take().preamble_hook_region())?,
        )?;
        Ok(ProofInputs {
            children,
            output_header,
            poly_queries,
            witness_polys,
            circuit_id: Element::alloc(
                dr,
                allocator,
                proof.as_ref().map(|p| p.circuit_id().omega_j()),
            )?,
            unified: unified::Output::alloc_from_proof(dr, allocator, proof.as_ref().map(|p| *p))?,
        })
    }

    /// Allocate ProofInputs from the parts a proof's instance and stage carry:
    /// the child headers, the encoded output header, the witnessed
    /// polynomials' commitments and the poly-queries, the circuit id as its
    /// domain point, and the unified instance's values.
    #[allow(clippy::too_many_arguments)]
    pub fn alloc_from_parts(
        dr: &mut D,
        left_header: DriverValue<D, &[D::F]>,
        right_header: DriverValue<D, &[D::F]>,
        output_header: DriverValue<D, &[D::F]>,
        witness_polys: DriverValue<D, &[C::HostCurve]>,
        poly_queries: DriverValue<D, &[PolyQuery<C::HostCurve>]>,
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

        let children = ChildHeaders {
            left: alloc_header(dr, left_header)?,
            right: alloc_header(dr, right_header)?,
        };
        let output_header = alloc_header(dr, output_header)?;
        let (witness_polys, poly_queries) = Self::alloc_hook_region(
            dr,
            D::try_just(|| hook_region::<C>(witness_polys.take(), poly_queries.take()))?,
        )?;
        Ok(ProofInputs {
            children,
            output_header,
            poly_queries,
            witness_polys,
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
        // 2 proofs * (3 headers * HEADER_SIZE + the hook region + 1
        // circuit_id + unified instance wires)
        2 * (3 * HEADER_SIZE
            + HookLayout::of::<C::Profile>().poly_query_instance_len()
            + 1
            + unified::NUM_WIRES)
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
        assert_stage_values(&Stage::<
            crate::profile::Profiled<Pasta, crate::AppHooks<4, 2>>,
            R,
            { HEADER_SIZE },
        >::default());
    }
}
