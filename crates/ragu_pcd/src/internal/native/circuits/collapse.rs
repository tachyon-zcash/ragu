//! Verifies both layers of the native quotient fold.
//!
//! The circuit enforces the children's application k(y) values against their
//! headers. For each group of the children's claims, it enforces that folding
//! the group's k(y) targets with the [`inner_error`] stage's quotient under mu
//! gives the collapsed value the [`outer_error`] stage witnessed. Outside the
//! base case, it enforces that folding the collapsed values with the outer
//! quotient under mu' gives the unified instance's c. The unified k(y) values
//! are enforced by [`super::hashes_1`].
//!
//! A profile's statement targets come from its headers; its binding targets
//! come from the extension commitments in the points binding stage. That
//! stage is loaded only when the profile declares a native binding circuit.
//! Its point contracts remain the responsibility of [`super::bind_endoscalar`].
//!
//! The inner quotient is fixed before mu is derived, and the outer quotient
//! before mu'.
//!
//! ## Staging
//!
//! This circuit uses [`inner_error`] as its final stage, which inherits in the
//! following chain:
//! - [`points::BindingStage`] (unenforced, and loaded only for a profile whose
//!   native extension binds; its curve membership is `bind_endoscalar`'s)
//! - [`preamble`] (unenforced; the circuits that own its fields enforce its
//!   contracts)
//! - [`outer_error`] (enforced)
//! - [`inner_error`] (enforced)
//!
//! ## Base case
//!
//! When the current step declares [`Dummy`] for both of its inputs — which
//! only the internal [`Bootstrap`] step does — the prover may witness any $c$
//! value without constraint. This is what lets [`finalize`] fold two
//! synthesized dummy proofs, which carry no meaningful revdot claim, into the
//! bootstrap proof that verifies. The constraint is enforced whenever
//! [`is_base_case`] returns false.
//!
//! For every application step the suffix read here is a constant that
//! [`padded::for_header`] bakes into the step's application circuit, so no
//! application step can present the [`Dummy`] suffix and every application
//! fuse has its child claims enforced — including one whose children carry the
//! unit `()` header. See [`is_dummy_input`] for how that binding is
//! established, and for the internal [`Rerandomize`] step, whose suffix is a
//! witness wire constrained away from `Dummy`.
//!
//! [`Dummy`]: crate::header::Dummy
//! [`Bootstrap`]: crate::step::internal::bootstrap::Bootstrap
//! [`Rerandomize`]: crate::step::internal::rerandomize::Rerandomize
//! [`finalize`]: crate::ApplicationBuilder::finalize
//! [`padded::for_header`]: crate::step::internal::padded::for_header
//! [`is_dummy_input`]: super::super::stages::preamble::ProofInputs::is_dummy_input
//!
//! [`is_base_case`]: super::super::stages::preamble::Output::is_base_case
//! [`inner_error`]: super::super::stages::inner_error
//! [`outer_error`]: super::super::stages::outer_error
//! [`preamble`]: super::super::stages::preamble
//! [`points::BindingStage`]: super::super::stages::points::BindingStage

use core::marker::PhantomData;

use ragu_circuits::{
    WithAux,
    polynomials::Rank,
    staging::{MultiStage, MultiStageCircuit, StageBuilder},
};
use ragu_core::{
    Cycle, Result,
    drivers::{Driver, DriverValue},
    gadgets::Bound,
    maybe::Maybe,
};
use ragu_primitives::{GadgetExt as _, allocator::Standard, vec::FixedVec};

use super::super::{
    claims::{TwoProofKySource, ky_values},
    stages::{
        inner_error as native_inner_error, outer_error as native_outer_error,
        preamble as native_preamble,
    },
    unified::{self, OutputBuilder},
};
use crate::{
    internal::{fold_revdot, ky},
    profile::{Profile, ProfiledCycle},
};

/// Circuit that verifies both layers of the revdot reduction.
///
/// See the [module-level documentation] for details on the operations
/// performed by this circuit.
///
/// [module-level documentation]: self
pub struct Circuit<C: Cycle, R, const HEADER_SIZE: usize, FP: fold_revdot::Parameters> {
    _marker: PhantomData<(C, R, FP)>,
}

impl<C: ProfiledCycle, R: Rank, const HEADER_SIZE: usize, FP: fold_revdot::Parameters>
    Circuit<C, R, HEADER_SIZE, FP>
{
    /// Creates the multi-stage circuit for both revdot folding layers.
    pub fn new() -> MultiStage<C::CircuitField, R, Self> {
        MultiStage::new(Circuit {
            _marker: PhantomData,
        })
    }
}

/// Witness for the native collapse circuit.
pub struct Witness<
    'a,
    C: ProfiledCycle,
    R: Rank,
    const HEADER_SIZE: usize,
    FP: fold_revdot::Parameters,
> {
    /// The binding stage: the children's walked commitments, for the
    /// nested extension stages the binding circuit's k(y) is over.
    pub binding: &'a super::super::stages::points::BindingWitness<C::NestedCurve, C::Profile>,
    /// Witness for the preamble stage (contains child unified instances with c values).
    pub preamble_witness: &'a native_preamble::Witness<'a, C, R, HEADER_SIZE>,
    /// The unified instance containing challenges and accumulated coverage.
    pub unified: unified::Instance<C>,
    /// Witness for the inner error stage (layer 1 error terms).
    pub inner_error_witness: &'a native_inner_error::Witness<C, FP>,
    /// Witness for the outer error stage (layer 2 error terms + collapsed values).
    pub outer_error_witness: &'a native_outer_error::Witness<C, FP>,
}

impl<C: ProfiledCycle, R: Rank, const HEADER_SIZE: usize, FP: fold_revdot::Parameters>
    MultiStageCircuit<C::CircuitField, R> for Circuit<C, R, HEADER_SIZE, FP>
{
    type Last = native_inner_error::Stage<C, R, HEADER_SIZE, FP>;

    type Instance<'source> = &'source unified::Instance<C>;
    type Witness<'source> = Witness<'source, C, R, HEADER_SIZE, FP>;
    type Output = unified::InternalOutputKind<C>;
    type Aux<'source> = unified::Instance<C>;

    fn instance<'dr, 'source: 'dr, D: Driver<'dr, F = C::CircuitField>>(
        &self,
        _: &mut D,
        _: DriverValue<D, Self::Instance<'source>>,
    ) -> Result<Bound<'dr, D, Self::Output>>
    where
        Self: 'dr,
    {
        unreachable!("instance for internal circuits is not invoked")
    }

    fn witness<'a, 'dr, 'source: 'dr, D: Driver<'dr, F = C::CircuitField>>(
        &self,
        builder: StageBuilder<'a, 'dr, D, R, (), Self::Last>,
        witness: DriverValue<D, Self::Witness<'source>>,
    ) -> Result<WithAux<Bound<'dr, D, Self::Output>, DriverValue<D, Self::Aux<'source>>>>
    where
        Self: 'dr,
    {
        type Binding<C, P> = super::super::stages::points::BindingStage<C, P>;
        // The binding stage is loaded, and so in the circuit's claim, only
        // for a profile whose native extension binds: the circuit reads
        // its extension points for the binding k(y) and nothing else.
        let extension = C::Profile::native_extension();
        let (binding, builder) = if extension.binding.is_some() {
            let (binding, builder) = builder.add_stage::<Binding<C::NestedCurve, C::Profile>>()?;
            (Some(binding), builder)
        } else {
            (
                None,
                builder.skip_stage::<Binding<C::NestedCurve, C::Profile>>()?,
            )
        };
        let (preamble, builder) =
            builder.add_stage::<native_preamble::Stage<C, R, HEADER_SIZE>>()?;
        let (outer_error, builder) =
            builder.add_stage::<native_outer_error::Stage<C, R, HEADER_SIZE, FP>>()?;
        let (inner_error, builder) =
            builder.add_stage::<native_inner_error::Stage<C, R, HEADER_SIZE, FP>>()?;
        let dr = builder.finish();
        let binding = match binding {
            Some(binding) => Some(binding.unenforced(dr, witness.as_ref().map(|w| w.binding))?),
            None => None,
        };
        let preamble = preamble.unenforced(dr, witness.as_ref().map(|w| w.preamble_witness))?;
        let outer_error =
            outer_error.enforced(dr, witness.as_ref().map(|w| w.outer_error_witness))?;
        let inner_error =
            inner_error.enforced(dr, witness.as_ref().map(|w| w.inner_error_witness))?;

        let allocator = &mut Standard::new();
        let mut unified_output = OutputBuilder::new(witness.map(|w| w.unified));

        // Compute application k(y) values and enforce equality with staged
        // values witnessed in outer_error. The y challenge is derived in
        // hashes_1 and read (not received) here, since hashes_1 owns coverage.
        let y = unified_output.y.read(dr, allocator)?;
        let left_application_ky = preamble.left.application_ky(dr, &y)?;
        let right_application_ky = preamble.right.application_ky(dr, &y)?;

        left_application_ky.enforce_equal(dr, &outer_error.left.application)?;
        right_application_ky.enforce_equal(dr, &outer_error.right.application)?;

        // Get layer 1 folding challenges from the unified instance.
        let mu = unified_output.mu.read(dr, allocator)?;
        let fold_products = fold_revdot::ClaimFolder::new(&mu);

        // Assemble k(y) values from multiple sources. The ordering must match
        // claims's iteration order for correct folding correspondence.
        // Sources include:
        // - Child c values from preamble (the children's final revdot claims)
        // - Application and unified k(y) evaluations from outer_error
        // The statement circuit's k(y) values come straight from the
        // preamble, as the application ones are above, and the
        // binding circuit's from the children's nested extension stage
        // commitments the binding stage walks. Reuse the same y wire for
        // these targets: each unified slot may be read only once.
        let (left_statement, right_statement) = if extension.statement.is_some() {
            (
                preamble.left.statement_ky::<C::Profile>(dr, &y)?,
                preamble.right.statement_ky::<C::Profile>(dr, &y)?,
            )
        } else {
            (None, None)
        };
        let (left_binding, right_binding) = match (&extension.binding, &binding) {
            (Some(declared), Some(binding)) => {
                let bound = |child: &super::super::stages::points::ChildBinding<'dr, D, _, _>| {
                    ky::bound(Some(declared), |j| child.extension[j as usize].clone())
                };
                (
                    ky::binding_ky(dr, &y, &bound(&binding.left))?,
                    ky::binding_ky(dr, &y, &bound(&binding.right))?,
                )
            }
            _ => (None, None),
        };
        let ky = TwoProofKySource::new(
            dr,
            preamble.left.unified.c.clone(),
            preamble.right.unified.c.clone(),
            &outer_error.left,
            &outer_error.right,
            left_statement,
            right_statement,
            left_binding,
            right_binding,
        );
        let mut ky = ky_values::<C::Profile, _>(&ky);

        // Verify each group's layer 1 reduction. For each group, fold the
        // inner error terms with the corresponding k(y) values and enforce the
        // result matches the collapsed value witnessed in outer error.
        for (i, error_terms) in inner_error.error_terms.iter().enumerate() {
            let ky = FixedVec::from_fn(|_| ky.next().unwrap());

            fold_products
                .fold_inner::<FP>(dr, error_terms, &ky)?
                .enforce_equal(dr, &outer_error.collapsed[i])?;
        }

        // The second folding layer uses its own challenge.
        let mu_prime = unified_output.mu_prime.read(dr, allocator)?;

        // Compute the final folded revdot claim c via layer 2 reduction.
        // The collapsed values checked above are this layer's k(y) inputs.
        {
            let fold_products = fold_revdot::ClaimFolder::new(&mu_prime);
            let computed_c = fold_products.fold_outer::<FP>(
                dr,
                &outer_error.error_terms,
                &outer_error.collapsed,
            )?;

            // Retrieve the witnessed c from the unified instance and mark it
            // as covered by this circuit.
            let witnessed_c = unified_output.c.receive(dr, allocator)?;

            // Enforce witnessed_c == computed_c, except in the base case: the
            // internal bootstrap step, the only step declaring `Dummy`
            // inputs. There the prover may witness any c, which is what lets it
            // fuse two synthesized proofs that do not verify; the resulting
            // proof attests nothing in return.
            preamble
                .is_base_case(dr, allocator)?
                .not(dr)
                .conditional_enforce_equal(dr, allocator, &witnessed_c, &computed_c)?;
        }

        let (output, aux) = unified_output.finish(dr, allocator)?;
        Ok(WithAux::new(output, aux))
    }
}
