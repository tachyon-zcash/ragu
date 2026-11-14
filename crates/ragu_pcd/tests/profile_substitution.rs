//! Submit another profile's complete proof payload to a fixed receiving setup.
//! The copying helpers preserve every field, including all commitment caches
//! and compression messages. Exhaustive destructuring keeps those copies
//! complete when either proof representation changes.

use ragu_backend::ReferenceBackend;
use ragu_circuits::polynomials::{ProductionRank, R, Rank};
use ragu_core::{
    Cycle, Error, Result,
    drivers::{Driver, DriverValue},
    maybe::Maybe,
    pasta::{Fp, Fq, Pasta},
};
use ragu_primitives::{Element, GadgetExt, allocator::Standard as Allocator};
use rand::{SeedableRng, rngs::StdRng};
use udon::field::Field;

use super::{Proof, recursive_propagation_tests::support::Value};
use crate::{
    Application, ApplicationBuilder, CompressedProof, Pcd,
    compress::instance::Instance,
    ipa::IpaCycle,
    profile::{Aggregator, Profile, Profiled, ProfiledCycle, Shape, Standard, testing::Proving},
    step::{Encoded, Index, Oracles, Step},
};

const HEADER_SIZE: usize = 4;
type C<P> = Profiled<Pasta, P>;
type App<P, R> = Application<'static, C<P>, R, HEADER_SIZE>;
type TestPcd<P> = Pcd<C<P>, ProductionRank, Value>;

#[path = "compressed_profile_attacks.rs"]
mod compressed_attacks;

#[path = "verifier_setup.rs"]
mod verifier_setup;

macro_rules! copy_fields {
    ($value:expr, $structure:ident { $($field:ident),* $(,)? }) => {{
        let $structure { $($field,)* } = $value;
        $structure { $($field,)* }
    }};
}

fn copy_proof_payload<
    S: Cycle,
    T: Cycle<
            CircuitField = S::CircuitField,
            ScalarField = S::ScalarField,
            HostCurve = S::HostCurve,
            NestedCurve = S::NestedCurve,
        >,
    Rk: Rank,
>(
    proof: Proof<S, Rk>,
) -> Proof<T, Rk> {
    copy_fields!(
        proof,
        Proof {
            bridge_alpha,
            circuit_id,
            left_header,
            right_header,
            native_application_rx,
            native_application_stage_rx,
            native_preamble_rx,
            native_inner_error_rx,
            native_outer_error_rx,
            native_a_poly,
            native_b_poly,
            native_query_rx,
            native_registry_xy_poly,
            native_eval_rx,
            native_p_poly,
            native_hashes_1_rx,
            native_hashes_2_rx,
            native_collapse_rx,
            native_compute_v_rx,
            native_bind_challenges_rxs,
            native_bind_beta_rx,
            native_bind_endoscalar_rx,
            native_endoscaling_step_rxs,
            native_extension_circuit_rxs,
            native_extension_stage_rxs,
            native_points_binding_rx,
            native_points_children_rx,
            native_points_registry_wx_rx,
            native_points_ab_rx,
            native_points_f_rx,
            native_points_walk_rx,
            online_polynomials,
            online_openings,
            bridge_preamble_rx,
            bridge_hash_rx,
            bridge_s_prime_rx,
            bridge_inner_error_rx,
            bridge_outer_error_rx,
            bridge_query_rx,
            bridge_f_rx,
            bridge_eval_rx,
            bridge_ab_rx,
            nested_endoscaling_step_rxs,
            nested_extension_circuit_rxs,
            nested_extension_stage_rxs,
            nested_endoscalar_rx,
            nested_points_rx,
            nested_a_poly,
            nested_b_poly,
            nested_registry_xy_poly,
            nested_p_poly,
            nested_challenges_rx,
            nested_challenges_partial,
            nested_collapse_rx,
            nested_compute_v_rx,
            nested_endoscaling_step_commitments,
            nested_extension_circuit_commitments,
            nested_extension_stage_commitments,
            nested_endoscalar_commitment,
            nested_points_commitment,
            nested_a_commitment,
            nested_b_commitment,
            nested_registry_xy_commitment,
            nested_p_commitment,
            nested_challenges_commitment,
            nested_collapse_commitment,
            nested_compute_v_commitment,
            w,
            y,
            z,
            mu,
            mu_prime,
            x,
            alpha,
            u,
            pre_beta,
            native_application_commitment,
            native_application_stage_commitment,
            native_preamble_commitment,
            native_inner_error_commitment,
            native_outer_error_commitment,
            native_a_commitment,
            native_b_commitment,
            native_query_commitment,
            native_registry_xy_commitment,
            native_eval_commitment,
            native_p_commitment,
            native_hashes_1_commitment,
            native_hashes_2_commitment,
            native_collapse_commitment,
            native_compute_v_commitment,
            native_bind_challenges_commitments,
            native_bind_beta_commitment,
            native_bind_endoscalar_commitment,
            native_endoscaling_step_commitments,
            native_extension_circuit_commitments,
            native_extension_stage_commitments,
            native_points_binding_commitment,
            native_points_children_commitment,
            native_points_registry_wx_commitment,
            native_points_ab_commitment,
            native_points_f_commitment,
            native_points_walk_commitment,
            online_commitments,
            bridge_preamble_commitment,
            bridge_hash_commitment,
            bridge_s_prime_commitment,
            bridge_inner_error_commitment,
            bridge_outer_error_commitment,
            bridge_query_commitment,
            bridge_f_commitment,
            bridge_eval_commitment,
            bridge_ab_commitment,
        }
    )
}

fn copy_compressed_payload<
    S: Cycle,
    T: Cycle<
            CircuitField = S::CircuitField,
            ScalarField = S::ScalarField,
            HostCurve = S::HostCurve,
            NestedCurve = S::NestedCurve,
        >,
>(
    proof: CompressedProof<S>,
) -> CompressedProof<T> {
    let CompressedProof {
        instance,
        native,
        nested,
    } = proof;
    let instance = copy_fields!(
        instance,
        Instance {
            circuit_id,
            left_header,
            right_header,
            online,
            native,
            native_registry_xy,
            native_p,
            online_commitments,
            nested,
            nested_registry_xy,
            nested_p,
            nested_challenges_partial,
            bridge_alpha,
            c,
            v,
            nested_c,
            nested_v,
            left,
            right,
            a_at_u,
            b_at_u,
            nested_left,
            nested_right,
            nested_a_at_u,
            nested_b_at_u,
        }
    );
    CompressedProof {
        instance,
        native,
        nested,
    }
}

/// A seed is either constrained to a fixed public value or unconstrained.
struct Seed {
    expected: Option<Fp>,
}

impl<Cy: Cycle<CircuitField = Fp>> Step<Cy> for Seed {
    const INDEX: Index = Index::new(0);
    type Witness<'source> = Fp;
    type Aux<'source> = ();
    type Left = ();
    type Right = ();
    type Output = Value;

    fn witness<'dr, 'source: 'dr, D: Driver<'dr, F = Fp>, const HS: usize>(
        &self,
        dr: &mut D,
        _: &mut Oracles<'_, 'dr, D, Cy, Self>,
        witness: DriverValue<D, Fp>,
        _: DriverValue<D, ()>,
        _: DriverValue<D, ()>,
    ) -> Result<(
        (
            Encoded<'dr, D, (), HS>,
            Encoded<'dr, D, (), HS>,
            Encoded<'dr, D, Value, HS>,
        ),
        DriverValue<D, Fp>,
        DriverValue<D, ()>,
    )>
    where
        Self: 'dr,
    {
        let value = Element::alloc(dr, &mut Allocator::new(), witness.clone())?;
        if let Some(expected) = self.expected {
            let expected = Element::constant(dr, expected);
            value.enforce_equal(dr, &expected)?;
        }
        Ok((
            (
                Encoded::from_gadget(()),
                Encoded::from_gadget(()),
                Encoded::from_gadget(value),
            ),
            witness,
            D::unit(),
        ))
    }
}

/// The parent adds the exact child-header wires it returns to the adapter.
struct Sum;

impl<Cy: Cycle<CircuitField = Fp>> Step<Cy> for Sum {
    const INDEX: Index = Index::new(1);
    type Witness<'source> = ();
    type Aux<'source> = ();
    type Left = Value;
    type Right = Value;
    type Output = Value;

    fn witness<'dr, 'source: 'dr, D: Driver<'dr, F = Fp>, const HS: usize>(
        &self,
        dr: &mut D,
        _: &mut Oracles<'_, 'dr, D, Cy, Self>,
        _: DriverValue<D, ()>,
        left: DriverValue<D, Fp>,
        right: DriverValue<D, Fp>,
    ) -> Result<(
        (
            Encoded<'dr, D, Value, HS>,
            Encoded<'dr, D, Value, HS>,
            Encoded<'dr, D, Value, HS>,
        ),
        DriverValue<D, Fp>,
        DriverValue<D, ()>,
    )>
    where
        Self: 'dr,
    {
        let allocator = &mut Allocator::new();
        let left = Element::alloc(dr, allocator, left)?;
        let right = Element::alloc(dr, allocator, right)?;
        let output = left.add(dr, &right);
        let data = output.value().map(|value| *value);
        Ok((
            (
                Encoded::from_gadget(left),
                Encoded::from_gadget(right),
                Encoded::from_gadget(output),
            ),
            data,
            D::unit(),
        ))
    }
}

/// A custom profile whose application seed omits the fixed-value constraint.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
struct Permissive;

impl Profile for Permissive {
    const NAME: &'static str = "permissive substitution fixture";
    const NATIVE_EXTENSION: usize = 0;
    const NESTED_EXTENSION: usize = 0;

    type Context<'params, Base, Rk, B>
        = ()
    where
        Base: IpaCycle + ProfiledCycle<Profile = Standard>,
        Rk: Rank,
        B: crate::SelectableBackend;
}

/// Builds the application, installing the given tags instead of the derived
/// ones where supplied. The seam stands in for another setup: the derivation
/// gives these circuits their own tags.
fn application<P: Profile, Rk: Rank>(
    tags: (Option<Fp>, Option<Fq>),
    expected: Option<Fp>,
) -> Result<App<P, Rk>>
where
    P::Context<'static, Pasta, Rk, ReferenceBackend>: Default,
{
    let mut builder = ApplicationBuilder::<C<P>, Rk, HEADER_SIZE>::new()
        .register(Seed { expected })?
        .register(Sum)?;
    if let Some(native) = tags.0 {
        builder = builder.with_native_tag(native);
    }
    if let Some(nested) = tags.1 {
        builder = builder.with_nested_tag(nested);
    }
    builder.finalize(if Rk::RANK <= 13 {
        crate::pasta::baked()
    } else {
        crate::pasta::baked_aggregator()
    })
}

#[derive(Clone, Copy, Debug)]
enum DifferentTags {
    Both,
    Native,
    Nested,
}

fn check_both_verifiers<P: Profile, Rk: Rank>(
    app: &App<P, Rk>,
    pcd: &Pcd<C<P>, Rk, Value>,
    expected: bool,
    rng: &mut StdRng,
) -> Result<()> {
    assert_eq!(
        app.verify_uncompressed(pcd, &mut *rng)?,
        expected,
        "ordinary verifier"
    );
    let compressed = app.compress(pcd, rng)?;
    assert_eq!(
        app.verify_compressed(&compressed)?,
        expected,
        "compressed verifier"
    );
    Ok(())
}

/// Submits the sender's payload to receivers of profile `T`: first one with
/// the tags its registries derive, which accepts the payload exactly when
/// `share_registries` says the two profiles register the same circuits; then
/// ones whose tags differ from the sender's in either registry or both,
/// standing in for another setup, which must reject it however it is reused.
fn check_same_shape<S: Profile, T: Profile>(
    sender_constraint: Option<Fp>,
    receiver_constraint: Option<Fp>,
    foreign_value: Fp,
    local_value: Fp,
    share_registries: bool,
) -> Result<()>
where
    S::Context<'static, Pasta, ProductionRank, ReferenceBackend>: Default,
    T::Context<'static, Pasta, ProductionRank, ReferenceBackend>: Default,
{
    assert_eq!(Shape::of::<S>(), Shape::of::<T>());
    let sender = application::<S, ProductionRank>((None, None), sender_constraint)?;
    let (native_tag, nested_tag) = (sender.native_registry.tag(), sender.nested_registry.tag());
    let mut rng = StdRng::seed_from_u64(0x908_1501);
    let (source, ()) = sender.seed(
        &mut rng,
        Seed {
            expected: sender_constraint,
        },
        foreign_value,
    )?;
    assert!(sender.verify_uncompressed(&source, &mut rng)?);
    let compressed_source = sender.compress(&source, &mut rng)?;
    assert!(sender.verify_compressed(&compressed_source)?);

    // Tags are derived from the registered circuits, so a receiver with its
    // own derived tags holds the sender's registries exactly when the two
    // profiles register the same circuits, and only then accepts the payload.
    let derived = application::<T, ProductionRank>((None, None), receiver_constraint)?;
    assert_eq!(
        derived.native_registry.tag() == native_tag && derived.nested_registry.tag() == nested_tag,
        share_registries,
        "the profiles' registries"
    );
    let foreign = copy_proof_payload::<C<S>, C<T>, ProductionRank>(source.proof().clone())
        .carry::<Value>(foreign_value);
    check_both_verifiers(&derived, &foreign, share_registries, &mut rng)?;
    let compressed = copy_compressed_payload::<C<S>, C<T>>(compressed_source.proof().clone())
        .carry::<Value>(foreign_value);
    assert_eq!(derived.verify_compressed(&compressed)?, share_registries);

    for changed in [
        DifferentTags::Both,
        DifferentTags::Native,
        DifferentTags::Nested,
    ] {
        // A receiving setup whose tags differ from the sender's in the given
        // registries and agree in the others, whatever the derivation gives
        // the receiver's own circuits: the test seam isolates either tag while
        // the profile types and proof payloads still differ.
        let tags = match changed {
            DifferentTags::Both => (Some(native_tag + Fp::ONE), Some(nested_tag + Fq::ONE)),
            DifferentTags::Native => (Some(native_tag + Fp::ONE), Some(nested_tag)),
            DifferentTags::Nested => (Some(native_tag), Some(nested_tag + Fq::ONE)),
        };
        let receiver = application::<T, ProductionRank>(tags, receiver_constraint)?;
        assert_eq!(
            receiver.native_registry.tag() == native_tag,
            matches!(changed, DifferentTags::Nested)
        );
        assert_eq!(
            receiver.nested_registry.tag() == nested_tag,
            matches!(changed, DifferentTags::Native)
        );
        let (local, ()) = receiver.seed(
            &mut rng,
            Seed {
                expected: receiver_constraint,
            },
            local_value,
        )?;
        check_both_verifiers(&receiver, &local, true, &mut rng)?;

        let foreign = copy_proof_payload::<C<S>, C<T>, ProductionRank>(source.proof().clone())
            .carry::<Value>(foreign_value);
        assert!(
            foreign.proof().well_formed::<HEADER_SIZE>(),
            "same-shape substitution must reach the claim checks"
        );
        let compressed = copy_compressed_payload::<C<S>, C<T>>(compressed_source.proof().clone())
            .carry::<Value>(foreign_value);
        assert!(
            !receiver.verify_compressed(&compressed)?,
            "foreign compressed payload: {changed:?}"
        );
        check_both_verifiers(&receiver, &foreign, false, &mut rng)?;
        let refreshed = receiver.rerandomize(foreign.clone(), &mut rng)?;
        check_both_verifiers(&receiver, &refreshed, false, &mut rng)?;

        let (parent, ()) = receiver.fuse(&mut rng, Sum, (), local.clone(), local.clone())?;
        assert_eq!(*parent.data(), local_value + local_value);
        check_both_verifiers(&receiver, &parent, true, &mut rng)?;
        let (grandparent, ()) = receiver.fuse(&mut rng, Sum, (), parent, local.clone())?;
        check_both_verifiers(&receiver, &grandparent, true, &mut rng)?;

        for foreign_on_left in [true, false] {
            let (left, right) = if foreign_on_left {
                (foreign.clone(), local.clone())
            } else {
                (local.clone(), foreign.clone())
            };
            let (parent, ()) = receiver.fuse(&mut rng, Sum, (), left, right)?;
            assert_eq!(*parent.data(), foreign_value + local_value);
            check_both_verifiers(&receiver, &parent, false, &mut rng)?;
            let (left, right) = if foreign_on_left {
                (parent, local.clone())
            } else {
                (local.clone(), parent)
            };
            let (grandparent, ()) = receiver.fuse(&mut rng, Sum, (), left, right)?;
            check_both_verifiers(&receiver, &grandparent, false, &mut rng)?;
        }
    }
    Ok(())
}

/// The aggregator declares no extension yet, so it registers the standard
/// profile's circuits and derives its tags: a standard payload verifies under
/// it. Under any other tags, as once the aggregator's decompression circuits
/// land, the payload is rejected.
#[test]
fn aggregator_accepts_standard_payloads_only_with_the_same_registries() -> Result<()> {
    check_same_shape::<Standard, Aggregator>(
        Some(Fp::from(7)),
        Some(Fp::from(7)),
        Fp::from(7),
        Fp::from(7),
        true,
    )
}

/// The converse of
/// [`aggregator_accepts_standard_payloads_only_with_the_same_registries`].
#[test]
fn standard_accepts_aggregator_payloads_only_with_the_same_registries() -> Result<()> {
    check_same_shape::<Aggregator, Standard>(
        Some(Fp::from(7)),
        Some(Fp::from(7)),
        Fp::from(7),
        Fp::from(7),
        true,
    )
}

#[test]
fn weaker_profile_cannot_bypass_standard_constraints() -> Result<()> {
    // A Standard leaf must be 7. The foreign profile accepts 9 instead,
    // so rejection here also protects an independently false statement.
    assert_ne!(Fp::from(9), Fp::from(7));
    check_same_shape::<Permissive, Standard>(
        None,
        Some(Fp::from(7)),
        Fp::from(9),
        Fp::from(7),
        false,
    )
}

#[test]
fn standard_cannot_substitute_for_a_weaker_profile() -> Result<()> {
    check_same_shape::<Standard, Permissive>(
        Some(Fp::from(7)),
        None,
        Fp::from(7),
        Fp::from(9),
        false,
    )
}

fn check_different_shapes<S: Profile, T: Profile>() -> Result<()>
where
    S::Context<'static, Pasta, R<14>, ReferenceBackend>: Default,
    T::Context<'static, Pasta, R<14>, ReferenceBackend>: Default,
{
    assert_ne!(Shape::of::<S>(), Shape::of::<T>());
    let sender = application::<S, R<14>>((None, None), Some(Fp::from(7)))?;
    let receiver = application::<T, R<14>>((None, None), Some(Fp::from(7)))?;
    let mut rng = StdRng::seed_from_u64(0x908_1502);
    let (source, ()) = sender.seed(
        &mut rng,
        Seed {
            expected: Some(Fp::from(7)),
        },
        Fp::from(7),
    )?;
    let (local, ()) = receiver.seed(
        &mut rng,
        Seed {
            expected: Some(Fp::from(7)),
        },
        Fp::from(7),
    )?;
    assert!(sender.verify_uncompressed(&source, &mut rng)?);
    assert!(receiver.verify_uncompressed(&local, &mut rng)?);
    let compressed = sender.compress(&source, &mut rng)?;
    assert!(sender.verify_compressed(&compressed)?);
    let local_compressed = receiver.compress(&local, &mut rng)?;
    assert!(receiver.verify_compressed(&local_compressed)?);

    let foreign =
        copy_proof_payload::<C<S>, C<T>, R<14>>(source.into_parts().0).carry::<Value>(Fp::from(7));
    assert!(!foreign.proof().well_formed::<HEADER_SIZE>());
    assert!(!receiver.verify_uncompressed(&foreign, &mut rng)?);
    assert!(matches!(
        receiver.compress(&foreign, &mut rng),
        Err(Error::InvalidWitness(_))
    ));
    let compressed = copy_compressed_payload::<C<S>, C<T>>(compressed.into_parts().0)
        .carry::<Value>(Fp::from(7));
    assert!(!receiver.verify_compressed(&compressed)?);
    Ok(())
}

#[test]
fn standard_cannot_substitute_for_an_extended_profile() -> Result<()> {
    check_different_shapes::<Standard, Proving>()
}

#[test]
fn extended_profile_cannot_substitute_for_standard() -> Result<()> {
    check_different_shapes::<Proving, Standard>()
}
