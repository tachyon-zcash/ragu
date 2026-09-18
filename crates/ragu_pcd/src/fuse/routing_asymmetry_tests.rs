//! Review R10: adversarial left/right routing for ordered application steps.
//!
//! The children have distinct public data and proof objects. Each attack swaps
//! one representation of their roles while freezing the ordered relation and
//! every other object. Polynomial commitment caches are repaired when their
//! polynomial changes, so rejection reaches the routed obligation rather than
//! stopping at a stale-cache check.

use alloc::vec::Vec;

use ragu_arithmetic::{CurveAffine, Cycle};
use ragu_backend::{Backend, ReferenceBackend};
use ragu_circuits::{
    polynomials::{Rank, sparse},
    staging::Stage,
};
use ragu_core::Result;
use ragu_pasta::{Fp, Fq, Pasta};
use rand::{SeedableRng, rngs::StdRng};

use super::{
    C, HEADER_SIZE, R,
    test_steps::{Add, Leaf, Number, OrderedAdd},
};
use crate::{
    Application, ApplicationBuilder, Pcd, Proof,
    fuzzing::corrupt::{
        Binding, Corruption, NativeCommitment, NativeRx, NestedCommitment, NestedRx, RxComponent,
    },
    internal::{native, nested},
    verify::VerificationChecks,
};

type App = Application<'static, C, R, HEADER_SIZE>;
type Node = Pcd<C, R, Number>;
type QueryStage = nested::stages::query::Stage<<C as Cycle>::HostCurve, R>;
type ChildrenStage = native::stages::points::ChildrenStage<<C as Cycle>::NestedCurve>;

const LEFT: Fp = Fp::from_raw([19, 0, 0, 0]);
const RIGHT: Fp = Fp::from_raw([43, 0, 0, 0]);
const EXPORT_RX_POSITION: usize = 28;
const QUERY_PREFIX_VALUES: usize = 4 + 45 + 1;
const QUERY_CHILD_VALUES: usize = 42 + 4;
const CHILDREN_POINTS_PER_CHILD: usize = 33;

struct Fixture {
    app: App,
    left: Node,
    right: Node,
    parent: Node,
}

fn fixture() -> Result<Fixture> {
    let app = ApplicationBuilder::<C, R, HEADER_SIZE>::new()
        .register(Leaf)?
        .register(Add)?
        .register(OrderedAdd)?
        .finalize(Pasta::baked())?;
    let mut rng = StdRng::seed_from_u64(0x8730_0a10);
    let left = app.seed(&mut rng, Leaf, LEFT)?.0;
    let right = app.seed(&mut rng, Leaf, RIGHT)?.0;
    let parent = app
        .fuse(
            &mut StdRng::seed_from_u64(0x8730_0a11),
            OrderedAdd,
            (),
            left.clone(),
            right.clone(),
        )?
        .0;
    assert_eq!(*parent.data(), LEFT + RIGHT + RIGHT);
    for node in [&left, &right, &parent] {
        assert!(checks(&app, node, "honest fixture")?.all());
    }
    Ok(Fixture {
        app,
        left,
        right,
        parent,
    })
}

fn checks(app: &App, node: &Node, context: &str) -> Result<VerificationChecks> {
    let (accepted, checks) = app.verify_with_checks(node, StdRng::seed_from_u64(0x8730_dec1))?;
    let checks = checks.expect("valid metadata must reach the decider predicates");
    assert_eq!(accepted, checks.all(), "{context}: {checks:?}");
    Ok(checks)
}

fn stage_degree<F, S>(value: usize) -> usize
where
    F: ragu_arithmetic::ff::Field,
    S: Stage<F, R>,
{
    let gate = S::skip_gates() + value / 2;
    if value.is_multiple_of(2) {
        2 * R::n() - 1 - gate
    } else {
        4 * R::n() - 1 - gate
    }
}

fn stage_values<F, S>(rx: &sparse::Polynomial<F, R>) -> Vec<F>
where
    F: ragu_arithmetic::ff::Field,
    S: Stage<F, R>,
{
    let coefficients: Vec<_> = rx.iter_coeffs().collect();
    (0..S::values())
        .map(|value| coefficients[stage_degree::<F, S>(value)])
        .collect()
}

fn swap_stage_values<F, S>(rx: &mut sparse::Polynomial<F, R>, left: usize, right: usize)
where
    F: ragu_arithmetic::ff::Field,
    S: Stage<F, R>,
{
    assert!(left < S::values() && right < S::values());
    let mut coefficients: Vec<_> = rx.iter_coeffs().collect();
    let left = stage_degree::<F, S>(left);
    let right = stage_degree::<F, S>(right);
    assert_ne!(coefficients[left], coefficients[right]);
    coefficients.swap(left, right);
    *rx = sparse::Polynomial::from_coeffs(coefficients);
}

fn repair_native_cache(changed: &mut Proof<C, R>, rx: NativeRx) {
    let commitment = ReferenceBackend::sparse_commit_to_affine(
        &changed[match rx {
            NativeRx::PointsChildren => native::RxIndex::PointsChildren,
            _ => unreachable!("this test repairs only the children-points stage"),
        }],
        C::host_generators(Pasta::baked()),
    );
    *changed.native_commitment_cache_mut(NativeCommitment::Rx(rx)) = commitment;
}

fn repair_nested_cache(changed: &mut Proof<C, R>, rx: NestedRx) {
    let commitment = ReferenceBackend::sparse_commit_to_affine(
        &changed[match rx {
            NestedRx::BridgeQuery => nested::RxIndex::BridgeQuery,
            _ => unreachable!("this test repairs only the query bridge"),
        }],
        C::nested_generators(Pasta::baked()),
    );
    *changed.nested_commitment_cache_mut(NestedCommitment::Rx(rx)) = commitment;
}

fn assert_only_headers_swapped(original: &Proof<C, R>, changed: &Proof<C, R>) {
    assert_eq!(changed.left_header(), original.right_header());
    assert_eq!(changed.right_header(), original.left_header());
    let mut restored = changed.clone();
    assert_eq!(
        restored.corrupt(Corruption::SwapHeaders),
        Binding::MustReject
    );
    assert_eq!(restored.test_mismatch(original), None);
}

fn assert_only_query_pair_swapped(original: &Proof<C, R>, changed: &Proof<C, R>) {
    let mut restored = changed.clone();
    *restored.nested_rx_mut(NestedRx::BridgeQuery) = original[nested::RxIndex::BridgeQuery].clone();
    *restored.nested_commitment_cache_mut(NestedCommitment::Rx(NestedRx::BridgeQuery)) =
        original.bridge_query_commitment();
    assert_eq!(restored.test_mismatch(original), None);
}

fn assert_only_commitment_pair_swapped(original: &Proof<C, R>, changed: &Proof<C, R>) {
    let mut restored = changed.clone();
    *restored.native_component_mut(RxComponent::Rx(NativeRx::PointsChildren)) =
        original[native::RxIndex::PointsChildren].clone();
    *restored.native_commitment_cache_mut(NativeCommitment::Rx(NativeRx::PointsChildren)) =
        original.native_rx_commitment(native::RxIndex::PointsChildren);
    assert_eq!(restored.test_mismatch(original), None);
}

#[test]
fn ordered_parent_rejects_single_role_instance_commitment_and_query_swaps() -> Result<()> {
    let Fixture {
        app,
        left,
        right,
        parent,
    } = fixture()?;

    // Child-instance attack: only the two headers move. The application and
    // unified bridge claims retain their ordered left/right interpretation.
    let mut changed = parent.proof().clone();
    assert_eq!(
        changed.corrupt(Corruption::SwapHeaders),
        Binding::MustReject
    );
    assert_only_headers_swapped(parent.proof(), &changed);
    let changed = changed.carry::<Number>(*parent.data());
    let instance = checks(&app, &changed, "single child-instance swap")?;
    assert!(!instance.native_revdot);
    assert!(instance.commitments);

    // Query attack: independently pin the two positions to Export evaluations
    // at the parent's xz, swap just those values, and repair the bridge cache.
    assert_eq!(nested::RxIndex::Export.position(), EXPORT_RX_POSITION);
    assert_eq!(nested::RxIndex::NUM, 42);
    assert_eq!(nested::InternalCircuitIndex::NUM, 45);
    let left_query = QUERY_PREFIX_VALUES + EXPORT_RX_POSITION;
    let right_query = QUERY_PREFIX_VALUES + QUERY_CHILD_VALUES + EXPORT_RX_POSITION;
    let original_query = stage_values::<Fq, QueryStage>(&parent.proof().bridge_query_rx);
    let xz =
        nested::challenge::<C>(parent.proof().x())? * nested::challenge::<C>(parent.proof().z())?;
    assert_eq!(
        original_query[left_query],
        ReferenceBackend::sparse_eval(&left.proof()[nested::RxIndex::Export], xz)
    );
    assert_eq!(
        original_query[right_query],
        ReferenceBackend::sparse_eval(&right.proof()[nested::RxIndex::Export], xz)
    );
    let mut changed = parent.proof().clone();
    swap_stage_values::<Fq, QueryStage>(
        changed.nested_rx_mut(NestedRx::BridgeQuery),
        left_query,
        right_query,
    );
    repair_nested_cache(&mut changed, NestedRx::BridgeQuery);
    assert_only_query_pair_swapped(parent.proof(), &changed);
    let changed = changed.carry::<Number>(*parent.data());
    let query = checks(&app, &changed, "single child-query swap")?;
    assert!(
        query.commitments,
        "the repaired cache must not decide rejection: {query:?}"
    );
    assert!(
        !query.nested_revdot,
        "the nested child-query claim must reject: {query:?}"
    );

    // Commitment attack: ChildrenStage holds 33 non-binding commitments for
    // each child. Swap only Export's two affine coordinates and repair the
    // native commitment to that stage polynomial.
    assert_eq!(native::stages::points::NUM_CHILDREN_POINTS, 66);
    let left_point = EXPORT_RX_POSITION;
    let right_point = CHILDREN_POINTS_PER_CHILD + EXPORT_RX_POSITION;
    let original_points =
        stage_values::<Fp, ChildrenStage>(&parent.proof().native_points_children_rx);
    let point_values = |point: <C as Cycle>::NestedCurve| {
        let coordinates = point.coordinates().unwrap();
        [*coordinates.x(), *coordinates.y()]
    };
    assert_eq!(
        &original_points[2 * left_point..2 * left_point + 2],
        point_values(left.proof().nested_rx_commitment(nested::RxIndex::Export))
    );
    assert_eq!(
        &original_points[2 * right_point..2 * right_point + 2],
        point_values(right.proof().nested_rx_commitment(nested::RxIndex::Export))
    );
    let mut changed = parent.proof().clone();
    let rx = changed.native_component_mut(RxComponent::Rx(NativeRx::PointsChildren));
    swap_stage_values::<Fp, ChildrenStage>(rx, 2 * left_point, 2 * right_point);
    swap_stage_values::<Fp, ChildrenStage>(rx, 2 * left_point + 1, 2 * right_point + 1);
    repair_native_cache(&mut changed, NativeRx::PointsChildren);
    assert_only_commitment_pair_swapped(parent.proof(), &changed);
    let changed = changed.carry::<Number>(*parent.data());
    let commitment = checks(&app, &changed, "single child-commitment swap")?;
    assert!(
        commitment.commitments,
        "the repaired cache must not decide rejection: {commitment:?}"
    );
    assert!(
        !commitment.native_revdot,
        "the native child-point claim must reject: {commitment:?}"
    );

    Ok(())
}

#[test]
fn full_semantic_swap_preserves_only_the_commutative_statement() -> Result<()> {
    let Fixture {
        app,
        left,
        right,
        parent,
    } = fixture()?;
    let ordered_swapped = app
        .fuse(
            &mut StdRng::seed_from_u64(0x8730_0a12),
            OrderedAdd,
            (),
            right.clone(),
            left.clone(),
        )?
        .0;
    assert_eq!(*ordered_swapped.data(), RIGHT + LEFT + LEFT);
    assert_ne!(ordered_swapped.data(), parent.data());
    assert!(checks(&app, &ordered_swapped, "recomputed ordered swap")?.all());

    let commutative = app
        .fuse(
            &mut StdRng::seed_from_u64(0x8730_0a13),
            Add,
            (),
            left.clone(),
            right.clone(),
        )?
        .0;
    let commutative_swapped = app
        .fuse(
            &mut StdRng::seed_from_u64(0x8730_0a14),
            Add,
            (),
            right,
            left,
        )?
        .0;
    assert_eq!(commutative.data(), commutative_swapped.data());
    assert!(checks(&app, &commutative, "commutative control")?.all());
    assert!(checks(&app, &commutative_swapped, "swapped commutative control")?.all());
    Ok(())
}
