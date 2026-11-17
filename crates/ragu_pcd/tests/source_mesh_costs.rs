//! Reproducible shape, circuit and wire costs. Print them with
//! `just test source_oracle_cost_census --nocapture`.

use ragu_circuits::{
    polynomials::{R, Rank},
    staging::{MultiStage, StageExt},
    testing::synthesis_counts,
};
use ragu_core::{
    Cycle, Result,
    pasta::{Fp, Fq, Pasta},
};
use udon::field::Field;

use super::SourceCapacity;
use crate::{
    CompressedProof, Proof,
    internal::{native, nested},
    profile::{
        Profile, Profiled, Shape, Standard,
        online::{
            circuit,
            stages::{self, Native, Nested},
        },
    },
};

fn census<P: Profile, Rk: Rank>(label: &str) -> Result<()> {
    type C<P> = Profiled<Pasta, P>;
    type Host = <Pasta as Cycle>::HostCurve;
    let shape = Shape::of::<P>();
    let core_p = synthesis_counts(&native::circuits::compute_v::Circuit::<C<P>, Rk, 2>::new())?;
    let core_q = synthesis_counts(&MultiStage::<Fq, Rk, _>::new(
        nested::circuits::compute_v::Circuit::<Host, Rk, P>::new(),
    ))?;
    // Walk length also enlarges the other circuits. Check every fixed circuit,
    // rather than assuming a fitting walk and compute-v imply a fitting setup.
    let params = if Rk::RANK == 13 {
        crate::pasta::baked()
    } else {
        crate::pasta::baked_aggregator()
    };
    let (_, domain) = native::total_circuit_counts::<P>(1);
    let mut fixed = alloc::vec![
        (
            "hashes_1",
            synthesis_counts(&native::circuits::hashes_1::Circuit::<
                C<P>,
                Rk,
                2,
                native::RevdotParameters<P>,
            >::new(params, domain))?
        ),
        (
            "hashes_2",
            synthesis_counts(&native::circuits::hashes_2::Circuit::<
                C<P>,
                Rk,
                2,
                native::RevdotParameters<P>,
            >::new(params))?
        ),
        (
            "collapse",
            synthesis_counts(&native::circuits::collapse::Circuit::<
                C<P>,
                Rk,
                2,
                native::RevdotParameters<P>,
            >::new())?
        ),
        ("compute_v", core_p),
        (
            "bind_beta",
            synthesis_counts(&native::circuits::bind_beta::Circuit::<C<P>, Rk, 2>::new(
                params
            ))?
        ),
        (
            "bind_endoscalar",
            synthesis_counts(&native::circuits::bind_endoscalar::Circuit::<C<P>, Rk>::new())?
        ),
    ];
    for k in 0..native::NUM_BINDERS {
        let counts =
            crate::with_binder!(k, C<P>, Rk, 2, params, |circuit| synthesis_counts(&circuit))?;
        fixed.push(("bind_challenges", counts));
    }
    for (name, counts) in &fixed {
        std::println!(
            "V6-FIXED {label} native.{name}: gates={} constraints={}",
            counts.num_gates,
            counts.num_constraints
        );
        assert!(
            counts.num_gates <= Rk::n(),
            "{label}: {name} exceeds the gate budget"
        );
        assert!(
            counts.num_constraints < Rk::num_coeffs(),
            "{label}: {name} exceeds the constraint budget"
        );
    }
    let collapse_q = synthesis_counts(&MultiStage::<Fq, Rk, _>::new(
        nested::circuits::collapse::Circuit::<Host, Rk, P>::new(),
    ))?;
    std::println!(
        "V6-FIXED {label} nested.collapse: gates={} constraints={}",
        collapse_q.num_gates,
        collapse_q.num_constraints
    );
    assert!(collapse_q.num_constraints < Rk::num_coeffs());
    let helper_p = if P::NATIVE_ONLINE.is_empty() {
        (0, 0)
    } else {
        let counts = synthesis_counts(&MultiStage::<Fp, Rk, _>::new(circuit::Circuit::<
            Fp,
            P,
            Native,
        >::with_source_tag(
            P::NATIVE_MESH.map(|_| Fp::ONE),
        )?))?;
        (counts.num_gates, counts.num_constraints)
    };
    let helper_q = if P::NESTED_ONLINE.is_empty() {
        (0, 0)
    } else {
        let counts = synthesis_counts(&MultiStage::<Fq, Rk, _>::new(circuit::Circuit::<
            Fq,
            P,
            Nested,
        >::with_source_tag(
            P::NESTED_MESH.map(|_| Fq::ONE),
        )?))?;
        (counts.num_gates, counts.num_constraints)
    };
    let mut walk_p = 0;
    let mut walk_q = 0;
    for step in 0..shape.native_steps {
        walk_p = walk_p.max(
            synthesis_counts(&native::circuits::endoscaling_step::Circuit::<C<P>, Rk>::new(step))?
                .num_gates,
        );
    }
    for step in 0..shape.nested_steps {
        walk_q = walk_q.max(
            synthesis_counts(&MultiStage::<Fq, Rk, _>::new(nested::EndoscalingStep::<
                Host,
                Rk,
                P,
            >::new(step)))?
            .num_gates,
        );
    }
    for gates in [
        core_p.num_gates,
        core_q.num_gates,
        collapse_q.num_gates,
        helper_p.0,
        helper_q.0,
        walk_p,
        walk_q,
    ] {
        assert!(
            gates <= Rk::n(),
            "{label}: {gates} gates exceed the rank budget"
        );
    }
    let stages_p = if P::NATIVE_ONLINE.is_empty() {
        [0; 3]
    } else {
        [
            <stages::InputStage<P, Native> as StageExt<Fp, Rk>>::num_gates(),
            <stages::QueryStage<P, Native> as StageExt<Fp, Rk>>::num_gates(),
            <stages::EvalStage<P, Native> as StageExt<Fp, Rk>>::num_gates(),
        ]
    };
    let stages_q = if P::NESTED_ONLINE.is_empty() {
        [0; 3]
    } else {
        [
            <stages::InputStage<P, Nested> as StageExt<Fq, Rk>>::num_gates(),
            <stages::QueryStage<P, Nested> as StageExt<Fq, Rk>>::num_gates(),
            <stages::EvalStage<P, Nested> as StageExt<Fq, Rk>>::num_gates(),
        ]
    };
    std::println!(
        "V6-CENSUS {label}: rank={} header=2 endos={}/{} rx={}/{} walks={}/{}:{}/{} shape_polynomials={} fold_claims={}/{} core={}/{}:{}/{} helpers={}/{}:{}/{} max_walk_gates={}/{} online_stages={:?}/{:?} nested_query_eval={}/{} proof_bytes={} compressed_bytes={} private_polys={}/{} private_queries={}/{} mesh_values={}/{}",
        Rk::RANK,
        P::NATIVE_ENDOSCALINGS_PER_STEP,
        P::NESTED_ENDOSCALINGS_PER_STEP,
        shape.native_rx,
        shape.nested_rx,
        shape.native_points,
        shape.native_steps,
        shape.nested_points,
        shape.nested_steps,
        shape.polynomials(),
        native::num_claims::<P>(),
        nested::num_claims::<P>(),
        core_p.num_gates,
        core_p.num_constraints,
        core_q.num_gates,
        core_q.num_constraints,
        helper_p.0,
        helper_p.1,
        helper_q.0,
        helper_q.1,
        walk_p,
        walk_q,
        stages_p,
        stages_q,
        <nested::stages::query::Stage<Host, Rk, P> as StageExt<Fq, Rk>>::num_gates(),
        <nested::stages::eval::Stage<Host, Rk, P> as StageExt<Fq, Rk>>::num_gates(),
        Proof::<C<P>, Rk>::encoded_len::<2>(),
        CompressedProof::<C<P>>::encoded_len::<Rk, 2>(),
        P::NATIVE_ONLINE.polynomials.len(),
        P::NESTED_ONLINE.polynomials.len(),
        P::NATIVE_ONLINE.openings.len(),
        P::NESTED_ONLINE.openings.len(),
        P::NATIVE_MESH.map_or(0, |m| m.claims_len()),
        P::NESTED_MESH.map_or(0, |m| m.claims_len())
    );
    Ok(())
}
/// Holds the fixture counts the book's V6 cost table derives, per field.
fn assert_fixture_counts(
    layout: crate::profile::online::Layout,
    mesh: crate::profile::online::mesh::Mesh,
) -> Result<()> {
    use crate::profile::online::Phase;
    let (r, h) = (mesh.restrictions().count(), mesh.helpers.len());
    let p = layout.polynomials.len() - mesh.polynomial_indices().len();
    let q = layout
        .openings
        .iter()
        .filter(|o| !mesh.polynomial_indices().contains(&o.polynomial))
        .count();
    assert_eq!((r, h, p, q), (11, 7, 1, 2));
    assert_eq!(layout.phase_range(Phase::BeforeW).len(), r + p);
    assert_eq!(layout.polynomials.len() - (r + p), h + 2);
    assert_eq!(mesh.polynomial_indices().len(), r + h + 2);
    assert_eq!(mesh.edges(layout)?.len(), r + h + 1);
    assert_eq!(layout.polynomials.len(), r + h + 2 + p);
    assert_eq!(layout.openings.len(), 2 * (r + h + 1) + q);
    Ok(())
}

#[test]
fn source_oracle_cost_census() -> Result<()> {
    for (layout, mesh) in [
        (SourceCapacity::NATIVE_ONLINE, SourceCapacity::NATIVE_MESH),
        (SourceCapacity::NESTED_ONLINE, SourceCapacity::NESTED_MESH),
    ] {
        assert_fixture_counts(layout, mesh.expect("fixture mesh"))?;
    }
    census::<Standard, R<13>>("main-standard")?;
    census::<Standard, R<14>>("main-matched")?;
    census::<SourceCapacity, R<14>>("v6-source-capacity")
}
