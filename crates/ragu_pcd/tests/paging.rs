//! Experimental: profiles that page the fuse's internal circuits prove and
//! verify. A paged circuit is cut into several circuits at the wallet rank,
//! with nothing but the profile's declaration saying so: its pages before
//! the last ride the profile's extension, and the last takes the circuit's
//! own slot.

use ragu_circuits::polynomials::{Rank, WalletRank};
use ragu_core::{
    Cycle, Result,
    pasta::{Fp, Pasta},
};
use ragu_pcd::{
    ApplicationBuilder, SelectableBackend,
    ipa::IpaCycle,
    profile::{Cut, Pages, Profile, Profiled, ProfiledCycle, Shape, Standard},
};
use ragu_testing::pcd::nontrivial::{Hash2, Merge2, WitnessLeaf};
use rand::{SeedableRng, rngs::StdRng};

const HEADER_SIZE: usize = 4;

/// The standard profile with every fuse circuit, on both sides, cut into
/// two pages or more that each load every stage their circuit reserves.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
struct PagedEverything;

impl Profile for PagedEverything {
    const NAME: &'static str = "paged-everything";
    const NATIVE_EXTENSION: usize = 0;
    const NESTED_EXTENSION: usize = 0;
    const PAGES: Pages = Pages {
        hashes_1: Cut::pages(2),
        hashes_2: Cut::pages(2),
        collapse: Cut::pages(3),
        compute_v: Cut::pages(5),
        bind_challenges: Cut::pages(2),
        bind_beta: Cut::pages(2),
        bind_endoscalar: Cut::pages(2),
        nested_collapse: Cut::pages(3),
        nested_compute_v: Cut::pages(5),
        ..Pages::WHOLE
    };
    // The pages add polynomials, whose commitments the walks' stages hold:
    // a step does less so that it still fits beside them.
    const NATIVE_ENDOSCALINGS_PER_STEP: usize = 3;
    const NESTED_ENDOSCALINGS_PER_STEP: usize = 3;

    type Context<'params, Base, R, B>
        = ()
    where
        Base: IpaCycle + ProfiledCycle<Profile = Standard>,
        R: Rank,
        B: SelectableBackend;

    ragu_pcd::paged_internal_circuits!();
}

/// The standard profile laid out as a profile whose stages do not fit one
/// polynomial end to end would be:
///
/// - the nested stages side by side, in four branches after the
///   bridge-hash stage, with each nested circuit that reserves them cut
///   into pages that load one branch each;
/// - the native walk stage beside the points input stages, with
///   `bind_endoscalar`, which reserves them all, cut likewise;
/// - both walks' steps paged: a step does twelve endoscalings rather than
///   four, in three pages that load the endoscalar's bits and read the
///   points they fold off the carry stage. On the nested side the first
///   of them loads the points as well; on the native side, where the bits
///   are in the walk stage, a page that loads the points input stages and
///   holds no gates comes first.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
struct SideBySide;

impl Profile for SideBySide {
    const NAME: &'static str = "side-by-side";
    const NATIVE_EXTENSION: usize = 0;
    const NESTED_EXTENSION: usize = 0;
    const PAGES: Pages = {
        use ragu_pcd::profile::paging::{
            native_loads::{self as native, INPUTS, WALK},
            nested_loads::{ERRORS, EVAL, POINTS, PREAMBLE, QUERY, STEP_BITS},
        };
        Pages {
            // A page for the first two stages and one for the query stage.
            // Then a page that loads the query stage and holds no gates
            // hands one that loads the eval stage what it reads of it,
            // over a carry stage the two share. The last loads the eval
            // stage.
            compute_v: Cut::loading(&[
                native::PREAMBLE,
                native::QUERY,
                native::QUERY,
                native::EVAL,
                native::EVAL,
            ])
            .idling(&[2])
            .sharing(&[(2, 2)]),
            // The circuits read little of their stages: a page that loads
            // the first two alone has most of one.
            bind_challenges: Cut::loading(&[native::PREAMBLE, native::EVAL]),
            bind_endoscalar: Cut::loading(&[INPUTS, WALK]),
            endoscaling_step: Cut::loading(&[INPUTS, WALK, WALK, WALK]).idling(&[0]),
            native_branches: true,
            // The circuit holds the points to their copies in the other
            // branches: two pages apart hold them to those of the
            // `preamble` branch, which are most of them, over a carry
            // stage of their own.
            nested_collapse: Cut::loading(&[
                POINTS, PREAMBLE, POINTS, PREAMBLE, ERRORS, QUERY, EVAL,
            ])
            .apart(&[2])
            .idling(&[5]),
            // A page for the `preamble` stage and one for the `inner_error`
            // branch, which the circuit reads little of, then as the
            // native `compute_v`.
            nested_compute_v: Cut::loading(&[PREAMBLE, ERRORS, QUERY, QUERY, EVAL, EVAL])
                .idling(&[1, 3])
                .sharing(&[(3, 2)]),
            nested_endoscaling_step: Cut::loading(&[POINTS, STEP_BITS, STEP_BITS]),
            nested_branches: true,
            ..Pages::WHOLE
        }
    };
    const NATIVE_ENDOSCALINGS_PER_STEP: usize = 12;
    const NESTED_ENDOSCALINGS_PER_STEP: usize = 12;

    type Context<'params, Base, R, B>
        = ()
    where
        Base: IpaCycle + ProfiledCycle<Profile = Standard>,
        R: Rank,
        B: SelectableBackend;

    ragu_pcd::paged_internal_circuits!();
}

/// Proves a leaf, a node over two leaves and a node over two nodes under
/// a profile, verifying each. The node over nodes is the one whose circuits
/// fold children that carry paged circuits' pages.
macro_rules! proves_and_verifies {
    ($profile:ty) => {{
        let pasta = ragu_pcd::pasta::baked();
        let poseidon_params = <Profiled<Pasta, $profile> as Cycle>::circuit_poseidon(pasta);
        let app = ApplicationBuilder::<Profiled<Pasta, $profile>, WalletRank, HEADER_SIZE>::new()
            .register(WitnessLeaf { poseidon_params })?
            .register(Hash2 { poseidon_params })?
            .register(Merge2 { poseidon_params })?
            .finalize(pasta)?;

        let mut rng = StdRng::seed_from_u64(0x9a6e);
        let (leaf, _) = app.seed(&mut rng, WitnessLeaf { poseidon_params }, Fp::from(42))?;
        assert!(app.verify_uncompressed(&leaf, &mut rng)?);
        let (node, _) = app.fuse(&mut rng, Hash2 { poseidon_params }, (), leaf.clone(), leaf)?;
        assert!(app.verify_uncompressed(&node, &mut rng)?);
        let (top, _) = app.fuse(&mut rng, Merge2 { poseidon_params }, (), node.clone(), node)?;
        assert!(app.verify_uncompressed(&top, &mut rng)?);
        Ok(())
    }};
}

#[test]
fn paging_adds_a_polynomial_for_each_page() {
    // For each paged circuit: a page circuit for each page before the last,
    // and the carry stage.
    let standard = Shape::of::<Standard>();
    let everything = Shape::of::<PagedEverything>();
    assert!(everything.native_rx > standard.native_rx + 2 + 2 + 3 + 5);
    assert!(everything.nested_rx >= standard.nested_rx + 3 + 5);
    // A step takes a polynomial for each of its pages and its carry
    // stage's, which the walks' sizes count.
    let side_by_side = Shape::of::<SideBySide>();
    assert!(side_by_side.native_rx > 5 * side_by_side.native_steps);
    assert!(side_by_side.nested_rx > 4 * side_by_side.nested_steps + 4 + 3);
}

/// Stages side by side cannot all be loaded by one circuit, so a profile
/// that lays them so says which each page of the circuits over them loads.
#[test]
fn stages_side_by_side_need_pages_that_say_what_they_load() {
    macro_rules! unpaged {
        ($name:ident, $pages:expr) => {
            #[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
            struct $name;

            impl Profile for $name {
                const NAME: &'static str = "unpaged";
                const NATIVE_EXTENSION: usize = 0;
                const NESTED_EXTENSION: usize = 0;
                const PAGES: Pages = $pages;
                const NATIVE_ENDOSCALINGS_PER_STEP: usize = 12;
                const NESTED_ENDOSCALINGS_PER_STEP: usize = 12;

                type Context<'params, Base, R, B>
                    = ()
                where
                    Base: IpaCycle + ProfiledCycle<Profile = Standard>,
                    R: Rank,
                    B: SelectableBackend;
            }
        };
    }
    unpaged!(
        Nested,
        Pages {
            nested_collapse: Cut::pages(3),
            ..SideBySide::PAGES
        }
    );
    unpaged!(
        Native,
        Pages {
            bind_endoscalar: Cut::WHOLE,
            ..SideBySide::PAGES
        }
    );

    assert!(SideBySide::check().is_ok());
    assert!(Nested::check().is_err());
    assert!(Native::check().is_err());
}

#[test]
fn every_circuit_in_pages_proves_and_verifies() -> Result<()> {
    proves_and_verifies!(PagedEverything)
}

#[test]
fn stages_side_by_side_and_paged_steps_prove_and_verify() -> Result<()> {
    proves_and_verifies!(SideBySide)
}

/// Prints how the profile's internal circuits size up and how the profile
/// cuts them, or `$cuts` does for the circuits it names. Run it with
/// `cargo test -p ragu_pcd --all-features --test paging census -- --ignored --nocapture`.
macro_rules! census {
    ($label:expr, $profile:ty, $header:expr, $cuts:expr) => {{
        use ragu_pcd::profile::paging::{native_census, nested_census};

        type C = Profiled<Pasta, $profile>;
        let shape = Shape::of::<$profile>();
        println!(
            "CENSUS {}: rx={}/{} points={}/{} steps={}/{}",
            $label,
            shape.native_rx,
            shape.nested_rx,
            shape.native_points,
            shape.nested_points,
            shape.native_steps,
            shape.nested_steps,
        );
        let cuts: &[(&'static str, Cut)] = $cuts;
        let pasta = ragu_pcd::pasta::baked();
        let mut census = native_census::<C, WalletRank, $header>(pasta, 3, cuts)?;
        census.extend(nested_census::<C, WalletRank>(cuts)?);
        for sizing in &census {
            let sizes: Vec<usize> = sizing.stages.iter().map(|range| range.len()).collect();
            println!(
                "CENSUS {} {}: gates={} constraints={} own={} stages={sizes:?}",
                $label, sizing.name, sizing.gates, sizing.constraints, sizing.own,
            );
            println!(
                "CENSUS {} {}   reads by twentieth: {:?}",
                $label, sizing.name, sizing.reads
            );
            match &sizing.pages {
                Err(error) => {
                    println!("CENSUS {} {}   DOES NOT CUT: {error}", $label, sizing.name);
                    if let Some(report) = &sizing.unbounded {
                        let gates: Vec<usize> =
                            report.pages.iter().map(|page| page.gates).collect();
                        println!(
                            "CENSUS {} {}   with 600 more gates: gates={gates:?} slots={} cuts={:?} in={:?} out={:?}",
                            $label, sizing.name, report.slots, report.cuts,
                            report.pages.iter().map(|page| page.imported_slots).collect::<Vec<_>>(),
                            report.pages.iter().map(|page| page.exported_wires).collect::<Vec<_>>(),
                        );
                    }
                }
                Ok((layout, report)) => {
                    let pages: Vec<String> = report
                        .pages
                        .iter()
                        .enumerate()
                        .map(|(index, page)| {
                            let reads: Vec<usize> = sizing
                                .stages
                                .iter()
                                .scan(1, |start, range| {
                                    let stage = *start..*start + range.len();
                                    *start = stage.end;
                                    Some(
                                        page.stage_gates
                                            .iter()
                                            .filter(|gate| stage.contains(gate))
                                            .count(),
                                    )
                                })
                                .collect();
                            format!(
                                "[from={} own={}/{} cons={} in={} out={} reads={reads:?}]",
                                layout.firsts[index],
                                page.gates,
                                layout.room(index),
                                page.constraints,
                                page.imported_slots,
                                page.exported_wires,
                            )
                        })
                        .collect();
                    println!(
                        "CENSUS {} {}   pages={} carry={:?} slots={} apart={:?} local={:?} cuts={:?} {}",
                        $label,
                        sizing.name,
                        report.pages.len(),
                        layout.carry,
                        report.slots,
                        report.apart,
                        report.local,
                        report.cuts,
                        pages.join(" "),
                    );
                }
            }
        }
        Ok(())
    }};
}

#[test]
#[ignore = "prints the side-by-side profile's census"]
fn census_side_by_side() -> Result<()> {
    census!("side-by-side", SideBySide, HEADER_SIZE, &[])
}

/// How each fuse circuit of the aggregator profile cuts into polynomials
/// of its rank, the wallet's, with the decompression extension's
/// polynomials: the stages side by side, the walks' steps paged, the
/// points the nested `collapse` holds to their copies on pages apart, and
/// the quotients the two `compute_v` circuits take on pages that share a
/// carry stage with the page that loads the `query` stage for them.
#[test]
#[ignore = "prints the aggregator profile's census"]
fn census_aggregator() -> Result<()> {
    census!("aggregator", ragu_pcd::profile::Aggregator<4>, 4, &[])
}

/// Prints the aggregator profile's census at the widest header, whose
/// circuits take the wide layouts.
#[test]
#[ignore = "prints the aggregator profile's census at the widest header"]
fn census_aggregator_wide() -> Result<()> {
    census!("aggregator", ragu_pcd::profile::Aggregator<195>, 195, &[])
}

/// Prints the chunk circuit counts the aggregator profile pins: those of
/// the schedules that verify a wallet's compressed proof in chunk circuits
/// at the aggregator rank.
#[test]
#[ignore = "prints the decompression's circuit counts at the aggregator rank"]
fn census_aggregator_counts() -> Result<()> {
    use ragu_circuits::polynomials::AggregatorRank;
    use ragu_pcd::profile::Aggregator;

    println!(
        "COUNTS header 4: {:?}",
        Aggregator::<4>::scheduled::<Pasta, AggregatorRank>()?
    );
    println!(
        "COUNTS header 195: {:?}",
        Aggregator::<195>::scheduled::<Pasta, AggregatorRank>()?
    );
    Ok(())
}
