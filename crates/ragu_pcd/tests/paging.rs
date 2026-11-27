//! Experimental: profiles that page the fuse's internal circuits prove and
//! verify. A paged circuit is cut into several circuits at the wallet rank,
//! with nothing but the profile's declaration saying so: its pages before
//! the last ride the profile's extension, and the last takes the circuit's
//! own slot.

use ragu_circuits::polynomials::{AggregatorRank, Rank, WalletRank};
use ragu_core::{
    Cycle, Result,
    pasta::{Fp, Pasta},
};
use ragu_pcd::{
    ApplicationBuilder, SelectableBackend,
    ipa::IpaCycle,
    profile::{Aggregator, Cut, Pages, Profile, Profiled, ProfiledCycle, Shape, Standard},
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
}

#[test]
fn standard_profile_keeps_every_internal_circuit_whole() {
    assert_eq!(Standard::PAGES, Pages::WHOLE);
}

#[test]
fn every_circuit_in_pages_proves_and_verifies() -> Result<()> {
    proves_and_verifies!(PagedEverything)
}

/// Prints how the profile's internal circuits size up and how the profile
/// cuts them, or `$cuts` does for the circuits it names. Run it with
/// `cargo test -p ragu_pcd --all-features --test paging census -- --ignored --nocapture`.
macro_rules! census {
    ($label:expr, $profile:ty, $rank:ty, $header:expr, $cuts:expr) => {{
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
        let mut census = native_census::<C, $rank, $header>(pasta, 3, cuts, false)?;
        census.extend(nested_census::<C, $rank>(cuts, false)?);
        for sizing in &census {
            let sizes: Vec<usize> = sizing.stages.iter().map(|range| range.len()).collect();
            println!(
                "CENSUS {} {}: gates={} constraints={} own={} stages={sizes:?}",
                $label, sizing.name, sizing.gates, sizing.constraints, sizing.own,
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
                        .map(|page| {
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
                                layout.window().start,
                                page.gates,
                                layout.room(),
                                page.constraints,
                                page.imported_slots,
                                page.exported_wires,
                            )
                        })
                        .collect();
                    println!(
                        "CENSUS {} {}   pages={} carry={:?} slots={} cuts={:?} {}",
                        $label,
                        sizing.name,
                        report.pages.len(),
                        layout.carry,
                        report.slots,
                        report.cuts,
                        pages.join(" "),
                    );
                }
            }
        }
        let failures: Vec<_> = census
            .iter()
            .filter_map(|sizing| {
                sizing
                    .pages
                    .as_ref()
                    .err()
                    .map(|error| format!("{}: {error}", sizing.name))
            })
            .collect();
        assert!(failures.is_empty(), "{failures:#?}");
        Ok(())
    }};
}

/// How each fuse circuit of the aggregator profile cuts into polynomials
/// at the aggregator rank, with the decompression extension's size.
#[test]
#[ignore = "prints the aggregator profile's census"]
fn census_aggregator() -> Result<()> {
    census!(
        "aggregator",
        ragu_pcd::profile::Aggregator<4>,
        AggregatorRank,
        4,
        &[]
    )
}

/// Prints the aggregator profile's census at the widest header, whose
/// stages and circuits are the largest.
#[test]
#[ignore = "prints the aggregator profile's census at the widest header"]
fn census_aggregator_wide() -> Result<()> {
    census!(
        "aggregator",
        ragu_pcd::profile::Aggregator<195>,
        AggregatorRank,
        195,
        &[]
    )
}

#[path = "support/paging_census.rs"]
mod census_support;
use census_support::header_pages_fit;

macro_rules! check_headers {
    ($($header:literal),+ $(,)?) => {
        $(header_pages_fit::<$header>()?;)+
    };
}

/// Check both sides of the aggregator's header-dependent schedule changes
/// in ordinary CI. The dedicated paging census checks every supported
/// header size in smaller build batches.
#[test]
fn aggregator_pages_fit_at_header_boundaries() -> Result<()> {
    check_headers!(
        1, 2, 9, 10, 33, 34, 41, 42, 57, 58, 65, 66, 97, 98, 129, 130, 153, 154, 161, 162, 185,
        186, 193, 194, 195,
    );
    Ok(())
}

/// The pages each fuse circuit's cut states under a profile, whether the
/// circuit cuts in them, and the fewest it cuts in.
macro_rules! fewest {
    ($profile:ty, $header:expr) => {{
        use ragu_pcd::profile::paging::{native_census, nested_census};

        // The ordinary census represents each walk with step zero. The
        // scheduled heavy run checks every step at each sampled width.
        #[cfg(ragu_pcd_nightly_tests)]
        let _ = walk_cuts::<$header>()?;
        type C = Profiled<Pasta, $profile>;
        let pasta = ragu_pcd::pasta::baked();
        let mut census = native_census::<C, AggregatorRank, $header>(pasta, 3, &[], true)?;
        census.extend(nested_census::<C, AggregatorRank>(&[], true)?);
        let found: Found = census
            .into_iter()
            .map(|sizing| {
                assert!(
                    sizing.pages.is_ok(),
                    "{} does not cut at header size {}: {:?}",
                    sizing.name,
                    $header,
                    sizing.pages
                );
                (
                    sizing.name,
                    sizing.cut.num_pages(),
                    sizing.fewest.unwrap_or_else(|| {
                        panic!(
                            "{} has no solver result at header size {}",
                            sizing.name, $header
                        )
                    }),
                )
            })
            .collect();
        ($header, found)
    }};
}

/// A census's findings on each circuit: its name, declared pages and the
/// fewest the solver found with the current profile's shape.
type Found = Vec<(&'static str, usize, usize)>;

/// Asserts the declared cuts fit at sampled headers, then prints the
/// fewest pages the solver finds. These are a sizing diagnostic:
/// changing the profile's page counts also changes its proof shape and can
/// change which smaller cuts fit.
#[test]
#[ignore = "prints the fewest pages the aggregator profile's layouts cut in"]
fn fewest_aggregator() -> Result<()> {
    use ragu_pcd::profile::Aggregator;

    let sizes: Vec<(usize, Found)> = vec![
        fewest!(Aggregator<1>, 1),
        fewest!(Aggregator<4>, 4),
        fewest!(Aggregator<33>, 33),
        fewest!(Aggregator<100>, 100),
        fewest!(Aggregator<154>, 154),
        fewest!(Aggregator<162>, 162),
        fewest!(Aggregator<195>, 195),
    ];
    let headers: Vec<usize> = sizes.iter().map(|(header, _)| *header).collect();
    for circuit in 0..sizes[0].1.len() {
        let (name, stated, _) = sizes[0].1[circuit];
        // The most pages any header size takes.
        let mut most = 0;
        let mut each = Vec::new();
        for (header, found) in &sizes {
            let (_, _, fewest) = found[circuit];
            most = most.max(fewest);
            each.push(format!("{header}: {fewest}"));
        }
        println!(
            "FEWEST headers {headers:?} {name}: states {stated:?}, takes {most:?}{} ({})",
            if most == stated {
                ""
            } else {
                " (above local minima)"
            },
            each.join("; "),
        );
    }
    Ok(())
}

/// The pages each paged circuit of a profile is cut into at one header
/// size, by the first eight bytes of the digest of what a registry holds
/// of them ([`Sizing::digest`](ragu_pcd::profile::paging::Sizing::digest)).
macro_rules! cuts {
    ($profile:ty, $header:expr) => {{
        use ragu_pcd::profile::paging::{native_census, nested_census};

        type C = Profiled<Pasta, $profile>;
        let pasta = ragu_pcd::pasta::baked();
        let mut census = native_census::<C, AggregatorRank, $header>(pasta, 3, &[], false)?;
        census.extend(nested_census::<C, AggregatorRank>(&[], false)?);
        let cuts: Vec<(&'static str, String)> = census
            .into_iter()
            .filter(|sizing| sizing.cut.num_pages() > 1)
            .map(|sizing| {
                let digest = sizing
                    .digest
                    .unwrap_or_else(|| panic!("{} does not cut: {:?}", sizing.name, sizing.pages));
                let digest = digest[..8]
                    .iter()
                    .map(|byte| format!("{byte:02x}"))
                    .collect();
                (sizing.name, digest)
            })
            .collect();
        cuts
    }};
}

/// The aggregator's cuts at small and maximum header sizes: for each
/// circuit its profile pages, the first step of each walk standing for the
/// walk, a digest of its pages.
///
/// The pager places a circuit's cuts where the circuit is registered, and
/// a circuit of the aggregator changes with the header size, so each size
/// has cuts of its own. A change to the pager that moves one, or to a
/// circuit, changes the circuits a registry holds, and proofs made before
/// it no longer verify: it fails here, where the fuse fixtures tell of it
/// at one header size alone. After an intended change, replace the table
/// with the one the failure prints.
const CUTS: [(usize, &[(&str, &str)]); 3] = [
    (
        4,
        &[
            ("native.compute_v", "9626a04eba40dc15"),
            ("native.bind_challenges_0", "877eb54c81141b60"),
            ("native.bind_challenges_1", "d8aa9ea4eb527b34"),
            ("native.bind_challenges_2", "bd223988f3dbd888"),
            ("native.bind_challenges_3", "52c876d9009ccae4"),
            ("native.bind_endoscalar", "bb7c1aaeee0895c4"),
            ("native.endoscaling_step", "50e47f43a0dddead"),
            ("nested.collapse", "19b4320b292910bc"),
            ("nested.compute_v", "2783ad6ff88005e5"),
            ("nested.endoscaling_step", "7a6ebe17acf6e454"),
        ],
    ),
    (
        9,
        &[
            ("native.compute_v", "978ac2abd1a30c20"),
            ("native.bind_challenges_0", "a1185d0ba523efec"),
            ("native.bind_challenges_1", "3181a1d9ac83da07"),
            ("native.bind_challenges_2", "a6c3b690ca34af0a"),
            ("native.bind_challenges_3", "091141dc9833e46b"),
            ("native.bind_endoscalar", "bb7c1aaeee0895c4"),
            ("native.endoscaling_step", "50e47f43a0dddead"),
            ("nested.collapse", "19b4320b292910bc"),
            ("nested.compute_v", "2783ad6ff88005e5"),
            ("nested.endoscaling_step", "7a6ebe17acf6e454"),
        ],
    ),
    (
        195,
        &[
            ("native.compute_v", "568597be69b7a505"),
            ("native.bind_challenges_0", "15ff056e1762c7fe"),
            ("native.bind_challenges_1", "2cb8f49cfb5a080d"),
            ("native.bind_challenges_2", "dfdcfffadf9c3120"),
            ("native.bind_challenges_3", "fa87d36b772fbe1c"),
            ("native.bind_endoscalar", "bb7c1aaeee0895c4"),
            ("native.endoscaling_step", "50e47f43a0dddead"),
            ("nested.collapse", "3685fbd5c2797682"),
            ("nested.compute_v", "f9ceb090e8134a17"),
            ("nested.endoscaling_step", "a972eeb134dffbba"),
        ],
    ),
];

#[test]
fn the_aggregators_cuts_are_pinned() -> Result<()> {
    use ragu_pcd::profile::Aggregator;

    let found = [
        (4, cuts!(Aggregator<4>, 4)),
        (9, cuts!(Aggregator<9>, 9)),
        (195, cuts!(Aggregator<195>, 195)),
    ];
    let mut table = String::new();
    let mut moved = Vec::new();
    for ((header, found), (pinned_header, pinned)) in found.iter().zip(CUTS) {
        assert_eq!(*header, pinned_header);
        table.push_str(&format!("    (\n        {header},\n        &[\n"));
        for (name, digest) in found {
            table.push_str(&format!("            (\"{name}\", \"{digest}\"),\n"));
            if !pinned.contains(&(*name, digest.as_str())) {
                moved.push(format!("{name} at header size {header}"));
            }
        }
        table.push_str("        ],\n    ),\n");
        if found.len() != pinned.len() {
            moved.push(format!(
                "{} paged circuits at header size {header}, where {} are pinned",
                found.len(),
                pinned.len()
            ));
        }
    }
    assert!(
        moved.is_empty(),
        "the pages of the aggregator's circuits changed: {moved:#?}\nIf the change is intended, \
         the table is now:\n{table}"
    );
    Ok(())
}

/// The census above represents each walk with step zero. Hash the pages of
/// every step, in order, so a changed valid cut in a later step also fails
/// the compatibility fixture.
fn walk_cuts_digest(census: Vec<ragu_pcd::profile::paging::Sizing>) -> String {
    assert!(census.len() > 1, "the walk has later steps to check");
    let mut state = blake2b_simd::Params::new()
        .hash_length(32)
        .personal(b"ragu_walk_pages_")
        .to_state();
    state.update(&(census.len() as u64).to_le_bytes());
    for (step, sizing) in census.into_iter().enumerate() {
        assert!(sizing.cut.num_pages() > 1, "step {step} is not paged");
        let digest = sizing.digest.unwrap_or_else(|| {
            panic!(
                "{} step {step} does not cut and check: {:?}",
                sizing.name, sizing.pages
            )
        });
        state.update(&(step as u64).to_le_bytes());
        state.update(&digest);
    }
    state.finalize().as_bytes()[..8]
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect()
}

fn walk_cuts<const H: usize>() -> Result<(usize, String, String)> {
    use ragu_pcd::profile::paging::{native_walk_census, nested_walk_census};
    type C<const H: usize> = Profiled<Pasta, Aggregator<H>>;
    Ok((
        H,
        walk_cuts_digest(native_walk_census::<C<H>, AggregatorRank>()?),
        walk_cuts_digest(nested_walk_census::<C<H>, AggregatorRank>()?),
    ))
}

const WALK_CUTS: [(usize, &str, &str); 2] = [
    (4, "76649aa184d5d4d0", "f732dd452a11b3de"),
    (195, "76649aa184d5d4d0", "e0944313cef039c5"),
];

#[test]
fn every_aggregator_walk_step_cut_is_pinned() -> Result<()> {
    let found = [walk_cuts::<4>()?, walk_cuts::<195>()?];
    for ((header, native, nested), (expected_header, expected_native, expected_nested)) in
        found.iter().zip(WALK_CUTS)
    {
        assert_eq!(*header, expected_header);
        assert_eq!(
            native, expected_native,
            "native walk at header size {header}"
        );
        assert_eq!(
            nested, expected_nested,
            "nested walk at header size {header}"
        );
    }
    Ok(())
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
