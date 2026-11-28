//! Profiles that page the fuse's internal circuits prove and verify. A
//! paged circuit is cut into several circuits at the wallet rank, with
//! nothing but the profile's declaration saying so: its pages before the
//! last ride the profile's extension, and the last takes the circuit's own
//! slot.

use ragu_circuits::polynomials::{AggregatorRank, Rank, WalletRank};
use ragu_core::{
    Cycle, Result,
    pasta::{Fp, Pasta},
};
use ragu_pcd::{
    ApplicationBuilder, SelectableBackend,
    ipa::IpaCycle,
    profile::{PageCount, PageCounts, Profile, Profiled, ProfiledCycle, Shape, Standard},
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
    const PAGE_COUNTS: PageCounts = PageCounts {
        hashes_1: PageCount::new(2).carrying(64),
        hashes_2: PageCount::new(2).carrying(64),
        collapse: PageCount::new(3).carrying(64),
        compute_v: PageCount::new(5).carrying(64),
        bind_challenges: PageCount::new(2).carrying(64),
        bind_beta: PageCount::new(2).carrying(64),
        bind_endoscalar: PageCount::new(2).carrying(64),
        nested_collapse: PageCount::new(3).carrying(64),
        nested_compute_v: PageCount::new(5).carrying(64),
        ..PageCounts::WHOLE
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
    assert_eq!(Standard::PAGE_COUNTS, PageCounts::WHOLE);
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
        let cuts: &[(&'static str, PageCount)] = $cuts;
        let pasta = ragu_pcd::pasta::baked();
        let mut census = native_census::<C, $rank, $header>(pasta, 3, cuts, false)?;
        census.extend(nested_census::<C, $rank>(cuts, false)?);
        // The decompression's two whole circuits, which the profile pages
        // as it does the fuse's.
        census.extend(<$profile>::decompression_census::<Pasta, $rank>(pasta, false)?);
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

/// How each fuse circuit of the aggregator profile, and each side of the
/// decompression, cuts into polynomials at the aggregator rank.
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
use census_support::{Most, header_pages_fit};

macro_rules! check_headers {
    ($most:ident; $($header:literal),+ $(,)?) => {
        $(header_pages_fit::<$header>(&mut $most)?;)+
    };
}

/// Check both sides of the aggregator's header-dependent schedule changes
/// in ordinary CI. The dedicated paging census checks every supported
/// header size in smaller build batches. Prints the most values each paged
/// circuit's pages carry over these sizes, beside what its carry stage
/// holds (`--nocapture`).
#[test]
fn aggregator_pages_fit_at_header_boundaries() -> Result<()> {
    let mut most = Most::default();
    check_headers!(
        most; 1, 2, 9, 10, 33, 34, 41, 42, 57, 58, 65, 66, 97, 98, 129, 130, 153, 154, 161, 162,
        185, 186, 193, 194, 195,
    );
    most.print();
    Ok(())
}

/// The pages the aggregator profile states for each fuse circuit and each
/// side of the decompression, whether the circuit cuts in them, and the
/// fewest it cuts in.
macro_rules! fewest {
    ($profile:ty, $header:expr) => {{
        use ragu_pcd::profile::paging::{native_census, nested_census};

        type C = Profiled<Pasta, $profile>;
        let pasta = ragu_pcd::pasta::baked();
        let mut census = native_census::<C, AggregatorRank, $header>(pasta, 3, &[], true)?;
        census.extend(nested_census::<C, AggregatorRank>(&[], true)?);
        census.extend(<$profile>::decompression_census::<Pasta, AggregatorRank>(
            pasta, true,
        )?);
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
                    sizing.count.num_pages(),
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

/// Asserts the declared cuts fit at sampled headers, and that each is the
/// fewest pages its circuit cuts into at one of them, printing the fewest
/// the solver finds at each. A count above that leaves pages with no gates
/// of their own, each still a polynomial of every proof, which nothing
/// else catches: the counts are set by hand and every other test only
/// holds a circuit to fit them. Changing a count changes the profile's
/// proof shape, which can change which smaller cuts fit, so the counts are
/// lowered until this passes. The heavy-tests workflow runs it with the
/// other ignored tests.
#[test]
#[ignore = "cuts every paged circuit of the aggregator into fewer pages at sampled headers"]
fn fewest_aggregator() -> Result<()> {
    use ragu_pcd::profile::Aggregator;

    // The decompression's native circuit takes its most pages at 189.
    let sizes: Vec<(usize, Found)> = vec![
        fewest!(Aggregator<1>, 1),
        fewest!(Aggregator<4>, 4),
        fewest!(Aggregator<33>, 33),
        fewest!(Aggregator<100>, 100),
        fewest!(Aggregator<154>, 154),
        fewest!(Aggregator<162>, 162),
        fewest!(Aggregator<189>, 189),
        fewest!(Aggregator<195>, 195),
    ];
    let headers: Vec<usize> = sizes.iter().map(|(header, _)| *header).collect();
    let mut above = Vec::new();
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
            "FEWEST headers {headers:?} {name}: states {stated:?}, takes {most:?} ({})",
            each.join("; "),
        );
        if most != stated {
            above.push(format!("{name}: states {stated}, takes {most}"));
        }
    }
    assert!(
        above.is_empty(),
        "a count the aggregator states is above the fewest pages its circuit cuts into at \
         headers {headers:?}: lower it, or sample the header size that takes it: {above:#?}"
    );
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
        census.extend(<$profile>::decompression_census::<Pasta, AggregatorRank>(
            pasta, false,
        )?);
        let cuts: Vec<(&'static str, String)> = census
            .into_iter()
            .filter(|sizing| sizing.count.num_pages() > 1)
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
/// circuit its profile pages, each side of the decompression among them, a
/// digest of its pages.
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
            ("decompression.native", "1e58f4ae28b64f66"),
            ("decompression.nested", "0caf8869c325a94d"),
        ],
    ),
    (
        9,
        &[
            ("decompression.native", "8bcb9420ad46b880"),
            ("decompression.nested", "8baba5b01a085e23"),
        ],
    ),
    (
        195,
        &[
            ("decompression.native", "ba3dc87bfab41a8f"),
            ("decompression.nested", "bfe79b5cee314901"),
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
