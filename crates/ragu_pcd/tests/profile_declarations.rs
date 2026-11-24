use ragu_circuits::polynomials::{AggregatorRank, R, WalletRank};

use super::{
    testing::{Crossing, CrossingBack, CrossingContext, Mismatched, Opening, Wider},
    *,
};
use crate::{compress::runs::num_runs, decompress::aggregator};

#[test]
fn endoscaling_counts_must_allow_convergent_walks() {
    #[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
    struct Walk<const N: usize, const M: usize>;

    impl<const N: usize, const M: usize> Profile for Walk<N, M> {
        const NAME: &'static str = "walk parameters";
        const NATIVE_EXTENSION: usize = 0;
        const NESTED_EXTENSION: usize = 0;
        const NATIVE_ENDOSCALINGS_PER_STEP: usize = N;
        const NESTED_ENDOSCALINGS_PER_STEP: usize = M;

        type Context<'params, Base, R, B>
            = ()
        where
            Base: IpaCycle + ProfiledCycle<Profile = Standard>,
            R: Rank,
            B: SelectableBackend;
    }

    for result in [
        Walk::<0, 4>::check(),
        Walk::<4, 0>::check(),
        Walk::<1, 1>::check(),
        Walk::<1, 4>::check(),
        Walk::<4, 1>::check(),
        Walk::<2, 2>::check(),
        Walk::<0, { usize::MAX }>::check(),
    ] {
        assert!(matches!(result, Err(Error::Initialization(_))));
    }

    fn converges<const N: usize, const M: usize>() {
        Walk::<N, M>::check().unwrap();
        let shape = Shape::of::<Walk<N, M>>();
        assert!(shape.native_steps > 0 && shape.nested_steps > 0);
    }
    converges::<1, 5>();
    converges::<5, 1>();
    converges::<2, 3>();
    converges::<3, 4>();
    converges::<4, 4>();
    // Validation must not overflow when multiplying the counts.
    converges::<{ usize::MAX }, { usize::MAX }>();
}

/// What the hooks register is held to the declaration: each stage's
/// mask at its bonding and a final mask at each later one, each staged
/// circuit over its declared stages' gates under the final mask that
/// starts where its last stage ends, and no stages for a circuit that
/// declares none.
#[test]
fn registrations_are_held_to_the_declaration() {
    use alloc::vec;

    use Registration::*;
    let single = |gates: Range<usize>| Staged(vec![gates]);
    let extension = Extension {
        circuits: vec![vec![0, 1], vec![], vec![0]],
        stages: 2,
        final_masks: vec![vec![0], vec![2]],
        statement: None,
        binding: None,
    };
    assert!(extension.is_consistent());
    let bondings = vec![Mask(1..4), Mask(4..9), FinalMask(9), FinalMask(4)];
    let circuits = vec![Staged(vec![1..4, 4..9]), Circuit, single(1..4)];
    assert!(
        extension
            .check_registered("native", &circuits, &bondings)
            .is_ok()
    );
    let refused = |circuits: Vec<Registration>, bondings: Vec<Registration>| {
        matches!(
            extension.check_registered("native", &circuits, &bondings),
            Err(Error::Initialization(_))
        )
    };
    // A circuit over other gates than its stages', in another order, or
    // short of a stage.
    assert!(refused(
        vec![Staged(vec![1..4, 4..10]), Circuit, single(1..4)],
        bondings.clone()
    ));
    assert!(refused(
        vec![Staged(vec![4..9, 1..4]), Circuit, single(1..4)],
        bondings.clone()
    ));
    assert!(refused(
        vec![single(1..4), Circuit, single(1..4)],
        bondings.clone()
    ));
    // A circuit declared over stages but registered without, and one
    // declared without but registered over one.
    assert!(refused(
        vec![Circuit, Circuit, single(1..4)],
        bondings.clone()
    ));
    assert!(refused(
        vec![Staged(vec![1..4, 4..9]), single(1..4), single(1..4)],
        bondings.clone()
    ));
    // A final mask elsewhere than where its circuits' last stage ends, a
    // stage's mask over other gates than its circuits load, and bondings
    // of the wrong kind.
    assert!(refused(
        circuits.clone(),
        vec![Mask(1..4), Mask(4..9), FinalMask(10), FinalMask(4)]
    ));
    assert!(refused(
        circuits.clone(),
        vec![Mask(1..4), Mask(4..8), FinalMask(9), FinalMask(4)]
    ));
    assert!(refused(
        circuits.clone(),
        vec![Mask(1..4), FinalMask(9), FinalMask(9), FinalMask(4)]
    ));
    assert!(refused(
        circuits.clone(),
        vec![Mask(1..4), Mask(4..9), Mask(9..12), FinalMask(4)]
    ));
    // Other counts than the declaration's.
    assert!(refused(circuits[..2].to_vec(), bondings.clone()));
    assert!(refused(circuits.clone(), bondings[..3].to_vec()));
}

#[test]
fn declared_extensions_check() {
    Standard::check().unwrap();
    Aggregator::<4>::check().unwrap();
    Aggregator::<195>::check().unwrap();
    assert!(Aggregator::<4>::native_extension().is_consistent());
    assert!(Aggregator::<4>::nested_extension().is_consistent());
    Wider::check().unwrap();
    Crossing::check().unwrap();
    CrossingBack::check().unwrap();
    assert!(Wider::native_extension().is_consistent());
    assert!(Wider::nested_extension().is_consistent());
    assert!(Mismatched::check().is_err());
}

/// A declaration is well formed only with every index in range, nothing
/// named twice, every circuit's stages in gate order, every staged
/// circuit under exactly one final mask, its last stage's, and a binding
/// circuit other than the statement circuit naming at least one stage,
/// none twice.
#[test]
fn consistency_binds_every_staged_circuit() {
    use alloc::vec;

    let extension = |circuits, stages, final_masks, statement| Extension {
        circuits,
        stages,
        final_masks,
        statement,
        binding: None,
    };
    // Two staged circuits, each under its last stage's final mask, one
    // without stages under none, and a statement circuit.
    assert!(
        extension(
            vec![vec![0], vec![0, 1], vec![]],
            2,
            vec![vec![0], vec![1]],
            Some(1)
        )
        .is_consistent()
    );
    // A stage, a circuit or a statement circuit out of range.
    assert!(!extension(vec![vec![2]], 2, vec![vec![0]], None).is_consistent());
    assert!(!extension(vec![vec![0]], 1, vec![vec![1]], None).is_consistent());
    assert!(!extension(vec![vec![0]], 1, vec![vec![0]], Some(1)).is_consistent());
    // A staged circuit under no final mask, or under two.
    assert!(!extension(vec![vec![0], vec![0]], 1, vec![vec![0]], None).is_consistent());
    assert!(!extension(vec![vec![0]], 1, vec![vec![0], vec![0]], None).is_consistent());
    // A circuit without stages under a final mask, and an empty one.
    assert!(!extension(vec![vec![]], 1, vec![vec![0]], None).is_consistent());
    assert!(!extension(vec![vec![0]], 1, vec![vec![0], vec![]], None).is_consistent());
    // One final mask over circuits with different last stages.
    assert!(!extension(vec![vec![0], vec![0, 1]], 2, vec![vec![0, 1]], None).is_consistent());
    // A stage or a circuit named twice.
    assert!(!extension(vec![vec![0, 0]], 1, vec![vec![0]], None).is_consistent());
    assert!(!extension(vec![vec![0]], 1, vec![vec![0, 0]], None).is_consistent());
    // A circuit's stages out of gate order: its final mask would be an
    // earlier stage's than the last it loads, under either grouping.
    assert!(!extension(vec![vec![1, 0]], 2, vec![vec![0]], None).is_consistent());
    assert!(extension(vec![vec![0, 1]], 2, vec![vec![0]], None).is_consistent());

    // Two circuits without stages, the first the statement circuit and
    // the second binding the other side's stages, which the other side
    // is to have.
    let binding = |circuit, stages| Extension {
        circuits: vec![vec![], vec![]],
        stages: 0,
        final_masks: vec![],
        statement: Some(0),
        binding: Some(Binding {
            circuit,
            stages,
            online: vec![],
            native_online: Vec::new(),
            openings: Vec::new(),
        }),
    };
    assert!(binding(1, vec![1, 0]).is_consistent());
    // The binding circuit out of range, or the statement circuit.
    assert!(!binding(2, vec![0]).is_consistent());
    assert!(!binding(0, vec![0]).is_consistent());
    // The binding naming no stage, or one twice.
    assert!(!binding(1, vec![]).is_consistent());
    assert!(!binding(1, vec![0, 0]).is_consistent());
}

/// The profile's checks refuse a malformed extension, a statement
/// circuit on the nested side, and a binding naming a stage the other
/// side does not have, from either side.
#[test]
fn malformed_declarations_are_refused() {
    use alloc::vec;

    /// A statement circuit past the circuits.
    #[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
    struct StrayStatement;

    impl Profile for StrayStatement {
        const NAME: &'static str = "stray statement";
        const NATIVE_EXTENSION: usize = 2;
        const NESTED_EXTENSION: usize = 0;

        type Context<'params, Base, R, B>
            = ()
        where
            Base: IpaCycle + ProfiledCycle<Profile = Standard>,
            R: Rank,
            B: SelectableBackend;

        fn native_extension() -> Extension {
            Extension {
                circuits: vec![vec![0]],
                stages: 1,
                final_masks: vec![vec![0]],
                statement: Some(1),
                binding: None,
            }
        }
    }

    /// A statement circuit on the nested side.
    #[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
    struct NestedStatement;

    impl Profile for NestedStatement {
        const NAME: &'static str = "nested statement";
        const NATIVE_EXTENSION: usize = 0;
        const NESTED_EXTENSION: usize = 2;

        type Context<'params, Base, R, B>
            = ()
        where
            Base: IpaCycle + ProfiledCycle<Profile = Standard>,
            R: Rank,
            B: SelectableBackend;

        fn nested_extension() -> Extension {
            Extension {
                circuits: vec![vec![0]],
                stages: 1,
                final_masks: vec![vec![0]],
                statement: Some(0),
                binding: None,
            }
        }
    }

    /// [`Crossing`] with its native binding naming one nested stage
    /// past the one the nested side has.
    #[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
    struct StrayBinding;

    impl Profile for StrayBinding {
        const NAME: &'static str = "stray binding";
        const NATIVE_EXTENSION: usize = 1;
        const NESTED_EXTENSION: usize = 2;

        type Context<'params, Base, R, B>
            = ()
        where
            Base: IpaCycle + ProfiledCycle<Profile = Standard>,
            R: Rank,
            B: SelectableBackend;

        fn native_extension() -> Extension {
            Extension {
                circuits: vec![vec![]],
                stages: 0,
                final_masks: vec![],
                statement: None,
                binding: Some(Binding {
                    circuit: 0,
                    stages: vec![0, 1],
                    online: vec![],
                    native_online: Vec::new(),
                    openings: Vec::new(),
                }),
            }
        }

        fn nested_extension() -> Extension {
            Crossing::nested_extension()
        }
    }

    /// [`CrossingBack`] with its nested binding naming one native stage
    /// past the one the native side has.
    #[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
    struct StrayNestedBinding;

    impl Profile for StrayNestedBinding {
        const NAME: &'static str = "stray nested binding";
        const NATIVE_EXTENSION: usize = 2;
        const NESTED_EXTENSION: usize = 1;

        type Context<'params, Base, R, B>
            = ()
        where
            Base: IpaCycle + ProfiledCycle<Profile = Standard>,
            R: Rank,
            B: SelectableBackend;

        fn native_extension() -> Extension {
            CrossingBack::native_extension()
        }

        fn nested_extension() -> Extension {
            Extension {
                circuits: vec![vec![]],
                stages: 0,
                final_masks: vec![],
                statement: None,
                binding: Some(Binding {
                    circuit: 0,
                    stages: vec![1],
                    online: vec![],
                    native_online: Vec::new(),
                    openings: Vec::new(),
                }),
            }
        }
    }

    assert!(StrayStatement::check().is_err());
    assert!(NestedStatement::check().is_err());
    assert!(StrayBinding::check().is_err());
    assert!(StrayNestedBinding::check().is_err());
}

/// A profile's name identifies it in diagnostics, so the checks refuse
/// an empty name and a built-in profile's name on any other profile, and
/// accept the built-in profiles' own.
#[test]
fn names_are_checked() {
    macro_rules! named {
        ($profile:ident, $name:expr) => {
            #[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
            struct $profile;

            impl Profile for $profile {
                const NAME: &'static str = $name;
                const NATIVE_EXTENSION: usize = 0;
                const NESTED_EXTENSION: usize = 0;

                type Context<'params, Base, R, B>
                    = ()
                where
                    Base: IpaCycle + ProfiledCycle<Profile = Standard>,
                    R: Rank,
                    B: SelectableBackend;
            }
        };
    }
    named!(Nameless, "");
    named!(StandardImpostor, "standard");
    named!(AggregatorImpostor, "aggregator");
    named!(Named, "named");

    // A profile that copies a built-in profile's token still carries
    // that profile's type, and is refused its name.
    macro_rules! forged {
        ($profile:ident, $name:expr, $from:ty) => {
            #[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
            struct $profile;

            impl Profile for $profile {
                const NAME: &'static str = $name;
                const BUILT_IN: Option<BuiltIn> = <$from as Profile>::BUILT_IN;
                const NATIVE_EXTENSION: usize = 0;
                const NESTED_EXTENSION: usize = 0;

                type Context<'params, Base, R, B>
                    = ()
                where
                    Base: IpaCycle + ProfiledCycle<Profile = Standard>,
                    R: Rank,
                    B: SelectableBackend;
            }
        };
    }
    forged!(StandardForger, "standard", Standard);
    forged!(AggregatorForger, "aggregator", Aggregator<4>);
    assert!(StandardForger::check().is_err());
    assert!(AggregatorForger::check().is_err());

    assert!(Nameless::check().is_err());
    assert!(StandardImpostor::check().is_err());
    assert!(AggregatorImpostor::check().is_err());
    assert!(Named::check().is_ok());
    assert!(Standard::check().is_ok());
    assert!(Aggregator::<4>::check().is_ok());
    assert!(testing::Twin::check().is_ok());
    assert!(testing::Decompressing::check().is_ok());
}

#[test]
fn extension_entries_take_their_places() {
    use native::{InternalCircuitIndex as NativeCircuit, RxIndex as NativeRx};
    use nested::{InternalCircuitIndex as NestedCircuit, RxIndex as NestedRx};

    // The extension lengthens the walks too, so count from the shape.
    let shape = Shape::of::<Wider>();
    let circuits = NativeCircuit::all::<Wider>();
    assert_eq!(circuits.len(), NativeCircuit::num::<Wider>());
    assert_eq!(
        circuits.len(),
        native::NUM_FIXED_INTERNAL + shape.native_steps + 6
    );
    let last_step = circuits
        .iter()
        .rposition(|id| matches!(id, NativeCircuit::EndoscalingStep(_)))
        .unwrap();
    assert_eq!(
        circuits[last_step + 1..last_step + 3],
        [
            NativeCircuit::ExtensionCircuit(0),
            NativeCircuit::ExtensionCircuit(1)
        ]
    );
    assert_eq!(
        circuits[circuits.len() - 4..],
        [
            NativeCircuit::ExtensionBonding(0),
            NativeCircuit::ExtensionBonding(1),
            NativeCircuit::ExtensionBonding(2),
            NativeCircuit::ExtensionBonding(3),
        ]
    );
    assert_eq!(
        NativeCircuit::ExtensionCircuit(1).circuit_index::<Wider>(),
        ragu_circuits::registry::CircuitIndex::new(last_step + 2)
    );

    let rx = NativeRx::all::<Wider>();
    assert_eq!(rx.len(), NativeRx::num::<Wider>());
    assert_eq!(rx.len(), native::NUM_FIXED_RX + shape.native_steps + 4);
    assert_eq!(
        rx[rx.len() - 4..],
        [
            NativeRx::ExtensionCircuit(0),
            NativeRx::ExtensionCircuit(1),
            NativeRx::ExtensionStage(0),
            NativeRx::ExtensionStage(1),
        ]
    );

    let circuits = NestedCircuit::all::<Wider>();
    assert_eq!(circuits.len(), NestedCircuit::num::<Wider>());
    assert_eq!(
        circuits.len(),
        nested::NUM_FIXED_INTERNAL + shape.nested_steps + 3
    );
    let compute_v = circuits
        .iter()
        .position(|&id| id == NestedCircuit::ComputeV)
        .unwrap();
    assert_eq!(circuits[compute_v + 1], NestedCircuit::ExtensionCircuit(0));
    assert_eq!(
        circuits[circuits.len() - 2..],
        [
            NestedCircuit::ExtensionBonding(0),
            NestedCircuit::ExtensionBonding(1)
        ]
    );
    let rx = NestedRx::all::<Wider>();
    assert_eq!(rx.len(), nested::NUM_FIXED_RX + shape.nested_steps + 2);
    assert_eq!(
        rx[rx.len() - 2..],
        [NestedRx::ExtensionCircuit(0), NestedRx::ExtensionStage(0)]
    );
}

#[test]
fn shape_follows_the_declared_extension() {
    assert_eq!(Shape::of::<Wider>(), Shape::solve(4, 2, 0, 4, 4));
    assert_ne!(Shape::of::<Wider>(), Shape::of::<Standard>());
    assert_eq!(
        native::RxIndex::num::<Wider>(),
        Shape::of::<Wider>().native_rx
    );
    assert_eq!(
        nested::RxIndex::num::<Wider>(),
        Shape::of::<Wider>().nested_rx
    );
}

#[test]
fn standard_is_the_crate_layout() {
    let shape = Shape::of::<Standard>();
    assert_eq!(
        shape,
        Shape {
            native_rx: 48,
            nested_points: 122,
            nested_steps: 31,
            nested_rx: 45,
            online_fq: 0,
            native_points: 108,
            native_steps: 27,
            source_polynomials: 0,
        }
    );
    assert_eq!(shape.polynomials(), 103);
}

#[test]
fn an_online_fq_polynomial_is_a_native_walk_point() {
    // The point joins the nested batch's commitments in the native
    // walk. A full walk then needs another native step, and with it
    // the batch grows.
    let base = Shape::solve(0, 0, 0, 4, 4);
    let with_fq = Shape::solve(0, 0, 1, 4, 4);
    assert_eq!(with_fq.online_fq, 1);
    assert_eq!(
        with_fq.native_points,
        nested::pcs::num_batched_points(with_fq.nested_rx, 0) + 1
    );
    assert!(with_fq.native_points > base.native_points);
}

#[test]
fn an_online_fq_polynomial_alone_fills_the_native_walk() {
    // The standard layout with the slot on. Its native walk has room
    // for one more point, so the point adds no step and no polynomial.
    let shape = Shape::of::<Opening>();
    assert_eq!(shape, Shape::solve(0, 0, 1, 4, 4));
    assert_eq!(
        shape,
        Shape {
            native_rx: 48,
            nested_points: 122,
            nested_steps: 31,
            nested_rx: 45,
            online_fq: 1,
            native_points: 109,
            native_steps: 27,
            source_polynomials: 0,
        }
    );
    assert_eq!(shape.polynomials(), 103);
    assert_eq!(native::RxIndex::num::<Opening>(), shape.native_rx);
    assert_eq!(nested::RxIndex::num::<Opening>(), shape.nested_rx);

    // A second point overflows the walk and adds a native step. The
    // children's commitments of that step's rx polynomial are two more
    // nested walk points, and the nested walk has room for them: one
    // more rx polynomial on the native side only.
    assert_eq!(
        Shape::solve(0, 0, 2, 4, 4),
        Shape {
            native_rx: 49,
            nested_points: 124,
            nested_steps: 31,
            nested_rx: 45,
            online_fq: 2,
            native_points: 110,
            native_steps: 28,
            source_polynomials: 0,
        }
    );
}

#[test]
fn check_refuses_more_online_fq_polynomials_than_a_step_opens() {
    #[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
    struct TooMany;
    impl Profile for TooMany {
        const NAME: &'static str = "too-many";
        const NATIVE_EXTENSION: usize = 0;
        const NESTED_EXTENSION: usize = 0;
        const ONLINE_FQ_POLYS: usize = crate::profile::NUM_ONLINE_FQ_POLYS + 1;

        type Context<'params, Base, R, B>
            = ()
        where
            Base: IpaCycle + ProfiledCycle<Profile = Standard>,
            R: Rank,
            B: SelectableBackend;
    }
    assert!(TooMany::check().is_err());
}

/// The aggregator's shape follows its pinned circuits, its one online
/// Fq polynomial and its online batches, and grows with the header size
/// through the transcript circuits.
#[test]
fn aggregator_declares_the_decompression() {
    let shape = Shape::of::<Aggregator<4>>();
    let per_step = Aggregator::<4>::ENDOSCALINGS_PER_STEP;
    let nested_stages = aggregator::nested_stages(num_runs::<WalletRank>());
    assert_eq!(nested_stages, 27, "a stage per run, then four");
    // Each field's online batch: its three stages and its helper among
    // the side's polynomials, the mesh's twenty polynomials among the
    // points the other side's walk folds, and the outgoing restriction
    // the proof retains.
    let batch = online::stages::RXS;
    let expected = |native_circuits: usize| {
        let mut shape = Shape::solve_with_online(
            native_circuits + 2 + 6 + batch,
            19 + 1 + nested_stages + batch,
            1 + 20,
            21,
            per_step,
            per_step,
        );
        shape.source_polynomials = 2;
        shape
    };
    assert_eq!(shape, expected(32));
    assert_eq!(Shape::of::<Aggregator<195>>(), expected(34));
    // The knob: at the wallet rank's four per step the walks are
    // far longer.
    assert!(shape.polynomials() < Shape::solve(56 + 2 + 6, 46 + 1 + 5, 1, 4, 4).polynomials());
    assert!(shape.polynomials() > Shape::of::<Standard>().polynomials());
    std::println!(
        "aggregator at header size 4: {shape:?}, {} polynomials",
        shape.polynomials()
    );
}

/// The hooks register only at the aggregator rank, and only for the
/// profile's header size.
#[test]
fn aggregator_hooks_refuse_other_parameters() {
    let params = crate::pasta::baked();
    let at_wallet_rank = Aggregator::<4>::register_native_circuit::<Pasta, WalletRank, 4>(
        0,
        CircuitSlot::new(RegistryBuilder::new()),
        params,
    );
    assert!(matches!(at_wallet_rank, Err(Error::Initialization(_))));
    let other_header = Aggregator::<4>::register_native_circuit::<Pasta, AggregatorRank, 195>(
        0,
        CircuitSlot::new(RegistryBuilder::new()),
        params,
    );
    assert!(matches!(other_header, Err(Error::Initialization(_))));
    let nested_at_wallet_rank = Aggregator::<4>::register_nested_circuit::<Pasta, WalletRank>(
        0,
        CircuitSlot::new(RegistryBuilder::new()),
        params,
    );
    assert!(matches!(
        nested_at_wallet_rank,
        Err(Error::Initialization(_))
    ));
}

#[test]
fn pasta_proves_in_the_standard_profile() {
    assert_eq!(
        Shape::of::<<Pasta as ProfiledCycle>::Profile>(),
        Shape::of::<Standard>()
    );
    assert_eq!(
        Shape::of::<<Profiled<Pasta, Aggregator<4>> as ProfiledCycle>::Profile>(),
        Shape::of::<Aggregator<4>>()
    );
}

#[test]
fn solve_finds_a_fixed_point_for_wider_profiles() {
    for (native_extension, nested_extension) in
        [(0, 0), (1, 0), (0, 1), (10, 10), (134, 116), (300, 300)]
    {
        let shape = Shape::solve(native_extension, nested_extension, 0, 4, 4);
        let again = Shape::with_native_steps(
            shape.native_steps,
            native_extension,
            nested_extension,
            0,
            0,
            4,
            4,
        );
        assert_eq!(
            again, shape,
            "({native_extension}, {nested_extension}) is not fixed"
        );
    }
}

#[test]
fn extensions_lengthen_both_walks() {
    // Each extra rx polynomial is two points in the other walk (one per
    // child), so a step there per two, and a quarter of a step back: an
    // extension costs about twice its own count in polynomials overall.
    let base = Shape::solve(0, 0, 0, 4, 4);
    let wider = Shape::solve(100, 0, 0, 4, 4);
    assert!(wider.nested_steps > base.nested_steps);
    assert!(wider.native_steps > base.native_steps);
    let extra = wider.polynomials() - base.polynomials();
    assert!(
        (150..=250).contains(&extra),
        "100 native polynomials cost {extra} overall"
    );
}

/// An extension proves: an application in the [`Proving`] profile,
/// one trivial circuit on each side and one online Fq polynomial per
/// step, seeds, fuses, verifies and compresses at the rank above the
/// wallet's, where the fuse has room for the two polynomials.
#[test]
fn an_extension_proves_verifies_and_compresses() -> Result<()> {
    use rand::{SeedableRng, rngs::StdRng};

    use super::testing::{Proving, UnitStep};
    use crate::ApplicationBuilder;

    const HEADER_SIZE: usize = 4;
    assert_ne!(Shape::of::<Proving>(), Shape::of::<Standard>());
    // Each step also commits an online Fq polynomial, which the nested
    // `compute_v` opens and folds in the step's own nested batch.
    assert_eq!(Shape::of::<Proving>().online_fq, 1);

    let app = ApplicationBuilder::<Profiled<Pasta, Proving>, R<14>, HEADER_SIZE>::new()
        .register(UnitStep)?
        .finalize(crate::pasta::baked_aggregator())?;
    let mut rng = StdRng::seed_from_u64(14);
    let (left, ()) = app.seed(&mut rng, UnitStep, ())?;
    let (right, ()) = app.seed(&mut rng, UnitStep, ())?;
    let (fused, ()) = app.fuse(&mut rng, UnitStep, (), left, right)?;
    assert!(app.verify_uncompressed(&fused, &mut rng)?);
    let compressed = app.compress(&fused, &mut rng)?;
    assert!(app.verify_compressed(&compressed)?);
    Ok(())
}

/// The slot proves without an extension: an application in the
/// [`Opening`] profile, one online Fq polynomial per step and nothing
/// else beyond the fuse, seeds, fuses, verifies and compresses at the
/// wallet rank.
#[test]
fn an_online_fq_polynomial_proves_verifies_and_compresses() -> Result<()> {
    use rand::{SeedableRng, rngs::StdRng};

    use super::testing::UnitStep;
    use crate::ApplicationBuilder;

    const HEADER_SIZE: usize = 4;

    let app = ApplicationBuilder::<Profiled<Pasta, Opening>, R<13>, HEADER_SIZE>::new()
        .register(UnitStep)?
        .finalize(crate::pasta::baked())?;
    let mut rng = StdRng::seed_from_u64(13);
    let (left, ()) = app.seed(&mut rng, UnitStep, ())?;
    let (right, ()) = app.seed(&mut rng, UnitStep, ())?;
    let (fused, ()) = app.fuse(&mut rng, UnitStep, (), left, right)?;
    assert!(app.verify_uncompressed(&fused, &mut rng)?);
    let compressed = app.compress(&fused, &mut rng)?;
    assert!(app.verify_compressed(&compressed)?);
    Ok(())
}

/// A binding circuit's claim holds only if its side's values are the
/// ones the other side's stage holds: a proof whose two sides disagree
/// fails the decider and the compressed verifier, and so does a parent
/// over it. Under `P`, with the two sides given their bits through a
/// [`CrossingContext`].
fn a_binding_holds_the_sides_to_each_other_under<P>() -> Result<()>
where
    P: Profile<
        Context<'static, Pasta, R<14>, ragu_acceleration::AcceleratedBackend> = CrossingContext<
            'static,
            Pasta,
        >,
    >,
{
    use rand::{SeedableRng, rngs::StdRng};

    use super::testing::UnitStep;
    use crate::ApplicationBuilder;

    let params = crate::pasta::baked_aggregator();
    let application = |native, nested| {
        ApplicationBuilder::<Profiled<Pasta, P>, R<14>, 4>::new()
            .register(UnitStep)?
            .finalize_with(
                params,
                CrossingContext {
                    params,
                    native,
                    nested,
                },
            )
    };
    let bits = [true, false, false, true];
    let mut other = bits;
    other[1] = !other[1];

    let honest = application(bits, bits)?;
    let mut rng = StdRng::seed_from_u64(15);
    let (left, ()) = honest.seed(&mut rng, UnitStep, ())?;
    let (right, ()) = honest.seed(&mut rng, UnitStep, ())?;
    let (fused, ()) = honest.fuse(&mut rng, UnitStep, (), left.clone(), right)?;
    assert!(honest.verify_uncompressed(&fused, &mut rng)?);
    let compressed = honest.compress(&fused, &mut rng)?;
    assert!(honest.verify_compressed(&compressed)?);

    // The same circuits, with the native side given other bits than the
    // digits the nested side holds.
    let disagreeing = application(bits, other)?;
    let (leaf, ()) = disagreeing.seed(&mut rng, UnitStep, ())?;
    assert!(!honest.verify_uncompressed(&leaf, &mut rng)?);
    let compressed = honest.compress(&leaf, &mut rng)?;
    assert!(!honest.verify_compressed(&compressed)?);
    let (parent, ()) = honest.fuse(&mut rng, UnitStep, (), leaf, left)?;
    assert!(!honest.verify_uncompressed(&parent, &mut rng)?);
    Ok(())
}

/// The native side binds: [`Crossing`]'s native binding circuit holds
/// the native bits to the nested digits stage.
#[test]
fn a_native_binding_holds_the_sides_to_each_other() -> Result<()> {
    a_binding_holds_the_sides_to_each_other_under::<Crossing>()
}

/// The nested side binds: [`CrossingBack`]'s nested binding circuit
/// holds the nested bits to the native digits stage.
#[test]
fn a_nested_binding_holds_the_sides_to_each_other() -> Result<()> {
    a_binding_holds_the_sides_to_each_other_under::<CrossingBack>()
}

/// Every polynomial of an extension is bound, on either side: a leaf
/// with one extension circuit's or stage's polynomial doubled, its
/// commitment recomputed so that only the claims disagree, fails the
/// decider and the compressed verifier, and so does a parent over it.
/// Under `P`, with both sides given the same bits through a
/// [`CrossingContext`].
fn extension_polynomials_are_bound_under<P>() -> Result<()>
where
    P: Profile<
        Context<'static, Pasta, R<14>, ragu_acceleration::AcceleratedBackend> = CrossingContext<
            'static,
            Pasta,
        >,
    >,
{
    use alloc::format;

    use rand::{SeedableRng, rngs::StdRng};

    use super::testing::UnitStep;
    use crate::ApplicationBuilder;

    let params = crate::pasta::baked_aggregator();
    let bits = [false, true, true, false];
    let app = ApplicationBuilder::<Profiled<Pasta, P>, R<14>, 4>::new()
        .register(UnitStep)?
        .finalize_with(
            params,
            CrossingContext {
                params,
                native: bits,
                nested: bits,
            },
        )?;
    let mut rng = StdRng::seed_from_u64(16);
    let (leaf, ()) = app.seed(&mut rng, UnitStep, ())?;
    let (sibling, ()) = app.seed(&mut rng, UnitStep, ())?;
    assert!(app.verify_uncompressed(&leaf, &mut rng)?);

    let native_extension = P::native_extension();
    let nested_extension = P::nested_extension();
    let mut corrupted = Vec::new();
    for k in 0..native_extension.circuits.len() as u32 {
        let mut proof = leaf.proof().clone();
        proof.double_native_extension_rx(params, native::RxIndex::ExtensionCircuit(k));
        corrupted.push((format!("native circuit {k}"), proof));
    }
    for j in 0..native_extension.stages as u32 {
        let mut proof = leaf.proof().clone();
        proof.double_native_extension_rx(params, native::RxIndex::ExtensionStage(j));
        corrupted.push((format!("native stage {j}"), proof));
    }
    for k in 0..nested_extension.circuits.len() as u32 {
        let mut proof = leaf.proof().clone();
        proof.double_nested_extension_rx(params, nested::RxIndex::ExtensionCircuit(k));
        corrupted.push((format!("nested circuit {k}"), proof));
    }
    for j in 0..nested_extension.stages as u32 {
        let mut proof = leaf.proof().clone();
        proof.double_nested_extension_rx(params, nested::RxIndex::ExtensionStage(j));
        corrupted.push((format!("nested stage {j}"), proof));
    }
    assert_eq!(
        corrupted.len(),
        native_extension.rx() + nested_extension.rx()
    );

    for (what, proof) in corrupted {
        let pcd = proof.carry::<()>(());
        assert!(
            !app.verify_uncompressed(&pcd, &mut rng)?,
            "{what}: the decider"
        );
        let compressed = app.compress(&pcd, &mut rng)?;
        assert!(
            !app.verify_compressed(&compressed)?,
            "{what}: the compressed verifier"
        );
        let (parent, ()) = app.fuse(&mut rng, UnitStep, (), pcd, sibling.clone())?;
        assert!(
            !app.verify_uncompressed(&parent, &mut rng)?,
            "{what}: a parent"
        );
    }
    Ok(())
}

/// [`Crossing`]'s three polynomials, its binding circuit's and the
/// nested circuit's and stage's.
#[test]
fn extension_polynomials_are_bound_with_a_native_binding() -> Result<()> {
    extension_polynomials_are_bound_under::<Crossing>()
}

/// [`CrossingBack`]'s three polynomials, the native circuit's and
/// stage's and its binding circuit's.
#[test]
fn extension_polynomials_are_bound_with_a_nested_binding() -> Result<()> {
    extension_polynomials_are_bound_under::<CrossingBack>()
}
