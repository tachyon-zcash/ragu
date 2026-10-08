//! Registry and staged-witness rejection through parents and grandparents.

use super::recursive_propagation_tests::support;

mod registry {
    //! Registry contents and circuit slots must stay bound through recursive proofs.
    //!
    //! The applications have the same headers and registry sizes, but disagree on
    //! a constant output. This gives the cross-application checks an independent
    //! validity condition, without inferring invalidity from an accumulator value.

    use alloc::{format, vec, vec::Vec};

    use proptest::prelude::*;
    use ragu_circuits::registry::{CircuitIndex, Tag};
    use ragu_core::{
        Result,
        drivers::{Driver, DriverValue},
        maybe::Maybe,
        pasta::{Fp, Fq},
    };
    use ragu_primitives::{Element, allocator::Standard};
    use rand::Rng;
    use udon::field::Field;

    use super::support::{self, C, HEADER_SIZE, R, Value};
    use crate::{
        ApplicationBuilder, RegistryTags,
        internal::native::InternalCircuitIndex,
        step::{Encoded, Index, Step},
    };

    /// A registered circuit fixes this value, independently of prover witnesses.
    struct ConstantSeed<const I: usize>(Fp);

    impl<const I: usize> Step<C> for ConstantSeed<I> {
        const INDEX: Index = Index::new(I);
        type Witness<'source> = ();
        type Aux<'source> = ();
        type Left = ();
        type Right = ();
        type Output = Value;

        fn witness<'dr, 'source: 'dr, D: Driver<'dr, F = Fp>, const N: usize>(
            &self,
            dr: &mut D,
            _: DriverValue<D, ()>,
            left: DriverValue<D, ()>,
            right: DriverValue<D, ()>,
        ) -> Result<(
            (
                Encoded<'dr, D, (), N>,
                Encoded<'dr, D, (), N>,
                Encoded<'dr, D, Value, N>,
            ),
            DriverValue<D, Fp>,
            DriverValue<D, ()>,
        )>
        where
            Self: 'dr,
        {
            let allocator = &mut Standard::new();
            let left = Encoded::new(dr, allocator, left)?;
            let right = Encoded::new(dr, allocator, right)?;
            let output = Element::constant(dr, self.0);
            let data = output.value().map(|v| *v);
            Ok(((left, right, Encoded::from_gadget(output)), data, D::unit()))
        }
    }

    fn app(first: Fp, second: Fp, extra_steps: usize) -> Result<support::App> {
        app_with_tags(first, second, extra_steps, None)
    }

    fn app_with_tags(
        first: Fp,
        second: Fp,
        extra_steps: usize,
        tags: Option<RegistryTags<C>>,
    ) -> Result<support::App> {
        let builder = ApplicationBuilder::<C, R, HEADER_SIZE>::new()
            .register(ConstantSeed::<0>(first))?
            .register(support::Merge::new())?
            .register(ConstantSeed::<2>(second))?
            .register_dummy_circuits(extra_steps)?;
        match tags {
            Some(tags) => builder.with_registry_tags(tags),
            None => builder,
        }
        .finalize(crate::pasta::baked())
    }

    /// Exercise the ordinary size and both sides of a registry-domain expansion.
    fn extra_steps() -> impl Strategy<Value = usize> {
        let base = crate::internal::native::total_circuit_counts(3).0;
        let boundary = (base + 1).next_power_of_two();
        let gap = boundary - base;
        proptest::sample::select(vec![0, gap - 1, gap, gap + 1])
    }

    fn check_registries(inputs: &support::Inputs, extra_steps: usize, reblind: bool) -> Result<()> {
        // Tags are setup inputs, not hashes computed by finalization. Give
        // each different setup its own tags and reuse both for an equivalent
        // setup. These reproducible draws are test fixtures only.
        let mut tag_rng = inputs.prover_rng();
        let first_native = Fp::random(|bytes| tag_rng.fill_bytes(bytes));
        let first_nested = Fq::random(|bytes| tag_rng.fill_bytes(bytes));
        let second_native = Fp::random(|bytes| tag_rng.fill_bytes(bytes));
        let second_nested = Fq::random(|bytes| tag_rng.fill_bytes(bytes));
        let tags = |native, nested| {
            Some(RegistryTags {
                native: Tag::new(native),
                nested: Tag::new(nested),
            })
        };
        let first = app_with_tags(
            inputs.left,
            inputs.right,
            extra_steps,
            tags(first_native, first_nested),
        )?;
        let second = app_with_tags(
            inputs.right,
            inputs.left,
            extra_steps,
            tags(second_native, second_nested),
        )?;
        let equivalent = app_with_tags(
            inputs.left,
            inputs.right,
            extra_steps,
            tags(first_native, first_nested),
        )?;
        assert_ne!(inputs.left, inputs.right);
        assert_eq!(
            first.native_registry.num_circuits(),
            second.native_registry.num_circuits()
        );
        assert_eq!(
            first.native_registry.log2_domain(),
            second.native_registry.log2_domain()
        );
        assert_ne!(first.nested_registry.tag(), second.nested_registry.tag());
        assert_ne!(first.native_registry.tag(), second.native_registry.tag());
        assert_eq!(
            first.native_registry.tag(),
            equivalent.native_registry.tag()
        );
        assert_eq!(
            first.nested_registry.tag(),
            equivalent.nested_registry.tag()
        );

        let mut rng = inputs.prover_rng();
        let first_leaf = first.seed(&mut rng, ConstantSeed::<0>(inputs.left), ())?.0;
        let second_leaf = second
            .seed(&mut rng, ConstantSeed::<0>(inputs.right), ())?
            .0;
        assert_eq!(*first_leaf.data(), inputs.left);
        assert_eq!(*second_leaf.data(), inputs.right);
        assert_eq!(
            first_leaf.proof().circuit_id(),
            second_leaf.proof().circuit_id()
        );
        assert!(equivalent.verify(&first_leaf, inputs.verifier_rng())?);

        for (name, source, target, mut foreign, mut sibling) in [
            (
                "first into second",
                &first,
                &second,
                first_leaf.clone(),
                second_leaf.clone(),
            ),
            (
                "second into first",
                &second,
                &first,
                second_leaf,
                first_leaf,
            ),
        ] {
            assert!(source.verify(&foreign, inputs.verifier_rng())?);
            assert!(
                !target.verify(&foreign, inputs.verifier_rng())?,
                "{name}: foreign seed"
            );
            if reblind {
                foreign = source.rerandomize(foreign, &mut rng)?;
                sibling = target.rerandomize(sibling, &mut rng)?;
            }
            assert!(source.verify(&foreign, inputs.verifier_rng())?);
            assert!(target.verify(&sibling, inputs.verifier_rng())?);
            assert!(
                !target.verify(&foreign, inputs.verifier_rng())?,
                "{name}: foreign child"
            );

            // The same production parent/grandparent paths must accept own-key
            // children and reject the foreign-key child in either position.
            for (child, expected) in [(&sibling, true), (&foreign, false)] {
                for (position, descendant) in
                    support::descendants(target, child, &sibling, &mut rng)?
                {
                    assert_eq!(
                        target.verify(&descendant, inputs.verifier_rng())?,
                        expected,
                        "{name}: {position}"
                    );
                }
            }
        }
        Ok(())
    }

    fn bonding_slots() -> Vec<CircuitIndex> {
        use InternalCircuitIndex::*;

        [
            PreambleStage,
            InnerErrorStage,
            OuterErrorStage,
            QueryStage,
            EvalStage,
            PointsBindingStage,
            PointsChildrenStage,
            PointsRegistryWxStage,
            PointsAbStage,
            PointsFStage,
            PointsWalkStage,
            InnerErrorFinalStaged,
            OuterErrorFinalStaged,
            EvalFinalStaged,
            PointsWalkFinalStaged,
        ]
        .into_iter()
        .map(InternalCircuitIndex::circuit_index)
        .collect()
    }

    fn check_slots(inputs: &support::Inputs, selector: usize) -> Result<()> {
        let app = app(inputs.left, inputs.right, 0)?;
        let mut rng = inputs.prover_rng();
        let child = app.seed(&mut rng, ConstantSeed::<0>(inputs.left), ())?.0;
        let other = app.seed(&mut rng, ConstantSeed::<2>(inputs.right), ())?.0;
        assert_ne!(child.data(), other.data());
        assert!(app.verify(&child, inputs.verifier_rng())?);
        assert!(app.verify(&other, inputs.verifier_rng())?);
        let sibling = support::sibling(&app, &child, &mut rng)?;
        assert!(app.verify(&sibling, inputs.verifier_rng())?);
        for (position, descendant) in support::descendants(&app, &child, &sibling, &mut rng)? {
            assert!(
                app.verify(&descendant, inputs.verifier_rng())?,
                "honest {position}"
            );
        }

        let registry = &app.native_registry;
        let bonding = bonding_slots();
        let domain_size = 1usize << registry.log2_domain();
        let unassigned: Vec<_> = (registry.num_circuits()..domain_size)
            .map(CircuitIndex::new)
            .collect();
        assert!(
            !unassigned.is_empty(),
            "the fixture needs unassigned domain points"
        );
        for &id in bonding.iter().chain(&unassigned) {
            assert!(registry.circuit_in_domain(id));
            assert_eq!(registry.wxy(id.omega_j(), Fp::from(3), Fp::ZERO), Fp::ZERO);
        }

        let replacement = other.proof().circuit_id();
        let cases = core::iter::once(("other application".into(), replacement))
            .chain(
                bonding
                    .iter()
                    .map(|&id| (format!("bonding {}", usize::from(id)), id)),
            )
            .chain(
                unassigned
                    .iter()
                    .map(|&id| (format!("unassigned {}", usize::from(id)), id)),
            );
        for (name, id) in cases {
            let (mut proof, data) = child.clone().into_parts();
            proof.circuit_id = id;
            assert!(
                !app.verify(&proof.carry::<Value>(data), inputs.verifier_rng())?,
                "{name}"
            );
        }

        // Every case checks one member of each class through all child positions;
        // the generated selector explores the complete classes across cases.
        for id in [
            replacement,
            bonding[selector % bonding.len()],
            unassigned[selector % unassigned.len()],
        ] {
            let (mut proof, data) = child.clone().into_parts();
            proof.circuit_id = id;
            let changed = proof.carry::<Value>(data);
            for (position, descendant) in support::descendants(&app, &changed, &sibling, &mut rng)?
            {
                assert!(
                    !app.verify(&descendant, inputs.verifier_rng())?,
                    "slot {}: {position}",
                    usize::from(id)
                );
            }
        }
        Ok(())
    }

    proptest! {
        #![proptest_config(support::config())]

        #[test]
        #[ignore = "recursion regression suite: run by the scheduled heavy-tests workflow"]
        fn same_sized_registries_reject_foreign_proofs_through_two_generations(
            inputs in support::inputs(),
            extra in extra_steps(),
            reblind in any::<bool>(),
        ) {
            check_registries(&inputs, extra, reblind).unwrap();
        }

        #[test]
        #[ignore = "recursion regression suite: run by the scheduled heavy-tests workflow"]
        fn circuit_slots_reject_application_bonding_and_unassigned_substitutions(
            inputs in support::inputs(),
            selector in any::<usize>(),
        ) {
            check_slots(&inputs, selector).unwrap();
        }
    }
}

mod stages {
    //! Check the deferred Boolean and curve-membership contracts of the walk stages.
    //!
    //! The mutations repair the stage commitment and preserve both walk endpoints.
    //! Production fusion must carry the inconsistency through either parent slot
    //! and every grandparent slot, including when both cycle sides are changed.

    use alloc::{sync::Arc, vec::Vec};

    use proptest::prelude::*;
    use ragu_backend::{Backend, ReferenceBackend};
    use ragu_circuits::{
        polynomials::sparse,
        staging::{StageReader, stage_wire_indices, wires_of},
    };
    use ragu_core::{
        Cycle, Result,
        pasta::{EpAffine, EqAffine, Fp, Fq},
    };
    use ragu_primitives::ENDOSCALAR_DIGITS;
    use ragu_testing::strategies;
    use udon::{curve::EndomorphismAffine as Affine, field::Field};

    use super::support::{self, C, R, Value};
    use crate::internal::{endoscalar::EndoscalarStage, native::stages::points::WalkStage, nested};

    /// The unsigned value of a radix-3 digit with twist wires `e1`, `e2`:
    /// 1 + (lambda - 1) e1 + (lambda^2 - 1) e2 + (3 - lambda) e1 e2, which is
    /// one of 1, lambda, lambda^2, 1 - lambda on bits.
    fn unsigned_digit<F: Field>(e1: F, e2: F) -> F {
        let lambda = F::ZETA;
        F::ONE
            + (lambda - F::ONE) * e1
            + (lambda.square() - F::ONE) * e2
            + (F::from(3) - lambda) * e1 * e2
    }

    /// The algebraic extension of the endoscalar map to arbitrary field wires,
    /// in the digit layout of `Endoscalar::group_scale`: two initial wires
    /// (s0, e0) contribute 2 (1 - 2 s0) (1 + (lambda - 1) e0), then every
    /// digit (s, e1, e2) contributes (1 - 2s) times its unsigned value after
    /// the accumulator is tripled.
    fn lifted<F: Field>(bits: &[F]) -> F {
        assert_eq!(bits.len(), u128::BITS as usize);
        let init =
            F::from(2) * (F::ONE - bits[0].double()) * (F::ONE + (F::ZETA - F::ONE) * bits[1]);
        bits[2..].chunks_exact(3).fold(init, |acc, digit| {
            acc * F::from(3) + (F::ONE - digit[0].double()) * unsigned_digit(digit[1], digit[2])
        })
    }

    /// Change two digits' sign bits and cancel their weighted contributions.
    /// Merely checking the lifted scalar cannot distinguish this malformed
    /// assignment.
    fn same_lift_bits<F: Field>(
        poly: &mut sparse::Polynomial<F, R>,
        wires: &[usize],
        (first, second): (usize, usize),
        delta: F,
    ) {
        assert!(first < second && second < ENDOSCALAR_DIGITS);
        assert_ne!(delta, F::ZERO);
        let reader = StageReader::new(poly);
        let mut bits: Vec<_> = wires.iter().map(|&wire| reader.read(wire)).collect();
        assert_eq!(bits.len(), u128::BITS as usize);
        assert!(bits.iter().all(|bit| *bit == F::ZERO || *bit == F::ONE));
        let packed = bits.iter().enumerate().fold(0u128, |value, (i, bit)| {
            value | (u128::from(*bit == F::ONE) << i)
        });
        let original = lifted(&bits);
        assert_eq!(original, ragu_primitives::lift_endoscalar(packed));

        // Digit i's sign wire weighs -2 * 3^(digits - 1 - i) times its
        // unsigned value, so a change of `delta` on the earlier digit is
        // cancelled by `delta * 3^(second - first)` scaled by the ratio of
        // the two unsigned values on the later one.
        let unsigned = |i: usize| unsigned_digit(bits[3 + 3 * i], bits[4 + 3 * i]);
        let compensation = delta
            * F::from(3).pow_u64((second - first) as u64)
            * unsigned(first)
            * unsigned(second).invert().unwrap();
        bits[2 + 3 * first] += delta;
        bits[2 + 3 * second] -= compensation;
        assert!(bits.iter().any(|bit| *bit != F::ZERO && *bit != F::ONE));
        assert_eq!(lifted(&bits), original);
        support::set_wires(poly, wires, &bits);
    }

    /// Keep the last interstitial (the walked commitment) fixed and place an
    /// off-curve coordinate pair into a generated earlier point slot.
    fn off_curve_point<P: Affine>(
        poly: &mut sparse::Polynomial<P::Base, R>,
        wires: &[usize],
        selector: usize,
        delta: P::Base,
    ) {
        assert!(wires.len() > 2 && wires.len().is_multiple_of(2));
        assert_ne!(delta, P::Base::ZERO);
        let index = 2 * (selector % (wires.len() / 2 - 1));
        let wires = &wires[index..index + 2];
        let reader = StageReader::new(poly);
        let x = reader.read(wires[0]);
        let y = reader.read(wires[1]);
        assert!(P::from_xy(x, y).is_some());
        let mut replacement = y + delta;
        if replacement.square() == y.square() {
            replacement += delta;
        }
        assert_ne!(replacement.square(), y.square());
        assert!(P::from_xy(x, replacement).is_none());
        support::set_wires(poly, wires, &[x, replacement]);
    }

    #[derive(Clone, Copy, Debug)]
    enum Mutation {
        Bits((usize, usize)),
        Point(usize),
    }

    fn check(
        app: &support::App,
        inputs: &support::Inputs,
        mutation: Mutation,
        native_delta: Fp,
        nested_delta: Fq,
    ) -> Result<()> {
        let (honest, _, _) = support::fused(app, inputs)?;
        let mut rng = inputs.prover_rng();
        let sibling = support::sibling(app, &honest, &mut rng)?;
        assert!(app.verify(&honest, inputs.verifier_rng())?);
        assert!(app.verify(&sibling, inputs.verifier_rng())?);
        let (native_wires, nested_wires) = match mutation {
            Mutation::Bits(_) => (
                stage_wire_indices::<_, R, WalkStage<EpAffine>>(|stage| {
                    wires_of(&stage.endoscalar)
                })?,
                stage_wire_indices::<Fq, R, EndoscalarStage>(|stage| wires_of(&stage))?,
            ),
            Mutation::Point(_) => (
                stage_wire_indices::<_, R, WalkStage<EpAffine>>(|stage| {
                    wires_of(&stage.interstitials)
                })?,
                stage_wire_indices::<_, R, nested::PointsStage<EqAffine>>(|stage| {
                    wires_of(&stage.interstitials)
                })?,
            ),
        };
        // Each walk's endpoint, the last interstitial, is its field's P.
        let native_endpoint = stage_wire_indices::<_, R, nested::PointsStage<EqAffine>>(|stage| {
            wires_of(stage.interstitials.last().unwrap())
        })?;
        let nested_endpoint =
            stage_wire_indices::<_, R, WalkStage<EpAffine>>(|stage| wires_of(stage.p()))?;

        for (native, nested) in [(false, false), (true, false), (false, true), (true, true)] {
            let (mut changed, data) = honest.clone().into_parts();
            if native {
                match mutation {
                    Mutation::Bits(pair) => same_lift_bits(
                        &mut changed.native_points_walk_rx,
                        &native_wires,
                        pair,
                        native_delta,
                    ),
                    Mutation::Point(selector) => off_curve_point::<EpAffine>(
                        &mut changed.native_points_walk_rx,
                        &native_wires,
                        selector,
                        native_delta,
                    ),
                }
                changed.native_points_walk_commitment.0 = ReferenceBackend::sparse_commit_to_affine(
                    &changed.native_points_walk_rx,
                    C::host_generators(app.params),
                );
            }
            if nested {
                match mutation {
                    Mutation::Bits(pair) => {
                        same_lift_bits(
                            &mut changed.nested_endoscalar_rx,
                            &nested_wires,
                            pair,
                            nested_delta,
                        );
                        changed.nested_endoscalar_commitment.0 =
                            ReferenceBackend::sparse_commit_to_affine(
                                &changed.nested_endoscalar_rx,
                                C::nested_generators(app.params),
                            );
                    }
                    Mutation::Point(selector) => {
                        off_curve_point::<EqAffine>(
                            Arc::make_mut(&mut changed.nested_points_rx),
                            &nested_wires,
                            selector,
                            nested_delta,
                        );
                        changed.nested_points_commitment.0 =
                            ReferenceBackend::sparse_commit_to_affine(
                                &changed.nested_points_rx,
                                C::nested_generators(app.params),
                            );
                    }
                }
            }
            let walked = StageReader::new(&changed.native_points_walk_rx);
            assert_eq!(
                nested_endpoint
                    .iter()
                    .map(|&wire| walked.read(wire))
                    .collect::<Vec<_>>(),
                support::coordinates(honest.proof().nested_p_commitment()),
                "{mutation:?}: the native walk must still end at the committed P_n"
            );
            let walked = StageReader::new(&changed.nested_points_rx);
            assert_eq!(
                native_endpoint
                    .iter()
                    .map(|&wire| walked.read(wire))
                    .collect::<Vec<_>>(),
                support::coordinates(honest.proof().native_p_commitment()),
                "{mutation:?}: the nested walk must still end at the committed P"
            );
            assert!(crate::verify::nested_points_match(&changed)?);
            let child = changed.carry::<Value>(data);
            let expected = !native && !nested;
            assert_eq!(
                app.verify(&child, inputs.verifier_rng())?,
                expected,
                "{mutation:?}, native {native}, nested {nested}: child"
            );
            for (position, descendant) in support::descendants(app, &child, &sibling, &mut rng)? {
                assert_eq!(
                    app.verify(&descendant, inputs.verifier_rng())?,
                    expected,
                    "{mutation:?}, native {native}, nested {nested}: {position}"
                );
            }
        }
        Ok(())
    }

    proptest! {
        #![proptest_config(support::config())]

        #[test]
        #[ignore = "recursion regression suite: run by the scheduled heavy-tests workflow"]
        fn same_lift_bit_substitutions_reject_through_two_generations(
            inputs in support::inputs(),
            pair in (0usize..ENDOSCALAR_DIGITS - 1)
                .prop_flat_map(|first| (Just(first), first + 1..ENDOSCALAR_DIGITS)),
            native_delta in strategies::nonzero_prime_field_element::<Fp>(),
            nested_delta in strategies::nonzero_prime_field_element::<Fq>(),
        ) {
            support::with_app(|app| check(app, &inputs, Mutation::Bits(pair), native_delta, nested_delta)).unwrap();
        }

        #[test]
        #[ignore = "recursion regression suite: run by the scheduled heavy-tests workflow"]
        fn off_curve_walk_points_reject_through_two_generations(
            inputs in support::inputs(),
            selector in any::<usize>(),
            native_delta in strategies::nonzero_prime_field_element::<Fp>(),
            nested_delta in strategies::nonzero_prime_field_element::<Fq>(),
        ) {
            support::with_app(|app| check(app, &inputs, Mutation::Point(selector), native_delta, nested_delta)).unwrap();
        }
    }
}
