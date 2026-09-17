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
    use ragu_arithmetic::ff::Field;
    use ragu_circuits::registry::CircuitIndex;
    use ragu_core::{
        Result,
        drivers::{Driver, DriverValue},
        maybe::Maybe,
    };
    use ragu_pasta::Fp;
    use ragu_primitives::{Element, allocator::Standard};

    use super::support::{self, C, HEADER_SIZE, R, Value};
    use crate::{
        ApplicationBuilder,
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
        ApplicationBuilder::<C, R, HEADER_SIZE>::new()
            .register(ConstantSeed::<0>(first))?
            .register(support::Merge::new())?
            .register(ConstantSeed::<2>(second))?
            .register_dummy_circuits(extra_steps)?
            .finalize(C::baked())
    }

    /// Exercise the ordinary size and both sides of a registry-domain expansion.
    fn extra_steps() -> impl Strategy<Value = usize> {
        let base = crate::internal::native::total_circuit_counts(3).0;
        let boundary = (base + 1).next_power_of_two();
        let gap = boundary - base;
        proptest::sample::select(vec![0, gap - 1, gap, gap + 1])
    }

    fn check_registries(inputs: &support::Inputs, extra_steps: usize, reblind: bool) -> Result<()> {
        let first = app(inputs.left, inputs.right, extra_steps)?;
        let second = app(inputs.right, inputs.left, extra_steps)?;
        let equivalent = app(inputs.left, inputs.right, extra_steps)?;
        assert_ne!(inputs.left, inputs.right);
        assert_eq!(
            first.native_registry.num_circuits(),
            second.native_registry.num_circuits()
        );
        assert_eq!(
            first.native_registry.log2_domain(),
            second.native_registry.log2_domain()
        );
        assert_eq!(first.nested_registry.tag(), second.nested_registry.tag());
        assert_ne!(first.native_registry.tag(), second.native_registry.tag());
        assert_eq!(
            first.native_registry.tag(),
            equivalent.native_registry.tag()
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
        fn same_sized_registries_reject_foreign_proofs_through_two_generations(
            inputs in support::inputs(),
            extra in extra_steps(),
            reblind in any::<bool>(),
        ) {
            check_registries(&inputs, extra, reblind).unwrap();
        }

        #[test]
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
    use ragu_arithmetic::{
        CurveAffine, Cycle,
        ff::{Field, WithSmallOrderMulGroup},
    };
    use ragu_backend::{Backend, ReferenceBackend};
    use ragu_circuits::polynomials::sparse;
    use ragu_core::Result;
    use ragu_pasta::{EpAffine, EqAffine, Fp, Fq};
    use ragu_testing::strategies;

    use super::support::{self, C, R, Value};
    use crate::internal::{
        endoscalar::EndoscalarStage,
        native::stages::points::WalkStage,
        nested,
        stage_wires::{StageReader, stage_wire_indices, wires_of},
    };

    /// The algebraic extension of the endoscalar map to arbitrary field wires.
    /// A pair (n, e) contributes (1 - 2n) * (1 + (zeta - 1)e).
    fn lifted<F: WithSmallOrderMulGroup<3>>(bits: &[F]) -> F {
        assert_eq!(bits.len(), u128::BITS as usize);
        bits.chunks_exact(2)
            .fold((F::ZETA + F::ONE).double(), |acc, pair| {
                acc.double() + (F::ONE - pair[0].double()) * (F::ONE + (F::ZETA - F::ONE) * pair[1])
            })
    }

    /// Change two negate bits and cancel their weighted contributions. Merely
    /// checking the lifted scalar cannot distinguish this malformed assignment.
    fn same_lift_bits<F: WithSmallOrderMulGroup<3>>(
        poly: &mut sparse::Polynomial<F, R>,
        wires: &[usize],
        (first, second): (usize, usize),
        delta: F,
    ) {
        assert!(first < second && second < u128::BITS as usize / 2);
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

        let factor = |i| F::ONE + (F::ZETA - F::ONE) * bits[2 * i + 1];
        let compensation = delta
            * F::from(2).pow_vartime([(second - first) as u64])
            * factor(first)
            * factor(second).invert().unwrap();
        bits[2 * first] += delta;
        bits[2 * second] -= compensation;
        assert!(bits.iter().any(|bit| *bit != F::ZERO && *bit != F::ONE));
        assert_eq!(lifted(&bits), original);
        support::set_wires(poly, wires, &bits);
    }

    /// Keep the last interstitial (the walked commitment) fixed and place an
    /// off-curve coordinate pair into a generated earlier point slot.
    fn off_curve_point<P: CurveAffine>(
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
        assert!(bool::from(P::from_xy(x, y).is_some()));
        let mut replacement = y + delta;
        if replacement.square() == y.square() {
            replacement += delta;
        }
        assert_ne!(replacement.square(), y.square());
        assert!(bool::from(P::from_xy(x, replacement).is_none()));
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
                    wires_of(&stage)
                })?,
            ),
        };

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
            assert_eq!(
                changed.native_p_commitment(),
                honest.proof().native_p_commitment()
            );
            assert_eq!(
                changed.nested_p_commitment(),
                honest.proof().nested_p_commitment()
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
        fn same_lift_bit_substitutions_reject_through_two_generations(
            inputs in support::inputs(),
            pair in (0usize..63).prop_flat_map(|first| (Just(first), first + 1..64)),
            native_delta in strategies::nonzero_prime_field_element::<Fp>(),
            nested_delta in strategies::nonzero_prime_field_element::<Fq>(),
        ) {
            support::with_app(|app| check(app, &inputs, Mutation::Bits(pair), native_delta, nested_delta)).unwrap();
        }

        #[test]
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
