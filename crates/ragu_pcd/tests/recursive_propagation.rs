//! Check proof bindings with the production prover and verifier through two generations.
//!
//! These tests edit proof fields and repair commitments locally, then use
//! `Application::fuse` and `Application::verify` to check rejection in descendants.

pub(crate) mod support {
    //! Shared inputs, proof fixtures built with `Application::seed` and
    //! `Application::fuse`, and local polynomial edits for the protocol properties.

    use alloc::{format, string::String, sync::Arc, vec, vec::Vec};
    use core::marker::PhantomData;

    use proptest::prelude::*;
    use ragu_arithmetic::{CurveAffine, Cycle, ff::Field};
    use ragu_backend::{Backend, ReferenceBackend};
    use ragu_circuits::polynomials::{ProductionRank, Rank, sparse};
    use ragu_core::{
        Result,
        drivers::{Driver, DriverValue},
        gadgets::{Bound, Kind},
        maybe::Maybe,
    };
    use ragu_pasta::{EpAffine, EqAffine, Fp, Fq, Pasta};
    use ragu_primitives::{
        Element,
        allocator::{Allocator, Standard},
        poseidon::Sponge,
    };
    use ragu_testing::strategies;
    use rand::{SeedableRng, rngs::StdRng};

    pub(crate) type C = Pasta;
    pub(crate) type R = ProductionRank;
    pub(crate) const HEADER_SIZE: usize = 4;
    use crate::{
        Application, ApplicationBuilder, Pcd, Proof,
        header::{Header, Suffix},
        internal::{
            Side,
            native::{
                self,
                stages::{eval as native_eval, points::BindingStage, preamble as native_preamble},
            },
            nested::{
                self,
                stages::{eval as nested_eval, preamble},
            },
            stage_wires::{StageReader, stage_wire_indices, wire_degree, wires_of},
        },
        step::{Encoded, Index, Step},
    };

    pub(crate) type App = Application<'static, C, R, HEADER_SIZE>;
    pub(crate) type TestPcd = Pcd<C, R, Value>;
    pub(crate) type UnitPcd = Pcd<C, R, ()>;

    pub(crate) struct Value;

    impl Header<Fp> for Value {
        const SUFFIX: Suffix = Suffix::new(0);
        type Data = Fp;
        type Output = Kind![Fp; Element<'_, _>];

        fn encode<'dr, D: Driver<'dr, F = Fp>, A: Allocator<'dr, D>>(
            dr: &mut D,
            allocator: &mut A,
            witness: DriverValue<D, Fp>,
        ) -> Result<Bound<'dr, D, Self::Output>> {
            Element::alloc(dr, allocator, witness)
        }
    }

    /// Hash both child headers and an independent salt into an application header.
    pub(crate) struct HashStep<L, H, const I: usize>(PhantomData<(L, H)>);

    impl<L, H, const I: usize> HashStep<L, H, I> {
        pub(crate) fn new() -> Self {
            Self(PhantomData)
        }
    }

    impl<L: Header<Fp>, H: Header<Fp>, const I: usize> Step<C> for HashStep<L, H, I> {
        const INDEX: Index = Index::new(I);
        type Witness<'source> = Fp;
        type Aux<'source> = ();
        type Left = L;
        type Right = H;
        type Output = Value;

        fn witness<'dr, 'source: 'dr, D: Driver<'dr, F = Fp>, const N: usize>(
            &self,
            dr: &mut D,
            witness: DriverValue<D, Fp>,
            left: DriverValue<D, L::Data>,
            right: DriverValue<D, H::Data>,
        ) -> Result<(
            (
                Encoded<'dr, D, L, N>,
                Encoded<'dr, D, H, N>,
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
            let salt = Element::alloc(dr, allocator, witness)?;
            let mut sponge = Sponge::new(dr, C::circuit_poseidon(C::baked()));
            let mut inputs = Vec::new();
            left.clone().write(dr, &mut inputs)?;
            right.clone().write(dr, &mut inputs)?;
            for input in inputs {
                sponge.absorb(dr, &input)?;
            }
            sponge.absorb(dr, &salt)?;
            let output = sponge.squeeze(dr)?;
            let data = output.value().map(|v| *v);
            Ok(((left, right, Encoded::from_gadget(output)), data, D::unit()))
        }
    }

    pub(crate) type Seed = HashStep<(), (), 0>;
    pub(crate) type Merge = HashStep<Value, Value, 1>;
    pub(crate) type UnitLeft = HashStep<(), Value, 2>;
    pub(crate) type UnitRight = HashStep<Value, (), 3>;

    fn build_app() -> Result<App> {
        ApplicationBuilder::<C, R, HEADER_SIZE>::new()
            .register(Seed::new())?
            .register(Merge::new())?
            .register(UnitLeft::new())?
            .register(UnitRight::new())?
            .finalize(C::baked())
    }

    std::thread_local! {
        static APP: App = build_app().expect("the property-test application must build");
    }

    pub(crate) fn with_app<T>(f: impl FnOnce(&App) -> T) -> T {
        APP.with(f)
    }

    /// Each recursive case checks all child positions over two generations.
    /// PROPTEST_CASES can increase the four-case default for longer campaigns.
    pub(crate) fn config() -> ProptestConfig {
        let mut config = ProptestConfig::with_cases(4);
        if let Some(cases) = std::env::var("PROPTEST_CASES")
            .ok()
            .and_then(|value| value.parse().ok())
        {
            config.cases = cases;
        }
        config
    }

    #[derive(Clone, Debug)]
    pub(crate) struct Inputs {
        pub(crate) proof_seed: u64,
        pub(crate) verifier_seed: u64,
        pub(crate) left: Fp,
        pub(crate) right: Fp,
        pub(crate) salt: Fp,
        pub(crate) left_depth: usize,
        pub(crate) right_depth: usize,
    }

    pub(crate) fn inputs() -> impl Strategy<Value = Inputs> {
        (
            strategies::edge_u64(),
            strategies::edge_u64(),
            strategies::prime_field_element::<Fp>(),
            strategies::nonzero_prime_field_element::<Fp>(),
            strategies::prime_field_element::<Fp>(),
            0usize..=2,
            0usize..=2,
        )
            .prop_map(
                |(proof_seed, verifier_seed, left, right, salt, left_depth, right_depth)| Inputs {
                    proof_seed,
                    verifier_seed,
                    left,
                    right: left + right,
                    salt,
                    left_depth,
                    right_depth,
                },
            )
    }

    impl Inputs {
        pub(crate) fn prover_rng(&self) -> StdRng {
            StdRng::seed_from_u64(self.proof_seed)
        }

        pub(crate) fn verifier_rng(&self) -> StdRng {
            StdRng::seed_from_u64(self.verifier_seed)
        }
    }

    /// Build balanced and unbalanced child trees through `Application::seed`
    /// and `Application::fuse`, using generated header data.
    pub(crate) fn fused(app: &App, inputs: &Inputs) -> Result<(TestPcd, TestPcd, TestPcd)> {
        let mut rng = inputs.prover_rng();
        let mut node = |value: Fp, depth: usize| -> Result<Pcd<C, R, Value>> {
            let mut proof = app.seed(&mut rng, Seed::new(), value)?.0;
            for level in 0..depth {
                let sibling = app
                    .seed(&mut rng, Seed::new(), value + Fp::from(level as u64 + 1))?
                    .0;
                let (left, right) = if level % 2 == 0 {
                    (proof, sibling)
                } else {
                    (sibling, proof)
                };
                proof = app
                    .fuse(
                        &mut rng,
                        Merge::new(),
                        inputs.salt + Fp::from(level as u64),
                        left,
                        right,
                    )?
                    .0;
            }
            Ok(proof)
        };
        let left = node(inputs.left, inputs.left_depth)?;
        let right = node(inputs.right, inputs.right_depth)?;
        let proofs = (left.clone(), right.clone());
        let parent = app
            .fuse(&mut rng, Merge::new(), inputs.salt, left, right)?
            .0;
        Ok((parent, proofs.0, proofs.1))
    }

    /// Fuse two bootstrap proofs to distinguish ordinary unit inputs from the base case.
    pub(crate) fn unit_fused(app: &App, inputs: &Inputs) -> Result<(UnitPcd, UnitPcd, UnitPcd)> {
        use crate::step::internal::rerandomize::Rerandomize;
        let mut rng = StdRng::seed_from_u64(inputs.proof_seed.wrapping_sub(1));
        let left = app.bootstrap_pcd();
        let right = app.bootstrap_pcd();
        let parent = app
            .fuse(
                &mut rng,
                Rerandomize::<()>::new(),
                (),
                left.clone(),
                right.clone(),
            )?
            .0;
        Ok((parent, left, right))
    }

    pub(crate) fn sibling(
        app: &App,
        child: &Pcd<C, R, Value>,
        rng: &mut StdRng,
    ) -> Result<Pcd<C, R, Value>> {
        let salt = Fp::random(&mut *rng);
        let sibling = app
            .fuse(rng, Merge::new(), salt, child.clone(), child.clone())?
            .0;
        assert_ne!(child.data(), sibling.data());
        Ok(sibling)
    }

    /// Use `Application::fuse` to build both parent positions and all four
    /// grandparent positions. Callers check whether each descendant verifies.
    pub(crate) fn descendants(
        app: &App,
        child: &Pcd<C, R, Value>,
        sibling: &Pcd<C, R, Value>,
        rng: &mut StdRng,
    ) -> Result<Vec<(String, Pcd<C, R, Value>)>> {
        let mut proofs = Vec::new();
        for parent_side in [Side::Left, Side::Right] {
            let (left, right) = match parent_side {
                Side::Left => (child.clone(), sibling.clone()),
                Side::Right => (sibling.clone(), child.clone()),
            };
            let salt = Fp::random(&mut *rng);
            let parent = app.fuse(&mut *rng, Merge::new(), salt, left, right)?.0;
            assert_copied_endpoints(parent.proof(), child.proof(), parent_side)?;
            for grandparent_side in [Side::Left, Side::Right] {
                let (left, right) = match grandparent_side {
                    Side::Left => (parent.clone(), sibling.clone()),
                    Side::Right => (sibling.clone(), parent.clone()),
                };
                let salt = Fp::random(&mut *rng);
                let grandparent = app.fuse(&mut *rng, Merge::new(), salt, left, right)?.0;
                assert_copied_endpoints(grandparent.proof(), parent.proof(), grandparent_side)?;
                proofs.push((
                    format!("grandparent {grandparent_side:?} / parent {parent_side:?}"),
                    grandparent,
                ));
            }
            proofs.push((format!("parent {parent_side:?}"), parent));
        }
        Ok(proofs)
    }

    /// Check the production parent's stored stages to ensure substituted
    /// endpoints, claims, challenges and circuit ID reached the copied instance.
    pub(crate) fn assert_copied_endpoints(
        parent: &Proof<C, R>,
        child: &Proof<C, R>,
        side: Side,
    ) -> Result<()> {
        let native = stage_wire_indices::<_, R, preamble::Stage<EqAffine, R>>(|stage| {
            let child = match side {
                Side::Left => &stage.left,
                Side::Right => &stage.right,
            };
            wires_of(&child.stashed_p)
        })?;
        let reader = StageReader::new(&parent[nested::RxIndex::BridgePreamble]);
        assert_eq!(
            native
                .iter()
                .map(|&wire| reader.read(wire))
                .collect::<Vec<_>>(),
            coordinates(child.native_p_commitment()),
            "{side:?}: copied native endpoint"
        );
        let nested = stage_wire_indices::<_, R, BindingStage<EpAffine>>(|stage| {
            let child = match side {
                Side::Left => &stage.left,
                Side::Right => &stage.right,
            };
            let mut wires = Vec::new();
            for point in [
                &child.p,
                &child.a,
                &child.b,
                &child.registry_xy,
                &child.challenges,
            ]
            .into_iter()
            .chain(child.bridges.iter())
            {
                wires.extend(wires_of(point)?);
            }
            Ok(wires)
        })?;
        let reader = StageReader::new(&parent.native_points_binding_rx);
        let expected: Vec<_> = [
            child.nested_p_commitment(),
            child.nested_a_commitment(),
            child.nested_b_commitment(),
            child.nested_registry_xy_commitment(),
            child.nested_challenges_commitment(),
        ]
        .into_iter()
        .chain(
            nested::RxIndex::BRIDGES
                .iter()
                .map(|&id| child.nested_rx_commitment(id)),
        )
        .flat_map(coordinates)
        .collect();
        assert_eq!(
            nested
                .iter()
                .map(|&wire| reader.read(wire))
                .collect::<Vec<_>>(),
            expected,
            "{side:?}: copied nested commitments"
        );
        let circuit_id = stage_wire_indices::<
            _,
            R,
            crate::internal::native::stages::preamble::Stage<C, R, HEADER_SIZE>,
        >(|stage| {
            let child = match side {
                Side::Left => &stage.left,
                Side::Right => &stage.right,
            };
            wires_of(&child.circuit_id)
        })?;
        assert_eq!(circuit_id.len(), 1);
        assert_eq!(
            StageReader::new(&parent.native_preamble_rx).read(circuit_id[0]),
            child.circuit_id().omega_j(),
            "{side:?}: copied circuit id"
        );
        let native_claims = stage_wire_indices::<
            _,
            R,
            crate::internal::native::stages::preamble::Stage<C, R, HEADER_SIZE>,
        >(|stage| {
            let child = match side {
                Side::Left => &stage.left,
                Side::Right => &stage.right,
            };
            let mut wires = wires_of(&child.unified.c)?;
            wires.extend(wires_of(&child.unified.pre_beta)?);
            wires.extend(wires_of(&child.unified.nested_challenges_partial)?);
            Ok(wires)
        })?;
        let reader = StageReader::new(&parent.native_preamble_rx);
        let expected: Vec<_> = [child.native_c(), child.pre_beta()]
            .into_iter()
            .chain(coordinates(child.nested_challenges_partial()))
            .collect();
        assert_eq!(
            native_claims
                .iter()
                .map(|&wire| reader.read(wire))
                .collect::<Vec<_>>(),
            expected,
            "{side:?}: copied native claim and challenge binding"
        );
        let nested_claim = stage_wire_indices::<_, R, preamble::Stage<EqAffine, R>>(|stage| {
            let child = match side {
                Side::Left => &stage.left,
                Side::Right => &stage.right,
            };
            wires_of(&child.nested.c)
        })?;
        assert_eq!(nested_claim.len(), 1);
        assert_eq!(
            StageReader::new(&parent[nested::RxIndex::BridgePreamble]).read(nested_claim[0]),
            child.nested_c(),
            "{side:?}: copied nested claim"
        );
        Ok(())
    }

    pub(crate) fn edit<F: Field>(poly: &mut sparse::Polynomial<F, R>, f: impl FnOnce(&mut Vec<F>)) {
        let mut coefficients = poly.iter_coeffs().collect();
        f(&mut coefficients);
        *poly = sparse::Polynomial::from_coeffs(coefficients);
    }

    /// Positions span the complete trace polynomial, with extra weight at its
    /// four wire-region boundaries. The two positions need not be adjacent.
    pub(crate) fn positions() -> impl Strategy<Value = (usize, usize)> {
        let n = R::n();
        prop_oneof![
            1 => proptest::sample::select(vec![
                (0, 1), (n - 1, n), (2 * n - 1, 2 * n),
                (3 * n - 1, 3 * n), (R::num_coeffs() - 2, R::num_coeffs() - 1),
            ]),
            3 => strategies::bounded_edge_usize(R::num_coeffs() - 2)
                .prop_flat_map(|low| (Just(low), (low + 1)..R::num_coeffs())),
        ]
    }

    /// Add delta * (X^high - root^(high-low) * X^low), preserving evaluation
    /// at root using the supplied coefficient positions.
    pub(crate) fn add_rooted_term<F: Field>(
        poly: &mut sparse::Polynomial<F, R>,
        root: F,
        (low, high): (usize, usize),
        delta: F,
    ) {
        assert!(low < high && high < R::num_coeffs());
        assert_ne!(delta, F::ZERO);
        edit(poly, |coefficients| {
            coefficients[low] -= delta * root.pow_vartime([(high - low) as u64]);
            coefficients[high] += delta;
        });
    }

    pub(crate) fn set_wires<F: Field>(
        poly: &mut sparse::Polynomial<F, R>,
        wires: &[usize],
        values: &[F],
    ) {
        assert_eq!(wires.len(), values.len());
        edit(poly, |coefficients| {
            for (&wire, &value) in wires.iter().zip(values) {
                coefficients[wire_degree::<R>(wire)] = value;
            }
        });
    }

    pub(crate) fn coordinates<P: CurveAffine>(point: P) -> [P::Base; 2] {
        let coordinates = point
            .coordinates()
            .into_option()
            .expect("fixture point is not the identity");
        [*coordinates.x(), *coordinates.y()]
    }

    /// A commitment cache a property recomputes after editing the polynomial
    /// it caches, so that a rejection is the binding's and not a stale
    /// cache's. The decider recomputes every cache; these are the ones the
    /// edits here reach.
    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    pub(crate) enum Cache {
        NativePreamble,
        NativeEval,
        BridgeEval,
        NestedChallenges,
    }

    pub(crate) fn native_commit(app: &App, poly: &sparse::Polynomial<Fp, R>) -> EqAffine {
        ReferenceBackend::sparse_commit_to_affine(poly, C::host_generators(app.params))
    }

    pub(crate) fn nested_commit(app: &App, poly: &sparse::Polynomial<Fq, R>) -> EpAffine {
        ReferenceBackend::sparse_commit_to_affine(poly, C::nested_generators(app.params))
    }

    /// Recomputes `cache` from the polynomial it caches.
    pub(crate) fn recommit(app: &App, proof: &mut Proof<C, R>, cache: Cache) {
        match cache {
            Cache::NativePreamble => {
                proof.native_preamble_commitment.0 = native_commit(app, &proof.native_preamble_rx);
            }
            Cache::NativeEval => {
                proof.native_eval_commitment.0 = native_commit(app, &proof.native_eval_rx);
            }
            Cache::BridgeEval => {
                proof.bridge_eval_commitment = nested_commit(app, &proof.bridge_eval_rx);
            }
            Cache::NestedChallenges => {
                proof.nested_challenges_commitment.0 =
                    nested_commit(app, &proof.nested_challenges_rx);
            }
        }
    }

    /// The wires carrying a child's deferred PCS claim into the root's
    /// `compute_v`: $p_c(u)$ in the eval stage, and $v_c$ and $u_c$ in the
    /// preamble stage's copy of the child's unified instance.
    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    pub(crate) enum ChildWire {
        EvalLeftP,
        EvalRightP,
        PreambleLeftV,
        PreambleLeftU,
    }

    impl ChildWire {
        pub(crate) const ALL: [Self; 4] = [
            Self::EvalLeftP,
            Self::EvalRightP,
            Self::PreambleLeftV,
            Self::PreambleLeftU,
        ];

        /// The wire's reservation index in its stage.
        pub(crate) fn index(self) -> Result<usize> {
            type EvalStage = native_eval::Stage<C, R, HEADER_SIZE>;
            type PreambleStage = native_preamble::Stage<C, R, HEADER_SIZE>;
            let wires = match self {
                Self::EvalLeftP => stage_wire_indices::<Fp, R, EvalStage>(|out| {
                    wires_of(&out.evaluations.left.p_poly)
                })?,
                Self::EvalRightP => stage_wire_indices::<Fp, R, EvalStage>(|out| {
                    wires_of(&out.evaluations.right.p_poly)
                })?,
                Self::PreambleLeftV => {
                    stage_wire_indices::<Fp, R, PreambleStage>(|out| wires_of(&out.left.unified.v))?
                }
                Self::PreambleLeftU => {
                    stage_wire_indices::<Fp, R, PreambleStage>(|out| wires_of(&out.left.unified.u))?
                }
            };
            assert_eq!(wires.len(), 1, "an element is one wire");
            Ok(wires[0])
        }

        /// Adds `delta` to the wire's value in its stage polynomial and, when
        /// `repair` is set, recommits the stage so the cache check passes.
        pub(crate) fn bump(
            self,
            app: &App,
            proof: &mut Proof<C, R>,
            delta: Fp,
            repair: bool,
        ) -> Result<()> {
            let wire = self.index()?;
            let (poly, cache) = match self {
                Self::EvalLeftP | Self::EvalRightP => {
                    (&mut proof.native_eval_rx, Cache::NativeEval)
                }
                Self::PreambleLeftV | Self::PreambleLeftU => {
                    (&mut proof.native_preamble_rx, Cache::NativePreamble)
                }
            };
            let old = StageReader::<Fp, R>::new(poly).read(wire);
            set_wires(poly, &[wire], &[old + delta]);
            if repair {
                recommit(app, proof, cache);
            }
            Ok(())
        }
    }

    /// Copies the native eval commitment into the `eval` bridge stage's
    /// `native_eval` slot and recommits the bridge, so that the nested export
    /// circuit's stage copy matches the cache again. What remains
    /// inconsistent is the transcript: `pre_beta` was squeezed over the old
    /// bridge commitment.
    pub(crate) fn repair_bridge_eval_slot(app: &App, proof: &mut Proof<C, R>) -> Result<()> {
        let [x, y] = coordinates(proof.native_rx_commitment(native::RxIndex::Eval));
        let wires = stage_wire_indices::<Fq, R, nested_eval::Stage<EqAffine, R>>(|out| {
            wires_of(&out.native_eval)
        })?;
        set_wires(Arc::make_mut(&mut proof.bridge_eval_rx), &wires, &[x, y]);
        recommit(app, proof, Cache::BridgeEval);
        Ok(())
    }

    /// The synthesized dummy, retyped to the header an application step
    /// declares for its children: a child that never ran, presented as one
    /// that did.
    pub(crate) fn dummy_as_value(app: &App) -> TestPcd {
        app.dummy_proof().carry(Fp::ZERO)
    }
}

mod accumulator {
    //! Rejection must propagate through parent and grandparent proofs.

    use proptest::prelude::*;
    use ragu_arithmetic::{Cycle, ff::Field};
    use ragu_backend::{Backend, ReferenceBackend};
    use ragu_core::Result;
    use ragu_pasta::{Fp, Fq};
    use ragu_testing::strategies;
    use rand::{SeedableRng, rngs::StdRng};

    use super::support::{self, C, R};
    use crate::{Pcd, header::Header};

    /// Rescale A and B inversely, preserve their raw c, and recompute their
    /// commitment caches with the production backend.
    fn rescaled<H: Header<Fp>>(
        app: &support::App,
        honest: &Pcd<C, R, H>,
        native: Option<Fp>,
        nested: Option<Fq>,
    ) -> Pcd<C, R, H> {
        let (mut proof, data) = honest.clone().into_parts();
        if let Some(scale) = native {
            proof.native_a_poly.scale(scale);
            proof.native_b_poly.scale(scale.invert().unwrap());
            proof.native_a_commitment.0 = ReferenceBackend::sparse_commit_to_affine(
                &proof.native_a_poly,
                C::host_generators(app.params),
            );
            proof.native_b_commitment.0 = ReferenceBackend::sparse_commit_to_affine(
                &proof.native_b_poly,
                C::host_generators(app.params),
            );
            assert_ne!(
                proof.native_a_commitment.0,
                honest.proof().native_a_commitment.0
            );
        }
        if let Some(scale) = nested {
            proof.nested_a_poly.scale(scale);
            proof.nested_b_poly.scale(scale.invert().unwrap());
            proof.nested_a_commitment.0 = ReferenceBackend::sparse_commit_to_affine(
                &proof.nested_a_poly,
                C::nested_generators(app.params),
            );
            proof.nested_b_commitment.0 = ReferenceBackend::sparse_commit_to_affine(
                &proof.nested_b_poly,
                C::nested_generators(app.params),
            );
            assert_ne!(
                proof.nested_a_commitment(),
                honest.proof().nested_a_commitment()
            );
        }
        // These edits must change the polynomials while preserving the raw
        // claims and satisfying the decider's commitment-cache comparisons.
        for (poly, commitment) in [
            (&proof.native_a_poly, proof.native_a_commitment.0),
            (&proof.native_b_poly, proof.native_b_commitment.0),
        ] {
            assert_eq!(
                ReferenceBackend::sparse_commit_to_affine(poly, C::host_generators(app.params)),
                commitment
            );
        }
        for (poly, commitment) in [
            (&proof.nested_a_poly, proof.nested_a_commitment()),
            (&proof.nested_b_poly, proof.nested_b_commitment()),
        ] {
            assert_eq!(
                ReferenceBackend::sparse_commit_to_affine(poly, C::nested_generators(app.params)),
                commitment
            );
        }
        assert_eq!(proof.native_c(), honest.proof().native_c());
        assert_eq!(proof.nested_c(), honest.proof().nested_c());
        proof.carry::<H>(data)
    }

    fn check(
        app: &support::App,
        inputs: &support::Inputs,
        native_scale: Fp,
        nested_scale: Fq,
    ) -> Result<()> {
        let (honest, _, _) = support::fused(app, inputs)?;
        let (unit, _, _) = support::unit_fused(app, inputs)?;
        let mut rng = StdRng::seed_from_u64(inputs.proof_seed.wrapping_add(1));
        let sibling = support::sibling(app, &honest, &mut rng)?;
        assert!(app.verify(&honest, inputs.verifier_rng())?);
        assert!(app.verify(&unit, inputs.verifier_rng())?);
        assert!(app.verify(&sibling, inputs.verifier_rng())?);
        for (native, nested) in [(false, false), (true, false), (false, true), (true, true)] {
            let should_accept = !native && !nested;
            let scales = (
                native.then_some(native_scale),
                nested.then_some(nested_scale),
            );
            let changed_unit = rescaled(app, &unit, scales.0, scales.1);
            assert_eq!(
                app.verify(&changed_unit, inputs.verifier_rng())?,
                should_accept,
                "unit headers: native={native}, nested={nested}"
            );
            let child = rescaled(app, &honest, scales.0, scales.1);
            assert_eq!(
                app.verify(&child, inputs.verifier_rng())?,
                should_accept,
                "application headers: native={native}, nested={nested}"
            );
            for (position, descendant) in support::descendants(app, &child, &sibling, &mut rng)? {
                assert_eq!(
                    app.verify(&descendant, inputs.verifier_rng())?,
                    should_accept,
                    "{position}: native={native}, nested={nested}"
                );
            }
        }
        Ok(())
    }

    proptest! {
        #![proptest_config(support::config())]

        #[test]
        fn rescaled_accumulators_reject_through_parent_and_grandparent(
            inputs in support::inputs(),
            native_scale in strategies::nonzero_prime_field_element::<Fp>()
                .prop_filter("nontrivial native rescaling", |scale| *scale != Fp::ONE),
            nested_scale in strategies::nonzero_prime_field_element::<Fq>()
                .prop_filter("nontrivial nested rescaling", |scale| *scale != Fq::ONE),
        ) {
            support::with_app(|app| check(app, &inputs, native_scale, nested_scale)).unwrap();
        }
    }
}

mod endpoints {
    //! Substituted batch polynomials must fail even when their evaluations,
    //! commitment caches, walk endpoints, and copied instances agree.

    use alloc::sync::Arc;

    use proptest::prelude::*;
    use ragu_arithmetic::Cycle;
    use ragu_backend::{Backend, ReferenceBackend};
    use ragu_core::Result;
    use ragu_pasta::{EpAffine, EqAffine, Fp, Fq};
    use ragu_testing::strategies;
    use rand::{SeedableRng, rngs::StdRng};

    use super::support::{self, C, R, Value, coordinates};
    use crate::internal::{
        native::stages::points::WalkStage,
        nested,
        stage_wires::{StageReader, stage_wire_indices, wires_of},
    };

    fn check(
        app: &support::App,
        inputs: &support::Inputs,
        native_positions: (usize, usize),
        nested_positions: (usize, usize),
        native_delta: Fp,
        nested_delta: Fq,
    ) -> Result<()> {
        let (honest, _, _) = support::fused(app, inputs)?;
        let mut rng = StdRng::seed_from_u64(inputs.proof_seed.wrapping_add(1));
        let sibling = support::sibling(app, &honest, &mut rng)?;
        assert!(app.verify(&honest, inputs.verifier_rng())?);
        assert!(app.verify(&sibling, inputs.verifier_rng())?);

        let native_endpoint = stage_wire_indices::<_, R, nested::PointsStage<EqAffine>>(|stage| {
            wires_of(stage.interstitials.last().unwrap())
        })?;
        let nested_endpoint =
            stage_wire_indices::<_, R, WalkStage<EpAffine>>(|stage| wires_of(stage.p()))?;

        for (native, nested) in [(false, false), (true, false), (false, true), (true, true)] {
            let (mut changed, data) = honest.clone().into_parts();
            let native_v = changed.v();
            let nested_v = changed.nested_v()?;
            if native {
                let old = changed.native_p_commitment();
                let u = changed.u();
                support::add_rooted_term(
                    &mut changed.native_p_poly,
                    u,
                    native_positions,
                    native_delta,
                );
                let point = ReferenceBackend::sparse_commit_to_affine(
                    &changed.native_p_poly,
                    C::host_generators(app.params),
                );
                changed.native_p_commitment.0 = point;
                assert_ne!(old, point);
                support::set_wires(
                    Arc::make_mut(&mut changed.nested_points_rx),
                    &native_endpoint,
                    &coordinates(point),
                );
                changed.nested_points_commitment.0 = ReferenceBackend::sparse_commit_to_affine(
                    &changed.nested_points_rx,
                    C::nested_generators(app.params),
                );
                assert_eq!(changed.nested_instance()?.exported[8], point);
                let reader = StageReader::new(&changed.nested_points_rx);
                assert_eq!(
                    native_endpoint
                        .iter()
                        .map(|&wire| reader.read(wire))
                        .collect::<alloc::vec::Vec<_>>(),
                    coordinates(point)
                );
            }
            if nested {
                let old = changed.nested_p_commitment();
                let u = nested::challenge::<C>(changed.u())?;
                support::add_rooted_term(
                    &mut changed.nested_p_poly,
                    u,
                    nested_positions,
                    nested_delta,
                );
                let point = ReferenceBackend::sparse_commit_to_affine(
                    &changed.nested_p_poly,
                    C::nested_generators(app.params),
                );
                changed.nested_p_commitment.0 = point;
                assert_ne!(old, point);
                support::set_wires(
                    &mut changed.native_points_walk_rx,
                    &nested_endpoint,
                    &coordinates(point),
                );
                changed.native_points_walk_commitment.0 = ReferenceBackend::sparse_commit_to_affine(
                    &changed.native_points_walk_rx,
                    C::host_generators(app.params),
                );
                let reader = StageReader::new(&changed.native_points_walk_rx);
                assert_eq!(
                    nested_endpoint
                        .iter()
                        .map(|&wire| reader.read(wire))
                        .collect::<alloc::vec::Vec<_>>(),
                    coordinates(point)
                );
            }
            assert_eq!(changed.v(), native_v);
            assert_eq!(changed.nested_v()?, nested_v);
            assert!(crate::verify::nested_points_match(&changed)?);
            let child = changed.carry::<Value>(data);
            let expected = !native && !nested;
            assert_eq!(
                app.verify(&child, inputs.verifier_rng())?,
                expected,
                "child: native={native}, nested={nested}"
            );
            for (position, descendant) in support::descendants(app, &child, &sibling, &mut rng)? {
                assert_eq!(
                    app.verify(&descendant, inputs.verifier_rng())?,
                    expected,
                    "{position}: native={native}, nested={nested}"
                );
            }
        }
        Ok(())
    }

    proptest! {
        #![proptest_config(support::config())]

        #[test]
        fn coordinated_endpoints_reject_through_parent_and_grandparent(
            inputs in support::inputs(),
            native_positions in support::positions(),
            nested_positions in support::positions(),
            native_delta in strategies::nonzero_prime_field_element::<Fp>(),
            nested_delta in strategies::nonzero_prime_field_element::<Fq>(),
        ) {
            support::with_app(|app| check(
                app, &inputs, native_positions, nested_positions, native_delta, nested_delta,
            )).unwrap();
        }
    }
}

mod timing {
    //! A later witness cannot replace a point already fixed by the transcript.
    //! The nested registry's late commitment must also remain bound in descendants.

    use alloc::{sync::Arc, vec::Vec};

    use proptest::prelude::*;
    use ragu_arithmetic::{CurveAffine, Cycle, ff::Field, group::Curve};
    use ragu_backend::{Backend, ReferenceBackend};
    use ragu_circuits::{polynomials::Rank, registry::CircuitIndex, staging::StageExt};
    use ragu_core::{Result, drivers::emulator::Emulator, maybe::Maybe};
    use ragu_pasta::{EpAffine, EqAffine, Fp, Fq};
    use ragu_primitives::{GadgetExt, Point};
    use ragu_testing::strategies;
    use rand::{SeedableRng, rngs::StdRng};

    use super::support::{self, C, R, Value, coordinates};
    use crate::{
        Proof, RAGU_TAG,
        internal::{
            native::{
                self,
                stages::points::{AbStage, FStage},
            },
            nested::{
                self,
                stages::{ab, f},
            },
            stage_wires::{StageReader, stage_wire_indices, wires_of},
            transcript::Transcript,
        },
        proof::bridge_alpha_power,
    };

    /// Derive expected challenges with the production transcript operations and
    /// an explicit absorption schedule, for comparison with the stored challenges.
    fn challenges(app: &support::App, proof: &Proof<C, R>) -> Result<Vec<Fp>> {
        let mut dr = Emulator::execute();
        let mut transcript = Transcript::new(&mut dr, C::circuit_poseidon(app.params), RAGU_TAG)?;
        let mut result = Vec::new();
        for (point, count) in [
            (proof.bridge_preamble_commitment(), 1),
            (proof.bridge_s_prime_commitment(), 2),
            (proof.bridge_inner_error_commitment(), 2),
            (proof.bridge_outer_error_commitment(), 2),
            (proof.bridge_ab_commitment(), 1),
            (proof.bridge_query_commitment(), 1),
            (proof.bridge_f_commitment(), 1),
            (proof.bridge_eval_commitment(), 1),
        ] {
            Point::constant(&mut dr, point)?.write(&mut dr, &mut transcript)?;
            for _ in 0..count {
                result.push(*transcript.challenge(&mut dr)?.value().take());
            }
        }
        Ok(result)
    }

    fn check(
        app: &support::App,
        inputs: &support::Inputs,
        point_scale: Fq,
        registry_positions: (usize, usize),
        registry_delta: Fq,
    ) -> Result<()> {
        let (honest, _, _) = support::fused(app, inputs)?;
        let mut rng = StdRng::seed_from_u64(inputs.proof_seed.wrapping_add(1));
        let sibling = support::sibling(app, &honest, &mut rng)?;
        assert!(app.verify(&honest, inputs.verifier_rng())?);
        assert!(app.verify(&sibling, inputs.verifier_rng())?);
        let original = challenges(app, honest.proof())?;
        let proof = honest.proof();
        assert_eq!(
            original,
            [
                proof.w(),
                proof.y(),
                proof.z(),
                proof.mu(),
                proof.nu(),
                proof.mu_prime(),
                proof.nu_prime(),
                proof.x(),
                proof.alpha(),
                proof.u(),
                proof.pre_beta(),
            ]
        );

        // Include an honest control through the same recursive construction.
        for case in [
            "honest",
            "ab_after_x",
            "registry_after_u",
            "registry_after_all_openings",
        ] {
            let (mut changed, data) = honest.clone().into_parts();
            match case {
                "ab_after_x" => {
                    let wires = stage_wire_indices::<_, R, AbStage<EpAffine>>(|stage| {
                        wires_of(&stage.registry_wy)
                    })?;
                    let reader = StageReader::new(&changed.native_points_ab_rx);
                    let old = EpAffine::from_xy(reader.read(wires[0]), reader.read(wires[1]))
                        .into_option()
                        .expect("the stored registry point is on the curve");
                    let replacement = (old * point_scale).to_affine();
                    assert_ne!(replacement, old);
                    let point = coordinates(replacement);
                    support::set_wires(&mut changed.native_points_ab_rx, &wires, &point);
                    let new_ab = ReferenceBackend::sparse_commit_to_affine(
                        &changed.native_points_ab_rx,
                        C::host_generators(app.params),
                    );
                    changed.native_points_ab_commitment.0 = new_ab;
                    assert_ne!(
                        new_ab,
                        honest
                            .proof()
                            .native_rx_commitment(native::RxIndex::PointsAb)
                    );

                    // Rebuild the deterministic AB bridge around the changed stage,
                    // including its original blinding, rather than leave a stale copy.
                    let bridge = ab::Stage::<EqAffine, R>::rx(
                        bridge_alpha_power(changed.bridge_alpha, nested::RxIndex::BridgeAB),
                        &ab::Witness {
                            a: changed.native_commitment(native::RxComponent::AbA),
                            b: changed.native_commitment(native::RxComponent::AbB),
                            native_points_ab: new_ab,
                        },
                    )?;
                    changed.bridge_ab_commitment.0 = ReferenceBackend::sparse_commit_to_affine(
                        &bridge,
                        C::nested_generators(app.params),
                    );
                    changed.bridge_ab_rx.0 = Arc::new(bridge);
                    let replayed = challenges(app, &changed)?;
                    assert_eq!(replayed[..7], original[..7]);
                    assert_ne!(replayed[7], changed.x(), "the replacement must change x");
                }
                "registry_after_u" | "registry_after_all_openings" => {
                    // registry_xy is committed after alpha but before u. Preserve its
                    // old opening at u_n to exercise more than a changed evaluation.
                    let u = nested::challenge::<C>(changed.u())?;
                    let w = nested::challenge::<C>(changed.w())?;
                    let old_u = changed.nested_registry_xy_poly.eval(u);
                    let old_w = changed.nested_registry_xy_poly.eval(w);
                    if case == "registry_after_u" {
                        support::add_rooted_term(
                            &mut changed.nested_registry_xy_poly,
                            u,
                            registry_positions,
                            registry_delta,
                        );
                        assert_ne!(changed.nested_registry_xy_poly.eval(w), old_w);
                    } else {
                        let domain_size = 1usize << app.nested_registry.log2_domain();
                        let openings: Vec<_> = (0..domain_size)
                            .map(|i| {
                                let point = CircuitIndex::new(i).omega_j();
                                (point, changed.nested_registry_xy_poly.eval(point))
                            })
                            .collect();
                        let offset = registry_positions.0 % (R::num_coeffs() - domain_size - 2);
                        // Add delta * X^offset * (X^N - 1) * (X-u) * (X-w).
                        // This preserves every registry-domain opening as well
                        // as both old transcript-derived evaluation points.
                        support::edit(&mut changed.nested_registry_xy_poly, |coefficients| {
                            for (degree, coefficient) in [(0, u * w), (1, -u - w), (2, Fq::ONE)] {
                                coefficients[offset + degree] -= registry_delta * coefficient;
                                coefficients[offset + domain_size + degree] +=
                                    registry_delta * coefficient;
                            }
                        });
                        for (point, value) in openings {
                            assert_eq!(changed.nested_registry_xy_poly.eval(point), value);
                        }
                        assert_eq!(changed.nested_registry_xy_poly.eval(w), old_w);
                    }
                    assert_eq!(changed.nested_registry_xy_poly.eval(u), old_u);
                    let point = ReferenceBackend::sparse_commit_to_affine(
                        &changed.nested_registry_xy_poly,
                        C::nested_generators(app.params),
                    );
                    changed.nested_registry_xy_commitment.0 = point;
                    assert_ne!(point, honest.proof().nested_registry_xy_commitment());

                    let wires = stage_wire_indices::<_, R, FStage<EpAffine>>(|stage| {
                        wires_of(&stage.registry_xy)
                    })?;
                    support::set_wires(
                        &mut changed.native_points_f_rx,
                        &wires,
                        &coordinates(point),
                    );
                    let new_f = ReferenceBackend::sparse_commit_to_affine(
                        &changed.native_points_f_rx,
                        C::host_generators(app.params),
                    );
                    changed.native_points_f_commitment.0 = new_f;
                    let copy = stage_wire_indices::<_, R, f::Stage<EqAffine, R>>(|stage| {
                        wires_of(&stage.native_points_f)
                    })?;
                    support::set_wires(
                        Arc::make_mut(&mut changed.bridge_f_rx),
                        &copy,
                        &coordinates(new_f),
                    );
                    changed.bridge_f_commitment = ReferenceBackend::sparse_commit_to_affine(
                        &changed.bridge_f_rx,
                        C::nested_generators(app.params),
                    );
                    let replayed = challenges(app, &changed)?;
                    assert_eq!(
                        replayed[..9],
                        original[..9],
                        "the commitment is later than alpha"
                    );
                    assert_ne!(replayed[9], changed.u(), "the replacement must change u");
                }
                "honest" => {}
                _ => unreachable!(),
            }
            assert_eq!(changed.x(), honest.proof().x());
            assert_eq!(changed.u(), honest.proof().u());
            assert!(crate::verify::nested_points_match(&changed)?);
            let child = changed.carry::<Value>(data);
            let expected = case == "honest";
            assert_eq!(
                app.verify(&child, inputs.verifier_rng())?,
                expected,
                "{case}: child"
            );
            for (position, descendant) in support::descendants(app, &child, &sibling, &mut rng)? {
                assert_eq!(
                    app.verify(&descendant, inputs.verifier_rng())?,
                    expected,
                    "{case}: {position}"
                );
            }
        }
        Ok(())
    }

    proptest! {
        #![proptest_config(support::config())]

        #[test]
        fn later_witnesses_cannot_replace_transcript_bound_points(
            inputs in support::inputs(),
            point_scale in strategies::nonzero_prime_field_element::<Fq>()
                .prop_filter("a different registry point", |scale| *scale != Fq::ONE),
            registry_positions in support::positions(),
            registry_delta in strategies::nonzero_prime_field_element::<Fq>(),
        ) {
            support::with_app(|app| check(app, &inputs, point_scale, registry_positions, registry_delta)).unwrap();
        }
    }
}

mod commitments {
    //! The challenge-stage and walked commitments must match the proof's values.

    use alloc::vec::Vec;

    use proptest::prelude::*;
    use ragu_arithmetic::{
        Cycle, FixedGenerators,
        ff::Field,
        group::{Curve, CurveAffine},
    };
    use ragu_backend::{Backend, ReferenceBackend};
    use ragu_circuits::{
        polynomials::{Rank, sparse},
        staging::Stage,
    };
    use ragu_core::Result;
    use ragu_pasta::{Fq, Pasta};
    use ragu_testing::strategies;

    use super::support::{self, C, HEADER_SIZE, R};
    use crate::{Pcd, Proof, header::Header, internal::nested};

    fn check_coefficients<H: Header<ragu_pasta::Fp>>(
        app: &support::App,
        pcd: &Pcd<C, R, H>,
        inputs: &support::Inputs,
        delta: Fq,
    ) -> Result<()> {
        type ChallengeStage = nested::stages::challenges::Stage<<C as Cycle>::HostCurve, R>;

        let parent = pcd.proof();
        let verify = |proof: Proof<C, R>| {
            app.verify(&proof.carry::<H>(pcd.data().clone()), inputs.verifier_rng())
        };
        assert!(verify(parent.clone())?, "the honest parent must verify");

        // Change every lift, the base-case sign and their padding wires, then
        // the system alpha, which is fixed to zero for the unblinded stage.
        let coefficients = (0..ChallengeStage::values())
            .map(|slot| {
                let gate = ChallengeStage::skip_gates() + slot / 2;
                if slot % 2 == 0 {
                    2 * R::n() - 1 - gate
                } else {
                    4 * R::n() - 1 - gate
                }
            })
            .chain(core::iter::once(2 * R::n() - 1));
        for coefficient in coefficients {
            let mut changed = parent.clone();
            let mut coefficients: Vec<_> = changed.nested_challenges_rx.iter_coeffs().collect();
            coefficients[coefficient] += delta;
            changed.nested_challenges_rx = sparse::Polynomial::from_coeffs(coefficients);
            assert!(
                !verify(changed.clone())?,
                "accepted changed challenge stage coefficient {coefficient}"
            );
            changed.nested_challenges_commitment.0 = ReferenceBackend::sparse_commit_to_affine(
                &changed.nested_challenges_rx,
                C::nested_generators(app.params),
            );
            // Keep the exported partial consistent with the edited commitment:
            // it contains every term except beta's. Rejection must still hold
            // after both commitment representations have been repaired.
            if coefficient
                != crate::internal::native::circuits::bind_beta::generator_index::<C, R>()
            {
                changed.nested_challenges_partial = (changed.nested_challenges_partial.to_curve()
                    + C::nested_generators(app.params).g()[coefficient] * delta)
                    .to_affine();
            }
            assert!(
                !verify(changed)?,
                "accepted repaired challenge stage coefficient {coefficient}"
            );
        }

        Ok(())
    }

    fn check_challenge_commitment(
        app: &support::App,
        parent: &Proof<C, R>,
        sign: Fq,
    ) -> Result<()> {
        use ragu_arithmetic::{
            Cycle, FixedGenerators,
            group::{Curve, Group},
        };
        use ragu_circuits::staging::StageExt;

        use crate::internal::native::{
            circuits::{
                bind_beta,
                bind_challenges::{NUM_BINDERS, NUM_BOUND},
            },
            stages::eval::{BindingPartials, generator_index},
        };

        let pasta = app.params;

        // 1. The stored stage is the unblinded stage of the lifts, the sign and
        //    beta's lift.
        let lifts = parent.challenges().lifts::<C>()?;
        let (challenge_lifts, beta_lift) = lifts.split_at(NUM_BOUND);
        let challenges = nested::stages::challenges::Witness::new::<_, HEADER_SIZE>(
            challenge_lifts.try_into().unwrap(),
            parent.left_header(),
            parent.right_header(),
            beta_lift[0],
        );
        assert_eq!(challenges.base_case_sign, sign);
        let expected = nested::stages::challenges::Stage::<ragu_pasta::EqAffine, R>::rx(
            Fq::ZERO,
            &challenges,
        )?;
        assert!(
            parent
                .nested_challenges_rx()
                .iter_coeffs()
                .eq(expected.iter_coeffs()),
            "nested challenge stage is not the stage of the lifts"
        );

        // 2. Its commitment is the fixed generator combination the binding
        //    circuits recompute, term by term: the binders' terms, then beta's.
        let generators = Pasta::nested_generators(pasta);
        let mut binding = ragu_pasta::Ep::identity();
        for (i, lift) in challenge_lifts.iter().enumerate() {
            binding += generators.g()[generator_index::<C, R>(i)] * *lift;
        }
        binding +=
            generators.g()[generator_index::<C, R>(nested::stages::challenges::SIGN_INDEX)] * sign;
        let beta_term = generators.g()[bind_beta::generator_index::<C, R>()] * beta_lift[0];
        assert_eq!(
            parent.nested_challenges_commitment(),
            (binding + beta_term).to_affine(),
            "challenge commitment is not the generator combination of the lifts"
        );
        assert_eq!(
            parent.nested_challenges_partial(),
            binding.to_affine(),
            "the exported binding is not the commitment without beta's term"
        );

        // 3. The eval stage's partials are the running sums the binders check;
        //    the last binder's sum is the exported binding.
        let partials = BindingPartials::compute::<C, R, ReferenceBackend>(pasta, &challenges);
        let mut acc = ragu_pasta::Ep::identity();
        for k in 0..NUM_BINDERS {
            for (i, lift) in challenge_lifts
                .iter()
                .enumerate()
                .take(2 * (k + 1))
                .skip(2 * k)
            {
                acc += generators.g()[generator_index::<C, R>(i)] * *lift;
            }
            if k + 1 == NUM_BINDERS {
                acc += generators.g()
                    [generator_index::<C, R>(nested::stages::challenges::SIGN_INDEX)]
                    * sign;
                assert_eq!(partials.binding, acc.to_affine(), "binding");
            } else {
                assert_eq!(partials.partials[k], acc.to_affine(), "partial {k}");
            }
        }
        assert_eq!(parent.nested_challenges_partial(), partials.binding);

        Ok(())
    }

    /// The parent's root stage holds each child's bridge, challenge-stage and
    /// persistent polynomial commitments. Its own persistent points match the
    /// decider's caches, including $P_n$ at the walk's last interstitial.
    fn check_walk<H: Header<ragu_pasta::Fp>>(
        app: &support::App,
        parent_pcd: &Pcd<C, R, H>,
        left_pcd: &Pcd<C, R, H>,
        right_pcd: &Pcd<C, R, H>,
        inputs: &support::Inputs,
        replacement_scalar: Fq,
    ) -> Result<()> {
        use ragu_arithmetic::{
            CurveAffine,
            group::{Curve, Group},
        };

        use crate::internal::{
            native::{
                RxIndex,
                stages::points::{BindingStage, WalkStage},
            },
            stage_wires::{StageReader, stage_wire_indices, wires_of},
        };

        type Nested = <C as ragu_arithmetic::Cycle>::NestedCurve;
        let coordinates = |point: Nested| -> [ragu_pasta::Fp; 2] {
            let c = point
                .coordinates()
                .into_option()
                .expect("a walked point is not the identity");
            [*c.x(), *c.y()]
        };

        let (parent, left, right) = (parent_pcd.proof(), left_pcd.proof(), right_pcd.proof());

        // The root stage, wire by wire, against the children's caches.
        let binding = StageReader::<ragu_pasta::Fp, R>::new(&parent[RxIndex::PointsBinding]);
        let wires = stage_wire_indices::<_, R, BindingStage<Nested>>(|stage| wires_of(&stage))?;
        let held: alloc::vec::Vec<ragu_pasta::Fp> =
            wires.iter().map(|&i| binding.read(i)).collect();
        let expected: alloc::vec::Vec<ragu_pasta::Fp> = [left, right]
            .into_iter()
            .flat_map(|child| {
                [
                    child.bridge_preamble_commitment(),
                    child.bridge_s_prime_commitment(),
                    child.bridge_inner_error_commitment(),
                    child.bridge_outer_error_commitment(),
                    child.bridge_ab_commitment(),
                    child.bridge_query_commitment(),
                    child.bridge_f_commitment(),
                    child.bridge_eval_commitment(),
                    child.nested_challenges_commitment(),
                    child.nested_a_commitment(),
                    child.nested_b_commitment(),
                    child.nested_registry_xy_commitment(),
                    child.nested_p_commitment(),
                ]
            })
            .flat_map(coordinates)
            .collect();
        assert_eq!(
            held, expected,
            "the root stage does not hold the children's points"
        );

        // The walk's last interstitial, against this step's cache.
        let walk = StageReader::<ragu_pasta::Fp, R>::new(&parent[RxIndex::PointsWalk]);
        let wires = stage_wire_indices::<_, R, WalkStage<Nested>>(|stage| wires_of(stage.p()))?;
        let last: alloc::vec::Vec<ragu_pasta::Fp> = wires.iter().map(|&i| walk.read(i)).collect();
        assert_eq!(
            last,
            coordinates(parent.nested_p_commitment()).to_vec(),
            "P_n is not the walk's last interstitial"
        );

        for pcd in [parent_pcd, left_pcd, right_pcd] {
            assert!(crate::verify::nested_points_match(pcd.proof())?);
            assert!(app.verify(pcd, inputs.verifier_rng())?);
        }

        // Exercise the decider's point comparison in isolation: a valid point
        // in the cache must still be the one carried by the walk's stage.
        let caches: [fn(&mut Proof<C, R>) -> &mut Nested; 3] = [
            |proof| &mut proof.nested_a_commitment.0,
            |proof| &mut proof.nested_b_commitment.0,
            |proof| &mut proof.nested_registry_xy_commitment.0,
        ];
        let generated = (ragu_pasta::Ep::generator() * replacement_scalar).to_affine();
        for (name, cache) in ["A_n", "B_n", "registry_xy"].into_iter().zip(caches) {
            let mut changed = parent.clone();
            let original = *cache(&mut changed);
            assert_ne!(generated, original, "replacement must change {name}");
            for point in [
                -original,
                generated,
                <Nested as ragu_arithmetic::group::CurveAffine>::identity(),
            ] {
                *cache(&mut changed) = point;
                assert!(
                    !crate::verify::nested_points_match(&changed)?,
                    "mismatched {name}"
                );
            }
        }

        Ok(())
    }

    proptest! {
        #![proptest_config(support::config())]

        #[test]
        fn nested_commitments_bind_challenges_and_walks(
            inputs in support::inputs(),
            delta in strategies::nonzero_prime_field_element::<Fq>(),
            replacement in strategies::nonzero_prime_field_element::<Fq>(),
        ) {
            support::with_app(|app| {
                let (parent, left, right) = support::fused(app, &inputs)?;
                check_coefficients(app, &parent, &inputs, delta)?;
                check_challenge_commitment(app, parent.proof(), -Fq::ONE)?;
                check_walk(app, &parent, &left, &right, &inputs, replacement)?;
                let (parent, left, right) = support::unit_fused(app, &inputs)?;
                check_coefficients(app, &parent, &inputs, delta)?;
                check_challenge_commitment(app, parent.proof(), -Fq::ONE)?;
                check_walk(app, &parent, &left, &right, &inputs, replacement)?;
                let bootstrap = app.bootstrap_pcd();
                check_coefficients(app, &bootstrap, &inputs, delta)?;
                check_challenge_commitment(app, bootstrap.proof(), Fq::ONE)
            }).unwrap();
        }
    }
}
