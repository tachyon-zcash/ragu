//! Review A01: a finite, symbolic protocol inventory, independent of ALL,
//! INSTANCE, the production claim builders, and the infinite RHS zero tail.
//! Tokens retain both the child and component; bonding groups retain Horner
//! slot boundaries. In particular, Loading sums seven stages *within* each
//! child's slot, whereas final-stage masks fold individual traces.

use alloc::{borrow::Cow, vec, vec::Vec};
use core::marker::PhantomData;

use ragu_arithmetic::{DeferredField, ff::PrimeField};
use ragu_backend::ReferenceBackend;
use ragu_circuits::{
    polynomials::{ProductionRank, Rank, sparse},
    registry::{CircuitIndex, Registry},
};
use ragu_core::Result;
use ragu_pasta::{Fp, Fq, Pasta};

use super::{Builder, Source};
use crate::{
    ApplicationBuilder,
    internal::{native, nested},
};

type Token<C> = (usize, C);

struct Symbols<C> {
    proofs: usize,
    marker: PhantomData<C>,
}

impl<C: Copy> Source for Symbols<C> {
    type RxComponent = C;
    type Rx = Token<C>;
    type AppCircuitId = usize;

    fn rx(&self, component: C) -> impl Iterator<Item = Token<C>> {
        (0..self.proofs).map(move |child| (child, component))
    }

    fn app_circuits(&self) -> impl Iterator<Item = usize> {
        0..self.proofs
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Rhs {
    Raw(usize),
    Application(usize),
    Bridge(usize),
    Unified(usize),
    One(usize),
    Zero,
}

impl<C> native::claims::KySource for Symbols<C> {
    type Ky = Rhs;

    fn raw_c(&self) -> impl Iterator<Item = Rhs> {
        (0..self.proofs).map(Rhs::Raw)
    }
    fn application_ky(&self) -> impl Iterator<Item = Rhs> {
        (0..self.proofs).map(Rhs::Application)
    }
    fn unified_bridge_ky(&self) -> impl Iterator<Item = Rhs> {
        (0..self.proofs).map(Rhs::Bridge)
    }
    fn unified_ky(&self) -> impl Iterator<Item = Rhs> + Clone {
        (0..self.proofs).map(Rhs::Unified)
    }
    fn ones(&self) -> impl Iterator<Item = Rhs> + Clone {
        (0..self.proofs).map(Rhs::One)
    }
    fn zero(&self) -> Rhs {
        Rhs::Zero
    }
}

impl<C> nested::claims::KySource for Symbols<C> {
    type Ky = Rhs;

    fn raw_c(&self) -> impl Iterator<Item = Rhs> {
        (0..self.proofs).map(Rhs::Raw)
    }
    fn unified_ky(&self) -> impl Iterator<Item = Rhs> + Clone {
        (0..self.proofs).map(Rhs::Unified)
    }
    fn ones(&self) -> impl Iterator<Item = Rhs> + Clone {
        (0..self.proofs).map(Rhs::One)
    }
    fn zero(&self) -> Rhs {
        Rhs::Zero
    }
}

#[derive(Debug, PartialEq, Eq)]
enum Claim<I, C> {
    Raw(Token<C>, Token<C>),
    Application(usize, Token<C>),
    Circuit(I, Vec<Token<C>>),
    Bonding(I, Vec<Vec<Token<C>>>),
}

struct Recorder<I, C>(Vec<Claim<I, C>>);

impl native::claims::Processor<Token<native::RxComponent>, usize>
    for Recorder<native::InternalCircuitIndex, native::RxComponent>
{
    fn raw_claim(&mut self, a: Token<native::RxComponent>, b: Token<native::RxComponent>) {
        self.0.push(Claim::Raw(a, b));
    }
    fn circuit_claim(&mut self, id: usize, rx: Token<native::RxComponent>) {
        self.0.push(Claim::Application(id, rx));
    }
    fn internal_circuit_claim(
        &mut self,
        id: native::InternalCircuitIndex,
        rxs: impl Iterator<Item = Token<native::RxComponent>>,
    ) {
        self.0.push(Claim::Circuit(id, rxs.collect()));
    }
    fn grouped_bonding_claim(
        &mut self,
        id: native::InternalCircuitIndex,
        groups: impl Iterator<Item = impl Iterator<Item = Token<native::RxComponent>>>,
    ) -> Result<()> {
        self.0
            .push(Claim::Bonding(id, groups.map(Iterator::collect).collect()));
        Ok(())
    }
}

impl nested::claims::Processor<Token<nested::RxComponent>>
    for Recorder<nested::InternalCircuitIndex, nested::RxComponent>
{
    fn raw_claim(&mut self, a: Token<nested::RxComponent>, b: Token<nested::RxComponent>) {
        self.0.push(Claim::Raw(a, b));
    }
    fn internal_circuit_claim(
        &mut self,
        id: nested::InternalCircuitIndex,
        rxs: impl Iterator<Item = Token<nested::RxComponent>>,
    ) {
        self.0.push(Claim::Circuit(id, rxs.collect()));
    }
    fn grouped_bonding_claim(
        &mut self,
        id: nested::InternalCircuitIndex,
        groups: impl Iterator<Item = impl Iterator<Item = Token<nested::RxComponent>>>,
    ) -> Result<()> {
        self.0
            .push(Claim::Bonding(id, groups.map(Iterator::collect).collect()));
        Ok(())
    }
}

struct Inventory<I, C> {
    proofs: usize,
    claims: Vec<Claim<I, C>>,
    rhs: Vec<Rhs>,
}

impl<I: Copy, C: Copy> Inventory<I, C> {
    fn new(proofs: usize, a: C, b: C) -> Self {
        Self {
            proofs,
            claims: (0..proofs)
                .map(|child| Claim::Raw((child, a), (child, b)))
                .collect(),
            rhs: (0..proofs).map(Rhs::Raw).collect(),
        }
    }

    fn circuit(&mut self, id: I, components: &[C], rhs: fn(usize) -> Rhs) {
        for child in 0..self.proofs {
            self.claims.push(Claim::Circuit(
                id,
                components.iter().map(|&c| (child, c)).collect(),
            ));
            self.rhs.push(rhs(child));
        }
    }

    fn bonding(&mut self, id: I, components: &[C]) {
        self.claims.push(Claim::Bonding(
            id,
            components
                .iter()
                .flat_map(|&c| (0..self.proofs).map(move |child| vec![(child, c)]))
                .collect(),
        ));
        self.rhs.push(Rhs::Zero);
    }
}

fn native_inventory(proofs: usize) -> Inventory<native::InternalCircuitIndex, native::RxComponent> {
    use native::{
        InternalCircuitIndex as I,
        RxComponent::{AbA, AbB, Rx},
        RxIndex::*,
    };
    let mut expected = Inventory::new(proofs, AbA, AbB);
    for child in 0..proofs {
        expected
            .claims
            .push(Claim::Application(child, (child, Rx(Application))));
        expected.rhs.push(Rhs::Application(child));
    }
    expected.circuit(
        I::Hashes1Circuit,
        &[Rx(Hashes1), Rx(Preamble), Rx(OuterError)],
        Rhs::Bridge,
    );
    expected.circuit(
        I::Hashes2Circuit,
        &[Rx(Hashes2), Rx(OuterError)],
        Rhs::Unified,
    );
    expected.circuit(
        I::InnerCollapseCircuit,
        &[
            Rx(InnerCollapse),
            Rx(Preamble),
            Rx(InnerError),
            Rx(OuterError),
        ],
        Rhs::Unified,
    );
    expected.circuit(
        I::OuterCollapseCircuit,
        &[Rx(OuterCollapse), Rx(Preamble), Rx(OuterError)],
        Rhs::Unified,
    );
    expected.circuit(
        I::ComputeVCircuit,
        &[Rx(ComputeV), Rx(Preamble), Rx(Query), Rx(Eval)],
        Rhs::Unified,
    );
    for k in 0..5 {
        expected.circuit(
            I::BindChallengesCircuit(k),
            &[Rx(BindChallenges(k)), Rx(Preamble), Rx(Query), Rx(Eval)],
            Rhs::Unified,
        );
    }
    expected.circuit(
        I::BindBetaCircuit,
        &[
            Rx(BindBeta),
            Rx(PointsBinding),
            Rx(Preamble),
            Rx(OuterError),
        ],
        Rhs::Unified,
    );
    let walk = [
        Rx(PointsBinding),
        Rx(PointsChildren),
        Rx(PointsRegistryWx),
        Rx(PointsAb),
        Rx(PointsF),
        Rx(PointsWalk),
    ];
    expected.circuit(
        I::BindEndoscalarCircuit,
        &[&[Rx(BindEndoscalar)], &walk[..]].concat(),
        Rhs::Unified,
    );
    for step in 0..25 {
        expected.circuit(
            I::EndoscalingStep(step),
            &[&[Rx(EndoscalingStep(step))], &walk[..]].concat(),
            Rhs::One,
        );
    }
    for (id, rx) in [
        (I::PreambleStage, Preamble),
        (I::InnerErrorStage, InnerError),
        (I::OuterErrorStage, OuterError),
        (I::QueryStage, Query),
        (I::EvalStage, Eval),
        (I::PointsBindingStage, PointsBinding),
        (I::PointsChildrenStage, PointsChildren),
        (I::PointsRegistryWxStage, PointsRegistryWx),
        (I::PointsAbStage, PointsAb),
        (I::PointsFStage, PointsF),
        (I::PointsWalkStage, PointsWalk),
    ] {
        expected.bonding(id, &[Rx(rx)]);
    }
    expected.bonding(I::InnerErrorFinalStaged, &[Rx(InnerCollapse)]);
    expected.bonding(
        I::OuterErrorFinalStaged,
        &[Rx(Hashes1), Rx(Hashes2), Rx(OuterCollapse), Rx(BindBeta)],
    );
    expected.bonding(
        I::EvalFinalStaged,
        &[
            vec![Rx(ComputeV)],
            (0..5).map(|k| Rx(BindChallenges(k))).collect(),
        ]
        .concat(),
    );
    expected.bonding(
        I::PointsWalkFinalStaged,
        &[
            vec![Rx(BindEndoscalar)],
            (0..25).map(|k| Rx(EndoscalingStep(k))).collect(),
        ]
        .concat(),
    );
    expected
}

fn nested_inventory(proofs: usize) -> Inventory<nested::InternalCircuitIndex, nested::RxComponent> {
    use nested::{
        InternalCircuitIndex as I,
        RxComponent::{AbA, AbB, Rx},
        RxIndex::*,
    };
    let mut expected = Inventory::new(proofs, AbA, AbB);
    for step in 0..28 {
        expected.circuit(
            I::EndoscalingStep(step),
            &[
                Rx(EndoscalingStep(step)),
                Rx(EndoscalarStage),
                Rx(PointsStage),
            ],
            Rhs::One,
        );
    }
    for (id, own) in [
        (I::Export, Export),
        (I::Collapse, Collapse),
        (I::ComputeV, ComputeV),
    ] {
        expected.circuit(
            id,
            &[
                Rx(own),
                Rx(EndoscalarStage),
                Rx(PointsStage),
                Rx(BridgePreamble),
                Rx(BridgeSPrime),
                Rx(BridgeInnerError),
                Rx(BridgeOuterError),
                Rx(BridgeAB),
                Rx(BridgeQuery),
                Rx(BridgeF),
                Rx(BridgeEval),
                Rx(ChallengeStage),
            ],
            Rhs::Unified,
        );
    }
    expected.bonding(I::EndoscalarStage, &[Rx(EndoscalarStage)]);
    expected.bonding(I::PointsStage, &[Rx(PointsStage)]);
    expected.bonding(
        I::PointsFinalStaged,
        &(0..28).map(|k| Rx(EndoscalingStep(k))).collect::<Vec<_>>(),
    );
    for (id, rx) in [
        (I::BridgePreamble, BridgePreamble),
        (I::BridgeSPrime, BridgeSPrime),
        (I::BridgeInnerError, BridgeInnerError),
        (I::BridgeOuterError, BridgeOuterError),
        (I::BridgeAB, BridgeAB),
        (I::BridgeQuery, BridgeQuery),
        (I::BridgeF, BridgeF),
        (I::BridgeEval, BridgeEval),
        (I::ChallengeStage, ChallengeStage),
    ] {
        expected.bonding(id, &[Rx(rx)]);
    }
    expected.bonding(
        I::ChallengeFinalStaged,
        &[Rx(Export), Rx(Collapse), Rx(ComputeV)],
    );
    expected.claims.push(Claim::Bonding(
        I::Loading,
        (0..proofs)
            .map(|child| {
                [
                    PointsStage,
                    BridgePreamble,
                    BridgeSPrime,
                    BridgeInnerError,
                    BridgeAB,
                    BridgeQuery,
                    BridgeF,
                ]
                .map(|c| (child, Rx(c)))
                .to_vec()
            })
            .collect(),
    ));
    expected.rhs.push(Rhs::Zero);
    expected
}

fn assert_inventory<I: core::fmt::Debug + PartialEq, C: core::fmt::Debug + PartialEq>(
    actual: Recorder<I, C>,
    mut rhs: impl Iterator<Item = Rhs>,
    expected: Inventory<I, C>,
    nonzero: usize,
    zero: usize,
) {
    // Compare the finite claim list *before* zipping with the infinite RHS.
    assert_eq!(actual.0.len(), nonzero + zero, "finite claim count");
    assert_eq!(
        expected.claims.len(),
        nonzero + zero,
        "expected claim count"
    );
    assert_eq!(expected.rhs.len(), nonzero + zero, "expected RHS count");
    for (position, (actual, expected)) in actual.0.iter().zip(&expected.claims).enumerate() {
        assert_eq!(
            actual, expected,
            "claim {position}: ID, children, components and fold slots"
        );
    }
    assert_eq!(
        expected.rhs.iter().position(|r| *r == Rhs::Zero),
        Some(nonzero)
    );
    for (position, want) in expected.rhs.into_iter().enumerate() {
        assert_eq!(rhs.next(), Some(want), "RHS at claim {position}");
    }
    for _ in 0..16 {
        assert_eq!(rhs.next(), Some(Rhs::Zero), "zero padding must continue");
    }
}

#[test]
fn native_claims_and_rhs_match_finite_protocol_inventory() -> Result<()> {
    for proofs in [1, 2] {
        let source = Symbols {
            proofs,
            marker: PhantomData,
        };
        let mut actual = Recorder(Vec::new());
        native::claims::build(&source, &mut actual)?;
        assert_inventory(
            actual,
            native::claims::ky_values(&source),
            native_inventory(proofs),
            39 * proofs,
            15,
        );
    }
    Ok(())
}

#[test]
fn nested_claims_and_rhs_match_finite_protocol_inventory() -> Result<()> {
    for proofs in [1, 2] {
        let source = Symbols {
            proofs,
            marker: PhantomData,
        };
        let mut actual = Recorder(Vec::new());
        nested::claims::build(&source, &mut actual)?;
        assert_inventory(
            actual,
            nested::claims::ky_values(&source),
            nested_inventory(proofs),
            32 * proofs,
            14,
        );
    }
    Ok(())
}

fn native_is_circuit(id: native::InternalCircuitIndex) -> bool {
    use native::InternalCircuitIndex as I;

    matches!(
        id,
        I::Hashes1Circuit
            | I::Hashes2Circuit
            | I::InnerCollapseCircuit
            | I::OuterCollapseCircuit
            | I::ComputeVCircuit
            | I::BindChallengesCircuit(_)
            | I::BindBetaCircuit
            | I::BindEndoscalarCircuit
            | I::EndoscalingStep(_)
    )
}

fn nested_is_circuit(id: nested::InternalCircuitIndex) -> bool {
    use nested::InternalCircuitIndex as I;

    matches!(
        id,
        I::EndoscalingStep(_) | I::Export | I::Collapse | I::ComputeV
    )
}

fn dense_eval<F: PrimeField>(coeffs: &[F], x: F) -> F {
    coeffs
        .iter()
        .rev()
        .fold(F::ZERO, |acc, coefficient| acc * x + coefficient)
}

/// Review A04: compare the production claim transform to coefficient-by-
/// coefficient arithmetic for every registered circuit and bonding role.
/// A distinct monomial at each role makes an accidental `rx(x)` query in
/// place of `rx(xz)` visible without depending on another claim builder.
fn check_every_claim_role<F>(
    registry: &Registry<'_, F, ProductionRank>,
    roles: impl IntoIterator<Item = (CircuitIndex, bool)>,
) where
    F: PrimeField + DeferredField,
{
    type R = ProductionRank;

    let y = F::from(5);
    let z = F::from(7);
    let x = F::from(11);
    let num_coeffs = R::num_coeffs();

    for (position, (id, is_circuit)) in roles.into_iter().enumerate() {
        let degree = 3 + position * 37;
        assert!(degree < num_coeffs / 2, "fixture monomial exceeds rank");
        let coefficient = F::from(position as u64 + 2);
        let mut rx_coeffs = vec![F::ZERO; degree + 1];
        rx_coeffs[degree] = coefficient;
        let rx = sparse::Polynomial::<F, R>::from_coeffs(rx_coeffs);

        let sy = registry.circuit_y(id, y);
        let sy_coeffs: Vec<_> = sy.iter_coeffs().collect();
        let tz = R::tz(z);
        let tz_coeffs: Vec<_> = tz.iter_coeffs().collect();

        let mut builder = Builder::<Cow<'_, sparse::Polynomial<F, R>>, F, R, ReferenceBackend>::new(
            registry, y, z,
        );
        if is_circuit {
            builder.circuit_impl(id, Cow::Borrowed(&rx));
        } else {
            builder.bonding_impl(id, Cow::Borrowed(&rx));
        }

        assert_eq!(builder.a.len(), 1, "role {position} a count");
        assert_eq!(builder.b.len(), 1, "role {position} b count");
        assert!(
            builder.a[0].iter_coeffs().eq(rx.iter_coeffs()),
            "role {position} a"
        );

        let expected_b: Vec<_> = sy_coeffs
            .iter()
            .zip(&tz_coeffs)
            .enumerate()
            .map(|(k, (&sy_k, &tz_k))| {
                if is_circuit {
                    sy_k + tz_k
                        + if k == degree {
                            coefficient * z.pow_vartime([degree as u64])
                        } else {
                            F::ZERO
                        }
                } else {
                    sy_k
                }
            })
            .collect();
        let actual_b = builder.b[0].as_ref();
        assert!(
            actual_b.iter_coeffs().eq(expected_b.iter().copied()),
            "role {position} coefficient transform"
        );

        let expected_at_x = if is_circuit {
            coefficient * (x * z).pow_vartime([degree as u64])
                + registry.circuit_xy(id, x, y)
                + dense_eval(&tz_coeffs, x)
        } else {
            registry.circuit_xy(id, x, y)
        };
        assert_eq!(
            dense_eval(&expected_b, x),
            expected_at_x,
            "role {position} independent evaluation"
        );
        assert_eq!(
            actual_b.eval(x),
            expected_at_x,
            "role {position} sparse evaluation"
        );
        assert_eq!(
            dense_eval(&sy_coeffs, x),
            registry.circuit_xy(id, x, y),
            "role {position} registry coefficient/evaluation agreement"
        );

        let expected_revdot = coefficient * expected_b[num_coeffs - 1 - degree];
        assert_eq!(
            rx.revdot(actual_b),
            expected_revdot,
            "role {position} direct dense revdot"
        );
        assert_eq!(
            registry.circuit_xy(id, x, F::ZERO),
            if is_circuit { F::ONE } else { F::ZERO },
            "role {position} k0 semantics"
        );
    }
}

#[test]
fn every_native_and_nested_claim_role_matches_direct_monomial_arithmetic() -> Result<()> {
    type R = ProductionRank;
    const HEADER_SIZE: usize = 4;

    let app = ApplicationBuilder::<Pasta, R, HEADER_SIZE>::new()
        .register_dummy_circuits(3)?
        .finalize(Pasta::baked())?;

    let native_roles = native::InternalCircuitIndex::ALL
        .into_iter()
        .map(|id| (id.circuit_index(), native_is_circuit(id)))
        // Internal framework steps and the dummy application slots are all
        // ordinary circuits and follow the internal role inventory.
        .chain(
            (native::InternalCircuitIndex::NUM..app.native_registry().num_circuits())
                .map(|index| (CircuitIndex::new(index), true)),
        );
    check_every_claim_role::<Fp>(app.native_registry(), native_roles);

    let nested_roles = nested::InternalCircuitIndex::ALL
        .into_iter()
        .map(|id| (id.circuit_index(), nested_is_circuit(id)));
    check_every_claim_role::<Fq>(&app.nested_registry, nested_roles);

    Ok(())
}
