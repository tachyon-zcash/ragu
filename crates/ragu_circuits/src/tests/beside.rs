//! Stages laid side by side: a stage that overrides its position to sit at
//! the gates another stage takes, and the circuits that load one or the
//! other.
//!
//! The trunk stage is the root. `Left` follows it. `Right` is `Left`'s
//! child, so by default it follows `Left`; in the `Beside` layout it
//! overrides [`Stage::skip_gates`] to follow the trunk instead, at `Left`'s
//! gates. A circuit that reads `Right` then loads the trunk and `Right`
//! alone, with [`StageBuilder::add_stage_beside`], and its own gates start
//! where `Right` ends.

use core::marker::PhantomData;

use ragu_core::{
    Error, Result,
    drivers::{Driver, DriverValue},
    gadgets::{Bound, Kind},
    maybe::Maybe,
    pasta::Fp,
};
use ragu_primitives::{
    Element, GadgetExt,
    vec::{ConstLen, FixedVec},
};
use udon::field::Field;

use crate::{
    CircuitExt, WithAux,
    registry::{CircuitIndex, RegistryBuilder},
    staging::{MultiStage, MultiStageCircuit, Stage, StageBuilder, StageExt},
    testing::synthesis_counts,
};

type R = crate::polynomials::TestRank;

/// Where `Right` is laid.
trait Layout: Send + Sync + 'static {
    const BESIDE: bool;
}

/// `Right` follows its parent, `Left`.
struct Chained;
/// `Right` follows the trunk, at `Left`'s gates.
struct Beside;

impl Layout for Chained {
    const BESIDE: bool = false;
}

impl Layout for Beside {
    const BESIDE: bool = true;
}

/// Defines a stage of `$n` elements after `$Parent`.
macro_rules! elements_stage {
    ($Stage:ident $(<$L:ident>)?, $Parent:ty, $n:literal $(, $skip:item)?) => {
        struct $Stage$(<$L>(PhantomData<$L>))?;

        impl$(<$L>)? Default for $Stage$(<$L>)? {
            fn default() -> Self {
                elements_stage!(@new $Stage $(, $L)?)
            }
        }

        impl$(<$L: Layout>)? Stage<Fp, R> for $Stage$(<$L>)? {
            type Parent = $Parent;
            type Witness<'source> = &'source [Fp; $n];
            type OutputKind = Kind![Fp; FixedVec<Element<'_, _>, ConstLen<$n>>];

            fn values() -> usize {
                $n
            }

            fn witness<'dr, 'source: 'dr, D: Driver<'dr, F = Fp>>(
                &self,
                dr: &mut D,
                witness: DriverValue<D, Self::Witness<'source>>,
            ) -> Result<Bound<'dr, D, Self::OutputKind>>
            where
                Self: 'dr,
            {
                FixedVec::try_from_fn(|i| {
                    Element::alloc(dr, &mut (), witness.as_ref().map(|w| w[i]))
                })
            }

            $($skip)?
        }
    };
    (@new $Stage:ident) => { $Stage };
    (@new $Stage:ident, $L:ident) => { $Stage(PhantomData) };
}

elements_stage!(Trunk, (), 4);
elements_stage!(Left, Trunk, 10);
elements_stage!(
    Right<L>,
    Left,
    6,
    fn skip_gates() -> usize {
        if L::BESIDE {
            <Trunk as Stage<Fp, R>>::skip_gates() + <Trunk as StageExt<Fp, R>>::num_gates()
        } else {
            <Left as Stage<Fp, R>>::skip_gates() + <Left as StageExt<Fp, R>>::num_gates()
        }
    }
);

/// The stages' values.
#[derive(Clone)]
struct Values {
    trunk: [Fp; 4],
    left: [Fp; 10],
    right: [Fp; 6],
}

impl Values {
    /// Values that satisfy both circuits: `left[0]` is the square of
    /// `trunk[0]` and `right[0]` the square of `trunk[1]`.
    fn honest() -> Self {
        let trunk = [3u64, 5, 7, 11].map(Fp::from);
        let mut left = [Fp::from(2); 10];
        let mut right = [Fp::from(9); 6];
        left[0] = trunk[0].square();
        right[0] = trunk[1].square();
        Values { trunk, left, right }
    }
}

/// Enforces that `value` is the square of `base`, with some gates of the
/// circuit's own.
fn hold_square<'dr, D: Driver<'dr, F = Fp>>(
    dr: &mut D,
    base: &Element<'dr, D>,
    value: &Element<'dr, D>,
) -> Result<()> {
    base.mul(dr, base)?.enforce_equal(dr, value)
}

/// Reads `Left`: loads the trunk and `Left`.
struct ReadsLeft;

impl MultiStageCircuit<Fp, R> for ReadsLeft {
    type Last = Left;
    type Instance<'source> = ();
    type Witness<'source> = &'source Values;
    type Output = Kind![Fp; ()];
    type Aux<'source> = ();

    fn instance<'dr, 'source: 'dr, D: Driver<'dr, F = Fp>>(
        &self,
        _: &mut D,
        _: DriverValue<D, ()>,
    ) -> Result<Bound<'dr, D, Self::Output>> {
        Ok(())
    }

    fn witness<'a, 'dr, 'source: 'dr, D: Driver<'dr, F = Fp>>(
        &self,
        dr: StageBuilder<'a, 'dr, D, R, (), Self::Last>,
        witness: DriverValue<D, Self::Witness<'source>>,
    ) -> Result<WithAux<Bound<'dr, D, Self::Output>, DriverValue<D, Self::Aux<'source>>>> {
        let (trunk, dr) = dr.add_stage::<Trunk>()?;
        let (left, dr) = dr.add_stage::<Left>()?;
        let dr = dr.finish();
        let trunk = trunk.unenforced(dr, witness.as_ref().map(|w| &w.trunk))?;
        let left = left.unenforced(dr, witness.as_ref().map(|w| &w.left))?;
        hold_square(dr, &trunk[0], &left[0])?;
        Ok(WithAux::new((), D::unit()))
    }
}

/// How a circuit that reads `Right` reaches it.
#[derive(Clone, Copy, PartialEq)]
enum Reach {
    /// Reserves `Left` and adds `Right` as its child.
    Through,
    /// Adds `Right` after the trunk, beside `Left`.
    Beside,
}

/// Reads `Right` in layout `L`.
struct ReadsRight<L> {
    reach: Reach,
    _marker: PhantomData<L>,
}

impl<L> ReadsRight<L> {
    fn new(reach: Reach) -> Self {
        ReadsRight {
            reach,
            _marker: PhantomData,
        }
    }
}

impl<L: Layout> MultiStageCircuit<Fp, R> for ReadsRight<L> {
    type Last = Right<L>;
    type Instance<'source> = ();
    type Witness<'source> = &'source Values;
    type Output = Kind![Fp; ()];
    type Aux<'source> = ();

    fn instance<'dr, 'source: 'dr, D: Driver<'dr, F = Fp>>(
        &self,
        _: &mut D,
        _: DriverValue<D, ()>,
    ) -> Result<Bound<'dr, D, Self::Output>> {
        Ok(())
    }

    fn witness<'a, 'dr, 'source: 'dr, D: Driver<'dr, F = Fp>>(
        &self,
        dr: StageBuilder<'a, 'dr, D, R, (), Self::Last>,
        witness: DriverValue<D, Self::Witness<'source>>,
    ) -> Result<WithAux<Bound<'dr, D, Self::Output>, DriverValue<D, Self::Aux<'source>>>> {
        let (trunk, dr) = dr.add_stage::<Trunk>()?;
        let (right, dr) = match self.reach {
            Reach::Through => dr.skip_stage::<Left>()?.add_stage::<Right<L>>()?,
            Reach::Beside => dr.add_stage_beside::<Right<L>>()?,
        };
        let dr = dr.finish();
        let trunk = trunk.unenforced(dr, witness.as_ref().map(|w| &w.trunk))?;
        let right = right.unenforced(dr, witness.as_ref().map(|w| &w.right))?;
        hold_square(dr, &trunk[1], &right[0])?;
        Ok(WithAux::new((), D::unit()))
    }
}

/// In the `Beside` layout `Right` takes `Left`'s first gates, and a circuit
/// that reaches it beside `Left` reserves `Left`'s gates no more.
#[test]
fn a_stage_laid_beside_another_shares_its_gates() {
    let skip = |stage: fn() -> usize| stage();
    let left = skip(<Left as Stage<Fp, R>>::skip_gates);
    assert_eq!(left, 1 + 2);
    assert_eq!(skip(<Right<Beside> as Stage<Fp, R>>::skip_gates), left);
    assert_eq!(skip(<Right<Chained> as Stage<Fp, R>>::skip_gates), left + 5);

    let gates = |circuit: &dyn Fn() -> Result<usize>| circuit().unwrap();
    let through = gates(&|| {
        Ok(
            synthesis_counts(&MultiStage::new(ReadsRight::<Chained>::new(Reach::Through)))?
                .num_gates,
        )
    });
    let beside = gates(&|| {
        Ok(synthesis_counts(&MultiStage::new(ReadsRight::<Beside>::new(Reach::Beside)))?.num_gates)
    });
    assert_eq!(through - beside, <Left as StageExt<Fp, R>>::num_gates());
}

/// A stage is added only at the gates its polynomial is at: as a child
/// when it follows its parent, beside when it follows the current stage.
#[test]
fn a_misplaced_stage_is_refused() {
    let refused =
        |circuit: &dyn Fn() -> Result<usize>| matches!(circuit(), Err(Error::Initialization(_)));
    // `Right` laid beside `Left` does not follow `Left`.
    assert!(refused(&|| {
        Ok(
            synthesis_counts(&MultiStage::new(ReadsRight::<Beside>::new(Reach::Through)))?
                .num_gates,
        )
    }));
    // `Right` laid after `Left` does not follow the trunk.
    assert!(refused(&|| {
        Ok(
            synthesis_counts(&MultiStage::new(ReadsRight::<Chained>::new(Reach::Beside)))?
                .num_gates,
        )
    }));
}

/// Whether the claim of the circuit `make` builds holds: its trace over
/// `values`, summed with the stage polynomials `stages`, against its
/// wiring polynomial. The trace satisfies the final mask of the circuit's
/// last stage.
fn claim_holds<C>(make: impl Fn() -> C, values: &Values, stages: &[&Poly]) -> bool
where
    C: for<'s> MultiStageCircuit<Fp, R, Instance<'s> = (), Witness<'s> = &'s Values>,
{
    let registry = RegistryBuilder::<Fp, R>::new()
        .register_internal_circuit(MultiStage::new(make()))
        .unwrap()
        .register_mask(<C::Last as StageExt<Fp, R>>::final_mask().unwrap())
        .finalize()
        .unwrap();
    let y = Fp::from(0x626573696465u64);

    let staged = MultiStage::new(make());
    let trace = staged.trace(values).unwrap().into_output();
    let rx = registry
        .assemble_with_alpha(&trace, CircuitIndex::new(0), Fp::ZERO)
        .unwrap();
    assert_eq!(
        rx.revdot(&registry.circuit_y(CircuitIndex::new(1), y)),
        Fp::ZERO
    );

    let mut sum = rx;
    for stage in stages {
        sum.add_assign(stage);
    }
    sum.revdot(&registry.circuit_y(CircuitIndex::new(0), y)) == staged.ky((), y).unwrap()
}

type Poly = crate::polynomials::sparse::Polynomial<Fp, R>;

/// A stage's polynomial for `values`, checked against the stage's own mask.
fn stage_rx<S: Stage<Fp, R> + Default>(witness: S::Witness<'_>) -> Poly {
    let rx = <S as StageExt<Fp, R>>::rx(Fp::ZERO, witness).unwrap();
    let registry = RegistryBuilder::<Fp, R>::new()
        .register_mask(<S as StageExt<Fp, R>>::stage_mask().unwrap())
        .finalize()
        .unwrap();
    let y = Fp::from(0x6d61736bu64);
    assert_eq!(
        rx.revdot(&registry.circuit_y(CircuitIndex::new(0), y)),
        Fp::ZERO
    );
    rx
}

/// Each circuit's claim holds over the trunk and the one branch it loads,
/// and over nothing else: the other branch's polynomial, at the same
/// gates, is not the stage the circuit reads.
#[test]
fn a_circuits_claim_takes_the_branch_it_loads() {
    let values = Values::honest();
    let trunk = stage_rx::<Trunk>(&values.trunk);
    let left = stage_rx::<Left>(&values.left);
    let right = stage_rx::<Right<Beside>>(&values.right);

    let reads_right = || ReadsRight::<Beside>::new(Reach::Beside);
    assert!(claim_holds(|| ReadsLeft, &values, &[&trunk, &left]));
    assert!(claim_holds(reads_right, &values, &[&trunk, &right]));

    // The other branch in the loaded one's place.
    assert!(!claim_holds(|| ReadsLeft, &values, &[&trunk, &right]));
    assert!(!claim_holds(reads_right, &values, &[&trunk, &left]));
    // Both branches at once: their gates overlap.
    assert!(!claim_holds(
        || ReadsLeft,
        &values,
        &[&trunk, &left, &right]
    ));
    assert!(!claim_holds(reads_right, &values, &[&trunk, &left, &right]));
    // No branch.
    assert!(!claim_holds(reads_right, &values, &[&trunk]));
}

/// A wrong value in a branch fails the circuit that reads that branch, and
/// not the circuit that reads the other.
#[test]
fn a_wrong_branch_value_fails_its_reader() {
    let honest = Values::honest();
    let trunk = stage_rx::<Trunk>(&honest.trunk);
    let left = stage_rx::<Left>(&honest.left);

    let mut wrong = honest.clone();
    wrong.right[0] += Fp::ONE;
    let right = stage_rx::<Right<Beside>>(&wrong.right);
    let reads_right = || ReadsRight::<Beside>::new(Reach::Beside);
    for witnessed in [&honest, &wrong] {
        assert!(!claim_holds(reads_right, witnessed, &[&trunk, &right]));
    }
    assert!(claim_holds(|| ReadsLeft, &wrong, &[&trunk, &left]));
}
