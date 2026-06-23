//! Value-level stage layouts for stages that are not known at Rust compile
//! time.
//!
//! The typed staging surface ([`Stage`](super::Stage),
//! [`MultiStageCircuit`](super::MultiStageCircuit)) pins a circuit's stage
//! hierarchy in the type system: the `Parent` chain and the `values()` /
//! `num_gates()` / `skip_gates()` associated functions determine the partial
//! trace layout statically. 
//!
//! However, some multistage circuit layouts cannot be known at compile time; notably, [`Step`](ragu_pcd::step::Step) circuits
//! that use the [`derive_challenge`](ragu_pcd::framework_hooks::FrameworkHooks::derive_challenge) framework hook.
//! [`InducedStages`](crate::staging::induced::InducedStages) mirror [`Stage`](super::Stage) chains, 
//! but their layouts can be determined at registry time, instead of Rust compile time.
//! 
//! * [`skip_gates`](InducedStages::skip_gates) / [`num_gates`](InducedStages::num_gates)
//!   mirror [`Stage::skip_gates`](super::Stage::skip_gates) and
//!   [`StageExt::num_gates`](super::StageExt::num_gates) — the fold over the
//!   `Parent` type chain becomes a fold over the recorded widths.
//! * [`mask`](InducedStages::mask) / [`final_mask`](InducedStages::final_mask)
//!   mirror [`StageExt::mask`](super::StageExt::mask) and
//!   [`StageExt::final_mask`](super::StageExt::final_mask).
//! * [`rx`](InducedStages::rx) mirrors
//!   [`StageExt::rx_configured`](super::StageExt::rx_configured), taking the
//!   stage's slot values directly instead of re-running a typed witness.

use alloc::{boxed::Box, vec::Vec};

use ragu_arithmetic::ff::Field;
use ragu_core::Result;

use super::mask::StageMask;
use crate::{
    BondingObject,
    polynomials::{Rank, sparse},
};

/// A discovered, value-level stage layout: the wire width of each induced
/// stage, in stage order.
///
/// See the [module documentation](self) for how this mirrors the typed
/// [`Stage`](super::Stage) geometry.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct InducedStages {
    widths: Vec<usize>,
}

impl InducedStages {
    /// Creates a layout from the wire width of each stage, in stage order.
    /// (does not count the final stage, which is left as implicit)
    pub fn new(widths: Vec<usize>) -> Self {
        Self { widths }
    }

    /// Returns the number of stages in this layout.
    pub fn len(&self) -> usize {
        self.widths.len()
    }

    /// Returns `true` if the layout contains no stages.
    pub fn is_empty(&self) -> bool {
        self.widths.is_empty()
    }

    /// Returns the wire width of the given stage.
    ///
    /// # Panics
    ///
    /// Panics if `stage >= self.len()`.
    pub fn width(&self, stage: usize) -> usize {
        self.widths[stage]
    }

    /// Returns the number of gates occupied by the given stage; the
    /// value-level mirror of [`StageExt::num_gates`](super::StageExt::num_gates).
    ///
    /// # Panics
    ///
    /// Panics if `stage >= self.len()`.
    pub fn num_gates(&self, stage: usize) -> usize {
        self.widths[stage].div_ceil(2)
    }

    /// Returns the number of gates to skip before the given stage, including
    /// the SYSTEM gate (gate 0); the value-level mirror of
    /// [`Stage::skip_gates`](super::Stage::skip_gates).
    ///
    /// # Panics
    ///
    /// Panics if `stage > self.len()` (equality is permitted: it yields the
    /// first gate after the last stage).
    pub fn skip_gates(&self, stage: usize) -> usize {
        1 + self.widths[..stage]
            .iter()
            .map(|w| w.div_ceil(2))
            .sum::<usize>()
    }

    /// Returns `skip_gates` for the final trace — the first gate after every
    /// stage in the layout. Mirrors what
    /// [`StageExt::final_mask`](super::StageExt::final_mask) computes from the
    /// last typed stage.
    pub fn final_skip_gates(&self) -> usize {
        self.skip_gates(self.len())
    }

    /// Creates the well-formedness mask for the given stage; the value-level
    /// mirror of [`StageExt::mask`](super::StageExt::mask).
    ///
    /// # Panics
    ///
    /// Panics if `stage >= self.len()`.
    pub fn mask<'a, F: Field, R: Rank>(&self, stage: usize) -> Result<BondingObject<'a, F, R>> {
        Ok(BondingObject::new(Box::new(StageMask::<R>::new(
            self.skip_gates(stage),
            self.num_gates(stage),
        )?)))
    }

    /// Creates the well-formedness mask for the final trace of a circuit with
    /// this stage layout; the value-level mirror of
    /// [`StageExt::final_mask`](super::StageExt::final_mask).
    pub fn final_mask<'a, F: Field, R: Rank>(&self) -> Result<BondingObject<'a, F, R>> {
        Ok(BondingObject::new(Box::new(StageMask::<R>::new_final(
            self.final_skip_gates(),
        )?)))
    }

    /// Computes the (partial) $r(X)$ polynomial for the given stage from its
    /// slot values; the value-level mirror of
    /// [`StageExt::rx_configured`](super::StageExt::rx_configured).
    ///
    /// `values` are the stage's wire values in canonical traversal order and
    /// may be shorter than the stage's gate capacity (the remainder is
    /// zero-padded). See `rx_configured` for the role of `alpha`.
    ///
    /// # Panics
    ///
    /// Panics if `stage >= self.len()`.
    pub fn rx<F: Field, R: Rank>(
        &self,
        stage: usize,
        alpha: F,
        values: &[F],
    ) -> Result<sparse::Polynomial<F, R>> {
        super::build_stage_rx(
            alpha,
            self.skip_gates(stage),
            self.num_gates(stage),
            2 * self.num_gates(stage),
            values,
        )
    }
}

#[cfg(test)]
mod tests {
    use core::marker::PhantomData;

    use ragu_arithmetic::ff::Field;
    use ragu_core::{
        drivers::{Driver, DriverValue},
        gadgets::{Bound, Gadget},
    };
    use ragu_pasta::Fp;
    use ragu_primitives::{Element, io::Write};

    use super::*;
    use crate::{
        WiringObject,
        staging::{Stage, StageExt, mask::global_project},
    };

    type R = crate::polynomials::ProductionRank;

    /// Typed twin of an induced layout with widths `[4, 3]`, used to check
    /// that the value-level geometry matches the typed geometry exactly.
    #[derive(Default)]
    struct TypedFour;

    #[derive(Gadget, Write)]
    struct FourElements<'dr, #[ragu(driver)] D: Driver<'dr>> {
        #[ragu(gadget)]
        a: Element<'dr, D>,
        #[ragu(gadget)]
        b: Element<'dr, D>,
        #[ragu(gadget)]
        c: Element<'dr, D>,
        #[ragu(gadget)]
        d: Element<'dr, D>,
    }

    impl Stage<Fp, R> for TypedFour {
        type Parent = ();
        type Witness<'source> = [Fp; 4];
        type OutputKind =
            <FourElements<'static, PhantomData<Fp>> as Gadget<'static, PhantomData<Fp>>>::Kind;

        fn values() -> usize {
            4
        }

        fn witness<'dr, 'source: 'dr, D: Driver<'dr, F = Fp>>(
            &self,
            dr: &mut D,
            witness: DriverValue<D, Self::Witness<'source>>,
        ) -> Result<Bound<'dr, D, Self::OutputKind>>
        where
            Self: 'dr,
        {
            use ragu_core::maybe::Maybe;
            use ragu_primitives::allocator::Standard;
            let alloc = &mut Standard::new();
            let a = Element::alloc(dr, alloc, witness.as_ref().map(|w| w[0]))?;
            let b = Element::alloc(dr, alloc, witness.as_ref().map(|w| w[1]))?;
            let c = Element::alloc(dr, alloc, witness.as_ref().map(|w| w[2]))?;
            let d = Element::alloc(dr, alloc, witness.as_ref().map(|w| w[3]))?;
            Ok(FourElements { a, b, c, d })
        }
    }

    /// Geometry-only twin of the second induced stage (width 3), chained onto
    /// [`TypedFour`] as its parent. Only its static geometry
    /// (`values` / `Parent`) is exercised, so the witness machinery is stubbed
    /// out like the base `()` stage.
    #[derive(Default)]
    struct TypedThree;

    impl Stage<Fp, R> for TypedThree {
        type Parent = TypedFour;
        type Witness<'source> = ();
        type OutputKind = ();

        fn values() -> usize {
            3
        }

        fn witness<'dr, 'source: 'dr, D: Driver<'dr, F = Fp>>(
            &self,
            _: &mut D,
            _: DriverValue<D, Self::Witness<'source>>,
        ) -> Result<Bound<'dr, D, Self::OutputKind>>
        where
            Self: 'dr,
        {
            Ok(())
        }
    }

    #[test]
    fn geometry_matches_typed_stages() {
        let layout = InducedStages::new(alloc::vec![4, 3]);

        assert_eq!(layout.len(), 2);
        assert_eq!(
            layout.skip_gates(0),
            <TypedFour as Stage<Fp, R>>::skip_gates()
        );
        assert_eq!(
            layout.num_gates(0),
            <TypedFour as StageExt<Fp, R>>::num_gates()
        );

        // Second stage: width 3, chained onto the first.
        assert_eq!(
            layout.skip_gates(1),
            <TypedThree as Stage<Fp, R>>::skip_gates()
        );
        assert_eq!(
            layout.num_gates(1),
            <TypedThree as StageExt<Fp, R>>::num_gates()
        );
        // The final trace starts right after the last stage.
        assert_eq!(
            layout.final_skip_gates(),
            <TypedThree as Stage<Fp, R>>::skip_gates()
                + <TypedThree as StageExt<Fp, R>>::num_gates()
        );
    }

    #[test]
    fn empty_layout() {
        let layout = InducedStages::new(alloc::vec![]);
        assert!(layout.is_empty());
        // The final trace starts right after the SYSTEM gate, like an
        // ordinary single-stage circuit.
        assert_eq!(layout.final_skip_gates(), 1);
    }

    /// The induced rx for a stage satisfies its own induced mask and fails the
    /// mask of a different stage — the same property the typed system
    /// guarantees (`test_staging_valid` in the mask module).
    #[test]
    fn induced_rx_satisfies_induced_mask() -> Result<()> {
        let layout = InducedStages::new(alloc::vec![4, 3]);

        let values_a = [Fp::from(7), Fp::from(11), Fp::from(13), Fp::from(17)];
        let values_b = [Fp::from(19), Fp::from(23), Fp::from(29)];

        let rx_a = layout.rx::<Fp, R>(0, Fp::ZERO, &values_a)?;
        let rx_b = layout.rx::<Fp, R>(1, Fp::ZERO, &values_b)?;

        let mask_a = layout.mask::<Fp, R>(0)?.into_inner();
        let mask_b = layout.mask::<Fp, R>(1)?.into_inner();

        let y = Fp::from(0x5eed);

        // sy() returns -notch; add global_project to recover the full mask.
        let full_sy = |mask: &dyn WiringObject<Fp, R>, y| {
            let mut poly = global_project::<Fp, R>(y);
            poly += &mask.sy(y, &[]);
            poly
        };

        assert_eq!(rx_a.revdot(&full_sy(&*mask_a, y)), Fp::ZERO);
        assert_eq!(rx_b.revdot(&full_sy(&*mask_b, y)), Fp::ZERO);
        assert_ne!(rx_a.revdot(&full_sy(&*mask_b, y)), Fp::ZERO);
        assert_ne!(rx_b.revdot(&full_sy(&*mask_a, y)), Fp::ZERO);

        Ok(())
    }

    /// The induced rx for a stage matches the typed `StageExt::rx` for an
    /// equivalent typed stage.
    #[test]
    fn induced_rx_matches_typed_rx() -> Result<()> {
        let layout = InducedStages::new(alloc::vec![4]);
        let values = [Fp::from(3), Fp::from(1), Fp::from(4), Fp::from(1)];

        let induced = layout.rx::<Fp, R>(0, Fp::from(42), &values)?;
        let typed = TypedFour::rx(Fp::from(42), values)?;

        let point = Fp::from(0xbeef);
        assert_eq!(induced.eval(point), typed.eval(point));

        Ok(())
    }
}
