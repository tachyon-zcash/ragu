//! Proof profiles.
//!
//! A profile is the set of internal circuits a proof carries beyond the
//! fuse's own, and so the shape of the proof: how many polynomials it holds
//! and how long the two endoscaling walks over them run. Every proof an
//! application makes has its profile's shape, and a proof is verified against
//! the registry it was made for, so the profile is fixed per application.
//!
//! Two profiles are foreseen. Wallets prove in [`Standard`]: the fuse alone,
//! compressed to a few kilobytes and sent over the network. Aggregators prove
//! in [`Aggregator`]: the fuse plus the circuits that verify a standard
//! compressed proof in circuit. A wallet's proof then enters an aggregator's
//! fuse as witness data rather than as a child, so the two shapes never have
//! to agree, and only the aggregator's proofs carry the extra polynomials.
//! The aggregator registry hardcodes the standard registry inside those
//! circuits; the standard registry knows nothing of the aggregator.
//!
//! Today the crate's layout is the standard profile's, spelled out as the
//! constants of the native and nested internal modules, and [`Shape::of`]
//! rederives it from the profile's declarations so the two cannot drift.
//! Making the layout generic over the profile, so one binary holds both
//! shapes, is the step the decompression circuits need and comes with them.

use crate::internal::{endoscalar, native, nested};

/// A proof profile: what a proof carries beyond the standard fuse.
///
/// The declarations are the roots of the proof's [`Shape`]. Each extra rx
/// polynomial on one side is a point the other side's walk folds, so an
/// extension lengthens both walks; [`Shape::solve`] works out by how much.
pub trait Profile: Copy + Default + Send + Sync + 'static {
    /// The native rx polynomials the profile adds to the standard fuse's: one
    /// per circuit or stage it registers on the native side.
    const NATIVE_EXTENSION: usize;

    /// The nested rx polynomials the profile adds, likewise one per nested
    /// circuit or stage.
    const NESTED_EXTENSION: usize;

    /// The native walk's step count.
    ///
    /// Pinned rather than derived, as the crate's layout pins it: the two
    /// walks size each other, and fixing one count breaks the cycle.
    /// [`Shape::of`] checks the pin is the fixed point, so a profile whose
    /// extensions move it fails to build until it is re-pinned.
    const NATIVE_ENDOSCALING_STEPS: usize;
}

/// The standard profile: the fuse alone. What wallets prove in.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Standard;

impl Profile for Standard {
    const NATIVE_EXTENSION: usize = 0;
    const NESTED_EXTENSION: usize = 0;
    const NATIVE_ENDOSCALING_STEPS: usize = 25;
}

/// The aggregator profile: the fuse plus the circuits that verify a
/// [`Standard`] compressed proof in circuit.
///
/// Those circuits do not exist yet, so the profile adds nothing and its shape
/// is [`Standard`]'s. When they land, their rx polynomial counts go here and
/// the walk is re-pinned to the fixed point [`Shape::solve`] reports.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Aggregator;

impl Profile for Aggregator {
    const NATIVE_EXTENSION: usize = 0;
    const NESTED_EXTENSION: usize = 0;
    const NATIVE_ENDOSCALING_STEPS: usize = 25;
}

/// The shape a profile gives a proof: its rx polynomial counts and the sizes
/// of the two endoscaling walks.
///
/// The sides size each other. Every native rx polynomial is a point the
/// nested walk folds, the nested walk's steps are nested rx polynomials, every
/// nested rx polynomial is a point the native walk folds, and the native
/// walk's steps are native rx polynomials. Going once around, a native step
/// adds about a quarter of a native step, so the map from a step count to the
/// count the batch then needs is a contraction with one fixed point, which
/// [`Shape::solve`] finds by iteration.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Shape {
    /// The native rx polynomials: the fixed ones, the walk's steps and the
    /// profile's extension.
    pub native_rx: usize,
    /// The nested-curve points the nested walk folds: the native batch.
    pub nested_points: usize,
    /// The nested walk's steps.
    pub nested_steps: usize,
    /// The nested rx polynomials.
    pub nested_rx: usize,
    /// The host-curve points the native walk folds: the nested batch.
    pub native_points: usize,
    /// The native walk's steps the batch needs. At the fixed point this is
    /// the count the native rx polynomials were sized with.
    pub native_steps: usize,
}

impl Shape {
    /// The shape of profile `P`.
    ///
    /// # Panics
    ///
    /// Fails to evaluate when `P`'s pinned native step count is not the
    /// fixed point of its extensions.
    pub const fn of<P: Profile>() -> Self {
        let shape = Self::solve(P::NATIVE_EXTENSION, P::NESTED_EXTENSION);
        assert!(
            shape.native_steps == P::NATIVE_ENDOSCALING_STEPS,
            "the profile's native step count is not the fixed point of its extensions; re-pin it"
        );
        shape
    }

    /// Solves the walk sizes for the given extensions, iterating the native
    /// step count to its fixed point.
    pub const fn solve(native_extension: usize, nested_extension: usize) -> Self {
        let mut native_steps = 1;
        let mut rounds = 0;
        loop {
            let shape = Self::with_native_steps(native_steps, native_extension, nested_extension);
            if shape.native_steps == native_steps {
                return shape;
            }
            rounds += 1;
            assert!(rounds < 64, "the walk sizes did not converge");
            native_steps = shape.native_steps;
        }
    }

    /// One pass around the cycle: the shape that `native_steps` native steps
    /// imply, whose `native_steps` is the count the resulting batch needs.
    const fn with_native_steps(
        native_steps: usize,
        native_extension: usize,
        nested_extension: usize,
    ) -> Self {
        let native_rx = native::NUM_FIXED_RX + native_steps + native_extension;
        let nested_points = nested::num_endoscaling_points(native_rx);
        let nested_steps =
            endoscalar::num_steps::<{ nested::ENDOSCALINGS_PER_STEP }>(nested_points);
        let nested_rx = nested::NUM_FIXED_RX + nested_steps + nested_extension;
        let native_points = nested::pcs::num_batched_points(nested_rx);
        let native_steps =
            endoscalar::num_steps::<{ native::ENDOSCALINGS_PER_STEP }>(native_points);
        Shape {
            native_rx,
            nested_points,
            nested_steps,
            nested_rx,
            native_points,
            native_steps,
        }
    }

    /// Every polynomial a proof of this shape carries: both sides' rx
    /// polynomials and, on each side, $a$, $b$, `registry_xy` and $p$.
    pub const fn polynomials(&self) -> usize {
        self.native_rx + 4 + self.nested_rx + 4
    }
}

// The crate's layout is the standard profile's shape. Each constant the
// layout spells out must agree with the rederivation, so an edit to either
// side that moves the shape fails here.
const _: () = {
    let shape = Shape::of::<Standard>();
    assert!(shape.native_rx == native::RxIndex::NUM);
    assert!(shape.nested_points == nested::NUM_ENDOSCALING_POINTS);
    assert!(shape.nested_steps == nested::NUM_ENDOSCALING_STEPS);
    assert!(shape.nested_rx == nested::RxIndex::NUM);
    assert!(shape.native_points == native::NUM_ENDOSCALING_POINTS);
    assert!(shape.native_steps == native::NUM_ENDOSCALING_STEPS);
};

// The aggregator's pin must be its fixed point too.
const _: () = {
    Shape::of::<Aggregator>();
};

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn standard_is_the_crate_layout() {
        let shape = Shape::of::<Standard>();
        assert_eq!(
            shape,
            Shape {
                native_rx: 49,
                nested_points: 113,
                nested_steps: 28,
                nested_rx: 42,
                native_points: 99,
                native_steps: 25,
            }
        );
        assert_eq!(shape.polynomials(), 99);
    }

    #[test]
    fn aggregator_matches_standard_until_its_circuits_land() {
        assert_eq!(Shape::of::<Aggregator>(), Shape::of::<Standard>());
    }

    #[test]
    fn solve_finds_a_fixed_point_for_wider_profiles() {
        for (native_extension, nested_extension) in
            [(0, 0), (1, 0), (0, 1), (10, 10), (134, 116), (300, 300)]
        {
            let shape = Shape::solve(native_extension, nested_extension);
            let again =
                Shape::with_native_steps(shape.native_steps, native_extension, nested_extension);
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
        let base = Shape::solve(0, 0);
        let wider = Shape::solve(100, 0);
        assert!(wider.nested_steps > base.nested_steps);
        assert!(wider.native_steps > base.native_steps);
        let extra = wider.polynomials() - base.polynomials();
        assert!(
            (150..=250).contains(&extra),
            "100 native polynomials cost {extra} overall"
        );
    }
}
