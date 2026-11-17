//! The shape a profile gives a proof.

use super::{Profile, Standard};
use crate::{
    protocol::{native, nested},
    verifier::recursive::gadgets::endoscalar,
};

/// The shape a profile gives a proof: its rx polynomial counts and the sizes
/// of the two endoscaling walks.
///
/// The profile's extensions are the roots: each extra rx polynomial on one
/// side is a point the other side's walk folds, so an extension lengthens
/// both walks. The sides size each other. Every native rx polynomial is a
/// point the nested walk folds, the nested walk's steps are nested rx
/// polynomials, every nested rx polynomial is a point the native walk folds,
/// and the native walk's steps are native rx polynomials. Going once around
/// at four endoscalings per step, a native step adds about a quarter of a
/// native step, so the map from a step count to the count the batch then
/// needs converges to a fixed point, which [`Shape::solve`] finds by
/// iteration from one step; more endoscalings per step converge faster.
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
    /// The step's own online polynomials over the scalar field (see
    /// [`Profile::ONLINE_FQ_POLYS`]).
    pub online_fq: usize,
    /// The nested-curve points the native walk folds: the nested batch,
    /// with the commitments of the step's own online polynomials over the
    /// scalar field.
    pub native_points: usize,
    /// The native walk's steps: the fixed point, where the count the batch
    /// needs is the count the native rx polynomials were sized with.
    pub native_steps: usize,
}

impl Shape {
    /// The shape of profile `P`.
    ///
    /// # Panics
    ///
    /// Panics under the same conditions as [`Self::solve`]. When used in
    /// a constant layout, an invalid shape fails at compile time.
    pub const fn of<P: Profile>() -> Self {
        Self::solve(
            P::NATIVE_EXTENSION,
            P::NESTED_EXTENSION,
            P::ONLINE_FQ_POLYS,
            P::NATIVE_ENDOSCALINGS_PER_STEP,
            P::NESTED_ENDOSCALINGS_PER_STEP,
        )
    }

    /// Solves the walk sizes for the given extensions and online Fq
    /// polynomials at the given endoscalings per native and nested step,
    /// iterating the native step count to its fixed point.
    ///
    /// # Panics
    ///
    /// Panics if an endoscaling count is zero or the walk sizes do not
    /// converge within 64 iterations.
    pub const fn solve(
        native_extension: usize,
        nested_extension: usize,
        online_fq: usize,
        native_endoscalings: usize,
        nested_endoscalings: usize,
    ) -> Self {
        let mut native_steps = 1;
        let mut rounds = 0;
        loop {
            let shape = Self::with_native_steps(
                native_steps,
                native_extension,
                nested_extension,
                online_fq,
                native_endoscalings,
                nested_endoscalings,
            );
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
    pub(super) const fn with_native_steps(
        native_steps: usize,
        native_extension: usize,
        nested_extension: usize,
        online_fq: usize,
        native_endoscalings: usize,
        nested_endoscalings: usize,
    ) -> Self {
        let native_rx = native::NUM_FIXED_RX + native_steps + native_extension;
        let nested_points = nested::num_endoscaling_points(native_rx);
        let nested_steps = endoscalar::num_steps(nested_endoscalings, nested_points);
        let nested_rx = nested::NUM_FIXED_RX + nested_steps + nested_extension;
        let native_points = nested::pcs::num_batched_points(nested_rx, online_fq);
        let native_steps = endoscalar::num_steps(native_endoscalings, native_points);
        Shape {
            native_rx,
            nested_points,
            nested_steps,
            nested_rx,
            online_fq,
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

// The standard profile's shape is the internal modules' constant layout: the
// native walk's pin and the lists the tests and the fuzzing vocabulary read as
// constants. Each constant must agree with the rederivation, so an edit to
// either side that moves the shape fails here.
const _: () = {
    let shape = Shape::of::<Standard>();
    assert!(shape.native_rx == native::RxIndex::NUM);
    assert!(shape.nested_points == nested::NUM_ENDOSCALING_POINTS);
    assert!(shape.nested_steps == nested::NUM_ENDOSCALING_STEPS);
    assert!(shape.nested_rx == nested::RxIndex::NUM);
    assert!(shape.native_points == native::NUM_ENDOSCALING_POINTS);
    assert!(shape.native_steps == native::NUM_ENDOSCALING_STEPS);
};
