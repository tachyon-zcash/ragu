//! Aiming the patcher engine at the production internal recursion circuits
//! (issue #793).
//!
//! [`Application::capture_internal_circuits`] hands every native internal
//! circuit and its honest witness — which exist only mid-fuse — to a visitor.
//! Here the visitor captures each circuit through the recording driver. When
//! the [stage overlay](ragu_testing::patcher::overlay_stages) can make the
//! capture self-consistent, the capture is checked faithful two ways:
//!
//! * `constraints_hold` — the overlay recovered the honest stage-wire values
//!   that `configure_stage` zeros, so the honest witness satisfies the
//!   recorded graph. This exercises the whole engine on a production circuit
//!   at once: routines (Poseidon permutations), pooled allocation, and
//!   multi-stage reservation.
//! * `playback` — a second, independent synthesis re-accepts the same
//!   witness, so the recording matches a live re-execution.
//!
//! # What this establishes, and what remains
//!
//! The harness works: a real fuse hands all five native internal circuits to
//! the visitor, and `hashes_1` (5561 wires) captures faithfully. But the
//! current stage overlay is generic — it recovers stage wires by deducing
//! from the *determined* wires, which it identifies with
//! [`discover_free_advice`](ragu_testing::patcher::discover_free_advice). On
//! the inconsistent raw capture that classification can misfire (a reserved
//! stage wire mistaken for a determined wire seeded at zero), and it does for
//! four of the five circuits — where the overlay correctly *fails closed*
//! (returns `InvalidWitness`) rather than yield an unsound capture. A robust
//! overlay needs the circuit's stage structure, which generic `capture`
//! cannot see; that, the instance-input declaration the determinism oracle
//! needs, and a worklist solver for the larger circuits, are the remaining
//! work.
//!
//! So this test asserts the harness runs over all five circuits and that
//! every capture that *succeeds* is faithful — it does not yet require all
//! five to overlay. It is the wired harness the oracle plugs into once the
//! overlay is strengthened.
//!
//! Gated behind `unstable-fuzzing` and run with
//! `cargo test -p ragu_pcd --features unstable-fuzzing`.

use ragu_arithmetic::Cycle;
use ragu_circuits::{Circuit, polynomials::ProductionRank};
use ragu_core::Result;
use ragu_pasta::{Fp, Pasta};
use ragu_pcd::{ApplicationBuilder, patcher::InternalCircuitVisitor};
use ragu_testing::{
    patcher::{capture, constraints_hold, playback},
    pcd::nontrivial::{Hash2, WitnessLeaf},
};
use rand::{SeedableRng, rngs::StdRng};

/// Captures each internal circuit; asserts every *successful* capture is
/// faithful and counts how many overlaid, so a regression that stops any
/// currently-working capture (e.g. `hashes_1`) is caught.
#[derive(Default)]
struct CaptureChecker {
    visited: usize,
    captured: usize,
}

impl<C: Cycle> InternalCircuitVisitor<C> for CaptureChecker {
    fn visit<'w, Cir: Circuit<C::CircuitField>>(
        &mut self,
        name: &'static str,
        circuit: &Cir,
        make_witness: impl Fn() -> Result<Cir::Witness<'w>>,
    ) -> Result<()> {
        self.visited += 1;
        // A capture that fails is the overlay failing closed on a staging
        // shape it cannot yet recover (see the module docs), not a soundness
        // problem — so it is tolerated. A capture that *succeeds* must be
        // faithful.
        if let Ok(cap) = capture(circuit, make_witness()?) {
            assert!(
                constraints_hold(&cap.recorder.events, &cap.recorder.values),
                "{name}: a successful capture must satisfy the recorded constraints",
            );
            assert!(
                playback(circuit, make_witness()?, cap.recorder.values.clone())?,
                "{name}: an independent playback must re-accept the captured witness",
            );
            self.captured += 1;
        }
        Ok(())
    }
}

/// A real fuse, with the patcher capturing every native internal circuit as
/// its honest witness is built.
#[test]
fn patcher_captures_internal_circuits() -> Result<()> {
    let pasta = Pasta::baked();
    let app = ApplicationBuilder::<Pasta, ProductionRank, 4>::new()
        .register(WitnessLeaf {
            poseidon_params: Pasta::circuit_poseidon(pasta),
        })?
        .register(Hash2 {
            poseidon_params: Pasta::circuit_poseidon(pasta),
        })?
        .finalize(pasta)?;

    let mut rng = StdRng::seed_from_u64(1234);
    let (leaf1, _) = app.seed(
        &mut rng,
        WitnessLeaf {
            poseidon_params: Pasta::circuit_poseidon(pasta),
        },
        Fp::from(42u64),
    )?;
    let (leaf2, _) = app.seed(
        &mut rng,
        WitnessLeaf {
            poseidon_params: Pasta::circuit_poseidon(pasta),
        },
        Fp::from(42u64),
    )?;

    let mut checker = CaptureChecker::default();
    app.capture_internal_circuits(
        &mut rng,
        Hash2 {
            poseidon_params: Pasta::circuit_poseidon(pasta),
        },
        (),
        leaf1,
        leaf2,
        &mut checker,
    )?;

    assert_eq!(
        checker.visited, 5,
        "all five native internal circuits visited"
    );
    assert!(
        checker.captured >= 1,
        "at least one production circuit must capture faithfully (hashes_1); \
         got {}",
        checker.captured,
    );
    Ok(())
}
