//! Fuzz the canonical revdot identity through `MultiStage`-as-`Circuit`,
//! exercising the staging plumbing in `crates/ragu_circuits/src/staging/`.
//!
//! For a satisfying witness `w` of a `MultiStageCircuit`, wrapped via
//! `MultiStage::new(_)` to implement the [`Circuit`] trait, the algebraic
//! identity from `tests/mod.rs:158-187` must hold:
//!
//! ```text
//! r.revdot(b) == ms.ky(instance, y)
//! where b = r + r.dilate(z) + s(X, y) + t(X, z)
//! ```
//!
//! `r` is the assembled trace polynomial; `s(X, y)` is derived from
//! `Registry::wy(omega_0, y)` minus the registry key term (same trick as
//! `fuzz_circuit_revdot_identity`, valid for a single-circuit registry
//! whose circuit is not a mask). `ms.ky(instance, y)` is the instance
//! polynomial evaluated at `y`.
//!
//! ## What this catches that the non-staged targets don't
//!
//! The `MultiStage`-as-`Circuit` path runs the user-supplied
//! `MultiStageCircuit::witness` body, which receives a [`StageBuilder`]
//! (`staging/builder.rs:73`). The builder allocates stage wires in a
//! two-phase protocol (phase 1: reserve, phase 2: inject), then hands the
//! injected wires to post-stage code that calls real driver ops. None of
//! that machinery is on `fuzz_circuit_witness` / `fuzz_circuit_revdot_identity`'s
//! path — those use plain `Circuit` impls without any stage.
//!
//! Specifically, this target re-runs the revdot identity under conditions
//! that exercise:
//!
//! - `StageBuilder::configure_stage` (`staging/builder.rs:198-242`) — wire
//!   counting via a wireless counter emulator, then real allocation through
//!   the supplied driver.
//! - `StageGuard::unenforced` / `unenforced_inner`
//!   (`staging/builder.rs:158-186`) — wireless witness execution followed
//!   by wire injection via `StageWireInjector` (`staging/builder.rs:99-115`).
//!   A bug that injects the wrong wires produces a trace polynomial that
//!   no longer satisfies the algebraic identity.
//! - `MultiStage::witness` (`staging/mod.rs:359-368`) — the adapter that
//!   makes `MultiStageCircuit` look like `Circuit` and threads `StageBuilder`
//!   into the user body.
//! - Parent-chain `skip_gates` arithmetic (`staging/mod.rs:220-222`) — one
//!   of the registered variants (`MscChain`) stacks `StageW4Child` on top
//!   of `StageW2`, so `skip_gates` recurses one level.
//!
//! `MultiStage::trace` (`mod.rs:359-368`) alone is not enough: the trace it
//! produces has zero-valued stage wire slots (`configure_stage` allocates
//! with `Coeff::Zero` at `staging/builder.rs:221`). The real $r(X)$ is
//! formed by adding `MultiStage::trace`'s output and each stage's
//! `StageExt::rx(0, witness_i)` polynomial (`staging/mod.rs:431`). In
//! production these are committed separately and summed at verification —
//! see `crates/ragu_pcd/src/fuse/_11_circuits.rs:63-148` for an
//! application of this pattern.
//!
//! The fuzz target reconstructs the full $r(X)$ that way and runs the
//! identity on the sum. `alpha = 0` everywhere prevents the SYSTEM gate's
//! `a[0]` from being double-counted across the trace and the stage rx
//! polynomials.
//!
//! ## Invariant A: per-stage isolation
//!
//! In addition to the combined-polynomial check above (Invariant B),
//! the target also runs the per-stage zero check from
//! `staging/mask.rs:456-491`, generalized to use only pub API: for each
//! stage in a variant's chain,
//!
//! ```text
//! StageType::rx(0, witness_i).revdot(s_mask(y)) == 0
//! ```
//!
//! where `s_mask(y)` is `Registry::circuit_y(0, y)` for a registry built
//! from a single `StageType::mask()` bonding object, minus the same
//! `digest * y^{4n-1}` key term Invariant B subtracts.
//!
//! Invariant A catches sum-preserving bugs that Invariant B misses — e.g.,
//! reversing two slots inside one stage's `rx_configured` and a
//! compensating reversal inside another stage's — because each stage is
//! checked against its own mask in isolation, not against an aggregate.
//!
//! ## final_mask check
//!
//! One additional structural check layers on top of Invariant A:
//!
//! - **`final_mask` zero check** (mirrors production proving at
//!   `crates/ragu_pcd/src/internal/endoscalar.rs:470`): the *assembled
//!   `MultiStage` trace polynomial* (before adding any stage `rx_i`) must
//!   revdot to zero against the last stage's `final_mask()`. The
//!   `final_mask` is constructed from `StageMask::new_final(skip+num)`
//!   (`staging/mask.rs:121`) and carves out `[last_stage_end, R::n())` —
//!   the post-stage gate range, where the assembled trace holds its only
//!   non-zero values. Stage-wire positions in the assembled trace are
//!   already zero because `StageBuilder::configure_stage` allocates them
//!   as `Coeff::Zero` (`staging/builder.rs:221`); the SYSTEM gate
//!   contributes nothing because `global_project` zeros it. Distinct
//!   code path from regular `mask()`, so a regression in `new_final` that
//!   doesn't affect `new` surfaces here.
//!
//! ## Circuit menu
//!
//! Three `MultiStageCircuit` variants, all using `TestRank` for ~2-5k
//! exec/s throughput parity with the other circuit-layer targets:
//!
//! - `Single2W`  — one `StageW2` stage, post-stage `square()` on the first wire.
//! - `Single4W`  — one `StageW4` stage, post-stage sum-then-square pattern.
//! - `Chain2x4`  — two stages (`StageW2` → `StageW4Child`), post-stage
//!   combines wires from both. Parent-chain `skip_gates` recurses.
//!
//! Each variant's `Instance` is the publicly-visible "Output" element
//! computed natively from the witness; the algebraic identity equates
//! that to the revdot side.

#![no_main]

use arbitrary::Arbitrary;
use core::marker::PhantomData;
use ff::Field;
use ff::PrimeField;
use libfuzzer_sys::fuzz_target;
use pasta_curves::Fp;
use ragu_circuits::{
    BondingObject, Circuit, CircuitExt, WithAux,
    polynomials::{Rank, TestRank, sparse},
    registry::{CircuitIndex, Registry, RegistryBuilder},
    staging::{MultiStage, MultiStageCircuit, Stage, StageBuilder, StageExt},
};
use ragu_core::{
    Result,
    drivers::{Driver, DriverValue},
    gadgets::{Bound, Gadget, Kind},
    maybe::Maybe,
};
use ragu_primitives::Element;
use std::sync::LazyLock;

// ---------------------------------------------------------------------------
// Stage definitions. Each stage allocates a fixed number of wires; the
// post-stage `MultiStageCircuit::witness` does the gadget ops.
//
// `Stage::witness` runs on stub drivers (wireless during reservation,
// wired-but-no-enforce during rx extraction). To keep behavior consistent
// across phases, stages only do plain `Element::alloc` here — gadget ops
// happen in the post-stage code where the real driver is in scope.
// ---------------------------------------------------------------------------

#[derive(ragu_core::gadgets::Gadget, ragu_primitives::io::Write)]
struct TwoWires<'dr, #[ragu(driver)] D: Driver<'dr>> {
    #[ragu(gadget)]
    a: Element<'dr, D>,
    #[ragu(gadget)]
    b: Element<'dr, D>,
}

#[derive(ragu_core::gadgets::Gadget, ragu_primitives::io::Write)]
struct FourWires<'dr, #[ragu(driver)] D: Driver<'dr>> {
    #[ragu(gadget)]
    a: Element<'dr, D>,
    #[ragu(gadget)]
    b: Element<'dr, D>,
    #[ragu(gadget)]
    c: Element<'dr, D>,
    #[ragu(gadget)]
    d: Element<'dr, D>,
}

/// 2-wire stage with parent `()`. Both wires are independent witnesses.
#[derive(Default)]
struct StageW2;

impl Stage<Fp, TestRank> for StageW2 {
    type Parent = ();
    type Witness<'source> = (Fp, Fp);
    type OutputKind =
        <TwoWires<'static, PhantomData<Fp>> as Gadget<'static, PhantomData<Fp>>>::Kind;

    fn values() -> usize {
        2
    }

    fn witness<'dr, 'source: 'dr, D: Driver<'dr, F = Fp>>(
        &self,
        dr: &mut D,
        witness: DriverValue<D, Self::Witness<'source>>,
    ) -> Result<Bound<'dr, D, Self::OutputKind>>
    where
        Self: 'dr,
    {
        let a = Element::alloc(dr, &mut (), witness.as_ref().map(|w| w.0))?;
        let b = Element::alloc(dr, &mut (), witness.as_ref().map(|w| w.1))?;
        Ok(TwoWires { a, b })
    }
}

/// 4-wire stage with parent `()`. All four wires are independent witnesses.
#[derive(Default)]
struct StageW4;

impl Stage<Fp, TestRank> for StageW4 {
    type Parent = ();
    type Witness<'source> = (Fp, Fp, Fp, Fp);
    type OutputKind =
        <FourWires<'static, PhantomData<Fp>> as Gadget<'static, PhantomData<Fp>>>::Kind;

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
        let a = Element::alloc(dr, &mut (), witness.as_ref().map(|w| w.0))?;
        let b = Element::alloc(dr, &mut (), witness.as_ref().map(|w| w.1))?;
        let c = Element::alloc(dr, &mut (), witness.as_ref().map(|w| w.2))?;
        let d = Element::alloc(dr, &mut (), witness.as_ref().map(|w| w.3))?;
        Ok(FourWires { a, b, c, d })
    }
}

/// 4-wire stage with `StageW2` as parent. Exercises `skip_gates` recursion.
#[derive(Default)]
struct StageW4Child;

impl Stage<Fp, TestRank> for StageW4Child {
    type Parent = StageW2;
    type Witness<'source> = (Fp, Fp, Fp, Fp);
    type OutputKind =
        <FourWires<'static, PhantomData<Fp>> as Gadget<'static, PhantomData<Fp>>>::Kind;

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
        let a = Element::alloc(dr, &mut (), witness.as_ref().map(|w| w.0))?;
        let b = Element::alloc(dr, &mut (), witness.as_ref().map(|w| w.1))?;
        let c = Element::alloc(dr, &mut (), witness.as_ref().map(|w| w.2))?;
        let d = Element::alloc(dr, &mut (), witness.as_ref().map(|w| w.3))?;
        Ok(FourWires { a, b, c, d })
    }
}

// ---------------------------------------------------------------------------
// MultiStageCircuit definitions. Each one wires up one or more stages and
// performs a small gadget computation on the injected wires, yielding an
// `Element` output that the verifier sees in `k(Y)`.
//
// The `Instance` for each is the natively-computed Output, supplied to
// `ms.ky(instance, y)` to form the right-hand side of the identity.
// ---------------------------------------------------------------------------

/// One `StageW2` stage. Post-stage: output = a^2.
#[derive(Clone, Default)]
struct Single2W;

impl MultiStageCircuit<Fp, TestRank> for Single2W {
    type Last = StageW2;
    type Instance<'source> = Fp;
    type Witness<'source> = (Fp, Fp);
    type Output = Kind![Fp; Element<'_, _>];
    type Aux<'source> = ();

    fn instance<'dr, 'source: 'dr, D: Driver<'dr, F = Fp>>(
        &self,
        dr: &mut D,
        instance: DriverValue<D, Fp>,
    ) -> Result<Bound<'dr, D, Self::Output>>
    where
        Self: 'dr,
    {
        Element::alloc(dr, &mut (), instance)
    }

    fn witness<'a, 'dr, 'source: 'dr, D: Driver<'dr, F = Fp>>(
        &self,
        builder: StageBuilder<'a, 'dr, D, TestRank, (), StageW2>,
        witness: DriverValue<D, (Fp, Fp)>,
    ) -> Result<WithAux<Bound<'dr, D, Self::Output>, DriverValue<D, ()>>>
    where
        Self: 'dr,
    {
        let (guard, builder) = builder.configure_stage(StageW2)?;
        let dr = builder.finish();
        let TwoWires { a, b: _ } = guard.unenforced(dr, witness)?;
        let out = a.square(dr)?;
        Ok(WithAux::new(out, D::unit()))
    }
}

impl Single2W {
    /// Native: `a^2`, ignoring `b`. Matches `witness` exactly.
    fn native_instance(witness: (Fp, Fp)) -> Fp {
        witness.0.square()
    }
}

/// One `StageW4` stage. Post-stage: output = (a + b) * (c + d).
#[derive(Clone, Default)]
struct Single4W;

impl MultiStageCircuit<Fp, TestRank> for Single4W {
    type Last = StageW4;
    type Instance<'source> = Fp;
    type Witness<'source> = (Fp, Fp, Fp, Fp);
    type Output = Kind![Fp; Element<'_, _>];
    type Aux<'source> = ();

    fn instance<'dr, 'source: 'dr, D: Driver<'dr, F = Fp>>(
        &self,
        dr: &mut D,
        instance: DriverValue<D, Fp>,
    ) -> Result<Bound<'dr, D, Self::Output>>
    where
        Self: 'dr,
    {
        Element::alloc(dr, &mut (), instance)
    }

    fn witness<'a, 'dr, 'source: 'dr, D: Driver<'dr, F = Fp>>(
        &self,
        builder: StageBuilder<'a, 'dr, D, TestRank, (), StageW4>,
        witness: DriverValue<D, (Fp, Fp, Fp, Fp)>,
    ) -> Result<WithAux<Bound<'dr, D, Self::Output>, DriverValue<D, ()>>>
    where
        Self: 'dr,
    {
        let (guard, builder) = builder.configure_stage(StageW4)?;
        let dr = builder.finish();
        let FourWires { a, b, c, d } = guard.unenforced(dr, witness)?;
        let lhs = a.add(dr, &b);
        let rhs = c.add(dr, &d);
        let out = lhs.mul(dr, &rhs)?;
        Ok(WithAux::new(out, D::unit()))
    }
}

impl Single4W {
    /// Native: `(a + b) * (c + d)`.
    fn native_instance(witness: (Fp, Fp, Fp, Fp)) -> Fp {
        (witness.0 + witness.1) * (witness.2 + witness.3)
    }
}

/// Two stages: `StageW2` parent, `StageW4Child` last. Post-stage: output =
/// (parent.a + child.a) * (parent.b + child.b).
///
/// Exercises `skip_gates` recursion at `staging/mod.rs:220-222`.
#[derive(Clone, Default)]
struct Chain2x4;

impl MultiStageCircuit<Fp, TestRank> for Chain2x4 {
    type Last = StageW4Child;
    type Instance<'source> = Fp;
    type Witness<'source> = ((Fp, Fp), (Fp, Fp, Fp, Fp));
    type Output = Kind![Fp; Element<'_, _>];
    type Aux<'source> = ();

    fn instance<'dr, 'source: 'dr, D: Driver<'dr, F = Fp>>(
        &self,
        dr: &mut D,
        instance: DriverValue<D, Fp>,
    ) -> Result<Bound<'dr, D, Self::Output>>
    where
        Self: 'dr,
    {
        Element::alloc(dr, &mut (), instance)
    }

    fn witness<'a, 'dr, 'source: 'dr, D: Driver<'dr, F = Fp>>(
        &self,
        builder: StageBuilder<'a, 'dr, D, TestRank, (), StageW4Child>,
        witness: DriverValue<D, ((Fp, Fp), (Fp, Fp, Fp, Fp))>,
    ) -> Result<WithAux<Bound<'dr, D, Self::Output>, DriverValue<D, ()>>>
    where
        Self: 'dr,
    {
        let (parent_guard, builder) = builder.configure_stage(StageW2)?;
        let (child_guard, builder) = builder.configure_stage(StageW4Child)?;
        let dr = builder.finish();

        let parent_witness = witness.as_ref().map(|w| w.0);
        let child_witness = witness.as_ref().map(|w| w.1);

        let TwoWires {
            a: parent_a,
            b: parent_b,
        } = parent_guard.unenforced(dr, parent_witness)?;
        let FourWires {
            a: child_a,
            b: child_b,
            c: _,
            d: _,
        } = child_guard.unenforced(dr, child_witness)?;

        let lhs = parent_a.add(dr, &child_a);
        let rhs = parent_b.add(dr, &child_b);
        let out = lhs.mul(dr, &rhs)?;
        Ok(WithAux::new(out, D::unit()))
    }
}

impl Chain2x4 {
    /// Native: `(parent.a + child.a) * (parent.b + child.b)`.
    fn native_instance(witness: ((Fp, Fp), (Fp, Fp, Fp, Fp))) -> Fp {
        let ((pa, pb), (ca, cb, _, _)) = witness;
        (pa + ca) * (pb + cb)
    }
}

// ---------------------------------------------------------------------------
// Per-variant memoized registries. Same `LazyLock<Option<Registry<...>>>`
// pattern as fuzz_circuit_revdot_identity's SIMPLE_REGISTRY but one slot per
// variant.
// ---------------------------------------------------------------------------

fn build_registry<C>(circuit: C) -> Option<Registry<'static, Fp, TestRank>>
where
    C: Circuit<Fp> + 'static,
{
    RegistryBuilder::<Fp, TestRank>::new()
        .register_circuit(circuit)
        .and_then(|b| b.finalize())
        .ok()
}

static SINGLE2W_REGISTRY: LazyLock<Option<Registry<'static, Fp, TestRank>>> =
    LazyLock::new(|| build_registry(MultiStage::<Fp, TestRank, _>::new(Single2W)));

static SINGLE4W_REGISTRY: LazyLock<Option<Registry<'static, Fp, TestRank>>> =
    LazyLock::new(|| build_registry(MultiStage::<Fp, TestRank, _>::new(Single4W)));

static CHAIN_REGISTRY: LazyLock<Option<Registry<'static, Fp, TestRank>>> =
    LazyLock::new(|| build_registry(MultiStage::<Fp, TestRank, _>::new(Chain2x4)));

/// Build a registry containing just one stage's `mask()` as a bonding
/// entry. The resulting registry's `circuit_y(0, y)` is the stage's full
/// mask polynomial (the framework's `RegistryAt::y` adds the global term
/// for masking circuits, recovering it from the `-notch`-only `sy()` that
/// the underlying `StageMask` returns) plus the `digest * y^{4n-1}` key
/// term — exactly the inputs Invariant A wants for its zero check, after
/// subtracting the key term.
fn build_mask_registry(mask: BondingObject<'static, Fp, TestRank>) -> Option<Registry<'static, Fp, TestRank>> {
    RegistryBuilder::<Fp, TestRank>::new()
        .register_bonding(mask)
        .finalize()
        .ok()
}

static MASK_REGISTRY_W2: LazyLock<Option<Registry<'static, Fp, TestRank>>> = LazyLock::new(|| {
    let mask: BondingObject<'static, Fp, TestRank> =
        <StageW2 as StageExt<Fp, TestRank>>::mask().ok()?;
    build_mask_registry(mask)
});

static MASK_REGISTRY_W4: LazyLock<Option<Registry<'static, Fp, TestRank>>> = LazyLock::new(|| {
    let mask: BondingObject<'static, Fp, TestRank> =
        <StageW4 as StageExt<Fp, TestRank>>::mask().ok()?;
    build_mask_registry(mask)
});

static MASK_REGISTRY_W4_CHILD: LazyLock<Option<Registry<'static, Fp, TestRank>>> = LazyLock::new(|| {
    let mask: BondingObject<'static, Fp, TestRank> =
        <StageW4Child as StageExt<Fp, TestRank>>::mask().ok()?;
    build_mask_registry(mask)
});

// Final-mask registries — one per stage type, built from
// `StageExt::final_mask()` instead of `mask()`. `final_mask` covers
// `[skip_gates, R::n())` (every gate after the stage's skip), whereas
// `mask` covers only the stage's own `[skip, skip+num)` slots. Used
// only for the LAST stage in a variant's chain.
static MASK_REGISTRY_W2_FINAL: LazyLock<Option<Registry<'static, Fp, TestRank>>> = LazyLock::new(|| {
    let mask: BondingObject<'static, Fp, TestRank> =
        <StageW2 as StageExt<Fp, TestRank>>::final_mask().ok()?;
    build_mask_registry(mask)
});

static MASK_REGISTRY_W4_FINAL: LazyLock<Option<Registry<'static, Fp, TestRank>>> = LazyLock::new(|| {
    let mask: BondingObject<'static, Fp, TestRank> =
        <StageW4 as StageExt<Fp, TestRank>>::final_mask().ok()?;
    build_mask_registry(mask)
});

static MASK_REGISTRY_W4_CHILD_FINAL: LazyLock<Option<Registry<'static, Fp, TestRank>>> = LazyLock::new(|| {
    let mask: BondingObject<'static, Fp, TestRank> =
        <StageW4Child as StageExt<Fp, TestRank>>::final_mask().ok()?;
    build_mask_registry(mask)
});

// ---------------------------------------------------------------------------
// Input shape — one variant per MultiStageCircuit. Same `Arbitrary` style
// as fuzz_circuit_revdot_identity.
// ---------------------------------------------------------------------------

#[derive(Arbitrary, Debug)]
enum CircuitChoice {
    Single2W {
        a_seed: u64,
        b_seed: u64,
        use_special: Option<u8>,
    },
    Single4W {
        a_seed: u64,
        b_seed: u64,
        c_seed: u64,
        d_seed: u64,
        use_special: Option<u8>,
    },
    Chain {
        parent_a_seed: u64,
        parent_b_seed: u64,
        child_a_seed: u64,
        child_b_seed: u64,
        child_c_seed: u64,
        child_d_seed: u64,
        use_special: Option<u8>,
    },
}

#[derive(Arbitrary, Debug)]
struct Input {
    circuit: CircuitChoice,
    y_seed: u64,
    z_seed: u64,
}

fn special_value(idx: u8) -> Fp {
    match idx % 8 {
        0 => Fp::ZERO,
        1 => Fp::ONE,
        2 => -Fp::ONE,
        3 => Fp::TWO_INV,
        4 => Fp::ROOT_OF_UNITY,
        5 => Fp::MULTIPLICATIVE_GENERATOR,
        6 => Fp::from(1u64 << 32),
        _ => Fp::from(u64::MAX),
    }
}

/// `special` overrides only the first witness slot for the variant, mirroring
/// `fuzz_circuit_revdot_identity`'s pattern of biasing the first witness toward
/// edge values without losing entropy in the rest.
fn maybe_special(seed: u64, special: Option<u8>) -> Fp {
    match special {
        Some(idx) => special_value(idx),
        None => Fp::from(seed),
    }
}

/// Same trick as `fuzz_circuit_revdot_identity::sy_from_registry`:
/// `Registry::wy(omega_0, y)` is `s(X, y)` plus the registry key term
/// `key.value() * y^{4n-1}` at slot `c[R::n() - 1]`. Subtract it to
/// recover the bare wiring polynomial. Valid because each MSC variant
/// is registered alone (single-circuit registry, non-mask).
fn sy_from_registry(
    registry: &Registry<'_, Fp, TestRank>,
    y: Fp,
) -> sparse::Polynomial<Fp, TestRank> {
    let omega_0 = CircuitIndex::new(0).omega_j::<Fp>();
    let mut wy = registry.wy(omega_0, y);
    if y != Fp::ZERO {
        let y_4n_minus_1 = y.pow_vartime([(4 * TestRank::n() - 1) as u64]);
        let mut key_view = sparse::View::<_, TestRank, _>::wiring();
        key_view.c.push(registry.digest() * y_4n_minus_1);
        let key_term = key_view.build();
        wy.sub_assign(&key_term);
    }
    wy
}

/// Same key-term subtraction as `sy_from_registry`, applied to a
/// mask-only registry. The mask-only registry's `circuit_y(0, y)` is the
/// stage's full mask polynomial plus the `digest * y^{4n-1}` key term;
/// subtracting the latter gives the bare mask polynomial that Invariant
/// A revdots against.
fn sy_from_mask_registry(
    mask_registry: &Registry<'_, Fp, TestRank>,
    y: Fp,
) -> sparse::Polynomial<Fp, TestRank> {
    let mut wy = mask_registry.circuit_y(CircuitIndex::new(0), y);
    if y != Fp::ZERO {
        let y_4n_minus_1 = y.pow_vartime([(4 * TestRank::n() - 1) as u64]);
        let mut key_view = sparse::View::<_, TestRank, _>::wiring();
        key_view.c.push(mask_registry.digest() * y_4n_minus_1);
        let key_term = key_view.build();
        wy.sub_assign(&key_term);
    }
    wy
}

/// Invariant A: assert that a single stage's `rx` polynomial revdots to
/// zero against its own mask polynomial. Per-stage discrimination —
/// catches bugs that Invariant B's combined-polynomial check would miss
/// when one stage's error is cancelled by another's. Panics with both
/// sides on failure.
fn check_stage_isolation(
    label: &str,
    stage_rx: &sparse::Polynomial<Fp, TestRank>,
    mask_registry: &Registry<'_, Fp, TestRank>,
    y: Fp,
) {
    let sy = sy_from_mask_registry(mask_registry, y);
    let actual = stage_rx.revdot(&sy);
    assert_eq!(
        actual,
        Fp::ZERO,
        "Invariant A violated for {label}: rx.revdot(mask) = {actual:?}, expected 0 at y={y:?}"
    );
}

/// Maps a sparse-polynomial coefficient degree (Trace perspective) back
/// to its `(wire, gate_index)`. Returns `None` for degrees outside `[0, 4n)`.
///
/// Mirror of `polynomials::sparse::view::Trace::map_to_blocks`:
/// - `c[i]` → degree `i`             (range `[0, n)`)
/// - `a[i]` → degree `2n - 1 - i`    (reversed, range `[n, 2n)`)
/// - `b[i]` → degree `2n + i`        (range `[2n, 3n)`)
/// - `d[i]` → degree `4n - 1 - i`    (reversed, range `[3n, 4n)`)
fn trace_degree_to_gate(deg: usize) -> Option<usize> {
    let n = TestRank::n();
    if deg < n {
        Some(deg) // c[i]
    } else if deg < 2 * n {
        Some(2 * n - 1 - deg) // a[i]
    } else if deg < 3 * n {
        Some(deg - 2 * n) // b[i]
    } else if deg < 4 * n {
        Some(4 * n - 1 - deg) // d[i]
    } else {
        None
    }
}

/// Structural cross-stage discrimination check (robust replacement for the
/// adversarially-fragile `rx.revdot(foreign_mask) ≠ 0` algebraic version).
/// Asserts that every non-zero coefficient of `stage_rx` maps back (under
/// the Trace perspective) to a gate index inside the stage's declared
/// `[skip, skip + num)` range — or to gate 0 (the SYSTEM gate, where
/// `rx_configured` places `alpha`).
///
/// Catches `rx_configured` slot-leak bugs deterministically, without
/// going through `y`, so libfuzzer can't adversarially construct
/// witness/y pairs that hide the bug. Stronger than Invariant A:
/// Invariant A catches via the algebraic identity which can be
/// adversarially zeroed; this catches via direct structural inspection.
fn check_stage_slot_range(
    label: &str,
    stage_rx: &sparse::Polynomial<Fp, TestRank>,
    own_skip: usize,
    own_num: usize,
) {
    for (deg, val) in stage_rx.iter_coeffs().enumerate() {
        if val == Fp::ZERO {
            continue;
        }
        let gate = trace_degree_to_gate(deg)
            .unwrap_or_else(|| panic!("{label}: degree {deg} out of range"));
        // Gate 0 (SYSTEM) is allowed because `rx_configured` writes
        // `alpha` to `a[0]`. Otherwise the non-zero must lie in the
        // stage's declared range.
        let in_own_range = gate == 0 || (gate >= own_skip && gate < own_skip + own_num);
        assert!(
            in_own_range,
            "Structural cross-mask check failed for {label}: rx has \
             non-zero coefficient at degree {deg} (gate {gate}), which \
             lies outside the stage's declared range [{own_skip}, {}). \
             This stage's rx_configured is writing to a slot it shouldn't \
             — a value-preserving slot leak that Invariant A's algebraic \
             check can miss under adversarial witness/y combinations.",
            own_skip + own_num
        );
    }
}

/// Run the Invariant B oracle and the bare-MultiStage-trace `final_mask`
/// check together. `stage_rx_sum` is added to the assembled trace before
/// the algebraic identity is checked (per the canonical derivation), but
/// the bare assembled trace alone is checked against `final_mask_registry`
/// first — this mirrors production proving at
/// `crates/ragu_pcd/src/internal/endoscalar.rs:470`.
///
/// Returns `(expected_ky, actual_revdot)` so the caller's panic message
/// can show both sides of the Invariant B check.
fn check_identity<C: Circuit<Fp>>(
    label: &str,
    registry: &Registry<'_, Fp, TestRank>,
    circuit: &C,
    witness: C::Witness<'_>,
    instance: C::Instance<'_>,
    stage_rx_sum: sparse::Polynomial<Fp, TestRank>,
    final_mask_registry: Option<&Registry<'_, Fp, TestRank>>,
    y: Fp,
    z: Fp,
) -> Option<(Fp, Fp)> {
    let trace = circuit.trace(witness).ok()?.into_output();

    // alpha = 0 so the algebraic identity holds without an extra revdot
    // term — same rationale as fuzz_circuit_revdot_identity. The stage rx
    // polynomials are also computed with alpha = 0; together with the
    // trace's a[0]=0 the gate-0 SYSTEM constraint stays clean.
    let multistage_trace = registry
        .assemble_with_alpha(&trace, CircuitIndex::new(0), Fp::ZERO)
        .expect("assemble_with_alpha failed on a registered MultiStage circuit");

    // final_mask: the bare assembled MultiStage trace (no stage rx yet)
    // must revdot to zero against the last stage's final_mask polynomial.
    // The final_mask carves out [last_stage_end, R::n()); the assembled
    // trace's post-stage gate values live in that range, so the revdot
    // collects them weighted by zero. Stage-wire positions in the
    // assembled trace are zero (StageBuilder allocates them as
    // Coeff::Zero), so the SYSTEM gate and earlier gates contribute
    // nothing either.
    if let Some(fm_reg) = final_mask_registry {
        let fm_sy = sy_from_mask_registry(fm_reg, y);
        let fm_actual = multistage_trace.revdot(&fm_sy);
        assert_eq!(
            fm_actual,
            Fp::ZERO,
            "final_mask check failed for {label}: \
             assembled_multistage_trace.revdot(final_mask) = {fm_actual:?}, expected 0 at y={y:?}"
        );
    }

    let mut r = multistage_trace;
    r.add_assign(&stage_rx_sum);

    let mut b = r.clone();
    b.dilate(z);
    b.add_assign(&sy_from_registry(registry, y));
    b.add_assign(&TestRank::tz(z));

    let expected_ky = circuit
        .ky(instance, y)
        .expect("ky should not fail on a MultiStage Fp instance");
    let actual = r.revdot(&b);
    Some((expected_ky, actual))
}

fuzz_target!(|input: Input| {
    if std::env::var("DEBUG_INPUT").is_ok() {
        eprintln!("{:#?}", input);
        return;
    }

    let y = Fp::from(input.y_seed);
    let z = Fp::from(input.z_seed);

    match input.circuit {
        CircuitChoice::Single2W {
            a_seed,
            b_seed,
            use_special,
        } => {
            let registry = match SINGLE2W_REGISTRY.as_ref() {
                Some(r) => r,
                None => return,
            };
            let a = maybe_special(a_seed, use_special);
            let b = Fp::from(b_seed);
            let witness = (a, b);
            let circuit = MultiStage::<Fp, TestRank, _>::new(Single2W);
            let instance = Single2W::native_instance(witness);
            // Pin StageW2's declared offsets against hand-coded constants.
            // Catches symmetric `skip_gates` bugs that would shift both
            // `rx_configured` and `StageMask::new` together — invariants
            // A/B and final_mask all stay structurally satisfied under
            // such a shift, but this assertion fails immediately.
            debug_assert_eq!(<StageW2 as Stage<Fp, TestRank>>::skip_gates(), 1);
            debug_assert_eq!(<StageW2 as StageExt<Fp, TestRank>>::num_gates(), 1);

            let stage_w2_rx = match StageW2::rx(Fp::ZERO, (a, b)) {
                Ok(p) => p,
                Err(_) => return,
            };
            // Structural cross-mask check (robust replacement for the
            // dropped algebraic version): assert non-zero positions land
            // only in StageW2's declared range or the SYSTEM gate.
            check_stage_slot_range("Single2W/StageW2", &stage_w2_rx, 1, 1);
            // Invariant A: per-stage isolation against the stage's own mask.
            if let Some(mask_reg) = MASK_REGISTRY_W2.as_ref() {
                check_stage_isolation("Single2W/StageW2", &stage_w2_rx, mask_reg, y);
            }
            // Invariant B (with bundled final_mask check on the bare trace):
            // StageW2 is the last (and only) stage in this variant.
            let Some((expected, actual)) = check_identity(
                "Single2W",
                registry,
                &circuit,
                witness,
                instance,
                stage_w2_rx,
                MASK_REGISTRY_W2_FINAL.as_ref(),
                y,
                z,
            ) else {
                return;
            };
            assert_eq!(
                expected, actual,
                "Single2W staging identity violated: \
                 witness={witness:?}, instance={instance:?}, y={y:?}, z={z:?}, \
                 expected_ky={expected:?}, actual_revdot={actual:?}"
            );
        }
        CircuitChoice::Single4W {
            a_seed,
            b_seed,
            c_seed,
            d_seed,
            use_special,
        } => {
            let registry = match SINGLE4W_REGISTRY.as_ref() {
                Some(r) => r,
                None => return,
            };
            let a = maybe_special(a_seed, use_special);
            let b = Fp::from(b_seed);
            let c = Fp::from(c_seed);
            let d = Fp::from(d_seed);
            let witness = (a, b, c, d);
            let circuit = MultiStage::<Fp, TestRank, _>::new(Single4W);
            let instance = Single4W::native_instance(witness);
            // Pin StageW4's declared offsets (same rationale as Single2W).
            debug_assert_eq!(<StageW4 as Stage<Fp, TestRank>>::skip_gates(), 1);
            debug_assert_eq!(<StageW4 as StageExt<Fp, TestRank>>::num_gates(), 2);

            let stage_w4_rx = match StageW4::rx(Fp::ZERO, witness) {
                Ok(p) => p,
                Err(_) => return,
            };
            check_stage_slot_range("Single4W/StageW4", &stage_w4_rx, 1, 2);
            if let Some(mask_reg) = MASK_REGISTRY_W4.as_ref() {
                check_stage_isolation("Single4W/StageW4", &stage_w4_rx, mask_reg, y);
            }
            let Some((expected, actual)) = check_identity(
                "Single4W",
                registry,
                &circuit,
                witness,
                instance,
                stage_w4_rx,
                MASK_REGISTRY_W4_FINAL.as_ref(),
                y,
                z,
            ) else {
                return;
            };
            assert_eq!(
                expected, actual,
                "Single4W staging identity violated: \
                 witness={witness:?}, instance={instance:?}, y={y:?}, z={z:?}, \
                 expected_ky={expected:?}, actual_revdot={actual:?}"
            );
        }
        CircuitChoice::Chain {
            parent_a_seed,
            parent_b_seed,
            child_a_seed,
            child_b_seed,
            child_c_seed,
            child_d_seed,
            use_special,
        } => {
            let registry = match CHAIN_REGISTRY.as_ref() {
                Some(r) => r,
                None => return,
            };
            let parent_a = maybe_special(parent_a_seed, use_special);
            let parent_b = Fp::from(parent_b_seed);
            let child_a = Fp::from(child_a_seed);
            let child_b = Fp::from(child_b_seed);
            let child_c = Fp::from(child_c_seed);
            let child_d = Fp::from(child_d_seed);
            let witness = (
                (parent_a, parent_b),
                (child_a, child_b, child_c, child_d),
            );
            let circuit = MultiStage::<Fp, TestRank, _>::new(Chain2x4);
            let instance = Chain2x4::native_instance(witness);

            // Pin parent and child stage offsets. Catches symmetric
            // `skip_gates` shifts that A/B/final_mask all stay structurally
            // satisfied under.
            debug_assert_eq!(<StageW2 as Stage<Fp, TestRank>>::skip_gates(), 1);
            debug_assert_eq!(<StageW2 as StageExt<Fp, TestRank>>::num_gates(), 1);
            debug_assert_eq!(<StageW4Child as Stage<Fp, TestRank>>::skip_gates(), 2);
            debug_assert_eq!(<StageW4Child as StageExt<Fp, TestRank>>::num_gates(), 2);

            // Stages composed in order: StageW2 then StageW4Child. Sum both
            // rx polynomials so the combined `r(X)` is consistent with what
            // the verifier would see after committing each stage separately.
            let parent_rx = match StageW2::rx(Fp::ZERO, (parent_a, parent_b)) {
                Ok(p) => p,
                Err(_) => return,
            };
            let child_rx = match StageW4Child::rx(Fp::ZERO, (child_a, child_b, child_c, child_d)) {
                Ok(p) => p,
                Err(_) => return,
            };
            // Structural cross-mask: each rx must write only into its own
            // declared range. Stronger than Invariant A; not adversarially
            // foolable via the revdot algebraic identity.
            check_stage_slot_range("Chain/parent StageW2", &parent_rx, 1, 1);
            check_stage_slot_range("Chain/child StageW4Child", &child_rx, 2, 2);
            // Invariant A: each stage checked against its own mask in isolation.
            if let Some(mask_reg) = MASK_REGISTRY_W2.as_ref() {
                check_stage_isolation("Chain/parent StageW2", &parent_rx, mask_reg, y);
            }
            if let Some(mask_reg) = MASK_REGISTRY_W4_CHILD.as_ref() {
                check_stage_isolation("Chain/child StageW4Child", &child_rx, mask_reg, y);
            }
            // Cross-mask discrimination (parent.rx vs child.mask and vice
            // versa) is intentionally NOT asserted here. The check
            // `rx.revdot(foreign_mask) != 0` is structurally fragile under
            // adversarial fuzzing: it reduces to a linear equation in the
            // witness and `y` (e.g.,
            // `child_a*y^(2n+2) + child_c*y^(2n+3) + child_b*y^2 + child_d*y^3 = 0`),
            // and the fuzzer readily finds (witness, y) pairs that
            // satisfy it. The canonical test at `staging/mask.rs:489` works
            // because it uses random witnesses where the probability of
            // hitting a degenerate point is `≤ deg/|F| ≈ 2^-254`; under
            // libfuzzer's coverage-guided search, that probability is
            // effectively 1. Invariant B catches any *systematic*
            // cross-stage indistinguishability via the algebraic identity,
            // so this gap is not coverage-relevant — it's specifically
            // the "this rx is structurally indistinguishable" claim that
            // can't be made on adversarial inputs.
            //
            // Invariant B (with bundled final_mask check on the bare trace):
            // StageW4Child is the chain's last stage; its final_mask covers
            // `[child_skip + child_num, R::n())`, the post-stage gate range.
            let mut stage_rx_sum = parent_rx;
            stage_rx_sum.add_assign(&child_rx);
            let Some((expected, actual)) = check_identity(
                "Chain2x4",
                registry,
                &circuit,
                witness,
                instance,
                stage_rx_sum,
                MASK_REGISTRY_W4_CHILD_FINAL.as_ref(),
                y,
                z,
            ) else {
                return;
            };
            assert_eq!(
                expected, actual,
                "Chain2x4 staging identity violated: \
                 witness={witness:?}, instance={instance:?}, y={y:?}, z={z:?}, \
                 expected_ky={expected:?}, actual_revdot={actual:?}"
            );
        }
    }
});
