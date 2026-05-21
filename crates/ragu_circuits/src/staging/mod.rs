//! Staging circuits for multi-stage witness computation.
//!
//! ## Background
//!
//! Circuits are evaluated over witnesses in Ragu by having the prover commit to
//! some polynomial $r(X)$ which [encodes the trace](crate::CircuitExt::trace),
//! and then checking to see if it satisfies the identity
//!
//! $$ \langle \kern-0.5em \langle \kern0.1em \mathbf{r}, \mathbf{r} \circ
//! \mathbf{z^{4n}} + \mathbf{s} + \mathbf{t} \kern0.1em \rangle \kern-0.5em
//! \rangle $$
//!
//! where $\mathbf{r}$ is the coefficient vector for $r(X)$, and $\mathbf{s},
//! \mathbf{t}$ are determined by $y$ and $z$ (respectively) to enforce the
//! gates and constraints (respectively) of the particular
//! circuit. We say that $\mathbf{s}$ is the coefficient vector for $s(X, Y)$ at
//! the restriction $Y = y$.
//!
//! ### Staging
//!
//! However, there are some situations where the prover would like to commit to
//! parts of their witness in one or more **stages**, and _then_ enforce the
//! combination of the stages in the above equation:
//!
//! * The prover may wish to commit to part of their witness first (which may
//!   include hundreds of allocated wires), receive a cryptographic commitment
//!   to that stage, and then apply a hash function to this succinct value to
//!   obtain a challenge value that reduces a claim about the partial trace to
//!   something that can be checked in fewer constraints.
//! * The prover may wish to have multiple circuits contain the same data (but
//!   perform different operations over it) but does not want to pay the cost of
//!   checking equivalence through instance wires.
//!
//! The solution is to decompose $r(X)$ like so:
//!
//! $$ r(X) = a(X) + b(X) + \cdots + f(X) $$
//!
//! where $a(X), b(X), \cdots$ are called _staging polynomials_ (corresponding
//! to a _stage_ of the trace) and $f(X)$ is a special "final" staging
//! polynomial that encodes the "remainder" of the wire assignment for
//! $r(X)$. The prover will commit to $a(X), b(X), \cdots$ independently, and
//! _then_ may commit to $f(X)$ and use instance wires to obtain cryptographic
//! commitments to $a(X), b(X)$ for the purpose of evaluating hash functions
//! that produce digests that are cryptographically bound to their contents.
//!
//! In order for this to work, each of the individual stages (including the
//! final stage) of the trace must be constrained to be well-formed, meaning
//! that their wire assignments cannot overlap. These well-formedness checks
//! use [bonding circuits](crate::BondingObject), whose traces can be folded
//! and checked in a single batched revdot claim.
//!
//! ## Usage
//!
//! The [`Stage`] trait allows you to define a **stage** for your multi-stage
//! wiring polynomial. Stages are (currently) designed so that they must be
//! built on top of previous stages, with the trivial `()` implementation for a
//! root stage provided by Ragu.
//!
//! ### Normal Stages
//!
//! [`StageExt::rx`] produces a staging polynomial for a given stage, given a
//! witness. The well-formedness check can be performed by applying a revdot
//! claim between the resulting [`Polynomial`](sparse::Polynomial) and the
//! stage's [staging mask](StageExt::mask).
//!
//! ```rust,ignore
//! let a = MyStage::rx(alpha, my_stage_witness)?;
//!
//! // Register the mask into a registry to obtain s(X, y).
//! let mask_handle = builder.register_bonding(MyStage::mask()?);
//! let registry = builder.finalize()?;
//!
//! let y = Fp::random(&mut rand::rng());
//! assert_eq!(a.revdot(&registry.y(mask_handle, y)), Fp::ZERO);
//! ```
//!
//! If two or more stage polynomials must satisfy the same well-formedness
//! check, they can be combined using a random challenge $z$:
//!
//! ```rust,ignore
//! let a = MyStage::rx(alpha_a, my_stage_witness)?;
//! let b = MyStage::rx(alpha_b, my_stage_witness)?;
//!
//! // Sample random challenge z after committing to `a` and `b`
//! let z = Fp::random(&mut rand::rng());
//!
//! let mut combined = a.clone();
//! combined.scale(z);
//! combined.add_assign(&b);
//!
//! let mask_handle = builder.register_bonding(MyStage::mask()?);
//! let registry = builder.finalize()?;
//!
//! let y = Fp::random(&mut rand::rng());
//! assert_eq!(combined.revdot(&registry.y(mask_handle, y)), Fp::ZERO);
//! ```
//!
//! ### Final Stage
//!
//! The [`MultiStageCircuit`] trait implements the overall circuit witness (combining all stages),
//! which is similar to the [`Circuit`] trait. The notable difference is that
//! during witness generation the circuit has access to a [`StageBuilder`] which
//! is used to load stages into the circuit synthesis according to the
//! implementation's hierarchy.
//!
//! Any implementation of [`MultiStageCircuit`] can be transformed into an
//! implementation of [`Circuit`] using the [`MultiStage`] adaptor. The resulting
//! [`StageExt::rx`] output contains the final trace polynomial $f(X)$, which
//! must be similarly checked to be well-formed using the
//! [`StageExt::final_mask`] method's staging mask (obtained from the
//! [`MultiStageCircuit::Last`] implementation).
//!
//! ### Combining the Stages
//!
//! Assuming stages are well-formed, they can be combined by merely adding them
//! together with the final staging polynomial, producing the desired $r(X)$.
//!
//! ## Gadget invariants
//!
//! Even if gadgets are fungible, any driver that modifies the wires of a
//! gadget risks breaking one of their invariants. [`Stage::witness`] only
//! guarantees to produce a gadget with the correct shape, but the prover
//! could lie and produce one that does not satisfy the invariants.
//! [`unenforced`](StageGuard::unenforced) takes the prover at their word,
//! or possibly relies on a different [`enforced`](StageGuard::enforced)
//! call to check it. [`enforced`](StageGuard::enforced) provides only the
//! guarantee that the gadget is
//! [`Consistent`](ragu_primitives::consistent::Consistent), which is only
//! implemented for gadgets that are capable of emitting constraints to
//! re-express all of their invariants.
//!
//! When called through [`StageBuilder`] (wire reservation and witness
//! computation), `Stage::witness` runs on a wireless emulator where
//! `gate`, `add`, and `enforce_zero` are all no-ops, so anything the
//! body writes to the supplied driver is discarded. During polynomial
//! extraction in [`StageExt::rx`], `Stage::witness` instead runs on a
//! wired emulator where `gate` and `add` execute to collect values;
//! `enforce_zero` is still a no-op, so any constraints the body emits
//! are still discarded.
//!
//! For the book-length version of this story, see the
//! [staging implementation chapter].
//!
//! [staging implementation chapter]: https://tachyon.z.cash/ragu/implementation/staging

pub(crate) mod bonding;
mod builder;
pub(crate) mod mask;
mod rx_driver;

use alloc::boxed::Box;

pub use builder::{StageBuilder, StageGuard};
use ff::Field;
use ragu_arithmetic::Coeff;
use ragu_core::{
    Result,
    drivers::{Driver, DriverValue, emulator::Emulator},
    gadgets::{Bound, GadgetKind},
    maybe::{Always, MaybeKind},
};
use ragu_primitives::{
    allocator::{Allocator, Standard},
    io::Write,
};
use rx_driver::RxDriver;

use crate::{
    BondingObject, Circuit, WithAux,
    polynomials::{Rank, sparse},
};

/// A partial trace component for a multi-stage circuit, producing a gadget of
/// type [`OutputKind`](Self::OutputKind) over the wires it commits to.
///
/// See the module-level [gadget invariants](self#gadget-invariants) section
/// for what `Stage` and its consumers do and do not guarantee about the
/// wires inside the produced gadget.
pub trait Stage<F: Field, R: Rank> {
    /// The parent stage for this stage. This is set to `()` for the base stage.
    type Parent: Stage<F, R>;

    /// The data needed to compute the assignment of this partial trace.
    type Witness<'source>: Send;

    /// The kind of gadget that this stage produces as output.
    ///
    /// Stage outputs are prover-internal: they carry data between stages but are
    /// not part of the circuit's public instance. The verifier never sees them.
    /// Contrast with [`MultiStageCircuit::Output`], which is the verifier-visible
    /// instance encoded into $k(Y)$.
    type OutputKind: GadgetKind<F>;

    /// Returns the number of values that are allocated in this stage.
    fn values() -> usize;

    /// Produce the stage's [`OutputKind`](Self::OutputKind) gadget and the
    /// wire values it commits to.
    ///
    /// Guarantees only the shape of the returned gadget — see the
    /// module-level [gadget invariants](self#gadget-invariants) section.
    /// The framework invokes this method only on stub drivers: a
    /// wireless emulator inside [`StageBuilder`] (where `gate`, `add`,
    /// and `enforce_zero` are all no-ops) or a wired emulator inside
    /// [`StageExt::rx`] (where `gate` and `add` execute to collect
    /// values, but `enforce_zero` remains a no-op). Either way, any
    /// constraints the body emits via `enforce_zero` are discarded.
    fn witness<'dr, 'source: 'dr, D: Driver<'dr, F = F>>(
        &self,
        dr: &mut D,
        witness: DriverValue<D, Self::Witness<'source>>,
    ) -> Result<Bound<'dr, D, Self::OutputKind>>
    where
        Self: 'dr;

    /// Returns the number of gates to skip before starting this
    /// stage. The count includes the SYSTEM gate (gate 0), so the base
    /// case `()` returns 1. **This should not be overridden by
    /// implementations except by the base implementation for `()`**.
    fn skip_gates() -> usize {
        Self::Parent::skip_gates() + Self::Parent::num_gates()
    }
}

impl<F: Field, R: Rank> Stage<F, R> for () {
    type Parent = ();
    type Witness<'source> = ();
    type OutputKind = ();

    fn values() -> usize {
        0
    }

    fn witness<'dr, 'source: 'dr, D: Driver<'dr, F = F>>(
        &self,
        _: &mut D,
        _: DriverValue<D, Self::Witness<'source>>,
    ) -> Result<Bound<'dr, D, Self::OutputKind>>
    where
        Self: 'dr,
    {
        Ok(())
    }

    fn skip_gates() -> usize {
        1
    }
}

/// Represents an actual circuit (much like a [`Circuit`]) with portions of its
/// witness computed in stages.
pub trait MultiStageCircuit<F: Field, R: Rank>: Sized + Send + Sync {
    /// The last explicitly defined stage of this multi-stage circuit.
    ///
    /// The trace polynomial has the form `r(X) = r'(X) + a(X) + b(X) + ...`
    /// where `a(X), b(X), ...` are stage polynomials (defined via [`Stage`],
    /// independently committable) and `r'(X)` is the "final" witness.
    ///
    /// `Last` is the final polynomial in the `a(X), b(X), ...` sequence. The "final"
    /// witness `r'(X)` is computed implicitly in [`witness`](Self::witness), which
    /// consumes outputs from all stage polynomials.
    type Last: Stage<F, R>;

    /// The type of data that is needed to construct the expected output of this
    /// circuit.
    type Instance<'source>: Send;

    /// The type of data that is needed to compute a satisfying witness for this
    /// circuit.
    type Witness<'source>: Send;

    /// The circuit's public instance, serialized into the $k(Y)$ instance
    /// polynomial that the verifier checks.
    ///
    /// Contrast with [`Stage::OutputKind`], which carries prover-internal data
    /// between stages.
    type Output: Write<F>;

    /// Auxiliary data produced during the computation of the
    /// [`witness`](MultiStageCircuit::witness) method that may be useful, such as
    /// interstitial witness material that is needed for future synthesis.
    type Aux<'source>: Send;

    /// Given an instance type for this circuit, use the provided [`Driver`] to
    /// return a `Self::Output` gadget that the _some_ corresponding witness
    /// should have produced as a result of the
    /// [`witness`](MultiStageCircuit::witness) method. This can be seen as
    /// "short-circuiting" the computation involving the witness, which a
    /// verifier would not have in its possession.
    fn instance<'dr, 'source: 'dr, D: Driver<'dr, F = F>>(
        &self,
        dr: &mut D,
        instance: DriverValue<D, Self::Instance<'source>>,
    ) -> Result<Bound<'dr, D, Self::Output>>
    where
        Self: 'dr;

    /// Given a witness type for this circuit, perform a computation using the
    /// provided [`Driver`] and return the `Self::Output` gadget that the
    /// verifier's instance should produce as a result of the
    /// [`instance`](MultiStageCircuit::instance) method.
    fn witness<'a, 'dr, 'source: 'dr, D: Driver<'dr, F = F>>(
        &self,
        dr: StageBuilder<'a, 'dr, D, R, (), Self::Last>,
        witness: DriverValue<D, Self::Witness<'source>>,
    ) -> Result<WithAux<Bound<'dr, D, Self::Output>, DriverValue<D, Self::Aux<'source>>>>
    where
        Self: 'dr;
}

/// Wrapper type that implements [`Circuit`] for a given [`MultiStageCircuit`].
pub struct MultiStage<F: Field, R: Rank, S: MultiStageCircuit<F, R>> {
    circuit: S,
    _marker: core::marker::PhantomData<(F, R)>,
}

impl<F: Field, R: Rank, S: MultiStageCircuit<F, R> + Clone> Clone for MultiStage<F, R, S> {
    fn clone(&self) -> Self {
        MultiStage {
            circuit: self.circuit.clone(),
            _marker: core::marker::PhantomData,
        }
    }
}

impl<F: Field, R: Rank, S: MultiStageCircuit<F, R>> MultiStage<F, R, S> {
    /// Creates a new [`Circuit`] implementation from the given staged
    /// `circuit`.
    pub fn new(circuit: S) -> Self {
        MultiStage {
            circuit,
            _marker: core::marker::PhantomData,
        }
    }

    /// Proxy for [`S::Last::final_mask`](StageExt::final_mask).
    pub fn final_mask<'a>(&self) -> Result<BondingObject<'a, F, R>> {
        S::Last::final_mask()
    }
}

impl<F: Field, R: Rank, S: MultiStageCircuit<F, R>> Circuit<F> for MultiStage<F, R, S> {
    type Instance<'source> = S::Instance<'source>;
    type Witness<'source> = S::Witness<'source>;
    type Output = S::Output;
    type Aux<'source> = S::Aux<'source>;

    fn instance<'dr, 'source: 'dr, D: Driver<'dr, F = F>>(
        &self,
        dr: &mut D,
        instance: DriverValue<D, S::Instance<'source>>,
    ) -> Result<Bound<'dr, D, Self::Output>>
    where
        Self: 'dr,
    {
        self.circuit.instance(dr, instance)
    }

    fn witness<'dr, 'source: 'dr, D: Driver<'dr, F = F>>(
        &self,
        dr: &mut D,
        witness: DriverValue<D, S::Witness<'source>>,
    ) -> Result<WithAux<Bound<'dr, D, Self::Output>, DriverValue<D, S::Aux<'source>>>>
    where
        Self: 'dr,
    {
        self.circuit.witness(StageBuilder::new(dr, |_| {}), witness)
    }
}

/// Extension trait blanket-implemented for all [`Stage<F, R>`](Stage) types.
pub trait StageExt<F: Field, R: Rank>: Stage<F, R> {
    /// Returns the number of gates used for allocations.
    fn num_gates() -> usize {
        Self::values().div_ceil(2)
    }

    /// Compute the (partial) $r(X)$ polynomial for this stage.
    ///
    /// `alpha` is placed at `a[0]` of the resulting polynomial. Stages
    /// have no ONE wire, so without alpha a stage trace could be all-zero;
    /// and any predictable wire slot can cancel in linear combinations of
    /// stage polynomials — either case produces a point-at-infinity
    /// commitment. A random alpha at `a[0]` prevents both.
    ///
    /// Pass a random field element in production; `F::ZERO` is acceptable
    /// in tests.
    fn rx_configured(
        &self,
        alpha: F,
        witness: Self::Witness<'_>,
    ) -> Result<sparse::Polynomial<F, R>> {
        let values = {
            let mut dr = Emulator::extractor();
            let out = self.witness(&mut dr, Always::maybe_just(|| witness))?;
            dr.wires(&out)?
        };

        if values.len() > Self::values() {
            return Err(ragu_core::Error::GateBoundExceeded {
                limit: Self::num_gates(),
            });
        }

        let mut dr = RxDriver::<F, R>::with_capacity(Self::skip_gates() + Self::num_gates());
        let mut allocator = Standard::default();

        // SYSTEM gate: alpha at a[0], 0 at d[0].
        allocator.alloc(&mut dr, || Ok(Coeff::Arbitrary(alpha)))?;
        allocator.alloc(&mut dr, || Ok(Coeff::Zero))?;

        // Skip gates 1..skip_gates: two zero allocs each.
        for _ in 0..(2 * (Self::skip_gates() - 1)) {
            allocator.alloc(&mut dr, || Ok(Coeff::Zero))?;
        }

        // Data values, padded with zeros to fill all stage slots.
        for value in &values {
            allocator.alloc(&mut dr, || Ok(Coeff::Arbitrary(*value)))?;
        }
        for _ in values.len()..Self::values() {
            allocator.alloc(&mut dr, || Ok(Coeff::Zero))?;
        }

        Ok(dr.build())
    }

    /// Compute the (partial) $r(X)$ polynomial for this stage, using a
    /// default implementation. See [`rx_configured`](Self::rx_configured)
    /// for details on the `alpha` parameter.
    fn rx(alpha: F, witness: Self::Witness<'_>) -> Result<sparse::Polynomial<F, R>>
    where
        Self: Default,
    {
        Self::default().rx_configured(alpha, witness)
    }

    /// Creates a bonding polynomial that enforces well-formedness checks on
    /// this stage's partial trace.
    ///
    /// Staging circuits do not behave like normal circuits because their
    /// SYSTEM gate carries only an alpha value in `a[0]` (no `d[0] = 1`
    /// ONE wire) and they are used solely for partial trace commitments.
    /// As a result, their mask must be computed differently.
    fn mask<'a>() -> Result<BondingObject<'a, F, R>> {
        Ok(BondingObject::new(Box::new(mask::StageMask::new(
            Self::skip_gates(),
            Self::num_gates(),
        )?)))
    }

    /// Creates a bonding polynomial that can be used to enforce well-formedness
    /// checks on any final trace (stage) that has this stage as its
    /// [`MultiStageCircuit::Last`] stage.
    fn final_mask<'a>() -> Result<BondingObject<'a, F, R>> {
        Ok(BondingObject::new(Box::new(mask::StageMask::new_final(
            Self::skip_gates() + Self::num_gates(),
        )?)))
    }

    /// Returns the generator index for the i-th first-value coefficient of
    /// this stage's alloc gates.
    ///
    /// With the `(a, 0, 0, d)` gate layout, the first allocated value occupies
    /// the $a$-wire position at degree
    /// $2n - 1 - \text{skip\_gates} - \text{coefficient\_index}$.
    fn generator_index_for_a(coefficient_index: usize) -> usize {
        assert!(
            coefficient_index < Self::num_gates(),
            "coefficient_index {} exceeds num_gates {}",
            coefficient_index,
            Self::num_gates()
        );

        2 * R::n() - 1 - Self::skip_gates() - coefficient_index
    }
}

impl<F: Field, R: Rank, S: Stage<F, R>> StageExt<F, R> for S {}
