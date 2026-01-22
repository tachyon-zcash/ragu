//! Staging circuits for multi-stage witness computation.
//!
//! ## Background
//!
//! Circuits are evaluated over witnesses in Ragu by having the prover commit to
//! some polynomial $r(X)$ which [encodes their witness](crate::CircuitExt::rx),
//! and then checking to see if it satisfies the identity
//!
//! $$ \langle \kern-0.5em \langle \kern0.1em \mathbf{r}, \mathbf{r} \circ
//! \mathbf{z^{4n}} + \mathbf{s} + \mathbf{t} \kern0.1em \rangle \kern-0.5em
//! \rangle $$
//!
//! where $\mathbf{r}$ is the coefficient vector for $r(X)$, and $\mathbf{s},
//! \mathbf{t}$ are determined by $y$ and $z$ (respectively) to enforce the
//! linear and multiplication constraints (respectively) of the particular
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
//!   obtain a challenge value that reduces a claim about the partial witness to
//!   something that can be checked in fewer constraints.
//! * The prover may wish to have multiple circuits contain the same data (but
//!   perform different operations over it) but does not want to pay the cost of
//!   using public inputs to check that they are equivalent.
//!
//! The solution is to decompose $r(X)$ like so:
//!
//! $$ r(X) = a(X) + b(X) + \cdots + f(X) $$
//!
//! where $a(X), b(X), \cdots$ are called _staging polynomials_ (corresponding
//! to a _stage_ of the witness) and $f(X)$ is a special "final" staging
//! polynomial that encodes the "remainder" of the witness assignment for
//! $r(X)$. The prover will commit to $a(X), b(X), \cdots$ independently, and
//! _then_ may commit to $f(X)$ and use public inputs to obtain cryptographic
//! commitments to $a(X), b(X)$ for the purpose of evaluating hash functions
//! that produce digests that are cryptographically bound to their contents.
//!
//! In order for this to work, each of the individual stages (including the
//! final stage) of the witness must be constrained to be well-formed, meaning
//! that their wire assignments cannot overlap. Some of these checks can be
//! batched efficiently because well-formedness checks of the kind we need are
//! highly linearized.
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
//! claim between the resulting [`Polynomial`](structured::Polynomial) and the
//! stage's [staging mask](StageExt::mask).
//!
//! ```rust,ignore
//! let a = MyStage::rx(my_stage_witness)?;
//!
//! let mask = MyStage::mask()?;
//! let y = Fp::random(thread_rng());
//! let registry_key = Fp::random(thread_rng());
//! assert_eq!(a.revdot(&mask.sy(y, registry_key)), Fp::ZERO);
//! ```
//!
//! If two or more stage polynomials must satisfy the same well-formedness
//! check, they can be combined using a random challenge $z$:
//!
//! ```rust,ignore
//! let a = MyStage::rx(my_stage_witness)?;
//! let b = MyStage::rx(my_stage_witness)?;
//!
//! // Sample random challenge z after committing to `a` and `b`
//! let z = Fp::random(thread_rng());
//!
//! let mut combined = a.clone();
//! combined.scale(z);
//! combined.add_assign(&b);
//!
//! let mask = MyStage::mask()?;
//! let y = Fp::random(thread_rng());
//! let registry_key = Fp::random(thread_rng());
//! assert_eq!(combined.revdot(&mask.sy(y, registry_key)), Fp::ZERO);
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
//! [`StageExt::rx`] output contains the final witness polynomial $f(X)$, which
//! must be similarly checked to be well-formed using the
//! [`StageExt::final_mask`] method's staging mask (obtained from the
//! [`MultiStageCircuit::Final`] implementation).
//!
//! ### Combining the Stages
//!
//! Assuming stages are well-formed, they can be combined by merely adding them
//! together with the final staging polynomial, producing the desired $r(X)$.

mod builder;
mod mask;

use ff::Field;
use ragu_core::{
    Result,
    drivers::{Driver, DriverValue, emulator::Emulator},
    gadgets::GadgetKind,
    maybe::{Always, MaybeKind},
};
use ragu_primitives::io::Write;

use alloc::boxed::Box;

use crate::{
    Circuit, CircuitObject,
    polynomials::{Rank, structured},
};

pub use builder::{StageBuilder, StageGuard};

/// Represents a partial witness component for a multi-stage circuit.
pub trait Stage<F: Field, R: Rank> {
    /// The parent stage for this stage. This is set to `()` for the base stage.
    type Parent: Stage<F, R>;

    /// The data needed to compute the assignment of this partial witness.
    type Witness<'source>: Send;

    /// The kind of gadget that this stage produces as output.
    type OutputKind: GadgetKind<F>;

    /// Returns the number of values that are allocated in this stage.
    fn values() -> usize;

    /// Computes the witness for this stage.
    fn witness<'dr, 'source: 'dr, D: Driver<'dr, F = F>>(
        &self,
        dr: &mut D,
        witness: DriverValue<D, Self::Witness<'source>>,
    ) -> Result<<Self::OutputKind as GadgetKind<F>>::Rebind<'dr, D>>
    where
        Self: 'dr;

    /// Returns the number of multiplication gates to skip before starting this
    /// stage, not including the ONE gate which is skipped in all stages. **This
    /// should not be overridden by implementations except by the base
    /// implementation for `()`**.
    fn skip_multiplications() -> usize {
        Self::Parent::skip_multiplications() + Self::Parent::num_multiplications()
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
    ) -> Result<<Self::OutputKind as GadgetKind<F>>::Rebind<'dr, D>>
    where
        Self: 'dr,
    {
        Ok(())
    }

    fn skip_multiplications() -> usize {
        0
    }
}

/// Represents an actual circuit (much like a [`Circuit`]) with portions of its
/// witness computed in stages.
pub trait MultiStageCircuit<F: Field, R: Rank>: Sized + Send + Sync {
    /// The final stage of this multi-stage circuit.
    type Final: Stage<F, R>;

    /// The type of data that is needed to construct the expected output of this
    /// circuit.
    type Instance<'source>: Send;

    /// The type of data that is needed to compute a satisfying witness for this
    /// circuit.
    type Witness<'source>: Send;

    /// Represents the output of a circuit computation which can be serialized.
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
    ) -> Result<<Self::Output as GadgetKind<F>>::Rebind<'dr, D>>
    where
        Self: 'dr;

    /// Given a witness type for this circuit, perform a computation using the
    /// provided [`Driver`] and return the `Self::Output` gadget that the
    /// verifier's instance should produce as a result of the
    /// [`instance`](MultiStageCircuit::instance) method.
    fn witness<'a, 'dr, 'source: 'dr, D: Driver<'dr, F = F>>(
        &self,
        dr: StageBuilder<'a, 'dr, D, R, (), Self::Final>,
        witness: DriverValue<D, Self::Witness<'source>>,
    ) -> Result<(
        <Self::Output as GadgetKind<F>>::Rebind<'dr, D>,
        DriverValue<D, Self::Aux<'source>>,
    )>
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

    /// Proxy for [`S::Final::final_mask`](StageExt::final_mask).
    pub fn final_mask<'a>(&self) -> Result<Box<dyn CircuitObject<F, R> + 'a>> {
        S::Final::final_mask()
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
    ) -> Result<<Self::Output as GadgetKind<F>>::Rebind<'dr, D>>
    where
        Self: 'dr,
    {
        self.circuit.instance(dr, instance)
    }

    fn witness<'dr, 'source: 'dr, D: Driver<'dr, F = F>>(
        &self,
        dr: &mut D,
        witness: DriverValue<D, S::Witness<'source>>,
    ) -> Result<(
        <Self::Output as GadgetKind<F>>::Rebind<'dr, D>,
        DriverValue<D, S::Aux<'source>>,
    )>
    where
        Self: 'dr,
    {
        self.circuit.witness(StageBuilder::new(dr), witness)
    }
}

/// Extension traits for staging circuits.
pub trait StageExt<F: Field, R: Rank>: Stage<F, R> {
    /// Returns the number of multiplication gates used for allocations.
    fn num_multiplications() -> usize {
        Self::values().div_ceil(2)
    }

    /// Compute the (partial) witness polynomial $r(X)$ for this stage.
    fn rx_configured(&self, witness: Self::Witness<'_>) -> Result<structured::Polynomial<F, R>> {
        let values = {
            let mut dr = Emulator::extractor();
            let out = self.witness(&mut dr, Always::maybe_just(|| witness))?;
            dr.wires(&out)?
        };

        if values.len() > Self::values() {
            return Err(ragu_core::Error::MultiplicationBoundExceeded(
                Self::num_multiplications(),
            ));
        }

        assert!(values.len() <= Self::values());

        let mut values = values.into_iter();
        let mut rx = structured::Polynomial::new();
        {
            let rx = rx.forward();

            // ONE is not set.
            rx.a.push(F::ZERO);
            rx.b.push(F::ZERO);
            rx.c.push(F::ZERO);

            for _ in 0..Self::skip_multiplications() {
                rx.a.push(F::ZERO);
                rx.b.push(F::ZERO);
                rx.c.push(F::ZERO);
            }

            for _ in 0..Self::num_multiplications() {
                let a = values.next().unwrap_or(F::ZERO);
                let b = values.next().unwrap_or(F::ZERO);
                rx.a.push(a);
                rx.b.push(b);
                rx.c.push(a * b);
            }
        }

        Ok(rx)
    }

    /// Compute the (partial) witness polynomial $r(X)$ for this stage, using a
    /// default implementation.
    fn rx(witness: Self::Witness<'_>) -> Result<structured::Polynomial<F, R>>
    where
        Self: Default,
    {
        Self::default().rx_configured(witness)
    }

    /// Converts this stage into a circuit object that _only_ enforces
    /// well-formedness checks on the stage.
    ///
    /// Staging circuits do not behave like normal circuits because they do not
    /// have a `ONE` wire and are used solely for partial witness commitments.
    /// As a result, they must be computed differently.
    fn mask<'a>() -> Result<Box<dyn CircuitObject<F, R> + 'a>> {
        Ok(Box::new(mask::StageMask::new(
            Self::skip_multiplications(),
            Self::num_multiplications(),
        )?))
    }

    /// Creates a circuit object that can be used to enforce well-formedness
    /// checks on any final witness (stage) that has this stage as its
    /// [`MultiStageCircuit::Final`] stage.
    fn final_mask<'a>() -> Result<Box<dyn CircuitObject<F, R> + 'a>> {
        Ok(Box::new(mask::StageMask::new_final(
            Self::skip_multiplications() + Self::num_multiplications(),
        )?))
    }
}

impl<F: Field, R: Rank, S: Stage<F, R>> StageExt<F, R> for S {}
