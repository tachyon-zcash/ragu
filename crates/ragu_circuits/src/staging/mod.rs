//! Tools for creating multi-stage circuits with partial witness commitments.

use ff::Field;
use ragu_core::{
    Result,
    drivers::{Driver, Simulator, Witness},
    gadgets::GadgetKind,
};
use ragu_primitives::serialize::GadgetSerialize;

use alloc::boxed::Box;

use crate::{
    Circuit, CircuitObject,
    polynomials::{Rank, structured},
};

mod builder;
mod extractor;
mod object;

pub use builder::StageBuilder;

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
        dr: &mut D,
        witness: Witness<D, Self::Witness<'source>>,
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
        _: &mut D,
        _: Witness<D, Self::Witness<'source>>,
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
pub trait StagedCircuit<F: Field, R: Rank>: Sized + Send + Sync {
    /// The final stage of this staged circuit.
    type Final: Stage<F, R>;

    /// The type of data that is needed to construct the expected output of this
    /// circuit.
    type Instance<'source>: Send;

    /// The type of data that is needed to compute a satisfying witness for this
    /// circuit.
    type Witness<'source>: Send;

    /// Represents the output of a circuit computation which can be serialized.
    type Output: GadgetSerialize<F>;

    /// Auxillary data produced during the computation of the
    /// [`witness`](StagedCircuit::witness) method that may be useful, such as
    /// interstitial witness material that is needed for future synthesis.
    type Aux<'source>: Send;

    /// Given an instance type for this circuit, use the provided [`Driver`] to
    /// return a `Self::Output` gadget that the _some_ corresponding witness
    /// should have produced as a result of the
    /// [`witness`](StagedCircuit::witness) method. This can be seen as
    /// "short-circuiting" the computation involving the witness, which a
    /// verifier would not have in its possession.
    fn instance<'dr, 'source: 'dr, D: Driver<'dr, F = F>>(
        &self,
        dr: &mut D,
        instance: Witness<D, Self::Instance<'source>>,
    ) -> Result<<Self::Output as GadgetKind<F>>::Rebind<'dr, D>>;

    /// Given a witness type for this circuit, perform a computation using the
    /// provided [`Driver`] and return the `Self::Output` gadget that the
    /// verifier's instance should produce as a result of the
    /// [`instance`](StagedCircuit::instance) method.
    fn witness<'a, 'dr, 'source: 'dr, D: Driver<'dr, F = F>>(
        &self,
        dr: StageBuilder<'a, 'dr, D, R, (), Self::Final>,
        witness: Witness<D, Self::Witness<'source>>,
    ) -> Result<(
        <Self::Output as GadgetKind<F>>::Rebind<'dr, D>,
        Witness<D, Self::Aux<'source>>,
    )>;
}

/// Wrapper type that implements [`Circuit`] for a given [`StagedCircuit`].
pub struct Staged<F: Field, R: Rank, S: StagedCircuit<F, R>> {
    circuit: S,
    _marker: core::marker::PhantomData<(F, R)>,
}

impl<F: Field, R: Rank, S: StagedCircuit<F, R> + Clone> Clone for Staged<F, R, S> {
    fn clone(&self) -> Self {
        Staged {
            circuit: self.circuit.clone(),
            _marker: core::marker::PhantomData,
        }
    }
}

impl<F: Field, R: Rank, S: StagedCircuit<F, R>> Staged<F, R, S> {
    /// Creates a new [`Circuit`] implementation from the given staged
    /// `circuit`.
    pub fn new(circuit: S) -> Self {
        Staged {
            circuit,
            _marker: core::marker::PhantomData,
        }
    }
}

impl<F: Field, R: Rank, S: StagedCircuit<F, R>> Circuit<F> for Staged<F, R, S> {
    type Instance<'source> = S::Instance<'source>;
    type Witness<'source> = S::Witness<'source>;
    type Output = S::Output;
    type Aux<'source> = S::Aux<'source>;

    fn instance<'dr, 'source: 'dr, D: Driver<'dr, F = F>>(
        &self,
        dr: &mut D,
        instance: Witness<D, S::Instance<'source>>,
    ) -> Result<<Self::Output as GadgetKind<F>>::Rebind<'dr, D>> {
        self.circuit.instance(dr, instance)
    }

    fn witness<'dr, 'source: 'dr, D: Driver<'dr, F = F>>(
        &self,
        dr: &mut D,
        witness: Witness<D, S::Witness<'source>>,
    ) -> Result<(
        <Self::Output as GadgetKind<F>>::Rebind<'dr, D>,
        Witness<D, S::Aux<'source>>,
    )> {
        self.circuit.witness(StageBuilder::new(dr), witness)
    }
}

/// Extension traits for staging circuits.
pub trait StageExt<F: Field, R: Rank>: Stage<F, R> {
    /// Returns the number of multiplication gates used for allocations.
    fn num_multiplications() -> usize {
        (Self::values() + 1) / 2
    }

    /// Compute the (partial) witness polynomial $r(X)$ for this stage.
    fn rx(witness: Self::Witness<'_>) -> Result<structured::Polynomial<F, R>> {
        let values = {
            // TODO(ebfull): This simulator checks multiplication and linear
            // constraints are satisfied, but we just need the wire values.
            // Perhaps we need something other than a Simulator, or we need the
            // Simulator to be more configurable.
            let mut out = None;
            Simulator::simulate(witness, |dr, witness| {
                out = Some(Self::witness(dr, witness)?);

                Ok(())
            })?;
            extractor::wires(&out.unwrap())?
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

    /// Converts this staging circuit into a circuit object.
    ///
    /// Staging circuits do not behave like normal circuits because they do not
    /// have a `ONE` wire and are used solely for partial witness commitments.
    /// As a result, they must be computed differently.
    fn into_object<'a>() -> Result<Box<dyn CircuitObject<F, R> + 'a>> {
        Ok(Box::new(object::StageObject::new(
            Self::skip_multiplications(),
            Self::num_multiplications(),
        )?))
    }

    /// Creates a staging circuit a final stage that has this stage as its
    /// parent.
    fn final_into_object<'a>() -> Result<Box<dyn CircuitObject<F, R> + 'a>> {
        Ok(Box::new(object::StageObject::new_max(
            Self::skip_multiplications() + Self::num_multiplications(),
        )?))
    }
}

impl<F: Field, R: Rank, S: Stage<F, R>> StageExt<F, R> for S {}
