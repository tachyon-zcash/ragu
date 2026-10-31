//! Native circuit reading a child's hook region out of its application stage.
//!
//! ## Operations
//!
//! A step's hooks land in the hook region at the head of its proof's
//! application stage (see [`Adapter`]): each witnessed polynomial's handle,
//! then each poly-query's handle, `x` and `y`. The step circuit binds those
//! wires to the stage, and the stage's commitment binds the stage polynomial.
//! The parent fuse that discharges the poly-queries works from its own copy
//! of them in the [`preamble`], so something has to tie that copy to the
//! child's stage, or the parent could discharge openings the child's step
//! never recorded.
//!
//! This circuit is that tie. It reserves the same block the step circuits
//! reserve and exposes the hook region's wires, in staging order, as its
//! public outputs. It has no trace of its own: its claim is over the child's
//! application stage polynomial alone, against the $k(Y)$ the parent computes
//! from its preamble copy ([`ProofInputs::hooks_ky`]). The claim holds only
//! if the copy equals what the stage holds. The stage's own mask keeps the
//! polynomial in its block.
//!
//! Only a profile whose steps witness polynomials registers it (see
//! [`reads_hooks`]); every other profile's registry is unchanged.
//!
//! ## Instance
//!
//! The hook region, highest degree first. The stage polynomial carries no
//! `ONE` wire, so the term that is the constant $1$ in every other circuit's
//! $k(Y)$ is zero here.
//!
//! [`Adapter`]: crate::step::internal::adapter::Adapter
//! [`preamble`]: super::super::stages::preamble
//! [`ProofInputs::hooks_ky`]: super::super::stages::preamble::ProofInputs::hooks_ky
//! [`reads_hooks`]: super::super::reads_hooks

use alloc::vec::Vec;
use core::marker::PhantomData;

use ragu_circuits::{WithAux, staging};
use ragu_core::{
    Coeff, Result,
    drivers::{Driver, DriverValue},
    gadgets::{Bound, Kind},
    maybe::Maybe,
};
use ragu_primitives::{
    Element,
    allocator::{Allocator, Standard},
    vec::{FixedVec, Len},
};
use udon::field::Field;

use crate::{framework_hooks::HookLayout, profile::Profile};

/// The hook region's length in profile `P`, in stage values.
pub struct HookRegionLen<P>(PhantomData<P>);

impl<P: Profile> Len for HookRegionLen<P> {
    fn len() -> usize {
        HookLayout::of::<P>().poly_query_instance_len()
    }
}

/// The hook-region reader over an application stage of `stage_size` values.
pub struct Circuit<P> {
    stage_size: usize,
    _marker: PhantomData<P>,
}

impl<P: Profile> Circuit<P> {
    pub fn new(stage_size: usize) -> Self {
        Circuit {
            stage_size,
            _marker: PhantomData,
        }
    }
}

impl<F: Field, P: Profile> ragu_circuits::Circuit<F> for Circuit<P> {
    type Instance<'source> = &'source [F];
    type Witness<'source> = &'source [F];
    type Output = Kind![F; FixedVec<Element<'_, _>, HookRegionLen<P>>];
    type Aux<'source> = ();

    fn instance<'dr, 'source: 'dr, D: Driver<'dr, F = F>>(
        &self,
        _: &mut D,
        _: DriverValue<D, Self::Instance<'source>>,
    ) -> Result<Bound<'dr, D, Self::Output>> {
        unreachable!("instance for internal circuits is not invoked")
    }

    fn witness<'dr, 'source: 'dr, D: Driver<'dr, F = F>>(
        &self,
        dr: &mut D,
        witness: DriverValue<D, Self::Witness<'source>>,
    ) -> Result<WithAux<Bound<'dr, D, Self::Output>, DriverValue<D, ()>>>
    where
        Self: 'dr,
    {
        // Reserve the block exactly as the adapter does, so the wires line up
        // with the stage's values; only the hook region is exposed.
        let hook_len = HookRegionLen::<P>::len();
        let allocator = &mut Standard::new();
        let mut hooks = Vec::with_capacity(hook_len);
        for i in 0..2 * staging::stage_gates(self.stage_size) {
            let wire = allocator.alloc(dr, || Ok(Coeff::Zero))?;
            if i < hook_len {
                hooks.push(Element::promote(wire, witness.as_ref().map(|w| w[i])));
            }
        }
        Ok(WithAux::new(FixedVec::try_from(hooks)?, D::unit()))
    }
}

#[cfg(test)]
mod tests {
    use ragu_circuits::{
        polynomials::{ProductionRank, Rank},
        registry::{CircuitIndex, RegistryBuilder},
    };
    use ragu_core::pasta::Fp;

    use super::*;
    use crate::AppHooks;

    type R = ProductionRank;
    /// A handle and one poly-query: `2 + (2 + 2)` hook values.
    type Hooks = AppHooks<1, 1>;

    /// The claim [`build`](crate::internal::native::claims::build) makes with
    /// this circuit over a stage polynomial: $\text{revdot}(r, r \circ z +
    /// s_y + t_z)$, whose target is the reader's $k(y)$.
    fn claim(stage_size: usize, stage: &[Fp], alpha: Fp, y: Fp, z: Fp) -> Result<Fp> {
        let registry = RegistryBuilder::<Fp, R>::new()
            .register_circuit(Circuit::<Hooks>::new(stage_size))?
            .finalize()?;
        let rx = staging::stage_rx::<_, R>(alpha, 1, stage_size, stage)?;
        let mut b = rx.clone();
        b.dilate(z);
        b.add_assign(&registry.circuit_y(CircuitIndex::new(0), y));
        b.add_assign(&R::tz(z));
        Ok(rx.revdot(&b))
    }

    /// The target the parent computes from its copy of the hook region:
    /// Horner over the values, then a zero where other circuits have `ONE`.
    fn target(hooks: &[Fp], y: Fp) -> Fp {
        hooks.iter().fold(Fp::ZERO, |acc, v| acc * y + v) * y
    }

    /// The claim holds against the hook region the stage holds, whatever the
    /// stage's blinding and whatever the step's own `Shared` values after the
    /// region, and fails against any other.
    #[test]
    fn the_claim_binds_the_hook_region() -> Result<()> {
        let hook_len = HookRegionLen::<Hooks>::len();
        assert_eq!(hook_len, 6);
        let staged: Vec<Fp> = (1..=hook_len as u64).map(Fp::from).collect();
        // The step's own shared gadget, after the hook region, odd-sized so
        // the block ends in a padding wire.
        let shared = [Fp::from(70u64), Fp::from(71u64), Fp::from(72u64)];
        let stage_size = hook_len + shared.len();
        let stage = [staged.as_slice(), &shared].concat();

        let (y, z) = (Fp::from(17u64), Fp::from(23u64));
        for alpha in [Fp::ZERO, Fp::from(11u64)] {
            let claim = claim(stage_size, &stage, alpha, y, z)?;
            assert_eq!(claim, target(&staged, y));
            for i in 0..hook_len {
                let mut forged = staged.clone();
                forged[i] += Fp::ONE;
                assert_ne!(claim, target(&forged, y), "hook value {i}");
            }
        }

        // A stage holding other hooks fails the parent's target.
        let mut other = stage.clone();
        other[0] = Fp::from(99u64);
        assert_ne!(
            claim(stage_size, &other, Fp::ONE, y, z)?,
            target(&staged, y)
        );
        Ok(())
    }
}
