//! Polynomial processor for the nested claim order.
use alloc::borrow::Cow;

use ragu_circuits::polynomials::{Rank, sparse};
use ragu_core::Result;
use udon::field::Field;

use crate::{
    profile::Profile,
    protocol::{
        claims::sum_polynomials,
        nested::{InternalCircuitIndex, claims::Processor},
    },
    prover::claims::Builder,
};
impl<'m, 'rx, P: Profile, F: Field, R: Rank, B: ragu_backend::Backend>
    Processor<P, &'rx sparse::Polynomial<F, R>>
    for Builder<'m, 'rx, Cow<'rx, sparse::Polynomial<F, R>>, F, R, B>
{
    fn raw_claim(&mut self, a: &'rx sparse::Polynomial<F, R>, b: &'rx sparse::Polynomial<F, R>) {
        self.a.push(Cow::Borrowed(a));
        self.b.push(Cow::Borrowed(b));
    }

    fn internal_circuit_claim(
        &mut self,
        id: InternalCircuitIndex,
        rxs: impl Iterator<Item = &'rx sparse::Polynomial<F, R>>,
    ) {
        let circuit_id = id.circuit_index::<P>();
        let rx = sum_polynomials(rxs);
        self.circuit_impl(circuit_id, rx);
    }

    fn grouped_bonding_claim(
        &mut self,
        id: InternalCircuitIndex,
        groups: impl Iterator<Item = impl Iterator<Item = &'rx sparse::Polynomial<F, R>>>,
    ) -> Result<()> {
        let circuit_id = id.circuit_index::<P>();
        let folded = self.fold_bonding_groups(groups);
        self.bonding_impl(circuit_id, folded);
        Ok(())
    }
}
