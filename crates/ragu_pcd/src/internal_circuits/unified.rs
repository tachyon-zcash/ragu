//! Unified instance/output interface
//!
//! Many internal circuits involved in the core protocol will share a common set
//! of public inputs so that k(Y) does not need to be evaluated many times, and
//! to make it easier to reconfigure the roles of individual circuits later.

use arithmetic::Cycle;
use ragu_circuits::polynomials::Rank;
use ragu_core::{
    Result,
    drivers::{Driver, DriverValue},
    gadgets::{Gadget, GadgetKind, Kind},
    maybe::Maybe,
};
use ragu_primitives::{Element, Point, io::Write};

use crate::{components::suffix::Suffix, proof::Proof};

#[allow(type_alias_bounds)]
pub type InternalOutputKind<C: Cycle> = Kind![C::CircuitField; Suffix<'_, _, Output<'_, _, C>>];

/// The number of wires in an `Output` gadget.
pub const NUM_WIRES: usize = 28;

#[derive(Gadget, Write)]
pub struct Output<'dr, D: Driver<'dr>, C: Cycle> {
    #[ragu(gadget)]
    pub nested_preamble_commitment: Point<'dr, D, C::NestedCurve>,
    #[ragu(gadget)]
    pub w: Element<'dr, D>,
    #[ragu(gadget)]
    pub nested_s_prime_commitment: Point<'dr, D, C::NestedCurve>,
    #[ragu(gadget)]
    pub y: Element<'dr, D>,
    #[ragu(gadget)]
    pub z: Element<'dr, D>,
    #[ragu(gadget)]
    pub nested_error_m_commitment: Point<'dr, D, C::NestedCurve>,
    #[ragu(gadget)]
    pub mu: Element<'dr, D>,
    #[ragu(gadget)]
    pub nu: Element<'dr, D>,
    #[ragu(gadget)]
    pub nested_error_n_commitment: Point<'dr, D, C::NestedCurve>,
    #[ragu(gadget)]
    pub mu_prime: Element<'dr, D>,
    #[ragu(gadget)]
    pub nu_prime: Element<'dr, D>,
    #[ragu(gadget)]
    pub c: Element<'dr, D>,
    #[ragu(gadget)]
    pub nested_ab_commitment: Point<'dr, D, C::NestedCurve>,
    #[ragu(gadget)]
    pub x: Element<'dr, D>,
    #[ragu(gadget)]
    pub nested_query_commitment: Point<'dr, D, C::NestedCurve>,
    #[ragu(gadget)]
    pub alpha: Element<'dr, D>,
    #[ragu(gadget)]
    pub nested_f_commitment: Point<'dr, D, C::NestedCurve>,
    #[ragu(gadget)]
    pub u: Element<'dr, D>,
    #[ragu(gadget)]
    pub nested_eval_commitment: Point<'dr, D, C::NestedCurve>,
    #[ragu(gadget)]
    pub beta: Element<'dr, D>,
}

pub struct Instance<C: Cycle> {
    pub nested_preamble_commitment: C::NestedCurve,
    pub w: C::CircuitField,
    pub nested_s_prime_commitment: C::NestedCurve,
    pub y: C::CircuitField,
    pub z: C::CircuitField,
    pub nested_error_m_commitment: C::NestedCurve,
    pub mu: C::CircuitField,
    pub nu: C::CircuitField,
    pub nested_error_n_commitment: C::NestedCurve,
    pub mu_prime: C::CircuitField,
    pub nu_prime: C::CircuitField,
    pub c: C::CircuitField,
    pub nested_ab_commitment: C::NestedCurve,
    pub x: C::CircuitField,
    pub nested_query_commitment: C::NestedCurve,
    pub alpha: C::CircuitField,
    pub nested_f_commitment: C::NestedCurve,
    pub u: C::CircuitField,
    pub nested_eval_commitment: C::NestedCurve,
    pub beta: C::CircuitField,
}

/// An entry in the shared public inputs for an internal circuit.
pub struct Slot<'a, 'dr, D: Driver<'dr>, T, C: Cycle> {
    value: Option<T>,
    alloc: fn(&mut D, &DriverValue<D, &'a Instance<C>>) -> Result<T>,
    _marker: core::marker::PhantomData<&'dr ()>,
}

impl<'a, 'dr, D: Driver<'dr>, T: Clone, C: Cycle> Slot<'a, 'dr, D, T, C> {
    pub(super) fn new(alloc: fn(&mut D, &DriverValue<D, &'a Instance<C>>) -> Result<T>) -> Self {
        Slot {
            value: None,
            alloc,
            _marker: core::marker::PhantomData,
        }
    }

    pub fn get(&mut self, dr: &mut D, instance: &DriverValue<D, &'a Instance<C>>) -> Result<T> {
        assert!(self.value.is_none(), "Slot::get: slot already filled");
        let value = (self.alloc)(dr, instance)?;
        self.value = Some(value.clone());
        Ok(value)
    }

    pub fn set(&mut self, value: T) {
        assert!(self.value.is_none(), "Slot::set: slot already filled");
        self.value = Some(value);
    }

    fn take(self, dr: &mut D, instance: &DriverValue<D, &'a Instance<C>>) -> Result<T> {
        self.value
            .map(Result::Ok)
            .unwrap_or_else(|| (self.alloc)(dr, instance))
    }
}

pub struct OutputBuilder<'a, 'dr, D: Driver<'dr>, C: Cycle> {
    pub nested_preamble_commitment: Slot<'a, 'dr, D, Point<'dr, D, C::NestedCurve>, C>,
    pub w: Slot<'a, 'dr, D, Element<'dr, D>, C>,
    pub nested_s_prime_commitment: Slot<'a, 'dr, D, Point<'dr, D, C::NestedCurve>, C>,
    pub y: Slot<'a, 'dr, D, Element<'dr, D>, C>,
    pub z: Slot<'a, 'dr, D, Element<'dr, D>, C>,
    pub nested_error_m_commitment: Slot<'a, 'dr, D, Point<'dr, D, C::NestedCurve>, C>,
    pub mu: Slot<'a, 'dr, D, Element<'dr, D>, C>,
    pub nu: Slot<'a, 'dr, D, Element<'dr, D>, C>,
    pub nested_error_n_commitment: Slot<'a, 'dr, D, Point<'dr, D, C::NestedCurve>, C>,
    pub mu_prime: Slot<'a, 'dr, D, Element<'dr, D>, C>,
    pub nu_prime: Slot<'a, 'dr, D, Element<'dr, D>, C>,
    pub c: Slot<'a, 'dr, D, Element<'dr, D>, C>,
    pub nested_ab_commitment: Slot<'a, 'dr, D, Point<'dr, D, C::NestedCurve>, C>,
    pub x: Slot<'a, 'dr, D, Element<'dr, D>, C>,
    pub nested_query_commitment: Slot<'a, 'dr, D, Point<'dr, D, C::NestedCurve>, C>,
    pub alpha: Slot<'a, 'dr, D, Element<'dr, D>, C>,
    pub nested_f_commitment: Slot<'a, 'dr, D, Point<'dr, D, C::NestedCurve>, C>,
    pub u: Slot<'a, 'dr, D, Element<'dr, D>, C>,
    pub nested_eval_commitment: Slot<'a, 'dr, D, Point<'dr, D, C::NestedCurve>, C>,
    pub beta: Slot<'a, 'dr, D, Element<'dr, D>, C>,
}

impl<'dr, D: Driver<'dr>, C: Cycle> Output<'dr, D, C> {
    /// Allocate an Output from a proof reference.
    pub fn alloc_from_proof<R: Rank>(
        dr: &mut D,
        proof: DriverValue<D, &Proof<C, R>>,
    ) -> Result<Self>
    where
        D: Driver<'dr, F = C::CircuitField>,
    {
        let nested_preamble_commitment = Point::alloc(
            dr,
            proof.view().map(|p| p.preamble.nested_preamble_commitment),
        )?;
        let w = Element::alloc(dr, proof.view().map(|p| p.internal_circuits.w))?;
        let nested_s_prime_commitment = Point::alloc(
            dr,
            proof.view().map(|p| p.s_prime.nested_s_prime_commitment),
        )?;
        let y = Element::alloc(dr, proof.view().map(|p| p.internal_circuits.y))?;
        let z = Element::alloc(dr, proof.view().map(|p| p.internal_circuits.z))?;
        let nested_error_m_commitment =
            Point::alloc(dr, proof.view().map(|p| p.error.nested_error_m_commitment))?;
        let mu = Element::alloc(dr, proof.view().map(|p| p.internal_circuits.mu))?;
        let nu = Element::alloc(dr, proof.view().map(|p| p.internal_circuits.nu))?;
        let nested_error_n_commitment =
            Point::alloc(dr, proof.view().map(|p| p.error.nested_error_n_commitment))?;
        let mu_prime = Element::alloc(dr, proof.view().map(|p| p.internal_circuits.mu_prime))?;
        let nu_prime = Element::alloc(dr, proof.view().map(|p| p.internal_circuits.nu_prime))?;
        let c = Element::alloc(dr, proof.view().map(|p| p.internal_circuits.c))?;
        let nested_ab_commitment =
            Point::alloc(dr, proof.view().map(|p| p.ab.nested_ab_commitment))?;
        let x = Element::alloc(dr, proof.view().map(|p| p.internal_circuits.x))?;
        let nested_query_commitment =
            Point::alloc(dr, proof.view().map(|p| p.query.nested_query_commitment))?;
        let alpha = Element::alloc(dr, proof.view().map(|p| p.internal_circuits.alpha))?;
        let nested_f_commitment = Point::alloc(dr, proof.view().map(|p| p.f.nested_f_commitment))?;
        let u = Element::alloc(dr, proof.view().map(|p| p.internal_circuits.u))?;
        let nested_eval_commitment =
            Point::alloc(dr, proof.view().map(|p| p.eval.nested_eval_commitment))?;
        let beta = Element::alloc(dr, proof.view().map(|p| p.internal_circuits.beta))?;

        Ok(Output {
            nested_preamble_commitment,
            w,
            nested_s_prime_commitment,
            y,
            z,
            nested_error_m_commitment,
            mu,
            nu,
            nested_error_n_commitment,
            mu_prime,
            nu_prime,
            c,
            nested_ab_commitment,
            x,
            nested_query_commitment,
            alpha,
            nested_f_commitment,
            u,
            nested_eval_commitment,
            beta,
        })
    }
}

impl<'a, 'dr, D: Driver<'dr, F = C::CircuitField>, C: Cycle> OutputBuilder<'a, 'dr, D, C> {
    pub fn new() -> Self {
        macro_rules! point_slot {
            ($field:ident) => {
                Slot::new(|dr, i: &DriverValue<D, &'a Instance<C>>| {
                    Point::alloc(dr, i.view().map(|i| i.$field))
                })
            };
        }
        macro_rules! element_slot {
            ($field:ident) => {
                Slot::new(|dr, i: &DriverValue<D, &'a Instance<C>>| {
                    Element::alloc(dr, i.view().map(|i| i.$field))
                })
            };
        }
        OutputBuilder {
            nested_preamble_commitment: point_slot!(nested_preamble_commitment),
            w: element_slot!(w),
            nested_s_prime_commitment: point_slot!(nested_s_prime_commitment),
            y: element_slot!(y),
            z: element_slot!(z),
            nested_error_m_commitment: point_slot!(nested_error_m_commitment),
            mu: element_slot!(mu),
            nu: element_slot!(nu),
            nested_error_n_commitment: point_slot!(nested_error_n_commitment),
            mu_prime: element_slot!(mu_prime),
            nu_prime: element_slot!(nu_prime),
            c: element_slot!(c),
            nested_ab_commitment: point_slot!(nested_ab_commitment),
            x: element_slot!(x),
            nested_query_commitment: point_slot!(nested_query_commitment),
            alpha: element_slot!(alpha),
            nested_f_commitment: point_slot!(nested_f_commitment),
            u: element_slot!(u),
            nested_eval_commitment: point_slot!(nested_eval_commitment),
            beta: element_slot!(beta),
        }
    }

    pub fn finish(
        self,
        dr: &mut D,
        instance: &DriverValue<D, &'a Instance<C>>,
    ) -> Result<<InternalOutputKind<C> as GadgetKind<D::F>>::Rebind<'dr, D>> {
        let zero = Element::zero(dr);
        Ok(Suffix::new(
            Output {
                nested_preamble_commitment: self.nested_preamble_commitment.take(dr, instance)?,
                w: self.w.take(dr, instance)?,
                nested_s_prime_commitment: self.nested_s_prime_commitment.take(dr, instance)?,
                y: self.y.take(dr, instance)?,
                z: self.z.take(dr, instance)?,
                nested_error_m_commitment: self.nested_error_m_commitment.take(dr, instance)?,
                mu: self.mu.take(dr, instance)?,
                nu: self.nu.take(dr, instance)?,
                nested_error_n_commitment: self.nested_error_n_commitment.take(dr, instance)?,
                mu_prime: self.mu_prime.take(dr, instance)?,
                nu_prime: self.nu_prime.take(dr, instance)?,
                c: self.c.take(dr, instance)?,
                nested_ab_commitment: self.nested_ab_commitment.take(dr, instance)?,
                x: self.x.take(dr, instance)?,
                nested_query_commitment: self.nested_query_commitment.take(dr, instance)?,
                alpha: self.alpha.take(dr, instance)?,
                nested_f_commitment: self.nested_f_commitment.take(dr, instance)?,
                u: self.u.take(dr, instance)?,
                nested_eval_commitment: self.nested_eval_commitment.take(dr, instance)?,
                beta: self.beta.take(dr, instance)?,
            },
            zero,
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ragu_circuits::polynomials::R;
    use ragu_core::{
        drivers::emulator::{Emulator, Wireless},
        maybe::Empty,
    };
    use ragu_pasta::{Fp, Pasta};

    #[test]
    fn num_wires_constant_is_correct() {
        // Use a wireless emulator with Empty witness - the emulator never reads witness values.
        let mut emulator = Emulator::<Wireless<Empty, Fp>>::wireless();
        let output = Output::<'_, _, Pasta>::alloc_from_proof::<R<16>>(&mut emulator, Empty)
            .expect("allocation should succeed");

        assert_eq!(
            output.num_wires(),
            NUM_WIRES,
            "NUM_WIRES constant does not match actual wire count"
        );
    }
}
