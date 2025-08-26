use arithmetic::Coeff;
use ff::Field;
use ragu_core::{
    Error, Result,
    drivers::{Driver, DriverTypes, LinearExpression},
    maybe::Empty,
};
use ragu_primitives::GadgetExt;

use alloc::{vec, vec::Vec};
use core::cell::RefCell;

use crate::{
    Circuit,
    polynomials::{Rank, structured},
};

/// Wires are identified by their allocated index or virtual index.
#[derive(Copy, Clone)]
enum WireIndex {
    A(usize),
    B(usize),
    C(usize),
    Virtual(usize),
}

/// The wire type provided by the driver contains a reference to the virtual
/// table, which allows reference-counted management of virtual wires.
struct Wire<'table, 'sy, F: Field, R: Rank> {
    index: WireIndex,
    table: Option<&'table RefCell<VirtualTable<'sy, F, R>>>,
}

impl<F: Field, R: Rank> From<WireIndex> for Wire<'_, '_, F, R> {
    fn from(index: WireIndex) -> Self {
        Wire { index, table: None }
    }
}

impl<F: Field, R: Rank> Clone for Wire<'_, '_, F, R> {
    fn clone(&self) -> Self {
        if let WireIndex::Virtual(index) = self.index {
            self.table.unwrap().borrow_mut().wires[index].refcount += 1;
        }

        Wire {
            index: self.index,
            table: self.table,
        }
    }
}

impl<F: Field, R: Rank> Drop for Wire<'_, '_, F, R> {
    fn drop(&mut self) {
        if let WireIndex::Virtual(_) = self.index {
            self.table.as_ref().unwrap().borrow_mut().free(self.index);
        }
    }
}

struct VirtualWire<F: Field> {
    refcount: usize,
    terms: Vec<(WireIndex, Coeff<F>)>,
    value: Coeff<F>,
}

struct VirtualTable<'sy, F: Field, R: Rank> {
    wires: Vec<VirtualWire<F>>,
    free: Vec<usize>,
    sy: structured::View<'sy, F, R, structured::Backward>,
}

impl<F: Field, R: Rank> VirtualTable<'_, F, R> {
    fn add(&mut self, index: WireIndex, value: Coeff<F>) {
        *match index {
            WireIndex::A(i) => &mut self.sy.a[i],
            WireIndex::B(i) => &mut self.sy.b[i],
            WireIndex::C(i) => &mut self.sy.c[i],
            WireIndex::Virtual(i) => {
                self.wires[i].value = self.wires[i].value + value;
                return;
            }
        } += value.value();
    }

    fn free(&mut self, index: WireIndex) {
        if let WireIndex::Virtual(index) = index {
            assert!(self.wires[index].refcount > 0);
            self.wires[index].refcount -= 1;
            if self.wires[index].refcount == 0 {
                let mut terms = vec![];
                core::mem::swap(&mut terms, &mut self.wires[index].terms);
                let value = self.wires[index].value;
                for (wire, coeff) in terms.drain(..) {
                    self.add(wire, value * coeff);
                    self.free(wire);
                }
                core::mem::swap(&mut terms, &mut self.wires[index].terms);
                self.free.push(index);
            }
        }
    }

    fn reinit(&mut self, index: WireIndex, terms: Vec<(WireIndex, Coeff<F>)>) {
        match index {
            WireIndex::Virtual(index) => {
                self.wires[index].terms = terms;
            }
            _ => unreachable!(),
        }
    }

    fn alloc(&mut self) -> (WireIndex, Vec<(WireIndex, Coeff<F>)>) {
        match self.free.pop() {
            Some(index) => {
                self.wires[index].refcount = 1;
                self.wires[index].value = Coeff::Zero;
                let mut terms = vec![];
                core::mem::swap(&mut terms, &mut self.wires[index].terms);

                (WireIndex::Virtual(index), terms)
            }
            None => {
                let index = self.wires.len();
                self.wires.push(VirtualWire {
                    refcount: 1,
                    terms: vec![],
                    value: Coeff::Zero,
                });
                (WireIndex::Virtual(index), vec![])
            }
        }
    }
}

struct Collector<'table, 'sy, F: Field, R: Rank> {
    multiplication_constraints: usize,
    linear_constraints: usize,
    y_inv: F,
    current_y: F,
    virtual_table: &'table RefCell<VirtualTable<'sy, F, R>>,
    available_b: Option<Wire<'table, 'sy, F, R>>,
    _marker: core::marker::PhantomData<R>,
}

struct TermCollector<F: Field>(Vec<(WireIndex, Coeff<F>)>, Coeff<F>);
impl<'table, 'sy, F: Field, R: Rank> LinearExpression<Wire<'table, 'sy, F, R>, F>
    for TermCollector<F>
{
    fn add_term(mut self, wire: &Wire<'table, 'sy, F, R>, coeff: Coeff<F>) -> Self {
        let wire = wire.clone();
        let tmp = (wire.index, coeff * self.1);

        // NB: We want to maintain the refcount because we're creating a virtual
        // wire which will have a reference to this wire.
        core::mem::forget(wire);
        self.0.push(tmp);
        self
    }

    fn gain(mut self, coeff: Coeff<F>) -> Self {
        self.1 = self.1 * coeff;
        self
    }
}

struct TermEnforcer<'table, 'sy, F: Field, R: Rank>(
    &'table RefCell<VirtualTable<'sy, F, R>>,
    Coeff<F>,
);
impl<'table, 'sy, F: Field, R: Rank> LinearExpression<Wire<'table, 'sy, F, R>, F>
    for TermEnforcer<'table, 'sy, F, R>
{
    fn add_term(self, wire: &Wire<'table, 'sy, F, R>, coeff: Coeff<F>) -> Self {
        self.0.borrow_mut().add(wire.index, coeff * self.1);
        self
    }

    fn gain(mut self, coeff: Coeff<F>) -> Self {
        self.1 = self.1 * coeff;
        self
    }
}

impl<'table, 'sy, F: Field, R: Rank> DriverTypes for Collector<'table, 'sy, F, R> {
    type MaybeKind = Empty;
    type LCadd = TermCollector<F>;
    type LCenforce = TermEnforcer<'table, 'sy, F, R>;
    type ImplField = F;
    type ImplWire = Wire<'table, 'sy, F, R>;
}

impl<'table, 'sy, F: Field, R: Rank> Driver<'_> for Collector<'table, 'sy, F, R> {
    type F = F;
    type Wire = Wire<'table, 'sy, F, R>;

    const ONE: Self::Wire = Wire {
        index: WireIndex::C(0),
        table: None,
    };

    fn alloc(&mut self, _: impl Fn() -> Result<Coeff<Self::F>>) -> Result<Self::Wire> {
        if let Some(wire) = self.available_b.take() {
            Ok(wire)
        } else {
            let (a, b, _) = self.mul(|| unreachable!())?;
            self.available_b = Some(b);

            Ok(a)
        }
    }

    fn mul(
        &mut self,
        _: impl Fn() -> Result<(Coeff<F>, Coeff<F>, Coeff<F>)>,
    ) -> Result<(Self::Wire, Self::Wire, Self::Wire)> {
        let index = self.multiplication_constraints;
        if index == R::n() {
            return Err(Error::MultiplicationBoundExceeded(R::n()));
        }
        self.multiplication_constraints += 1;

        {
            let mut table = self.virtual_table.borrow_mut();
            table.sy.a.push(F::ZERO);
            table.sy.b.push(F::ZERO);
            table.sy.c.push(F::ZERO);
        }

        let a = Wire::from(WireIndex::A(index));
        let b = Wire::from(WireIndex::B(index));
        let c = Wire::from(WireIndex::C(index));

        Ok((a, b, c))
    }

    fn add(&mut self, lc: impl Fn(Self::LCadd) -> Self::LCadd) -> Self::Wire {
        let (wire, terms) = self.virtual_table.borrow_mut().alloc();
        let terms = lc(TermCollector(terms, Coeff::One)).0;
        self.virtual_table.borrow_mut().reinit(wire, terms);

        Wire {
            index: wire,
            table: Some(self.virtual_table),
        }
    }

    fn enforce_zero(&mut self, lc: impl Fn(Self::LCenforce) -> Self::LCenforce) -> Result<()> {
        let q = self.linear_constraints;
        if q >= R::num_coeffs() {
            return Err(Error::LinearBoundExceeded(R::num_coeffs()));
        }
        self.linear_constraints += 1;

        lc(TermEnforcer(
            self.virtual_table,
            Coeff::Arbitrary(self.current_y),
        ));

        self.current_y *= self.y_inv;

        Ok(())
    }
}

pub fn eval<F: Field, C: Circuit<F>, R: Rank>(
    circuit: &C,
    y: F,
    num_linear_constraints: usize,
) -> Result<structured::Polynomial<F, R>> {
    let mut sy = structured::Polynomial::<F, R>::new();

    if y == F::ZERO {
        // If y is zero, the only linear constraint enforces the 'one' wire for
        // the public inputs.
        sy.backward().c.push(F::ONE);
        return Ok(sy);
    }

    {
        let virtual_table = RefCell::new(VirtualTable::<F, R> {
            wires: vec![],
            free: vec![],
            sy: sy.backward(),
        });
        {
            let mut collector = Collector::<'_, '_, F, R> {
                multiplication_constraints: 0,
                linear_constraints: 0,
                y_inv: y.invert().expect("y is not zero"),
                current_y: y.pow_vartime([(num_linear_constraints - 1) as u64]),
                virtual_table: &virtual_table,
                available_b: None,
                _marker: core::marker::PhantomData,
            };
            let one = collector.mul(|| unreachable!())?.2;

            let mut outputs = vec![];
            let (io, _) = circuit.witness(&mut collector, Empty)?;
            io.serialize(&mut collector, &mut outputs)?;

            for output in outputs {
                collector.enforce_zero(|lc| lc.add(output.wire()))?;
            }
            collector.enforce_zero(|lc| lc.add(&one))?;
            assert_eq!(collector.linear_constraints, num_linear_constraints);
        }

        // We should have ended up freeing all the wires; otherwise, there's
        // something goofy happening during synthesis that could mean there's a bug
        // in the circuit.
        let virtual_table = virtual_table.into_inner();
        assert_eq!(virtual_table.free.len(), virtual_table.wires.len());
    }

    Ok(sy)
}
