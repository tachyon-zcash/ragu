//! Common abstraction for orchestrating revdot claims.

use alloc::{borrow::Cow, vec::Vec};
use ff::PrimeField;
use ragu_circuits::{
    polynomials::{Rank, structured},
    registry::{CircuitIndex, Registry},
};

pub mod native;
pub mod nested;

/// Sum an iterator of polynomials, borrowing if only one element.
///
/// Returns `Cow::Borrowed` for a single polynomial, `Cow::Owned` for multiple.
/// Panics if the iterator is empty.
pub(crate) fn sum_polynomials<'rx, F: PrimeField, R: Rank>(
    mut rxs: impl Iterator<Item = &'rx structured::Polynomial<F, R>>,
) -> Cow<'rx, structured::Polynomial<F, R>> {
    let first = rxs.next().expect("must provide at least one rx polynomial");
    match rxs.next() {
        None => Cow::Borrowed(first),
        Some(second) => {
            let mut sum = first.clone();
            sum.add_assign(second);
            for rx in rxs {
                sum.add_assign(rx);
            }
            Cow::Owned(sum)
        }
    }
}

/// Trait for providing claim component values from sources.
///
/// This trait abstracts over what a "source" provides. For polynomial contexts
/// (verify, fuse), it provides polynomial references. For evaluation contexts
/// (`compute_v`), it provides single element evaluations (at $xz$).
///
/// Implementors provide access to rx values for all proofs they manage. The
/// `RxComponent` associated type defines which components can be requested.
pub trait Source {
    /// The type identifying which rx component to retrieve.
    /// For native claims, this is [`native::RxComponent`].
    type RxComponent: Copy;

    /// Opaque type for rx values.
    type Rx;

    /// Type for application circuit identifiers.
    type AppCircuitId;

    /// Get an iterator over rx values for all proofs for the given component.
    fn rx(&self, component: Self::RxComponent) -> impl Iterator<Item = Self::Rx>;

    /// Get an iterator over application circuit info for all proofs.
    fn app_circuits(&self) -> impl Iterator<Item = Self::AppCircuitId>;
}

/// Processor that builds polynomial vectors for revdot claims.
///
/// Accumulates (a, b) polynomial pairs for each claim type, using
/// the registry polynomial to transform rx polynomials appropriately.
pub struct Builder<'m, 'rx, F: PrimeField, R: Rank> {
    pub(crate) registry: &'m Registry<'m, F, R>,
    pub(crate) y: F,
    pub(crate) z: F,
    pub(crate) tz: structured::Polynomial<F, R>,
    /// The accumulated `a` polynomials for revdot claims.
    pub a: Vec<Cow<'rx, structured::Polynomial<F, R>>>,
    /// The accumulated `b` polynomials for revdot claims.
    pub b: Vec<Cow<'rx, structured::Polynomial<F, R>>>,
}

impl<'m, 'rx, F: PrimeField, R: Rank> Builder<'m, 'rx, F, R> {
    /// Create a new claim builder.
    pub fn new(registry: &'m Registry<'m, F, R>, y: F, z: F) -> Self {
        Self {
            registry,
            y,
            z,
            tz: R::tz(z),
            a: Vec::new(),
            b: Vec::new(),
        }
    }

    fn circuit_impl(
        &mut self,
        circuit_id: CircuitIndex,
        rx: Cow<'rx, structured::Polynomial<F, R>>,
    ) {
        let sy = self.registry.circuit_y(circuit_id, self.y);
        let mut b = rx.as_ref().clone();
        b.dilate(self.z);
        b.add_assign(&sy);
        b.add_assign(&self.tz);

        self.a.push(rx);
        self.b.push(Cow::Owned(b));
    }

    /// Shared stage accumulation logic for both native and nested `Processor` impls.
    pub(crate) fn stage_impl(
        &mut self,
        circuit_id: CircuitIndex,
        mut rxs: impl Iterator<Item = &'rx structured::Polynomial<F, R>>,
    ) -> ragu_core::Result<()> {
        let first = rxs.next().expect("must provide at least one rx polynomial");
        let sy = self.registry.circuit_y(circuit_id, self.y);

        let a = match rxs.next() {
            None => Cow::Borrowed(first),
            Some(second) => Cow::Owned(structured::Polynomial::fold(
                core::iter::once(first)
                    .chain(core::iter::once(second))
                    .chain(rxs),
                self.z,
            )),
        };

        self.a.push(a);
        self.b.push(Cow::Owned(sy));
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::borrow::Cow;
    use ff::Field;
    use ragu_circuits::polynomials::{TestRank, structured};
    use ragu_pasta::Fp;

    /// Issue #347: sum_polynomials with a single poly returns Cow::Borrowed.
    #[test]
    fn sum_single_borrows() {
        let poly = structured::Polynomial::<Fp, TestRank>::random(&mut rand::rng());
        let result = sum_polynomials([&poly].into_iter());
        assert!(matches!(result, Cow::Borrowed(_)));
        // Verify coefficients match
        let x = Fp::random(&mut rand::rng());
        assert_eq!(result.eval(x), poly.eval(x));
    }

    /// Issue #347: sum_polynomials with two polys returns Cow::Owned equal to p1+p2.
    #[test]
    fn sum_two_owns() {
        let mut rng = rand::rng();
        let p1 = structured::Polynomial::<Fp, TestRank>::random(&mut rng);
        let p2 = structured::Polynomial::<Fp, TestRank>::random(&mut rng);

        let result = sum_polynomials([&p1, &p2].into_iter());
        assert!(matches!(result, Cow::Owned(_)));

        let mut expected = p1.clone();
        expected.add_assign(&p2);
        // Verify result matches expected at a random evaluation point
        let x = Fp::random(&mut rand::rng());
        assert_eq!(result.eval(x), expected.eval(x));
    }

    /// Issue #347: sum_polynomials with many polys matches manual addition.
    #[test]
    fn sum_many() {
        let mut rng = rand::rng();
        let polys: Vec<structured::Polynomial<Fp, TestRank>> = (0..5)
            .map(|_| structured::Polynomial::random(&mut rng))
            .collect();

        let result = sum_polynomials(polys.iter());

        let mut expected = polys[0].clone();
        for p in &polys[1..] {
            expected.add_assign(p);
        }
        // Verify result matches expected at a random evaluation point
        let x = Fp::random(&mut rand::rng());
        assert_eq!(result.eval(x), expected.eval(x));
    }
}
