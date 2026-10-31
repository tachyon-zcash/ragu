//! Handles to the commitments behind witnessed polynomials.
//!
//! A witnessed polynomial is over [`Cycle::CircuitField`], so its commitment
//! $C$ lands on [`Cycle::HostCurve`], whose coordinates are in
//! [`Cycle::ScalarField`]. A step cannot hold one, so it gets a handle: the
//! affine coordinates of $C$'s name.
//!
//! The name of $C$ is the nested commitment to
//! $n_C(X) = C_x + C_y X + X^2$, which [`name_polynomial`] builds. Its
//! coordinates are in the circuit field, so a native circuit holds it as a
//! nested-curve point, and a parent can open it: the parent walks the name
//! into its nested batch and evaluates $n_C$ at $u_n$ from the commitment its
//! nested preamble stashes, so a name the stash's commitment does not take
//! fails the nested accumulator. Under discrete log among the nested
//! generators, distinct commitments have distinct names, $-C$'s included.

use alloc::{vec, vec::Vec};
use core::{array, marker::PhantomData};

use ragu_backend::Backend;
use ragu_circuits::polynomials::{Rank, sparse};
use ragu_core::{
    Cycle, Error, Result,
    drivers::{Driver, DriverValue},
    gadgets::Gadget,
    maybe::Maybe,
};
use ragu_primitives::{Element, consistent::Consistent, io::Write};
use udon::{curve::Affine as _, field::Field};

/// Circuit-field elements a handle occupies.
pub const HANDLE_WIRES: usize = 2;

/// Commits a witnessed polynomial's coefficients and names the commitment;
/// see [`commit_and_name`].
pub(crate) type CommitAndName<C> = fn(
    &[<C as Cycle>::CircuitField],
    &<C as Cycle>::Params,
) -> Result<(
    <C as Cycle>::HostCurve,
    [<C as Cycle>::CircuitField; HANDLE_WIRES],
)>;

/// The commitment the builder derives for a witnessed polynomial: the
/// coefficients at the application's rank `R`, committed through the selected
/// backend `B`.
pub(crate) fn commit<C: Cycle, R: Rank, B: Backend>(
    coefficients: &[C::CircuitField],
    params: &C::Params,
) -> C::HostCurve {
    let polynomial = sparse::Polynomial::<_, R>::from_coeffs(coefficients.to_vec());
    B::sparse_commit_to_affine(&polynomial, C::host_generators(params))
}

/// [`commit`], with the commitment's [`name`].
pub(crate) fn commit_and_name<C: Cycle, R: Rank, B: Backend>(
    coefficients: &[C::CircuitField],
    params: &C::Params,
) -> Result<(C::HostCurve, [C::CircuitField; HANDLE_WIRES])> {
    let commitment = commit::<C, R, B>(coefficients, params);
    Ok((commitment, name::<C, R, B>(commitment, params)?))
}

/// The nested polynomial a host commitment names:
/// $n_C(X) = C_x + C_y X + X^2$.
///
/// # Errors
///
/// Returns [`Error::InvalidWitness`] for the identity, which has no affine
/// coordinates: the zero polynomial cannot be witnessed.
pub(crate) fn name_polynomial<C: Cycle, R: Rank>(
    host: C::HostCurve,
) -> Result<sparse::Polynomial<C::ScalarField, R>> {
    let (x, y) = host
        .coordinates()
        .ok_or_else(|| Error::InvalidWitness("the identity commitment has no name".into()))?;
    Ok(sparse::Polynomial::from_coeffs(vec![
        x,
        y,
        C::ScalarField::ONE,
    ]))
}

/// The name of a host commitment: the affine coordinates of the nested
/// commitment to its [`name_polynomial`], at the application's rank `R`
/// through backend `B`, as the parent's nested batch commits it.
///
/// # Errors
///
/// As [`name_polynomial`].
pub(crate) fn name<C: Cycle, R: Rank, B: Backend>(
    host: C::HostCurve,
    params: &C::Params,
) -> Result<[C::CircuitField; HANDLE_WIRES]> {
    let polynomial = name_polynomial::<C, R>(host)?;
    let named = B::sparse_commit_to_affine(&polynomial, C::nested_generators(params));
    let (x, y) = named
        .coordinates()
        .ok_or_else(|| Error::InvalidWitness("a name is never the identity".into()))?;
    Ok([x, y])
}

/// A cross-field handle for a polynomial commitment: its name.
#[derive(Gadget, Write, Consistent)]
pub struct PolyHandle<'dr, D: Driver<'dr>, C: Cycle<CircuitField = D::F>> {
    #[ragu(gadget)]
    handle: [Element<'dr, D>; HANDLE_WIRES],
    #[ragu(phantom)]
    _cycle: PhantomData<C>,
}

impl<'dr, D: Driver<'dr>, C: Cycle<CircuitField = D::F>> PolyHandle<'dr, D, C> {
    pub(crate) fn new(
        dr: &mut D,
        params: &C::Params,
        commit_and_name: CommitAndName<C>,
        coefficients: &DriverValue<D, Vec<C::CircuitField>>,
    ) -> Result<(Self, DriverValue<D, C::HostCurve>)> {
        let to_commit = coefficients.as_ref();
        let named = D::try_just(move || commit_and_name(to_commit.take(), params))?;
        let point = named.as_ref().map(|(point, _)| *point);
        let handle = named.map(|(_, name)| name);

        Ok((Self::alloc(dr, handle)?, point))
    }

    pub(crate) fn alloc(dr: &mut D, handle: DriverValue<D, [D::F; HANDLE_WIRES]>) -> Result<Self> {
        Ok(Self {
            handle: [
                Element::alloc(dr, &mut (), handle.as_ref().map(|h| h[0]))?,
                Element::alloc(dr, &mut (), handle.as_ref().map(|h| h[1]))?,
            ],
            _cycle: PhantomData,
        })
    }

    pub(crate) fn wires(&self) -> [Element<'dr, D>; HANDLE_WIRES] {
        self.handle.clone()
    }

    pub(crate) fn value(&self) -> DriverValue<D, [D::F; HANDLE_WIRES]> {
        let limbs: [_; HANDLE_WIRES] = array::from_fn(|i| self.handle[i].value());
        D::just(move || limbs.map(|limb| *limb.take()))
    }
}

#[cfg(test)]
mod tests {
    use ragu_backend::ReferenceBackend;
    use ragu_circuits::polynomials::ProductionRank;
    use ragu_core::pasta::{Fp, Fq, Pasta};

    use super::*;

    type R = ProductionRank;

    fn committed(coeffs: &[u64]) -> <Pasta as Cycle>::HostCurve {
        let coeffs: Vec<Fp> = coeffs.iter().map(|&c| Fp::from(c)).collect();
        commit::<Pasta, R, ReferenceBackend>(&coeffs, crate::pasta::baked())
    }

    /// A name is the nested commitment to $n_C$, and $n_C$ evaluates to
    /// $C_x + C_y u + u^2$: what a parent's nested batch folds and what its
    /// nested `compute_v` recomputes from the stash.
    #[test]
    fn a_name_commits_to_its_name_polynomial() -> Result<()> {
        let params = crate::pasta::baked();
        let host = committed(&[3, 1, 4, 1, 5]);
        let polynomial = name_polynomial::<Pasta, R>(host)?;
        let nested = ReferenceBackend::sparse_commit_to_affine(
            &polynomial,
            Pasta::nested_generators(params),
        );
        let (x, y) = nested.coordinates().expect("not the identity");
        assert_eq!(name::<Pasta, R, ReferenceBackend>(host, params)?, [x, y]);

        let (cx, cy) = host.coordinates().expect("not the identity");
        let u = Fq::from(17u64);
        assert_eq!(polynomial.eval(u), cx + cy * u + u * u);
        Ok(())
    }

    /// $C_y$ enters the name, so $-C$, a valid point committing to the
    /// negated polynomial, has another name; and distinct commitments do.
    #[test]
    fn a_name_tells_commitments_apart() -> Result<()> {
        let params = crate::pasta::baked();
        let host = committed(&[3, 1, 4, 1, 5]);
        let named = name::<Pasta, R, ReferenceBackend>(host, params)?;
        assert_ne!(named, name::<Pasta, R, ReferenceBackend>(-host, params)?);
        assert_ne!(
            named,
            name::<Pasta, R, ReferenceBackend>(committed(&[2, 7, 1, 8]), params)?
        );
        Ok(())
    }

    /// The zero polynomial commits to the identity, which has no name.
    #[test]
    fn the_identity_has_no_name() {
        let identity = committed(&[]);
        assert!(matches!(
            name::<Pasta, R, ReferenceBackend>(identity, crate::pasta::baked()),
            Err(Error::InvalidWitness(_))
        ));
    }
}
