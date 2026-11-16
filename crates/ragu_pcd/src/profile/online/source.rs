//! Immutable source-registry operations captured by the enclosing setup.
//!
//! A profile chooses an actual registry once during application finalization.
//! Its prover context cannot replace that registry while preparing a proof.

use alloc::{sync::Arc, vec::Vec};
use core::marker::PhantomData;

use ragu_circuits::{
    polynomials::{Rank, sparse},
    registry::Registry,
};
use ragu_core::{Error, Result};
use udon::field::Field;

use crate::SelectableBackend;

trait Restrictions<F: Field>: Send + Sync {
    fn tag(&self) -> F;
    fn source_capacity(&self) -> usize;
    fn domain_log2(&self) -> u32;
    fn xy(&self, x: F, y: F) -> Vec<F>;
    fn wx(&self, w: F, x: F) -> Vec<F>;
    fn wy(&self, w: F, y: F) -> Vec<F>;
    fn evaluate(&self, w: F, x: F, y: F) -> F;
}

struct Borrowed<'a, F: Field, R: Rank, B: SelectableBackend> {
    registry: &'a Registry<'a, F, R>,
    backend: PhantomData<B>,
}
impl<F: Field, R: Rank, B: SelectableBackend> Restrictions<F> for Borrowed<'_, F, R, B> {
    fn tag(&self) -> F {
        self.registry.tag()
    }
    fn source_capacity(&self) -> usize {
        R::num_coeffs()
    }
    fn domain_log2(&self) -> u32 {
        self.registry.log2_domain()
    }
    fn xy(&self, x: F, y: F) -> Vec<F> {
        B::registry_xy(self.registry, x, y).iter_coeffs().collect()
    }
    fn wx(&self, w: F, x: F) -> Vec<F> {
        B::registry_at_x(&self.registry.at(w), x)
            .iter_coeffs()
            .collect()
    }
    fn wy(&self, w: F, y: F) -> Vec<F> {
        B::registry_at_y(&self.registry.at(w), y)
            .iter_coeffs()
            .collect()
    }
    fn evaluate(&self, w: F, x: F, y: F) -> F {
        <<B as SelectableBackend>::Verifier as ragu_backend::Backend>::registry_wxy(
            self.registry,
            w,
            x,
            y,
        )
    }
}

/// A setup-bound registry, independent of the enclosing circuit rank.
///
/// The implementation is sealed: callers can select a registry and a Ragu
/// backend, but cannot substitute arbitrary restriction/evaluation callbacks.
/// Clones share the same immutable borrowed registry and backend selection.
#[derive(Clone)]
pub struct SourceRegistry<'a, F: Field> {
    inner: Arc<dyn Restrictions<F> + 'a>,
}
impl<'a, F: Field> SourceRegistry<'a, F> {
    /// Captures the source registry and sealed backend selection.
    pub fn new<R: Rank, B: SelectableBackend>(registry: &'a Registry<'a, F, R>) -> Self {
        Self {
            inner: Arc::new(Borrowed::<F, R, B> {
                registry,
                backend: PhantomData,
            }),
        }
    }
    /// The sampled source setup tag.
    pub fn tag(&self) -> F {
        self.inner.tag()
    }
    /// Checks all source-axis degree bounds against the enclosing rank.
    ///
    /// # Errors
    ///
    /// Rejects a source rank or registry domain larger than the enclosing rank.
    pub fn check_rank<R: Rank>(&self) -> Result<()> {
        if self.inner.source_capacity() > R::num_coeffs()
            || 1usize
                .checked_shl(self.inner.domain_log2())
                .is_none_or(|size| size > R::num_coeffs())
        {
            return Err(Error::Initialization(
                "source registry exceeds the enclosing polynomial rank".into(),
            ));
        }
        Ok(())
    }
    fn polynomial<R: Rank>(&self, coefficients: Vec<F>) -> Result<sparse::Polynomial<F, R>> {
        self.check_rank::<R>()?;
        if coefficients.len() > R::num_coeffs() {
            return Err(Error::Initialization(
                "source restriction exceeds the enclosing rank".into(),
            ));
        }
        Ok(sparse::Polynomial::from_coeffs(coefficients))
    }
    /// The outgoing or input restriction m(W,x,y).
    ///
    /// # Errors
    ///
    /// Rejects restrictions that cannot fit the enclosing rank without truncation.
    pub fn xy<R: Rank>(&self, x: F, y: F) -> Result<sparse::Polynomial<F, R>> {
        self.polynomial(self.inner.xy(x, y))
    }
    /// The auxiliary restriction m(w,x,Y), fixed before y.
    ///
    /// # Errors
    ///
    /// Rejects restrictions that cannot fit the enclosing rank without truncation.
    pub fn wx<R: Rank>(&self, w: F, x: F) -> Result<sparse::Polynomial<F, R>> {
        self.polynomial(self.inner.wx(w, x))
    }
    /// The auxiliary restriction m(w,X,y), fixed before x.
    ///
    /// # Errors
    ///
    /// Rejects restrictions that cannot fit the enclosing rank without truncation.
    pub fn wy<R: Rank>(&self, w: F, y: F) -> Result<sparse::Polynomial<F, R>> {
        self.polynomial(self.inner.wy(w, y))
    }
    /// Evaluates the captured source with the sealed verifier backend.
    pub fn evaluate(&self, w: F, x: F, y: F) -> F {
        self.inner.evaluate(w, x, y)
    }
}

#[cfg(test)]
mod tests {
    use ragu_backend::{Backend, ReferenceBackend};
    use ragu_circuits::{
        polynomials::{R, TestRank},
        registry::{RegistryBuilder, Tag},
    };
    use ragu_core::pasta::{Fp, Fq};

    use super::*;

    fn check<F: Field>() -> Result<()> {
        let registry = RegistryBuilder::<F, TestRank>::new()
            .with_tag(Tag::new(F::from(7)))
            .register_circuit(())?
            .finalize()?;
        let source = SourceRegistry::new::<_, ReferenceBackend>(&registry);
        source.check_rank::<R<13>>()?;
        let (w, x, y) = (F::from(2), F::from(3), F::from(5));
        let expected = ReferenceBackend::registry_wxy(&registry, w, x, y);
        assert_eq!(source.tag(), F::from(7));
        assert_eq!(source.evaluate(w, x, y), expected);
        assert_eq!(
            ReferenceBackend::sparse_eval(&source.xy::<R<13>>(x, y)?, w),
            expected
        );
        assert_eq!(
            ReferenceBackend::sparse_eval(&source.wx::<R<13>>(w, x)?, y),
            expected
        );
        assert_eq!(
            ReferenceBackend::sparse_eval(&source.wy::<R<13>>(w, y)?, x),
            expected
        );
        let substituted = RegistryBuilder::<F, TestRank>::new()
            .with_tag(Tag::new(F::from(11)))
            .register_circuit(())?
            .finalize()?;
        let other = SourceRegistry::new::<_, ReferenceBackend>(&substituted);
        assert_ne!(source.evaluate(w, x, y), other.evaluate(w, x, y));
        assert_eq!(source.clone().evaluate(w, x, y), expected);
        let large = RegistryBuilder::<F, R<13>>::new()
            .register_circuit(())?
            .finalize()?;
        let large_source = SourceRegistry::new::<_, ReferenceBackend>(&large);
        assert!(large_source.check_rank::<TestRank>().is_err());
        assert!(large_source.xy::<TestRank>(x, y).is_err());
        Ok(())
    }
    #[test]
    fn restrictions_keep_source_identity_and_degree_bounds_across_ranks() -> Result<()> {
        check::<Fp>()?;
        check::<Fq>()
    }
}
