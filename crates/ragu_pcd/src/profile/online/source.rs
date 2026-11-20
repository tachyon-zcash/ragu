//! Immutable source-registry operations captured by the enclosing setup.
//!
//! A profile chooses an actual registry during application finalization.
//! A context-supplied source must remain the same for the application's
//! lifetime; see [`Profile::source_registries`](crate::profile::Profile::source_registries).

use alloc::{sync::Arc, vec::Vec};
use core::marker::PhantomData;

use ragu_backend::{Backend, RegistryEvaluation};
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
    fn registry(&self) -> &dyn RegistryEvaluation<F>;
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
    fn registry(&self) -> &dyn RegistryEvaluation<F> {
        self.registry
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
    /// Captures the source registry and the backend that prepares its restrictions.
    /// The enclosing application selects the backend for terminal verification.
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
    /// The base-two logarithm of the size of the domain the source
    /// interpolates its circuits over.
    pub(crate) fn domain_log2(&self) -> u32 {
        self.inner.domain_log2()
    }
    /// Checks all source-axis degree bounds against the enclosing rank.
    ///
    /// # Errors
    ///
    /// Rejects a source rank or registry domain larger than the enclosing rank.
    pub(crate) fn check_rank<R: Rank>(&self) -> Result<()> {
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
    pub(crate) fn xy<R: Rank>(&self, x: F, y: F) -> Result<sparse::Polynomial<F, R>> {
        self.polynomial(self.inner.xy(x, y))
    }
    /// The auxiliary restriction m(w,x,Y), fixed before y.
    ///
    /// # Errors
    ///
    /// Rejects restrictions that cannot fit the enclosing rank without truncation.
    pub(crate) fn wx<R: Rank>(&self, w: F, x: F) -> Result<sparse::Polynomial<F, R>> {
        self.polynomial(self.inner.wx(w, x))
    }
    /// The auxiliary restriction m(w,X,y), fixed before x.
    ///
    /// # Errors
    ///
    /// Rejects restrictions that cannot fit the enclosing rank without truncation.
    pub(crate) fn wy<R: Rank>(&self, w: F, y: F) -> Result<sparse::Polynomial<F, R>> {
        self.polynomial(self.inner.wy(w, y))
    }
    /// Evaluates the captured source with the enclosing application's verifier backend.
    pub(crate) fn evaluate<V: Backend>(&self, w: F, x: F, y: F) -> F {
        V::registry_wxy(self.inner.registry(), w, x, y)
    }
}

#[cfg(test)]
mod tests {
    use core::sync::atomic::{AtomicBool, Ordering};

    use ragu_backend::ReferenceBackend;
    use ragu_circuits::{
        polynomials::{R, TestRank},
        registry::RegistryBuilder,
    };
    use ragu_core::pasta::{Fp, Fq};

    use super::*;

    #[derive(Clone, Copy, Debug, Default)]
    struct TrackingVerifier;

    static EVALUATED: AtomicBool = AtomicBool::new(false);

    impl Backend for TrackingVerifier {
        fn registry_wxy<F: Field>(
            registry: &(impl RegistryEvaluation<F> + ?Sized),
            w: F,
            x: F,
            y: F,
        ) -> F {
            EVALUATED.store(true, Ordering::Relaxed);
            ReferenceBackend::registry_wxy(registry, w, x, y)
        }
    }

    fn check<F: Field>() -> Result<()> {
        let registry = RegistryBuilder::<F, TestRank>::new()
            .with_tag(F::from(7))
            .register_circuit(())?
            .finalize()?;
        let source = SourceRegistry::new::<_, ReferenceBackend>(&registry);
        source.check_rank::<R<13>>()?;
        let (w, x, y) = (F::from(2), F::from(3), F::from(5));
        let expected = ReferenceBackend::registry_wxy(&registry, w, x, y);
        assert_eq!(source.tag(), F::from(7));
        EVALUATED.store(false, Ordering::Relaxed);
        assert_eq!(source.evaluate::<TrackingVerifier>(w, x, y), expected);
        assert!(EVALUATED.load(Ordering::Relaxed));
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
            .with_tag(F::from(11))
            .register_circuit(())?
            .finalize()?;
        let other = SourceRegistry::new::<_, ReferenceBackend>(&substituted);
        assert_ne!(
            source.evaluate::<ReferenceBackend>(w, x, y),
            other.evaluate::<ReferenceBackend>(w, x, y)
        );
        assert_eq!(
            source.clone().evaluate::<ReferenceBackend>(w, x, y),
            expected
        );
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
