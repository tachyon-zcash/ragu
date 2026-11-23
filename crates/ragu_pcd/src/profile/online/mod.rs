//! Setup-fixed declarations for a profile's online polynomial openings.
//!
//! Polynomial order determines the commitment fold; opening order determines
//! the quotient fold. Repeated openings refer to the same polynomial index and
//! never add another commitment or evaluation at the batch point.
//!
//! [`SourceRegistry`] holds the immutable source-registry operations
//! captured by the enclosing setup.
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

pub mod circuit;
pub mod mesh;
pub(crate) mod prover;
pub mod stages;

#[cfg(test)]
#[path = "../../../tests/profile_online.rs"]
mod tests;

/// The last transcript boundary before a polynomial must be committed.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum Phase {
    /// Online polynomials, fixed before the step's first challenge.
    BeforeW,
    /// Auxiliary polynomials prepared from `w`, before `y`.
    BeforeY,
    /// Auxiliary polynomials prepared from `w` and `y`, before `x`.
    BeforeX,
    /// Auxiliary polynomials prepared from `w`, `y` and `x`, before `alpha`.
    BeforeAlpha,
}

impl Phase {
    /// The commitment deadlines in polynomial order.
    pub const ALL: [Self; 4] = [
        Self::BeforeW,
        Self::BeforeY,
        Self::BeforeX,
        Self::BeforeAlpha,
    ];
}

/// An enclosing-step challenge that can be an opening point.
///
/// On the nested side these mean the prescribed nested lifts. The batch point
/// `u` is deliberately absent: queries must be committed before `alpha`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Challenge {
    /// The challenge testing the online polynomials.
    W,
    /// The second registry coordinate challenge.
    Y,
    /// The first registry coordinate challenge.
    X,
}

/// The source of an opening point, fixed by setup rather than by the prover.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Point {
    /// An authenticated challenge of the enclosing step.
    Challenge(Challenge),
    /// A small integer embedded in the polynomial's field.
    Constant(u64),
    /// The registry domain point for this circuit index.
    Circuit(u32),
    /// A value from the input stage committed before `w`.
    Input(usize),
    /// A wire of `OnlineQuery`, constrained by the consuming circuit.
    ///
    /// This supports arbitrary field elements. The consumer must bind any
    /// relation to earlier input stages explicitly; the opening proves only
    /// evaluation at the point in this wire.
    Witness(usize),
}

/// One opening in quotient-fold order.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Opening {
    /// Index in [`Layout::polynomials`].
    pub polynomial: usize,
    /// Source of the point at which the polynomial is opened.
    pub point: Point,
    /// Index of the claimed value in `OnlineQuery`.
    ///
    /// Several openings can share this index to enforce an intersection
    /// equality without witnessing independent copies of its value.
    pub value: usize,
}

/// The online and auxiliary batch on one field, fixed for a profile type.
///
/// The empty layout adds no stages or circuits. Nonempty layouts have one
/// evaluation at `u` per polynomial, independent of the number of openings.
/// No entry creates an application or header slot.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Layout {
    /// Commitment deadlines, in commitment-fold order and phase order.
    pub polynomials: &'static [Phase],
    /// Opening claims, in quotient-fold order.
    pub openings: &'static [Opening],
    /// Number of input values committed before `w` and shared by consumers.
    pub inputs: usize,
    /// Number of separately witnessed point wires in `OnlineQuery`.
    pub points: usize,
    /// Number of claimed value wires in `OnlineQuery`.
    pub values: usize,
}

impl Layout {
    /// No online polynomials.
    pub const EMPTY: Self = Self {
        polynomials: &[],
        openings: &[],
        inputs: 0,
        points: 0,
        values: 0,
    };

    /// The distinct-polynomial indices committed at one deadline.
    ///
    /// Layout validation requires the polynomial list to follow phase order.
    pub fn phase_range(&self, phase: Phase) -> core::ops::Range<usize> {
        let start = self.polynomials.partition_point(|&p| p < phase);
        let end = self.polynomials.partition_point(|&p| p <= phase);
        start..end
    }

    /// Whether this declaration adds nothing.
    pub const fn is_empty(&self) -> bool {
        self.polynomials.is_empty()
            && self.openings.is_empty()
            && self.inputs == 0
            && self.points == 0
            && self.values == 0
    }

    /// Checks indices, phase order and coverage of all declared entries.
    ///
    /// # Errors
    ///
    /// Rejects out-of-range indices, unused polynomial/point/value slots and
    /// decreasing commitment phases. Repeated polynomial and value indices
    /// are allowed: they are how multi-point openings and mesh edges work.
    pub fn check(&self) -> Result<()> {
        let valid = self.polynomials.windows(2).all(|p| p[0] <= p[1])
            && self.openings.iter().all(|opening| {
                opening.polynomial < self.polynomials.len()
                    && opening.value < self.values
                    && match opening.point {
                        Point::Input(input) => input < self.inputs,
                        Point::Witness(point) => point < self.points,
                        _ => true,
                    }
            })
            && (0..self.polynomials.len()).all(|i| self.openings.iter().any(|o| o.polynomial == i))
            && (0..self.points).all(|i| self.openings.iter().any(|o| o.point == Point::Witness(i)))
            && (0..self.values).all(|i| self.openings.iter().any(|o| o.value == i));
        if valid {
            Ok(())
        } else {
            Err(Error::Initialization(
                "the profile's online opening layout is not well formed".into(),
            ))
        }
    }
}

/// The default bodies of the per-side preparation hooks on
/// [`Profile`](crate::profile::Profile), shared by the native and nested hooks
/// so that the two sides cannot drift apart.
pub(crate) mod defaults {
    use alloc::vec::Vec;

    use ragu_core::{Error, Result};
    use udon::field::Field;

    use super::{Phase, stages::Side};
    use crate::profile::Profile;

    fn side<S: Side>(native: &'static str, nested: &'static str) -> Error {
        Error::Initialization(if S::NATIVE { native } else { nested }.into())
    }

    /// Supplies only inherited mesh coordinates, which the protocol fills in.
    pub(crate) fn inputs<P: Profile, S: Side, F: Field>() -> Result<Vec<F>> {
        let layout = S::layout::<P>();
        let inherited_only = S::mesh::<P>().is_some_and(|mesh| {
            (0..layout.inputs).all(|i| mesh.inherited_coordinates().contains(&i))
        });
        if layout.inputs == 0 || inherited_only {
            Ok(alloc::vec![F::ZERO; layout.inputs])
        } else {
            Err(side::<S>(
                "the profile has no native online input prover",
                "the profile has no nested online input prover",
            ))
        }
    }

    /// Supplies nothing, which suffices when the mesh owns every slot of
    /// the phase.
    pub(crate) fn polynomials<P: Profile, S: Side, T>(phase: Phase) -> Result<Vec<T>> {
        let mesh = S::mesh::<P>();
        if S::layout::<P>()
            .phase_range(phase)
            .any(|i| !mesh.is_some_and(|mesh| mesh.owns(i)))
        {
            Err(side::<S>(
                "the profile has no native online polynomial prover",
                "the profile has no nested online polynomial prover",
            ))
        } else {
            Ok(Vec::new())
        }
    }

    /// Supplies no witness points, which suffices when none are declared.
    pub(crate) fn points<P: Profile, S: Side, F>() -> Result<Vec<F>> {
        if S::layout::<P>().points == 0 {
            Ok(Vec::new())
        } else {
            Err(side::<S>(
                "the profile has no native online query prover",
                "the profile has no nested online query prover",
            ))
        }
    }
}

#[cfg(test)]
mod layout_tests {
    use super::*;

    const LAYOUT: Layout = Layout {
        polynomials: &[Phase::BeforeW, Phase::BeforeY],
        openings: &[
            Opening {
                polynomial: 0,
                point: Point::Challenge(Challenge::W),
                value: 0,
            },
            Opening {
                polynomial: 0,
                point: Point::Circuit(3),
                value: 1,
            },
            Opening {
                polynomial: 1,
                point: Point::Witness(0),
                value: 0,
            },
        ],
        inputs: 0,
        points: 1,
        values: 2,
    };

    #[test]
    fn repeated_polynomials_and_shared_values_are_valid() -> Result<()> {
        Layout::EMPTY.check()?;
        LAYOUT.check()
    }

    #[test]
    fn malformed_layouts_reject() {
        for layout in [
            Layout {
                points: 0,
                ..LAYOUT
            },
            Layout {
                points: 2,
                ..LAYOUT
            },
            Layout {
                values: 1,
                ..LAYOUT
            },
            Layout {
                values: 3,
                ..LAYOUT
            },
            Layout {
                polynomials: &[Phase::BeforeW],
                ..LAYOUT
            },
            Layout {
                polynomials: &[Phase::BeforeW, Phase::BeforeY, Phase::BeforeX],
                ..LAYOUT
            },
            Layout {
                polynomials: &[Phase::BeforeY, Phase::BeforeW],
                ..LAYOUT
            },
            Layout {
                polynomials: &[Phase::BeforeW],
                ..Layout::EMPTY
            },
        ] {
            assert!(layout.check().is_err(), "accepted {layout:?}");
        }
    }
}

/// Challenges available when preparing a phase of the enclosing step.
///
/// The quotient and evaluation challenges are not available during preparation.
#[derive(Clone, Copy, Debug, Default)]
pub struct PreparationChallenges<F> {
    /// Available after the online input commitments.
    pub w: Option<F>,
    /// Available after the `BeforeY` auxiliary commitments.
    pub y: Option<F>,
    /// Available after the `BeforeX` auxiliary commitments.
    pub x: Option<F>,
}

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
mod source_tests {
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
