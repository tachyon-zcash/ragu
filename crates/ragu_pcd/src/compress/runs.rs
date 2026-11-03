//! The runs of scalar-field values the compression's transcript commits,
//! and where it commits them.
//!
//! The transcript runs over the circuit field, so it absorbs the scalar
//! field's values, the host curve's points and the nested curve's scalars,
//! as one nested-curve point per run of them: the run's commitment,
//! unblinded, at the generators the run's stage lands its values on in the
//! proof's decompression at the aggregator rank. Every compressed proof
//! commits its runs there, whether or not an aggregator decompresses it, so
//! that the aggregator's circuits can hold each absorbed point to its
//! stage; the Standard tables carry those generators past their end
//! (`pasta::STAGE_REACH`).

use alloc::{vec, vec::Vec};

use ragu_circuits::polynomials::{AggregatorRank, Rank};
use ragu_core::{Error, Result};

use super::{instance::OPENED, revdot::fold::Derived};
use crate::{
    internal::native,
    ipa::IpaCycle,
    profile::{Profile, ProfiledCycle},
};

/// The native commitments a proof in profile `P` lists, then its native
/// registry restriction's and $p$'s: the host-curve points the
/// scalar-field side's instance holds.
pub(crate) fn native_points_of<P: Profile>() -> usize {
    2 + native::RxIndex::num::<P>() + 2
}

/// The scalar field's values a proof's instance carries, which the
/// [`Scalars`](Run::Scalars) run holds.
pub(crate) const NESTED_SCALARS: usize = 9;

/// A run of scalar-field values the compression's transcript commits as
/// one point: the host curve's points and the nested curve's scalars
/// absorbed in a row, which the next circuit-field absorption or challenge
/// ends, in absorption order (see
/// [`CycleTranscript`](crate::ipa::CycleTranscript)). The instance's two
/// runs come before the sampled challenges, the host reduction's before
/// each of its challenges that a point precedes, and the nested
/// reduction's before each of its challenges that scalars precede; its
/// IPA's $c$ precedes no challenge and is never absorbed. Each run is a
/// stage of the scalar-field side of the proof's decompression.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Run {
    /// The host commitments the instance lists, its registry restriction's
    /// and $p$'s.
    Commitments,
    /// The scalar field's instance values.
    Scalars,
    /// The host reduction's inner error commitment.
    Inner,
    /// Its outer error commitment.
    Outer,
    /// Its $p$ and $q$.
    Split,
    /// Its batch's $f$.
    F,
    /// Its IPA's $\[S\]$.
    SCommitment,
    /// Its IPA's $j$-th round, $L_j$ then $R_j$.
    Round(usize),
    /// The nested reduction's two $\varepsilon$.
    Epsilons,
    /// Its derived openings, $p(1/r)$ and $q(r)$.
    Openings,
    /// Its batch's values.
    Evaluations,
}

/// The runs of a proof at rank `K`, in absorption order.
pub(crate) fn runs<K: Rank>() -> Vec<Run> {
    let mut runs = vec![
        Run::Commitments,
        Run::Scalars,
        Run::Inner,
        Run::Outer,
        Run::Split,
        Run::F,
        Run::SCommitment,
    ];
    runs.extend((0..K::RANK as usize).map(Run::Round));
    runs.extend([Run::Epsilons, Run::Openings, Run::Evaluations]);
    assert_eq!(runs.len(), num_runs::<K>());
    runs
}

/// The number of runs of a proof at rank `K`: [`runs`]'s length, one per
/// round of the host curve's IPA and ten besides.
pub(crate) const fn num_runs<K: Rank>() -> usize {
    10 + K::RANK as usize
}

impl Run {
    /// The run's stage shape in a proof of profile `P`: the points, then
    /// the elements, it holds.
    pub(crate) fn shape<P: Profile>(self) -> StageShape {
        let points = |points| StageShape {
            points,
            elements: 0,
        };
        let elements = |elements| StageShape {
            points: 0,
            elements,
        };
        match self {
            Run::Commitments => points(native_points_of::<P>()),
            Run::Scalars => elements(NESTED_SCALARS),
            Run::Inner | Run::Outer | Run::F | Run::SCommitment => points(1),
            Run::Split | Run::Round(_) => points(2),
            Run::Epsilons => elements(2),
            Run::Openings => elements(Derived::ALL.len() + 2),
            Run::Evaluations => elements(Derived::ALL.len() + 2 + OPENED),
        }
    }
}

/// A stage's size: its points and its elements.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct StageShape {
    pub points: usize,
    pub elements: usize,
}

impl StageShape {
    /// The stage's wires: two per point, one per element.
    pub(crate) const fn values(self) -> usize {
        2 * self.points + self.elements
    }

    /// The stage's gates: two wires each.
    pub(crate) const fn gates(self) -> usize {
        self.values().div_ceil(2)
    }
}

/// The generators the wires of a stage of `shape` land on at rank `R`
/// after `skip` gates, the SYSTEM gate among them: each point's $x$ and
/// $y$, then each element, two wires per gate in order, the even wire of
/// a gate at $2n - 1 - g$ and the odd at $4n - 1 - g$, as
/// `StageExt::rx` places a stage's values and `wire_degree` numbers
/// them.
pub(crate) fn shape_degrees<R: Rank>(
    skip: usize,
    shape: StageShape,
) -> (Vec<[usize; 2]>, Vec<usize>) {
    let degree = |wire: usize| {
        let gate = skip + wire / 2;
        if wire.is_multiple_of(2) {
            2 * R::n() - 1 - gate
        } else {
            4 * R::n() - 1 - gate
        }
    };
    let points = (0..shape.points)
        .map(|p| [degree(2 * p), degree(2 * p + 1)])
        .collect();
    let elements = (0..shape.elements)
        .map(|e| degree(2 * shape.points + e))
        .collect();
    (points, elements)
}

/// The gates each stage of a chain of `shapes` skips: the SYSTEM gate,
/// then every earlier stage's.
pub(crate) fn chain_skips(shapes: &[StageShape]) -> Vec<usize> {
    let mut skip = 1;
    shapes
        .iter()
        .map(|shape| {
            let own = skip;
            skip += shape.gates();
            own
        })
        .collect()
}

/// The generators each run's stage of the scalar-field side lands its
/// values on at rank `R`, for a proof of profile `P` at rank `K`, by run,
/// in the run's absorption order: each point's $x$ and $y$, then each
/// element. The run stages open that side's stage chain. What the
/// compression's transcript commits a run at ([`run_bases`]) and the
/// circuit-field side holds the absorbed point to through the run stage's
/// commitment.
pub(crate) fn run_degrees<P: Profile, K: Rank, R: Rank>() -> Vec<Vec<usize>> {
    let shapes: Vec<StageShape> = runs::<K>().into_iter().map(Run::shape::<P>).collect();
    chain_skips(&shapes)
        .into_iter()
        .zip(shapes)
        .map(|(skip, shape)| {
            let (points, elements) = shape_degrees::<R>(skip, shape);
            points.into_iter().flatten().chain(elements).collect()
        })
        .collect()
}

/// The nested generators the compression's transcript commits each run of
/// a proof at rank `K` in the profile of `C` at: the generators the run's
/// stage lands its values on in the proof's decompression at the
/// aggregator rank ([`run_degrees`]), in absorption order. A profile's
/// runs are laid out whether or not its decompression exists.
///
/// # Errors
///
/// Fails if `params` reaches no generator at a run's position: the
/// Standard tables stop short of the aggregator rank's, and
/// [`IpaCycle::nested_generator`] supplies the baked reach past them.
pub(crate) fn run_bases<C: IpaCycle + ProfiledCycle, K: Rank>(
    params: &C::Params,
) -> Result<Vec<Vec<C::NestedCurve>>> {
    run_degrees::<C::Profile, K, AggregatorRank>()
        .into_iter()
        .map(|degrees| {
            degrees
                .into_iter()
                .map(|degree| {
                    C::nested_generator(params, degree).ok_or_else(|| {
                        Error::Initialization(
                            alloc::format!(
                                "the parameters stop short of nested generator {degree}, which a run of the compression's transcript lands on at the aggregator rank"
                            )
                            .into(),
                        )
                    })
                })
                .collect()
        })
        .collect()
}
