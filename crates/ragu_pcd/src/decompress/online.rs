//! The decompression's registry queries, as the aggregator profile's
//! online batches and source-registry meshes.
//!
//! The native verifier of a compressed proof evaluates the wallet
//! registry $m(W, X, Y)$ itself. Every evaluation it takes is a value of
//! one of nine restrictions $m(W, a, b)$ at some $W$, on each field:
//!
//! - $(r, y_c)$, opened at each internal circuit's $\omega_j$: the claims'
//!   wiring restrictions.
//! - $(x, y)$, opened at each internal circuit's $\omega_j$ for the query
//!   stage's fixed registry, at $w$ for $m(w, x, y)$, at the proof's own
//!   circuit's for its selector, at $u$ for the eval stage's $m(u, x, y)$
//!   and at $w_c$ for the instance's opening.
//! - $(x_l, y_l)$ and $(x_r, y_r)$, opened at $w$: the children's
//!   registries at the proof's $w$.
//! - $(x_l, y)$ and $(x_r, y)$, opened at $w$: the proof's registry at the
//!   children's $x$.
//! - $(x_l, u)$, $(x_r, u)$ and $(u, y)$, opened at $w$: the eval stage's
//!   registry values.
//!
//! Here $w$, $x$, $y$ and $u$ are the decompressed proof's fuse
//! challenges, $x_l$, $y_l$, $x_r$ and $y_r$ its children's, and $r$,
//! $y_c$ and $w_c$ its compression's. A proof folds its own application
//! claim, so no claim's restriction is at its own circuit; the nested side
//! has no circuit of its own.
//!
//! [`MESH`] declares the nine as the restrictions a step introduces, with
//! the two it inherits from its children, and [`NATIVE`] and [`NESTED`]
//! the openings: the mesh's own intersections, then one opening per value
//! above, whose claimed-value wire of the query stage is the evaluation.
//! The step's fuse proves each wire is the committed polynomial's value at
//! its point, and the mesh that the polynomial is the wallet registry's
//! restriction at the coordinates the input stage holds, which the step
//! commits before its challenge. [`Values`] names the wires.
//!
//! Each batch also holds the challenge polynomial $s(X)$ of its field's
//! IPA ([`slot::IPA`]), which no mesh owns. The step commits it before
//! its $y$ and opens it at $y$, and the last value wire is the opening.

use alloc::vec::Vec;

use udon::field::Field;

use crate::{
    internal::{native, nested},
    profile::{
        Profile,
        online::{
            Challenge, Layout, Opening, Phase, Point,
            circuit::Witness,
            mesh::{Helper, Mesh, Restriction},
            stages::Side,
        },
    },
};

/// The input stage's wires: the two children's inherited coordinates,
/// which the fuse fills, then the decompressed proof's coordinates and
/// opening points.
pub(crate) mod input {
    /// The compression's $r$.
    pub const R: usize = 4;
    /// The compression's $y$.
    pub const Y_C: usize = 5;
    /// The fuse's $x$.
    pub const X: usize = 6;
    /// The fuse's $y$.
    pub const Y: usize = 7;
    /// The left child's $x$.
    pub const LEFT_X: usize = 8;
    /// The left child's $y$.
    pub const LEFT_Y: usize = 9;
    /// The right child's $x$.
    pub const RIGHT_X: usize = 10;
    /// The right child's $y$.
    pub const RIGHT_Y: usize = 11;
    /// The fuse's $u$.
    pub const U: usize = 12;
    /// The fuse's $w$.
    pub const W: usize = 13;
    /// The compression's $w$.
    pub const W_C: usize = 14;
    /// The nested side's wires.
    pub const NESTED: usize = 15;
    /// Native side: the proof's own circuit's domain point.
    pub const CIRCUIT: usize = 15;
    /// The native side's wires.
    pub const NATIVE: usize = 16;
}

/// The polynomial slots: the restrictions fixed before $w$, the two
/// inherited first, their helpers, the IPA's challenge polynomial, then
/// $U$ and the outgoing restriction.
pub(crate) mod slot {
    /// $m(W, r, y_c)$.
    pub const CLAIMS: usize = 2;
    /// $m(W, x, y)$.
    pub const XY: usize = 3;
    /// $m(W, x_l, y_l)$.
    pub const LEFT: usize = 4;
    /// $m(W, x_r, y_r)$.
    pub const RIGHT: usize = 5;
    /// $m(W, u, y)$.
    pub const U_Y: usize = 6;
    /// $m(W, x_l, y)$.
    pub const LEFT_Y: usize = 7;
    /// $m(W, x_r, y)$.
    pub const RIGHT_Y: usize = 8;
    /// $m(W, x_l, u)$.
    pub const LEFT_U: usize = 9;
    /// $m(W, x_r, u)$.
    pub const RIGHT_U: usize = 10;
    /// The first helper $T_a(Y) = m(w, a, Y)$.
    pub const HELPERS: usize = 11;
    /// $s(X)$, the challenge polynomial of the IPA over the batch's
    /// field: the host curve's in the native batch and the nested curve's
    /// in the nested batch. Its commitment is that IPA's $G'$.
    pub const IPA: usize = 18;
    /// $U(X) = m(w, X, y)$.
    pub const U: usize = 19;
    /// The outgoing restriction.
    pub const OUTGOING: usize = 20;
}

// The IPA's challenge polynomial is fixed with the helpers, before y. A
// polynomial fixed before w would add a commitment to the other side's
// input stage.
const POLYNOMIALS: [Phase; slot::OUTGOING + 1] = {
    let mut phases = [Phase::BeforeW; slot::OUTGOING + 1];
    let mut i = slot::HELPERS;
    while i < slot::U {
        phases[i] = Phase::BeforeY;
        i += 1;
    }
    phases[slot::U] = Phase::BeforeX;
    phases[slot::OUTGOING] = Phase::BeforeAlpha;
    phases
};

// Each batch opens its IPA's challenge polynomial at the step's y, and the
// side's verifier holds the opening to s(y). That makes the commitment the IPA's G'
// only if the step fixes the polynomial before it draws y.
const _: () = assert!(
    matches!(POLYNOMIALS[slot::IPA], Phase::BeforeW | Phase::BeforeY),
    "the IPA's challenge polynomial is committed before y, where it is opened"
);

const fn restriction(polynomial: usize, x: usize, y: usize, helper: usize) -> Restriction {
    Restriction {
        polynomial,
        x,
        y,
        helper: slot::HELPERS + helper,
    }
}

/// The helpers' coordinates: the children's inherited $x$, then $r$, $x$,
/// the decompressed proof's children's $x$ and $u$.
const HELPERS: [Helper; slot::IPA - slot::HELPERS] = {
    let coordinates = [
        0,
        2,
        input::R,
        input::X,
        input::LEFT_X,
        input::RIGHT_X,
        input::U,
    ];
    let mut helpers = [Helper {
        polynomial: 0,
        x: 0,
    }; slot::IPA - slot::HELPERS];
    let mut i = 0;
    while i < helpers.len() {
        helpers[i] = Helper {
            polynomial: slot::HELPERS + i,
            x: coordinates[i],
        };
        i += 1;
    }
    helpers
};

const INTRODUCED: [Restriction; 9] = [
    restriction(slot::CLAIMS, input::R, input::Y_C, 2),
    restriction(slot::XY, input::X, input::Y, 3),
    restriction(slot::LEFT, input::LEFT_X, input::LEFT_Y, 4),
    restriction(slot::RIGHT, input::RIGHT_X, input::RIGHT_Y, 5),
    restriction(slot::U_Y, input::U, input::Y, 6),
    restriction(slot::LEFT_Y, input::LEFT_X, input::Y, 4),
    restriction(slot::RIGHT_Y, input::RIGHT_X, input::Y, 5),
    restriction(slot::LEFT_U, input::LEFT_X, input::U, 4),
    restriction(slot::RIGHT_U, input::RIGHT_X, input::U, 5),
];

/// The mesh of either side: the children's outgoing restrictions, the
/// nine a step introduces for the proof its extension verifies, the helper
/// of each distinct first coordinate, $U$ and the outgoing restriction.
pub(crate) const MESH: Mesh = Mesh {
    inherited: [restriction(0, 0, 1, 0), restriction(1, 2, 3, 1)],
    introduced: &INTRODUCED,
    helpers: &HELPERS,
    u: slot::U,
    outgoing: slot::OUTGOING,
};

/// The mesh's intersections, each one shared value wire: a restriction
/// with its helper, a helper with $U$, and $U$ with the outgoing
/// restriction.
const EDGES: usize = 2 + INTRODUCED.len() + HELPERS.len() + 1;

/// The enclosing step's y challenge in the query stage, after w.
pub(crate) const QUERY_Y: usize = 1;

/// The query stage's value wires that hold the registry's evaluations, on
/// a side whose standard profile registers `circuits` internal circuits.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct Values {
    /// The internal circuits of the standard profile on this side.
    circuits: usize,
    /// Whether this is the native side, which has the proof's own circuit.
    native: bool,
}

impl Values {
    /// The native side's.
    pub(crate) const NATIVE: Self = Values {
        circuits: native::InternalCircuitIndex::NUM,
        native: true,
    };

    /// The nested side's.
    pub(crate) const NESTED: Self = Values {
        circuits: nested::InternalCircuitIndex::NUM,
        native: false,
    };

    /// $m(\omega_j, r, y_c)$ for internal circuit `j`: a claim's wiring
    /// restriction.
    ///
    /// # Panics
    ///
    /// Panics if `j` is not an internal circuit of the side.
    pub(crate) const fn claim(self, j: usize) -> usize {
        assert!(j < self.circuits, "an internal circuit of the side");
        EDGES + j
    }

    const fn fixed_base(self) -> usize {
        EDGES + self.circuits
    }

    /// $m(\omega_j, x, y)$ for internal circuit `j`: the query stage's
    /// fixed registry.
    ///
    /// # Panics
    ///
    /// Panics if `j` is not an internal circuit of the side.
    pub(crate) const fn fixed(self, j: usize) -> usize {
        assert!(j < self.circuits, "an internal circuit of the side");
        self.fixed_base() + j
    }

    /// $m(w, x, y)$.
    pub(crate) const fn at_w(self) -> usize {
        self.fixed_base() + self.circuits
    }

    /// Native side: $m(\omega, x, y)$ at the proof's own circuit, the
    /// registry selector of the application claim the proof folded itself.
    pub(crate) const fn at_circuit(self) -> usize {
        assert!(self.native, "the native side has the proof's own circuit");
        self.at_w() + 1
    }

    /// $m(u, x, y)$.
    pub(crate) const fn at_u(self) -> usize {
        self.at_w() + 1 + self.native as usize
    }

    /// $m(w_c, x, y)$: the instance's opening of the registry restriction.
    pub(crate) const fn at_w_c(self) -> usize {
        self.at_u() + 1
    }

    /// $m(w, x_l, y_l)$ and $m(w, x_r, y_r)$.
    pub(crate) const fn children(self) -> [usize; 2] {
        [self.at_w_c() + 1, self.at_w_c() + 2]
    }

    /// $m(w, x_l, y)$ and $m(w, x_r, y)$.
    pub(crate) const fn children_y(self) -> [usize; 2] {
        [self.at_w_c() + 3, self.at_w_c() + 4]
    }

    /// $m(w, x_l, u)$ and $m(w, x_r, u)$.
    pub(crate) const fn children_u(self) -> [usize; 2] {
        [self.at_w_c() + 5, self.at_w_c() + 6]
    }

    /// $m(w, u, y)$.
    pub(crate) const fn u_y(self) -> usize {
        self.at_w_c() + 7
    }

    /// $s(y)$: the value of the IPA's challenge polynomial at the
    /// enclosing step's $y$.
    pub(crate) const fn ipa(self) -> usize {
        self.u_y() + 1
    }

    /// The value wires: the mesh's intersections, then the evaluations.
    pub(crate) const fn len(self) -> usize {
        self.ipa() + 1
    }

    /// The wires the query stage's wire binding expects, in the order the
    /// native verifier lists its values: the fixed registry, $m(w, x, y)$,
    /// on the native side the proof's own circuit's restriction, then each
    /// child's registry at $w$ and the proof's registry at its $x$.
    pub(crate) fn query_binding(self) -> Vec<usize> {
        let mut wires: Vec<usize> = (0..self.circuits).map(|j| self.fixed(j)).collect();
        wires.push(self.at_w());
        if self.native {
            wires.push(self.at_circuit());
        }
        for child in 0..2 {
            wires.push(self.children()[child]);
            wires.push(self.children_y()[child]);
        }
        wires
    }

    /// The wires the eval stage's wire binding expects, by position: the
    /// children's registries at $u$, $m(w, u, y)$, nothing for the
    /// accumulator's $a(u)$ and $b(u)$, which the instance holds, and
    /// $m(u, x, y)$.
    pub(crate) const fn eval_binding(self) -> [Option<usize>; 6] {
        let [left, right] = self.children_u();
        [
            Some(left),
            Some(right),
            Some(self.u_y()),
            None,
            None,
            Some(self.at_u()),
        ]
    }

    /// The input stage's wires on this side.
    pub(crate) const fn inputs(self) -> usize {
        if self.native {
            input::NATIVE
        } else {
            input::NESTED
        }
    }

    /// The input stage's values, as the fuse lays the stage out: the
    /// source registry's tag, the inputs, then the other side's
    /// commitments fixed before $w$, two coordinates each.
    pub(crate) const fn input_stage(self) -> usize {
        1 + self.inputs() + 2 * slot::HELPERS
    }

    /// The query stage's values: the step's $w$, $y$ and $x$, then the
    /// claimed values.
    pub(crate) const fn query_stage(self) -> usize {
        3 + self.len()
    }

    /// Where input `index` sits among the input stage's values.
    pub(crate) const fn input_at(index: usize) -> usize {
        1 + index
    }

    /// Where value wire `value` sits among the query stage's values.
    pub(crate) const fn value_at(value: usize) -> usize {
        3 + value
    }

    /// The gates the two stages take at the front of the side's circuits,
    /// after the SYSTEM gate.
    pub(crate) const fn prefix_gates(self) -> usize {
        self.input_stage().div_ceil(2) + self.query_stage().div_ceil(2)
    }

    /// The openings: both ends of each intersection, then one per
    /// evaluation.
    const fn openings(self) -> usize {
        self.len() + EDGES
    }
}

/// The openings of a side in quotient-fold order, `LEN` of them: the mesh's
/// intersections in the order [`Mesh::edges`] lists them, then the
/// evaluations in [`Values`] order.
const fn openings<const LEN: usize>(values: Values) -> [Opening; LEN] {
    assert!(LEN == values.openings(), "one opening per declared end");
    let mut out = [Opening {
        polynomial: 0,
        point: Point::Constant(0),
        value: 0,
    }; LEN];
    let mut next = 0;
    let mut value = 0;

    // A restriction at the step's w meets its helper at the restriction's
    // second coordinate.
    let mut i = 0;
    while i < 2 + INTRODUCED.len() {
        let restriction = if i < 2 {
            MESH.inherited[i]
        } else {
            INTRODUCED[i - 2]
        };
        out[next] = Opening {
            polynomial: restriction.polynomial,
            point: Point::Challenge(Challenge::W),
            value,
        };
        out[next + 1] = Opening {
            polynomial: restriction.helper,
            point: Point::Input(restriction.y),
            value,
        };
        next += 2;
        value += 1;
        i += 1;
    }
    // A helper at the step's y meets U at the helper's coordinate.
    let mut i = 0;
    while i < HELPERS.len() {
        out[next] = Opening {
            polynomial: HELPERS[i].polynomial,
            point: Point::Challenge(Challenge::Y),
            value,
        };
        out[next + 1] = Opening {
            polynomial: slot::U,
            point: Point::Input(HELPERS[i].x),
            value,
        };
        next += 2;
        value += 1;
        i += 1;
    }
    // U at the step's x meets the outgoing restriction at its w.
    out[next] = Opening {
        polynomial: slot::U,
        point: Point::Challenge(Challenge::X),
        value,
    };
    out[next + 1] = Opening {
        polynomial: slot::OUTGOING,
        point: Point::Challenge(Challenge::W),
        value,
    };
    next += 2;
    value += 1;
    assert!(value == EDGES, "one value per intersection");

    // The claims' restrictions: m(W, r, y_c) at each internal circuit. The
    // proof folded its own application claim, so none is at its own.
    let mut j = 0;
    while j < values.circuits {
        out[next] = Opening {
            polynomial: slot::CLAIMS,
            point: Point::Circuit(j as u32),
            value,
        };
        next += 1;
        value += 1;
        j += 1;
    }
    // m(W, x, y): at each internal circuit, at w, on the native side at the
    // proof's own circuit, at u and at the compression's w.
    let mut j = 0;
    while j < values.circuits {
        out[next] = Opening {
            polynomial: slot::XY,
            point: Point::Circuit(j as u32),
            value,
        };
        next += 1;
        value += 1;
        j += 1;
    }
    let points = [input::W, input::CIRCUIT, input::U, input::W_C];
    let mut i = 0;
    while i < points.len() {
        let own = i == 1;
        if values.native || !own {
            out[next] = Opening {
                polynomial: slot::XY,
                point: Point::Input(points[i]),
                value,
            };
            next += 1;
            value += 1;
        }
        i += 1;
    }
    // The seven restrictions the verifier takes one value of, at w.
    let singles = [
        slot::LEFT,
        slot::RIGHT,
        slot::LEFT_Y,
        slot::RIGHT_Y,
        slot::LEFT_U,
        slot::RIGHT_U,
        slot::U_Y,
    ];
    let mut i = 0;
    while i < singles.len() {
        out[next] = Opening {
            polynomial: singles[i],
            point: Point::Input(input::W),
            value,
        };
        next += 1;
        value += 1;
        i += 1;
    }
    // The IPA's challenge polynomial, at the step's y.
    out[next] = Opening {
        polynomial: slot::IPA,
        point: Point::Challenge(Challenge::Y),
        value,
    };
    next += 1;
    value += 1;
    assert!(next == LEN, "every opening is listed");
    assert!(value == values.len(), "every value has an opening");
    out
}

// The compression lays a proof's runs out after the scalar field's online
// stages by a count it keeps for builds without the aggregator.
const _: () = assert!(
    Values::NESTED.prefix_gates() == crate::compress::runs::ONLINE_PREFIX_GATES,
    "the compression's runs follow the scalar field's online stages"
);

const NATIVE_OPENINGS: [Opening; Values::NATIVE.openings()] = openings(Values::NATIVE);
const NESTED_OPENINGS: [Opening; Values::NESTED.openings()] = openings(Values::NESTED);

/// The native side's batch: the mesh's polynomials and the openings of
/// the registry evaluations the circuit-field side reads.
pub(crate) const NATIVE: Layout = Layout {
    polynomials: &POLYNOMIALS,
    openings: &NATIVE_OPENINGS,
    inputs: input::NATIVE,
    points: 0,
    values: Values::NATIVE.len(),
};

/// The nested side's batch, as [`NATIVE`].
pub(crate) const NESTED: Layout = Layout {
    polynomials: &POLYNOMIALS,
    openings: &NESTED_OPENINGS,
    inputs: input::NESTED,
    points: 0,
    values: Values::NESTED.len(),
};

const INDICES: &[u32; 256] = &{
    let mut indices = [0; 256];
    let mut i = 0;
    while i < indices.len() {
        indices[i] = i as u32;
        i += 1;
    }
    indices
};

/// The first `circuits` extension circuits, as a profile names its online
/// consumers: every circuit of a side's extension loads the online stages
/// first.
///
/// # Panics
///
/// Panics, in constant evaluation, past the table's length.
pub(crate) const fn consumers(circuits: usize) -> &'static [u32] {
    INDICES.split_at(circuits).0
}

/// The online input and query stages a step's fuse committed, each
/// stage's values in the order the fuse lays them out, as the side's
/// circuits load them.
pub(crate) fn stages<F: Field, P: Profile, S: Side>(
    witness: &Witness<'_, F, P, S>,
) -> (Vec<F>, Vec<F>) {
    let input = witness
        .inputs
        .source_tag
        .iter()
        .chain(witness.inputs.values.iter())
        .chain(witness.inputs.foreign.iter())
        .copied()
        .collect();
    let query = witness
        .query
        .challenges
        .iter()
        .chain(witness.query.points.iter())
        .chain(witness.query.values.iter())
        .copied()
        .collect();
    (input, query)
}

#[cfg(test)]
mod tests {
    use ragu_circuits::{
        polynomials::AggregatorRank,
        staging::{Stage, StageExt},
    };
    use ragu_core::{
        Result,
        pasta::{Fp, Fq, Pasta},
    };

    use super::*;
    use crate::{
        decompress::{
            side,
            stages::{OnlineInputStage, OnlineQueryStage},
        },
        profile::{
            Aggregator,
            online::stages::{InputStage, Native, Nested, QueryStage},
        },
    };

    /// The side's circuits load the online stages as plain element stages.
    /// They are the fuse's own stages only if they take the same gates at
    /// the same place, for any header size the aggregator is declared at.
    #[test]
    fn the_sides_load_the_online_stages_the_fuse_commits() {
        type P = Aggregator<4>;
        type R = AggregatorRank;
        macro_rules! same {
            ($f:ty, $ours:ty, $fuse:ty, $values:expr) => {
                assert_eq!(<$ours as Stage<$f, R>>::values(), $values);
                assert_eq!(<$fuse as Stage<$f, R>>::values(), $values);
                assert_eq!(
                    <$ours as Stage<$f, R>>::skip_gates(),
                    <$fuse as Stage<$f, R>>::skip_gates()
                );
                assert_eq!(
                    <$ours as StageExt<$f, R>>::num_gates(),
                    <$fuse as StageExt<$f, R>>::num_gates()
                );
            };
        }
        same!(
            Fp,
            OnlineInputStage<Pasta, side::Native, R>,
            InputStage<P, Native>,
            Values::NATIVE.input_stage()
        );
        same!(
            Fp,
            OnlineQueryStage<Pasta, side::Native, R>,
            QueryStage<P, Native>,
            Values::NATIVE.query_stage()
        );
        same!(
            Fq,
            OnlineInputStage<Pasta, side::Nested, R>,
            InputStage<P, Nested>,
            Values::NESTED.input_stage()
        );
        same!(
            Fq,
            OnlineQueryStage<Pasta, side::Nested, R>,
            QueryStage<P, Nested>,
            Values::NESTED.query_stage()
        );
        for (values, query_end) in [
            (
                Values::NATIVE,
                <OnlineQueryStage<Pasta, side::Native, R> as Stage<Fp, R>>::skip_gates()
                    + <OnlineQueryStage<Pasta, side::Native, R> as StageExt<Fp, R>>::num_gates(),
            ),
            (
                Values::NESTED,
                <OnlineQueryStage<Pasta, side::Nested, R> as Stage<Fq, R>>::skip_gates()
                    + <OnlineQueryStage<Pasta, side::Nested, R> as StageExt<Fq, R>>::num_gates(),
            ),
        ] {
            // After the SYSTEM gate.
            assert_eq!(query_end, 1 + values.prefix_gates());
        }
    }

    #[test]
    fn the_layouts_and_the_mesh_are_well_formed() -> Result<()> {
        for layout in [NATIVE, NESTED] {
            MESH.check(layout)?;
            let edges = MESH.edges(layout)?;
            assert_eq!(edges.len(), EDGES);
            // The intersections come first, each on its own value wire.
            for (index, edge) in edges.iter().enumerate() {
                assert_eq!(edge, &layout.openings[2 * index..2 * index + 2]);
                assert_eq!(edge[0].value, index);
            }
        }
        NATIVE.check_circuit_points::<ragu_core::pasta::Fp>()?;
        NESTED.check_circuit_points::<ragu_core::pasta::Fq>()?;
        Ok(())
    }

    #[test]
    fn every_value_is_one_opening_of_its_restriction() {
        for (layout, values) in [(NATIVE, Values::NATIVE), (NESTED, Values::NESTED)] {
            let opening = |value: usize| {
                let mut found = layout.openings.iter().filter(|o| o.value == value);
                let opening = found.next().expect("the value has an opening");
                assert!(found.next().is_none(), "an evaluation is one opening");
                (opening.polynomial, opening.point)
            };
            let at = Point::Input;
            for j in 0..values.circuits {
                let circuit = Point::Circuit(j as u32);
                assert_eq!(opening(values.claim(j)), (slot::CLAIMS, circuit));
                assert_eq!(opening(values.fixed(j)), (slot::XY, circuit));
            }
            assert_eq!(opening(values.at_w()), (slot::XY, at(input::W)));
            assert_eq!(opening(values.at_u()), (slot::XY, at(input::U)));
            assert_eq!(opening(values.at_w_c()), (slot::XY, at(input::W_C)));
            for (wires, slots) in [
                (values.children(), [slot::LEFT, slot::RIGHT]),
                (values.children_y(), [slot::LEFT_Y, slot::RIGHT_Y]),
                (values.children_u(), [slot::LEFT_U, slot::RIGHT_U]),
            ] {
                for (wire, slot) in wires.into_iter().zip(slots) {
                    assert_eq!(opening(wire), (slot, at(input::W)));
                }
            }
            assert_eq!(opening(values.u_y()), (slot::U_Y, at(input::W)));
            if values.native {
                assert_eq!(opening(values.at_circuit()), (slot::XY, at(input::CIRCUIT)));
            }
            assert_eq!(
                opening(values.ipa()),
                (slot::IPA, Point::Challenge(Challenge::Y))
            );
            assert_eq!(layout.values, values.len());
        }
    }

    #[test]
    fn each_restriction_holds_the_coordinates_the_verifier_evaluates_at() {
        let coordinates = |polynomial: usize| {
            let restriction = MESH
                .introduced
                .iter()
                .find(|r| r.polynomial == polynomial)
                .expect("an introduced restriction");
            (restriction.x, restriction.y)
        };
        assert_eq!(coordinates(slot::CLAIMS), (input::R, input::Y_C));
        assert_eq!(coordinates(slot::XY), (input::X, input::Y));
        assert_eq!(coordinates(slot::LEFT), (input::LEFT_X, input::LEFT_Y));
        assert_eq!(coordinates(slot::RIGHT), (input::RIGHT_X, input::RIGHT_Y));
        assert_eq!(coordinates(slot::U_Y), (input::U, input::Y));
        assert_eq!(coordinates(slot::LEFT_Y), (input::LEFT_X, input::Y));
        assert_eq!(coordinates(slot::RIGHT_Y), (input::RIGHT_X, input::Y));
        assert_eq!(coordinates(slot::LEFT_U), (input::LEFT_X, input::U));
        assert_eq!(coordinates(slot::RIGHT_U), (input::RIGHT_X, input::U));
    }
}
