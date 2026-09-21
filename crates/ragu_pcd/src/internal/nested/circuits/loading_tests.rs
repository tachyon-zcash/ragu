//! Review R05: exact equality of Loading's linear relation space to an
//! independently named route inventory, plus its compiled registry entry.
//! No point witnesses are needed: this is an identity of linear maps, not a
//! rank-only check or a test at coincident point coordinates.

use alloc::{collections::BTreeMap, format, string::String, vec, vec::Vec};

use ragu_arithmetic::{Coeff, ff::Field};
use ragu_circuits::{
    Circuit as _,
    polynomials::{ProductionRank, Rank},
    registry::{CircuitIndex, RegistryBuilder},
    staging::MultiStage,
};
use ragu_core::{
    Result,
    drivers::{Driver, DriverTypes, LinearExpression},
    maybe::Empty,
};
use ragu_pasta::{EqAffine, Fq, Pasta};

use super::Circuit;
use crate::internal::{
    nested::{self, PointsStage, stages},
    stage_wires::{stage_wire_indices, wires_of},
};

type R = ProductionRank;
type Row = BTreeMap<usize, Fq>;

#[derive(Clone)]
enum Wire {
    Coordinate(usize),
    Sum(Row),
}

struct Expression {
    row: Row,
    gain: Fq,
}

impl Default for Expression {
    fn default() -> Self {
        Self {
            row: Row::new(),
            gain: Fq::ONE,
        }
    }
}

fn add(row: &mut Row, column: usize, coefficient: Fq) {
    let value = row.entry(column).or_insert(Fq::ZERO);
    *value += coefficient;
    if *value == Fq::ZERO {
        row.remove(&column);
    }
}

impl LinearExpression<Wire, Fq> for Expression {
    fn add_term(mut self, wire: &Wire, coeff: Coeff<Fq>) -> Self {
        let scale = self.gain * coeff.value();
        match wire {
            Wire::Coordinate(column) => add(&mut self.row, *column, scale),
            Wire::Sum(row) => {
                for (&column, &value) in row {
                    add(&mut self.row, column, scale * value);
                }
            }
        }
        self
    }

    fn gain(mut self, coeff: Coeff<Fq>) -> Self {
        self.gain *= coeff.value();
        self
    }
}

/// Columns are coefficients of s(X,Y), dual to trace coefficients under
/// revdot: a[g] -> 2n+g, d[g] -> g. Gate zero belongs to the system.
struct Recorder {
    gates: usize,
    rows: Vec<Row>,
}

impl DriverTypes for Recorder {
    type ImplField = Fq;
    type ImplWire = Wire;
    type MaybeKind = Empty;
    type LCadd = Expression;
    type LCenforce = Expression;
    type Extra = usize;

    fn gate(
        &mut self,
        _: impl Fn() -> Result<(Coeff<Fq>, Coeff<Fq>, Coeff<Fq>)>,
    ) -> Result<(Wire, Wire, Wire, usize)> {
        let g = self.gates;
        self.gates += 1;
        Ok((
            Wire::Coordinate(2 * R::n() + g),
            Wire::Coordinate(2 * R::n() - 1 - g),
            Wire::Coordinate(4 * R::n() - 1 - g),
            g,
        ))
    }

    fn assign_extra(&mut self, g: usize, _: impl Fn() -> Result<Coeff<Fq>>) -> Result<Wire> {
        Ok(Wire::Coordinate(g))
    }
}

impl<'dr> Driver<'dr> for Recorder {
    type F = Fq;
    type Wire = Wire;
    const ONE: Wire = Wire::Coordinate(0);

    fn add(&mut self, lc: impl Fn(Expression) -> Expression) -> Wire {
        Wire::Sum(lc(Expression::default()).row)
    }

    fn enforce_zero(&mut self, lc: impl Fn(Expression) -> Expression) -> Result<()> {
        self.rows.push(lc(Expression::default()).row);
        Ok(())
    }
}

fn recorded_rows() -> Result<Vec<Row>> {
    let circuit = MultiStage::new(Circuit::<EqAffine, R>::new());
    let mut recorder = Recorder {
        gates: 1,
        rows: Vec::new(),
    };
    circuit.witness(&mut recorder, Empty)?;
    let counts = ragu_circuits::testing::synthesis_counts(&circuit)?;
    assert_eq!(recorder.gates, counts.num_gates);
    assert_eq!(recorder.rows.len() + 1, counts.num_constraints);
    Ok(recorder.rows)
}

pub(crate) struct Route {
    name: String,
    pub(crate) destination: usize,
    pub(crate) source: usize,
}

impl Route {
    fn row(&self) -> Row {
        assert_ne!(
            self.destination, self.source,
            "{} is a tautology",
            self.name
        );
        Row::from([(self.destination, Fq::ONE), (self.source, -Fq::ONE)])
    }
}

/// Semantic stage-wire routes, also used by the point-contract attacks to
/// preserve Loading while assigning off-curve coordinates.
pub(crate) fn stage_routes() -> Result<Vec<Route>> {
    // Deliberately name fields directly: neither RxIndex::ALL, ChildOutput's
    // Index implementation nor the accumulation walker supplies this order.
    let mut names = Vec::new();
    let mut sources = stage_wire_indices::<Fq, R, stages::preamble::Stage<EqAffine, R>>(|out| {
        let mut sources = Vec::new();
        for (side, child) in [("left", &out.left), ("right", &out.right)] {
            let mut point = |name: &str, p| -> Result<()> {
                names.push(format!("{side}.{name}"));
                sources.extend(wires_of(p)?);
                Ok(())
            };
            point("application", &child.application)?;
            point("hashes_1", &child.hashes_1)?;
            point("hashes_2", &child.hashes_2)?;
            point("inner_collapse", &child.inner_collapse)?;
            point("outer_collapse", &child.outer_collapse)?;
            point("compute_v", &child.compute_v)?;
            for k in 0..5 {
                point(&format!("bind_challenges[{k}]"), &child.bind_challenges[k])?;
            }
            point("bind_beta", &child.bind_beta)?;
            point("bind_endoscalar", &child.bind_endoscalar)?;
            for k in 0..25 {
                point(
                    &format!("endoscaling_steps[{k}]"),
                    &child.endoscaling_steps[k],
                )?;
            }
            point("stashed_preamble", &child.stashed_preamble)?;
            point("stashed_inner_error", &child.stashed_inner_error)?;
            point("stashed_outer_error", &child.stashed_outer_error)?;
            point("stashed_query", &child.stashed_query)?;
            point("stashed_eval", &child.stashed_eval)?;
            point("stashed_points_binding", &child.stashed_points_binding)?;
            point("stashed_points_children", &child.stashed_points_children)?;
            point(
                "stashed_points_registry_wx",
                &child.stashed_points_registry_wx,
            )?;
            point("stashed_points_ab", &child.stashed_points_ab)?;
            point("stashed_points_f", &child.stashed_points_f)?;
            point("points_walk", &child.points_walk)?;
            point("stashed_ab_a", &child.stashed_ab_a)?;
            point("stashed_ab_b", &child.stashed_ab_b)?;
            point("stashed_registry_xy", &child.stashed_registry_xy)?;
            point("stashed_p", &child.stashed_p)?;
        }
        Ok(sources)
    })?;
    macro_rules! current {
        ($stage:ident, $($field:ident),+ $(,)?) => {
            sources.extend(stage_wire_indices::<Fq, R, stages::$stage::Stage<EqAffine, R>>(|out| {
                let mut wires = Vec::new();
                $(names.push(format!("{}.{}", stringify!($stage), stringify!($field)));
                wires.extend(wires_of(&out.$field)?);)+
                Ok(wires)
            })?);
        };
    }
    current!(s_prime, registry_wx0, registry_wx1);
    current!(inner_error, registry_wy);
    current!(ab, a, b);
    current!(query, registry_xy);
    current!(f, native_f);
    let destinations = stage_wire_indices::<Fq, R, PointsStage<EqAffine>>(|out| {
        let mut wires = wires_of(&out.inputs)?;
        wires.extend(wires_of(&out.initial)?);
        Ok(wires)
    })?;
    assert_eq!(names.len(), 113);
    assert_eq!(sources.len(), 226);
    assert_eq!(destinations.len(), 226);

    Ok(destinations
        .into_iter()
        .zip(sources)
        .enumerate()
        .map(|(i, (dst, src))| Route {
            name: format!(
                "{} <- {}.{}",
                if i < 224 {
                    format!("inputs[{}]", i / 2)
                } else {
                    "initial".into()
                },
                names[i / 2],
                if i % 2 == 0 { "x" } else { "y" }
            ),
            destination: dst,
            source: src,
        })
        .collect())
}

fn routes() -> Result<Vec<Route>> {
    // Independent reservation-to-wiring placement, without wire_degree (which
    // maps to the opposite, trace side of revdot).
    let degree = |index: usize| {
        1 + index / 2
            + if index.is_multiple_of(2) {
                2 * R::n()
            } else {
                0
            }
    };
    Ok(stage_routes()?
        .into_iter()
        .map(|route| Route {
            name: route.name,
            destination: degree(route.destination),
            source: degree(route.source),
        })
        .collect())
}

fn reduce(mut row: Row, basis: &BTreeMap<usize, Row>) -> Row {
    for (&pivot, vector) in basis {
        if let Some(scale) = row.get(&pivot).copied() {
            for (&column, &value) in vector {
                add(&mut row, column, -scale * value);
            }
        }
    }
    row
}

fn basis(rows: &[Row]) -> BTreeMap<usize, Row> {
    let mut basis = BTreeMap::new();
    for row in rows {
        let mut row = reduce(row.clone(), &basis);
        if let Some((&pivot, &value)) = row.first_key_value() {
            let inverse = value.invert().unwrap();
            for coefficient in row.values_mut() {
                *coefficient *= inverse;
            }
            basis.insert(pivot, row);
        }
    }
    basis
}

#[test]
fn loading_has_exact_coordinate_relation_space() -> Result<()> {
    let routes = routes()?;
    let rows = recorded_rows()?;
    assert_eq!(rows.len(), 226);
    let actual = basis(&rows);
    assert_eq!(actual.len(), 226);
    let expected = basis(&routes.iter().map(Route::row).collect::<Vec<_>>());
    assert_eq!(expected.len(), 226);
    for route in &routes {
        assert!(
            reduce(route.row(), &actual).is_empty(),
            "missing route: {}",
            route.name
        );
    }
    for (i, row) in rows.into_iter().enumerate() {
        assert!(
            reduce(row, &expected).is_empty(),
            "unexpected relation at row {i}"
        );
    }
    Ok(())
}

#[test]
fn loading_relation_oracle_detects_every_coordinate_mutation() -> Result<()> {
    let routes = routes()?;
    let rows: Vec<_> = routes.iter().map(Route::row).collect();
    let expected = basis(&rows);
    // Invertible row operations preserve the relation, even though raw rows
    // change: add row 1 to row 0, rescale it, then reverse emission order.
    let mut equivalent = rows.clone();
    for (&column, &value) in &rows[1] {
        add(&mut equivalent[0], column, value);
    }
    for value in equivalent[0].values_mut() {
        *value *= Fq::from(7);
    }
    equivalent.reverse();
    let equivalent = basis(&equivalent);
    assert_eq!(equivalent.len(), 226);
    assert!(
        rows.iter()
            .all(|row| reduce(row.clone(), &equivalent).is_empty())
    );

    for i in 0..rows.len() {
        let mut deleted = rows.clone();
        deleted.remove(i);
        assert!(
            !reduce(rows[i].clone(), &basis(&deleted)).is_empty(),
            "deletion: {}",
            routes[i].name
        );

        // Adjacent swaps touch x/y pairs, point and child boundaries, and
        // current-step boundaries; wraparound also touches initial -> input0.
        let j = (i + 1) % rows.len();
        let mut swapped = rows.clone();
        swapped[i] = Row::from([
            (routes[i].destination, Fq::ONE),
            (routes[j].source, -Fq::ONE),
        ]);
        swapped[j] = Row::from([
            (routes[j].destination, Fq::ONE),
            (routes[i].source, -Fq::ONE),
        ]);
        assert_eq!(
            basis(&swapped).len(),
            226,
            "a rank-only oracle would miss this swap"
        );
        assert!(
            !reduce(swapped[i].clone(), &expected).is_empty(),
            "swap: {}",
            routes[i].name
        );
        let mut perturbed = rows[i].clone();
        *perturbed.get_mut(&routes[i].source).unwrap() *= Fq::from(2);
        assert!(
            !reduce(perturbed, &expected).is_empty(),
            "coefficient: {}",
            routes[i].name
        );
        // An all-equal numerical fixture also misses every such swap.
        assert!(
            swapped
                .iter()
                .all(|row| row.values().copied().sum::<Fq>() == Fq::ZERO)
        );
    }
    Ok(())
}

#[test]
fn loading_compiled_registry_entry_matches_recorded_relations() -> Result<()> {
    let rows = recorded_rows()?;
    assert_eq!(rows.len(), 226);
    let isolated = RegistryBuilder::<Fq, R>::new()
        .register_bonding(MultiStage::new(Circuit::<EqAffine, R>::new()).into_bonding_object()?)
        .finalize()?;
    let registered = nested::register_all::<Pasta, R>(RegistryBuilder::new())?.finalize()?;

    // The raw circuit has these 226 rows plus the system ONE row, stripped
    // by into_bonding_object. After removing the known registry key monomial,
    // its Y degree is <=226. Comparing all X coefficients at 227 distinct
    // field points establishes polynomial identity, with no random challenge.
    for y in (0..=226).map(Fq::from) {
        let mut expected = vec![Fq::ZERO; R::num_coeffs()];
        let mut weight = y;
        for row in rows.iter().rev() {
            for (&column, &value) in row {
                expected[column] += weight * value;
            }
            weight *= y;
        }
        for (registry, index) in [
            (&isolated, CircuitIndex::new(0)),
            (
                &registered,
                nested::InternalCircuitIndex::Loading.circuit_index(),
            ),
        ] {
            let mut actual: Vec<_> = registry.circuit_y(index, y).iter_coeffs().collect();
            actual[R::num_coeffs() - 1] -=
                registry.tag() * y.pow_vartime([(R::num_coeffs() - 1) as u64]);
            assert_eq!(actual.len(), expected.len());
            for (column, (actual, expected)) in actual.iter().zip(&expected).enumerate() {
                assert_eq!(
                    actual, expected,
                    "compiled Loading X^{column} at y={y:?}, index={index:?}"
                );
            }
        }
    }
    Ok(())
}
