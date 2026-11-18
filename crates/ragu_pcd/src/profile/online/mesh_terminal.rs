//! Terminal source-registry closure and explicit mesh intersection openings.

use alloc::vec::Vec;

use ragu_circuits::polynomials::{Rank, sparse};
use ragu_core::{Error, Result};
use udon::field::Field;

use super::{Challenge, Layout, Point, mesh::Mesh, source::SourceRegistry};
use crate::compress::revdot::OpeningClaim;

/// Fuse coordinates in this polynomial field (the prescribed lifts on the nested side).
#[derive(Clone, Copy)]
pub(crate) struct Coordinates<F> {
    pub w: F,
    pub x: F,
    pub y: F,
}
impl Mesh {
    /// Reconstructs the source restrictions needed only during compression.
    /// Retained child polynomials are never replaced this way during fusion.
    pub(crate) fn terminal_polynomials<F: Field, R: Rank>(
        &self,
        source: &SourceRegistry<'_, F>,
        values: &[F],
        coordinates: Coordinates<F>,
    ) -> Result<Vec<sparse::Polynomial<F, R>>> {
        if values.len() != self.claims_len() {
            return Err(Error::InvalidWitness(
                "source mesh metadata length mismatch".into(),
            ));
        }
        let indices = self.coordinate_indices();
        let input = |i| {
            values[indices
                .iter()
                .position(|&j| i == j)
                .expect("declared source coordinate")]
        };
        self.polynomial_indices()
            .into_iter()
            .map(|index| {
                if let Some(r) = self.restrictions().find(|r| r.polynomial == index) {
                    source.xy(input(r.x), input(r.y))
                } else if let Some(h) = self.helpers.iter().find(|h| h.polynomial == index) {
                    source.wx(coordinates.w, input(h.x))
                } else if index == self.u {
                    source.wy(coordinates.w, coordinates.y)
                } else {
                    source.xy(coordinates.x, coordinates.y)
                }
            })
            .collect()
    }

    /// Both ends of every intersection, plus the outgoing restriction at tau.
    /// The commitments are appended once in `polynomial_indices()` order.
    pub(crate) fn terminal_claims<F: Field>(
        &self,
        layout: Layout,
        values: &[F],
        coordinates: Coordinates<F>,
        tau: F,
        outgoing: F,
        offset: usize,
    ) -> Result<Vec<OpeningClaim<F>>> {
        if values.len() != self.claims_len() {
            return Err(Error::InvalidWitness(
                "source mesh metadata length mismatch".into(),
            ));
        }
        let indices = self.coordinate_indices();
        let polynomials = self.polynomial_indices();
        let index = |i| {
            offset
                + polynomials
                    .iter()
                    .position(|&j| i == j)
                    .expect("declared mesh polynomial")
        };
        let mut claims = Vec::new();
        for (j, edge) in self.edges(layout)?.into_iter().enumerate() {
            for opening in edge {
                let point = match opening.point {
                    Point::Challenge(Challenge::W) => coordinates.w,
                    Point::Challenge(Challenge::X) => coordinates.x,
                    Point::Challenge(Challenge::Y) => coordinates.y,
                    Point::Input(i) => {
                        values[indices
                            .iter()
                            .position(|&k| i == k)
                            .expect("mesh coordinate")]
                    }
                    _ => {
                        return Err(Error::Initialization(
                            "unexpected mesh intersection point".into(),
                        ));
                    }
                };
                claims.push(OpeningClaim {
                    poly: index(opening.polynomial),
                    point,
                    value: values[indices.len() + j],
                });
            }
        }
        claims.push(OpeningClaim {
            poly: index(self.outgoing),
            point: tau,
            value: outgoing,
        });
        Ok(claims)
    }
}
