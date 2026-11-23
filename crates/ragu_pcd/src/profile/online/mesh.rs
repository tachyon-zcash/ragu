//! Fixed registry-mesh slots and the shared opening values joining them.
//!
//! This declaration is shape only. The source registry and its tag are captured
//! separately by setup; the parent binds inherited points and coordinates.
//!
//! The terminal check closes the mesh over the source registry and opens each
//! intersection explicitly; compression runs it.

use alloc::vec::Vec;

use ragu_circuits::polynomials::{Rank, sparse};
use ragu_core::{Error, Result};
use udon::field::Field;

use super::{Challenge, Layout, Phase, Point, SourceRegistry};
use crate::compress::revdot::OpeningClaim;

/// A pre-w restriction m(W,a,b) and the early wires defining (a,b).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Restriction {
    /// Its distinct-polynomial slot, fixed before w.
    pub polynomial: usize,
    /// Input-stage coordinate a.
    pub x: usize,
    /// Input-stage coordinate b.
    pub y: usize,
    /// The polynomial slot of T_a(Y)=m(w,a,Y).
    pub helper: usize,
}

/// One intermediate restriction T_a(Y), shared only by declared coordinate wires.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Helper {
    /// Its polynomial slot, fixed before y.
    pub polynomial: usize,
    /// Input-stage coordinate a, shared with the restrictions using this helper.
    pub x: usize,
}

/// One source-registry identity accumulator on a field.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Mesh {
    /// The left and right children's outgoing restrictions, in that order.
    pub inherited: [Restriction; 2],
    /// Additional restriction identities introduced by this step.
    pub introduced: &'static [Restriction],
    /// Every T_a used by either inherited or introduced restrictions.
    pub helpers: &'static [Helper],
    /// U(X)=m(w,X,y), fixed before x.
    pub u: usize,
    /// R_out(W)=m(W,x,y), fixed before alpha and retained for the parent.
    pub outgoing: usize,
}
impl Mesh {
    /// Early coordinates followed by one value for each mesh intersection.
    pub fn claims_len(&self) -> usize {
        self.coordinate_indices().len() + self.restrictions().count() + self.helpers.len() + 1
    }

    /// Selects the committed wires shared by the helper and terminal targets.
    ///
    /// # Errors
    ///
    /// Rejects an invalid layout or a witness with the wrong fixed lengths.
    pub(crate) fn claim_values<T: Clone>(
        &self,
        layout: Layout,
        inputs: &[T],
        values: &[T],
    ) -> Result<alloc::vec::Vec<T>> {
        if inputs.len() != layout.inputs || values.len() != layout.values {
            return Err(Error::InvalidWitness(
                "mesh witness length does not match its layout".into(),
            ));
        }
        Ok(self
            .coordinate_indices()
            .into_iter()
            .map(|i| inputs[i].clone())
            .chain(
                self.edges(layout)?
                    .into_iter()
                    .map(|edge| values[edge[0].value].clone()),
            )
            .collect())
    }

    /// The two children's coordinates from the common helper metadata.
    ///
    /// The caller must supply `claims_len()` values from a checked layout.
    pub(crate) fn inherited_values<T: Clone>(&self, values: &[T]) -> [T; 4] {
        let indices = self.coordinate_indices();
        self.inherited_coordinates().map(|i| {
            values[indices
                .iter()
                .position(|&j| j == i)
                .expect("inherited coordinate")]
            .clone()
        })
    }

    /// Every pre-w restriction, with inherited entries first.
    pub fn restrictions(&self) -> impl Iterator<Item = &Restriction> {
        self.inherited.iter().chain(self.introduced)
    }
    /// Checks phases, disjoint polynomial slots and every shared intersection.
    ///
    /// # Errors
    ///
    /// Rejects missing intersections, aliased slots, incorrect deadlines and
    /// inherited coordinates that do not have separate early input wires.
    pub fn check(&self, layout: Layout) -> Result<()> {
        layout.check()?;
        fn edge(layout: Layout, a: (usize, Point), b: (usize, Point)) -> bool {
            layout.openings.iter().any(|left| {
                (left.polynomial, left.point) == a
                    && layout.openings.iter().any(|right| {
                        (right.polynomial, right.point) == b && left.value == right.value
                    })
            })
        }
        let phase = |slot, expected| layout.polynomials.get(slot) == Some(&expected);
        let mut used = alloc::vec::Vec::new();
        let mut reserve = |slot| {
            if used.contains(&slot) {
                false
            } else {
                used.push(slot);
                true
            }
        };
        let valid = self.restrictions().all(|restriction| {
            phase(restriction.polynomial, Phase::BeforeW)
                && reserve(restriction.polynomial)
                && restriction.x < layout.inputs
                && restriction.y < layout.inputs
                && self.helpers.iter().any(|helper| {
                    helper.polynomial == restriction.helper && helper.x == restriction.x
                })
                && edge(
                    layout,
                    (restriction.polynomial, Point::Challenge(Challenge::W)),
                    (restriction.helper, Point::Input(restriction.y)),
                )
        }) && self.helpers.iter().all(|helper| {
            phase(helper.polynomial, Phase::BeforeY)
                && reserve(helper.polynomial)
                && helper.x < layout.inputs
                && self
                    .restrictions()
                    .any(|restriction| restriction.helper == helper.polynomial)
                && edge(
                    layout,
                    (helper.polynomial, Point::Challenge(Challenge::Y)),
                    (self.u, Point::Input(helper.x)),
                )
        }) && phase(self.u, Phase::BeforeX)
            && reserve(self.u)
            && phase(self.outgoing, Phase::BeforeAlpha)
            && reserve(self.outgoing)
            && edge(
                layout,
                (self.u, Point::Challenge(Challenge::X)),
                (self.outgoing, Point::Challenge(Challenge::W)),
            );
        if !valid {
            return Err(Error::Initialization(
                "the source-registry mesh declaration is not well formed".into(),
            ));
        }
        // The two children's coordinates must have separate early wires. New
        // restrictions may intentionally reuse those authenticated coordinates.
        let coordinates = [
            self.inherited[0].x,
            self.inherited[0].y,
            self.inherited[1].x,
            self.inherited[1].y,
        ];
        if coordinates
            .iter()
            .enumerate()
            .any(|(i, v)| coordinates[..i].contains(v))
        {
            return Err(Error::Initialization(
                "inherited mesh coordinates must occupy distinct input wires".into(),
            ));
        }
        Ok(())
    }
    /// Distinct mesh polynomial slots in the enclosing commitment-fold order.
    pub fn polynomial_indices(&self) -> alloc::vec::Vec<usize> {
        let mut indices: alloc::vec::Vec<_> = self
            .restrictions()
            .map(|r| r.polynomial)
            .chain(self.helpers.iter().map(|h| h.polynomial))
            .chain([self.u, self.outgoing])
            .collect();
        indices.sort_unstable();
        indices.dedup();
        indices
    }

    /// The early coordinate wires exported for terminal mesh openings.
    ///
    /// Each input index appears once, in input-stage order. Coincident field
    /// values do not alias independently declared wires.
    pub fn coordinate_indices(&self) -> alloc::vec::Vec<usize> {
        let mut indices: alloc::vec::Vec<_> =
            self.restrictions().flat_map(|r| [r.x, r.y]).collect();
        indices.sort_unstable();
        indices.dedup();
        indices
    }

    /// Shared intersection pairs in restriction, helper and outgoing order.
    ///
    /// Each pair uses one claimed-value wire. Repeated polynomial slots retain
    /// their original indices, so terminal openings need not duplicate them.
    ///
    /// # Errors
    ///
    /// Rejects an invalid declaration or a pair without a shared value wire.
    pub fn edges(&self, layout: Layout) -> Result<alloc::vec::Vec<[super::Opening; 2]>> {
        self.check(layout)?;
        self.restrictions()
            .map(|r| {
                (
                    (r.polynomial, Point::Challenge(Challenge::W)),
                    (r.helper, Point::Input(r.y)),
                )
            })
            .chain(self.helpers.iter().map(|h| {
                (
                    (h.polynomial, Point::Challenge(Challenge::Y)),
                    (self.u, Point::Input(h.x)),
                )
            }))
            .chain([(
                (self.u, Point::Challenge(Challenge::X)),
                (self.outgoing, Point::Challenge(Challenge::W)),
            )])
            .map(|(a, b)| {
                layout
                    .openings
                    .iter()
                    .find_map(|left| {
                        if (left.polynomial, left.point) != a {
                            return None;
                        }
                        layout
                            .openings
                            .iter()
                            .find(|right| {
                                (right.polynomial, right.point) == b && right.value == left.value
                            })
                            .map(|right| [*left, *right])
                    })
                    .ok_or_else(|| {
                        Error::Initialization("missing source-registry intersection".into())
                    })
            })
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::profile::online::Opening;

    const HELPERS: &[Helper] = &[
        Helper {
            polynomial: 3,
            x: 0,
        },
        Helper {
            polynomial: 4,
            x: 2,
        },
    ];
    const MESH: Mesh = Mesh {
        inherited: [
            Restriction {
                polynomial: 0,
                x: 0,
                y: 1,
                helper: 3,
            },
            Restriction {
                polynomial: 1,
                x: 2,
                y: 3,
                helper: 4,
            },
        ],
        introduced: &[Restriction {
            polynomial: 2,
            x: 0,
            y: 4,
            helper: 3,
        }],
        helpers: HELPERS,
        u: 5,
        outgoing: 6,
    };
    const OPENINGS: &[Opening] = &[
        Opening {
            polynomial: 0,
            point: Point::Challenge(Challenge::W),
            value: 0,
        },
        Opening {
            polynomial: 3,
            point: Point::Input(1),
            value: 0,
        },
        Opening {
            polynomial: 1,
            point: Point::Challenge(Challenge::W),
            value: 1,
        },
        Opening {
            polynomial: 4,
            point: Point::Input(3),
            value: 1,
        },
        Opening {
            polynomial: 2,
            point: Point::Challenge(Challenge::W),
            value: 2,
        },
        Opening {
            polynomial: 3,
            point: Point::Input(4),
            value: 2,
        },
        Opening {
            polynomial: 3,
            point: Point::Challenge(Challenge::Y),
            value: 3,
        },
        Opening {
            polynomial: 5,
            point: Point::Input(0),
            value: 3,
        },
        Opening {
            polynomial: 4,
            point: Point::Challenge(Challenge::Y),
            value: 4,
        },
        Opening {
            polynomial: 5,
            point: Point::Input(2),
            value: 4,
        },
        Opening {
            polynomial: 5,
            point: Point::Challenge(Challenge::X),
            value: 5,
        },
        Opening {
            polynomial: 6,
            point: Point::Challenge(Challenge::W),
            value: 5,
        },
    ];
    const LAYOUT: Layout = Layout {
        polynomials: &[
            Phase::BeforeW,
            Phase::BeforeW,
            Phase::BeforeW,
            Phase::BeforeY,
            Phase::BeforeY,
            Phase::BeforeX,
            Phase::BeforeAlpha,
        ],
        openings: OPENINGS,
        inputs: 5,
        points: 0,
        values: 6,
    };

    #[test]
    fn introduced_restrictions_can_share_an_inherited_helper() -> Result<()> {
        MESH.check(LAYOUT)?;
        assert_eq!(MESH.restrictions().count(), 3);
        assert_eq!(MESH.coordinate_indices(), [0, 1, 2, 3, 4]);
        assert_eq!(MESH.polynomial_indices(), [0, 1, 2, 3, 4, 5, 6]);
        for (edge, expected) in MESH.edges(LAYOUT)?.iter().zip(OPENINGS.chunks_exact(2)) {
            assert_eq!(edge, expected);
        }
        assert_eq!(MESH.edges(LAYOUT)?.len(), 6);
        Ok(())
    }

    #[test]
    fn every_intersection_needs_one_shared_value_wire() {
        for index in 0..OPENINGS.len() {
            let mut openings = OPENINGS.to_vec();
            openings[index].value = (openings[index].value + 1) % LAYOUT.values;
            let layout = Layout {
                openings: alloc::boxed::Box::leak(openings.into_boxed_slice()),
                ..LAYOUT
            };
            // Both polynomials still have openings. It is their equality that
            // has been removed, not an index or coverage requirement.
            layout.check().unwrap();
            assert!(MESH.check(layout).is_err(), "accepted altered edge {index}");
        }
    }

    #[test]
    fn carry_slots_and_deadlines_are_structural() {
        let mut mesh = MESH;
        mesh.inherited[1].polynomial = mesh.inherited[0].polynomial;
        assert!(mesh.check(LAYOUT).is_err());
        let mut mesh = MESH;
        mesh.inherited[1].x = mesh.inherited[0].x;
        mesh.helpers = &[
            Helper {
                polynomial: 3,
                x: 0,
            },
            Helper {
                polynomial: 4,
                x: 0,
            },
        ];
        assert!(mesh.check(LAYOUT).is_err());
        let mut mesh = MESH;
        mesh.inherited[0].y = 5;
        assert!(mesh.check(LAYOUT).is_err());
        for mesh in [
            Mesh {
                helpers: &[],
                ..MESH
            },
            Mesh {
                helpers: &[
                    Helper {
                        polynomial: 3,
                        x: 2,
                    },
                    Helper {
                        polynomial: 4,
                        x: 0,
                    },
                ],
                ..MESH
            },
            Mesh {
                helpers: const { &[HELPERS[0], HELPERS[1], HELPERS[0]] },
                ..MESH
            },
            Mesh {
                u: MESH.outgoing,
                outgoing: MESH.u,
                ..MESH
            },
        ] {
            assert!(mesh.check(LAYOUT).is_err());
        }
        for slot in 0..LAYOUT.polynomials.len() {
            let mut polynomials = LAYOUT.polynomials.to_vec();
            polynomials[slot] = match polynomials[slot] {
                Phase::BeforeW => Phase::BeforeY,
                Phase::BeforeY => Phase::BeforeX,
                Phase::BeforeX => Phase::BeforeAlpha,
                Phase::BeforeAlpha => Phase::BeforeX,
            };
            let layout = Layout {
                polynomials: alloc::boxed::Box::leak(polynomials.into_boxed_slice()),
                ..LAYOUT
            };
            assert!(
                MESH.check(layout).is_err(),
                "accepted changed deadline {slot}"
            );
        }
    }
}

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
