//! Hook layout configuration, and the framework-side state behind the hooks a
//! step reaches through [`StepCtx`](crate::ctx::StepCtx).
//!
//! The layout marker types ([`HookConfig`], [`HookLayout`], [`AppHooks`],
//! [`NoHooks`]) are the real `ragu_pcd` ones, re-exported — so these names
//! cannot drift, and migrating a consumer to real ragu is a no-op for them.
//! The framework-side sink mirrors `ragu_pcd`'s `framework_hooks::FrameworkHooks`
//! and is crate-private, as in real ragu: a step only ever touches it through
//! [`StepCtx`](crate::ctx::StepCtx).

use alloc::vec::Vec;

use ragu_arithmetic::{
    CurveAffine as _, Cycle as _, FixedGenerators as _,
    ff::{Field as _, PrimeField as _},
    group::GroupEncoding as _,
};
use ragu_core::{Error, Result};
use ragu_pasta::{Eq, Fp, Pasta};
pub use ragu_pcd::{AppHooks, HookConfig, HookLayout, NoHooks};

use crate::{
    poly_commitment::{self, PolyHandle},
    polynomial::Polynomial,
    sponge::Sponge,
};

/// Absorbed first by every challenge derivation, before the inputs — the same
/// `"raguchal"` tag as real ragu's `internal::challenge::DOMAIN_TAG`, so the
/// two derivations agree exactly.
const DOMAIN_TAG: u128 = u64::from_le_bytes(*b"raguchal") as u128;

/// A polynomial a step witnessed: the handle it was handed back, the
/// commitment that handle encodes, and the coefficients queries are checked
/// against. The commitment is kept because a [`PolyQuery`] records one and a
/// handle cannot be turned back into a point.
struct Witnessed {
    handle: PolyHandle,
    commitment: Eq,
    coefficients: Vec<Fp>,
}

/// An enforced poly-query. Mirrors `ragu_pcd`'s crate-private
/// `proof::PolyQuery`.
struct PolyQuery {
    com: Eq,
    x: Fp,
    y: Fp,
}

/// A derived challenge with the (sentinel-padded) inputs it absorbed. Mirrors
/// `ragu_pcd`'s crate-private `proof::DerivedChallenge`.
struct DerivedChallenge {
    inputs: Vec<Fp>,
    challenge: Fp,
}

/// Accumulates hook outputs during one
/// [`Step::witness`](crate::step::Step::witness) run; the application drains
/// it into the proof's witness transcript.
pub(crate) struct FrameworkHooks {
    poly_queries: Vec<PolyQuery>,
    witnessed_polys: Vec<Witnessed>,
    challenges: Vec<DerivedChallenge>,
    hook_layout: HookLayout,
}

impl FrameworkHooks {
    pub(crate) fn new(hook_layout: HookLayout) -> Self {
        Self {
            poly_queries: Vec::new(),
            witnessed_polys: Vec::new(),
            challenges: Vec::new(),
            hook_layout,
        }
    }

    pub(crate) fn witness_polynomial(&mut self, polynomial: Polynomial) -> Result<PolyHandle> {
        let commitment = polynomial.commit();
        let handle = PolyHandle::from_wires(poly_commitment::handle(commitment)?);
        self.witnessed_polys.push(Witnessed {
            handle: handle.clone(),
            commitment,
            coefficients: polynomial.coefficients().to_vec(),
        });
        Ok(handle)
    }

    pub(crate) fn evaluate(&self, handle: &PolyHandle, x: Fp) -> Result<Fp> {
        let found = self.witnessed_of(handle)?;
        Ok(ragu_arithmetic::eval(&found.coefficients, x))
    }

    /// The witnessed polynomial behind `handle`, looked up by wire equality —
    /// as in real ragu, where a handle resolves by its instance value. A
    /// polynomial re-witnessed in a later step yields the same wires and
    /// resolves; a handle smuggled across steps without re-witnessing does
    /// not.
    fn witnessed_of(&self, handle: &PolyHandle) -> Result<&Witnessed> {
        let sought = handle.wires();
        self.witnessed_polys
            .iter()
            .find(|w| w.handle.wires() == sought)
            .ok_or_else(|| {
                Error::InvalidWitness(
                    "poly-query rejected: the commitment names no polynomial this step witnessed"
                        .into(),
                )
            })
    }

    pub(crate) fn enforce_poly_query(&mut self, handle: &PolyHandle, x: Fp, y: Fp) -> Result<()> {
        let found = self.witnessed_of(handle)?;
        if ragu_arithmetic::eval(&found.coefficients, x) != y {
            return Err(Error::InvalidWitness(
                "poly-query rejected: the polynomial does not evaluate to the claimed value at the claimed point"
                    .into(),
            ));
        }
        let com = found.commitment;
        self.poly_queries.push(PolyQuery { com, x, y });
        Ok(())
    }

    pub(crate) fn derive_challenge(&mut self, inputs: &[Fp]) -> Result<Fp> {
        // Positions the caller left empty take a fixed sentinel, so that a
        // derivation absorbs the same count however few elements it was given.
        // Padding never truncates: an oversize input list is recorded as-is
        // and refused when the transcript is assembled.
        let mut witnessed = inputs.to_vec();
        while witnessed.len() < self.hook_layout.challenge_width {
            witnessed.push(sentinel());
        }

        let challenge = challenge_of(&witnessed)?;
        self.challenges.push(DerivedChallenge {
            inputs: witnessed,
            challenge,
        });
        Ok(challenge)
    }

    /// Fills whatever the body left unused up to the [`HookLayout`]. The
    /// polynomials go first, because a padding query has to name one and the
    /// body may have witnessed none. Mirrors `ragu_pcd`'s
    /// `FrameworkHooks::pad_to_layout`.
    #[expect(
        clippy::expect_used,
        reason = "mirrors real ragu, which panics for a polys = 0, queries > 0 layout"
    )]
    pub(crate) fn pad_to_layout(&mut self) -> Result<()> {
        // The constant $1$, whose commitment is `g[0]` — the same padding
        // polynomial real ragu derives.
        while self.witnessed_polys.len() < self.hook_layout.witness_polys {
            self.witness_polynomial(Polynomial::default())?;
        }

        // One opening of the first polynomial at zero, repeated.
        if self.poly_queries.len() < self.hook_layout.poly_queries {
            let first = self
                .witnessed_polys
                .first()
                .expect("a layout affording a query affords a polynomial");
            let handle = first.handle.clone();
            let constant_term = first.coefficients.first().copied().unwrap_or(Fp::ZERO);
            while self.poly_queries.len() < self.hook_layout.poly_queries {
                self.enforce_poly_query(&handle, Fp::ZERO, constant_term)?;
            }
        }

        // A derivation supplying nothing, which is what a padding challenge
        // is: every input position takes the sentinel.
        while self.challenges.len() < self.hook_layout.challenge_calls {
            self.derive_challenge(&[])?;
        }

        Ok(())
    }

    /// Enforces the [`HookLayout`] budget and serializes every hook output
    /// into the bytes the proof's witness hash covers.
    ///
    /// This is the mock's stand-in for instance assembly, which is where real
    /// ragu refuses an over-budget step — same [`Error::VectorLengthMismatch`]
    /// variant, same timing (during `seed`/`fuse`, after the step body ran and
    /// padding filled under-use). The numeric payload is per-list rather than
    /// real ragu's whole-instance length.
    pub(crate) fn into_transcript(self) -> Result<Vec<u8>> {
        let layout = self.hook_layout;
        check_len(layout.witness_polys, self.witnessed_polys.len())?;
        check_len(layout.poly_queries, self.poly_queries.len())?;
        check_len(layout.challenge_calls, self.challenges.len())?;
        for challenge in &self.challenges {
            check_len(layout.challenge_width, challenge.inputs.len())?;
        }

        let mut bytes = Vec::new();
        for witnessed in &self.witnessed_polys {
            for wire in witnessed.handle.wires() {
                bytes.extend_from_slice(wire.to_repr().as_ref());
            }
        }
        for query in &self.poly_queries {
            bytes.extend_from_slice(query.com.to_bytes().as_ref());
            bytes.extend_from_slice(query.x.to_repr().as_ref());
            bytes.extend_from_slice(query.y.to_repr().as_ref());
        }
        for challenge in &self.challenges {
            for input in &challenge.inputs {
                bytes.extend_from_slice(input.to_repr().as_ref());
            }
            bytes.extend_from_slice(challenge.challenge.to_repr().as_ref());
        }
        Ok(bytes)
    }
}

fn check_len(expected: usize, actual: usize) -> Result<()> {
    if expected == actual {
        Ok(())
    } else {
        Err(Error::VectorLengthMismatch { expected, actual })
    }
}

/// The value padding a challenge derivation's empty input positions: the
/// x-coordinate of the first nested generator. The same expression as real
/// ragu's, specialized to Pasta, so the sentinel is bit-identical.
fn sentinel() -> Fp {
    *Pasta::nested_generators(Pasta::baked()).g()[0]
        .coordinates()
        .expect("a fixed generator is not the identity")
        .x()
}

/// The challenge the (already sentinel-padded) absorbed elements derive: the
/// [`DOMAIN_TAG`] and then each input into the Poseidon [`Sponge`], one
/// squeeze out.
///
/// The same sponge, instantiation, and tag as real ragu's `challenge_of` in
/// `ragu_pcd::internal::challenge`, so the value is bit-identical to what a
/// real proof derives from the same inputs.
fn challenge_of(absorbed: &[Fp]) -> Result<Fp> {
    let mut sponge = Sponge::new();
    sponge.absorb(Fp::from_u128(DOMAIN_TAG))?;
    for &input in absorbed {
        sponge.absorb(input)?;
    }
    sponge.squeeze()
}
