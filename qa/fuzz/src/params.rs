//! Fuzzer-chosen field and rank, so a target is not pinned to a single
//! monomorphization for its whole life.
//!
//! Most of the generic pipeline was written against `Fp` and [`TestRank`],
//! and for a good reason: that is the cheap pair. `TestRank` is `R<7>`, so
//! `n = 32` gates and 128 coefficients; [`ProductionRank`] is `R<14>`, so
//! `n = 4096` and 16384 coefficients — 128 times the vector length,
//! and the polynomial work scales with it. A target that ran every input at
//! production rank would lose most of its executions per second, and
//! execution count is what finds bugs.
//!
//! The cost of that choice was that the rank actually shipped to users, and
//! the second field of the cycle, were exercised only where a target
//! happened to name them outright. Rank-specific arithmetic — anything
//! sensitive to `n`, to `log2_n`, or to a coefficient count that is no
//! longer a small number — was reachable in principle and unreached in
//! practice.
//!
//! This module restores both without handing the throughput back. The
//! fuzzer picks, but the distribution is deliberately lopsided: rank comes
//! out of a nominal one-in-sixteen draw, so most inputs stay at test rank
//! and a minority pay for production coverage. Fields are drawn evenly,
//! because `Fp` and `Fq` cost the same.
//!
//! "Nominal" is doing real work in that sentence. The ratio is exact for a
//! uniformly random byte and only approximate under a live fuzzer, whose
//! byte distribution is whatever coverage feedback drives it to. See
//! [`PRODUCTION_BAND`] for how the first version of this got it backwards,
//! and measure with a target's own stats hook rather than assuming.
//!
//! # Why a macro and not a type parameter
//!
//! [`Rank`](ragu_circuits::polynomials::Rank) is a sealed trait over a
//! const-generic `R<RANK>`, and the field is likewise a compile-time type.
//! Neither can be chosen at run time by value, so the choice has to be a
//! `match` that monomorphizes its body once per arm. [`with_rank!`] and
//! [`with_field!`] are that match, written once. The cost is that each
//! target's body is compiled twice per axis; the benefit is that a target
//! opts in by wrapping its body rather than by being rewritten.

use arbitrary::{Arbitrary, Unstructured};
#[doc(no_inline)]
pub use ragu_circuits::polynomials::{ProductionRank, TestRank};
#[doc(no_inline)]
pub use ragu_core::pasta::Fp;
pub use ragu_core::pasta::Fq;

/// The byte band that selects [`Production`](RankChoice::Production).
///
/// Sixteen values out of 256, so one draw in sixteen *for a uniformly random
/// byte*. The band sits in the middle of the range on purpose. The obvious
/// encoding — `int_in_range(0..=15)? == 0` — is a trap here: libFuzzer's
/// mutators emit `0x00` far more often than chance, so keying the rare arm
/// on zero inverts the intent. Measured, that version selected production
/// rank on 46% of inputs rather than 6%. `0x00` and `0xff` are both common
/// mutator outputs; a mid-range band avoids both.
///
/// The ratio is still only nominal: the fuzzer's byte distribution is
/// whatever coverage feedback drives it to, not uniform. Treat sixteen as
/// the dial, and measure with a target's own stats hook rather than
/// assuming.
const PRODUCTION_BAND: core::ops::Range<u8> = 0x50..0x60;

/// Which [`Rank`](ragu_circuits::polynomials::Rank) a target should run this
/// input at.
///
/// Skewed toward [`Test`](Self::Test) — see [`PRODUCTION_BAND`].
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RankChoice {
    /// `R<7>`: `n = 32`, 128 coefficients. The fast path.
    Test,
    /// `R<14>`: `n = 4096`, 16384 coefficients. What ships.
    Production,
}

impl<'a> Arbitrary<'a> for RankChoice {
    fn arbitrary(u: &mut Unstructured<'a>) -> arbitrary::Result<Self> {
        // A raw byte tested against a mid-range band — see `PRODUCTION_BAND`
        // for why this is not `int_in_range(..) == 0`. An exhausted
        // `Unstructured` yields zero, which falls outside the band and so
        // resolves to the cheap arm; a truncated input therefore costs
        // throughput rather than spending it.
        let byte = u.arbitrary::<u8>()?;
        Ok(if PRODUCTION_BAND.contains(&byte) {
            RankChoice::Production
        } else {
            RankChoice::Test
        })
    }

    fn size_hint(_: usize) -> (usize, Option<usize>) {
        (1, Some(1))
    }
}

impl RankChoice {
    /// The rank as it appears in a log line or a crash report.
    pub fn name(self) -> &'static str {
        match self {
            RankChoice::Test => "test",
            RankChoice::Production => "production",
        }
    }
}

/// Which field of the cycle a target should run this input over.
///
/// Drawn evenly: unlike rank, the two cost the same.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum FieldChoice {
    /// The Pallas base field, Vesta's scalar field.
    Fp,
    /// The Vesta base field, Pallas' scalar field.
    Fq,
}

impl<'a> Arbitrary<'a> for FieldChoice {
    fn arbitrary(u: &mut Unstructured<'a>) -> arbitrary::Result<Self> {
        // Hand-written rather than derived, for the same reason `RankChoice`
        // is: the derive picks a variant from a four-byte read, so a short
        // input silently pins the first variant, and the byte cost is four
        // times what a two-way choice needs. One low bit is the whole
        // decision.
        Ok(if u.arbitrary::<u8>()? & 1 == 0 {
            FieldChoice::Fp
        } else {
            FieldChoice::Fq
        })
    }

    fn size_hint(_: usize) -> (usize, Option<usize>) {
        (1, Some(1))
    }
}

impl FieldChoice {
    /// The field as it appears in a log line or a crash report.
    pub fn name(self) -> &'static str {
        match self {
            FieldChoice::Fp => "Fp",
            FieldChoice::Fq => "Fq",
        }
    }
}

/// Runs `$body` with `$R` bound to the rank `$choice` names.
///
/// The body is compiled once per arm, so it must type-check for both ranks —
/// which is the point: a body that only compiles at `TestRank` has a
/// hard-coded `n` in it somewhere.
///
/// ```ignore
/// with_rank!(input.rank, |R| {
///     let poly: Polynomial<Fp, R> = build::<R>(&input.coeffs);
///     assert_eq!(poly.eval(z), naive_eval::<R>(&input.coeffs, z));
/// })
/// ```
#[macro_export]
macro_rules! with_rank {
    ($choice:expr, |$R:ident| $body:block) => {
        match $choice {
            $crate::params::RankChoice::Test => {
                #[allow(dead_code)]
                type $R = $crate::params::TestRank;
                $body
            }
            $crate::params::RankChoice::Production => {
                #[allow(dead_code)]
                type $R = $crate::params::ProductionRank;
                $body
            }
        }
    };
}

/// Runs `$body` with `$F` bound to the field `$choice` names.
///
/// As with [`with_rank!`], the body is compiled once per arm and must
/// type-check for both — a body that only builds for `Fp` has reached for
/// something field-specific.
///
/// ```ignore
/// with_field!(input.field, |F| {
///     let a = F::from(input.a);
///     assert_eq!(a * a, a.square());
/// })
/// ```
#[macro_export]
macro_rules! with_field {
    ($choice:expr, |$F:ident| $body:block) => {
        match $choice {
            $crate::params::FieldChoice::Fp => {
                #[allow(dead_code)]
                type $F = $crate::params::Fp;
                $body
            }
            $crate::params::FieldChoice::Fq => {
                #[allow(dead_code)]
                type $F = $crate::params::Fq;
                $body
            }
        }
    };
}

#[cfg(test)]
mod tests {
    use ragu_circuits::polynomials::Rank;

    use super::*;

    /// The skew is the whole point of `RankChoice`; assert it rather than
    /// trusting the range arithmetic to stay right through an edit.
    #[test]
    fn rank_choice_is_skewed_toward_test() {
        // A flat sweep of every byte value stands in for the mutator: it is
        // the distribution `int_in_range` sees when the fuzzer is exploring
        // freely, and it makes the ratio exact rather than statistical.
        let mut production = 0usize;
        let mut test = 0usize;
        for byte in 0u8..=255 {
            let raw = [byte];
            let mut u = Unstructured::new(&raw);
            match RankChoice::arbitrary(&mut u).expect("one byte is enough") {
                RankChoice::Production => production += 1,
                RankChoice::Test => test += 1,
            }
        }
        assert_eq!(production + test, 256);
        assert_eq!(
            production, 16,
            "the band should be exactly one byte in sixteen"
        );
        assert_eq!(test, 240);

        // The band must avoid the two byte values libFuzzer emits most, or
        // the skew inverts in practice however good it looks on paper.
        for common in [0x00u8, 0xff] {
            let raw = [common];
            let mut u = Unstructured::new(&raw);
            assert_eq!(
                RankChoice::arbitrary(&mut u).unwrap(),
                RankChoice::Test,
                "0x{common:02x} is a high-frequency mutator byte and must not select \
                 the expensive arm",
            );
        }

        // An exhausted `Unstructured` must resolve to the cheap arm.
        let mut empty = Unstructured::new(&[]);
        assert_eq!(RankChoice::arbitrary(&mut empty).unwrap(), RankChoice::Test);
    }

    /// Guards the reason the skew exists: production rank really is the
    /// expensive one, by the factor the module doc claims.
    #[test]
    fn production_rank_is_128_times_test_rank() {
        assert_eq!(TestRank::RANK, 7);
        assert_eq!(ProductionRank::RANK, 14);
        assert_eq!(ProductionRank::n() / TestRank::n(), 128);
    }

    /// Both field arms are reachable from fuzzer bytes.
    #[test]
    fn field_choice_reaches_both_arms() {
        let mut seen_fp = false;
        let mut seen_fq = false;
        for byte in 0u8..=255 {
            let raw = [byte];
            let mut u = Unstructured::new(&raw);
            match FieldChoice::arbitrary(&mut u) {
                Ok(FieldChoice::Fp) => seen_fp = true,
                Ok(FieldChoice::Fq) => seen_fq = true,
                Err(_) => {}
            }
        }
        assert!(seen_fp && seen_fq, "one field arm is unreachable");

        // Even split, so neither field is the one that only gets looked at
        // when the fuzzer happens to be feeling generous.
        let fq = (0u8..=255)
            .filter(|b| {
                let raw = [*b];
                let mut u = Unstructured::new(&raw);
                FieldChoice::arbitrary(&mut u) == Ok(FieldChoice::Fq)
            })
            .count();
        assert_eq!(fq, 128, "expected an even field split, got {fq}/256 Fq");
    }
}
