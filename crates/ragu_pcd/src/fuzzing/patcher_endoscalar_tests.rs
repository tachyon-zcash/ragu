//! V07/V08: integer specifications and injected canonical-decomposition advice.
//!
//! Playback keeps the host witness at one, so out-of-range tests reach the
//! actual constraints despite from_element's honest-witness range check.
//! Calibration: change only boolean::decompose's CAPACITY to NUM_BITS. The
//! injected modulus/modulus+1 aliases then pass while the host check remains.

use alloc::vec;

use ragu_arithmetic::ff::{PrimeField, PrimeFieldBits, WithSmallOrderMulGroup};
use ragu_core::maybe::Maybe;
use ragu_pasta::Fq;
use ragu_primitives::{
    Endoscalar, EndoscalarChallenge, EndoscalarRangeError, GadgetExt, Simulator,
    extract_endoscalar, lift_endoscalar,
};
use ragu_testing::patcher::{Event, Playback, Recorder};

use super::*;
use crate::{
    fuzzing::corrupt::{Challenge, Corruption},
    internal::transcript::Transcript,
};

/// Four little-endian integer limbs; no arithmetic here reduces modulo F.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct Integer([u64; 4]);

impl Integer {
    fn power(bit: usize) -> Self {
        let mut limbs = [0; 4];
        limbs[bit / 64] = 1 << (bit % 64);
        Self(limbs)
    }

    fn add_one(mut self) -> Self {
        for limb in &mut self.0 {
            let (value, carry) = limb.overflowing_add(1);
            *limb = value;
            if !carry {
                return self;
            }
        }
        panic!("integer overflow")
    }

    fn sub_one(mut self) -> Self {
        for limb in &mut self.0 {
            let (value, borrow) = limb.overflowing_sub(1);
            *limb = value;
            if !borrow {
                return self;
            }
        }
        panic!("integer underflow")
    }

    fn bit(self, bit: usize) -> bool {
        self.0[bit / 64] >> (bit % 64) & 1 == 1
    }

    fn low(self) -> u128 {
        self.0[0] as u128 | (self.0[1] as u128) << 64
    }

    fn field<F: PrimeField>(self) -> F {
        let mut repr = F::Repr::default();
        assert_eq!(repr.as_ref().len(), 32);
        for (bytes, limb) in repr.as_mut().chunks_exact_mut(8).zip(self.0) {
            bytes.copy_from_slice(&limb.to_le_bytes());
        }
        F::from_repr(repr).expect("canonical integer")
    }

    fn modulus<F: PrimeField>() -> Self {
        let hex = F::MODULUS.strip_prefix("0x").unwrap();
        assert_eq!(hex.len(), 64);
        Self(core::array::from_fn(|i| {
            u64::from_str_radix(&hex[48 - 16 * i..64 - 16 * i], 16).unwrap()
        }))
    }
}

fn boundaries<F: PrimeField>() -> Vec<(Integer, bool)> {
    // Pasta's declared integer boundary, independently of extraction/range
    // helpers or field addition, which would wrap modulus-adjacent cases.
    assert_eq!(F::CAPACITY, 254);
    assert_eq!(F::NUM_BITS, 255);
    let mut cases = vec![(Integer([0; 4]), true), (Integer([1, 0, 0, 0]), true)];
    for bit in [127, 128, 129, 253, 254] {
        let value = Integer::power(bit);
        cases.extend([
            (value.sub_one(), true),
            (value, bit < 254),
            (value.add_one(), bit < 254),
        ]);
    }
    let p = Integer::modulus::<F>();
    cases.extend([(p.sub_one().sub_one(), false), (p.sub_one(), false)]);
    cases
}

/// Independent signed-integer recurrence: the lift is a + b*zeta.
fn lift<F: WithSmallOrderMulGroup<3>>(word: u128) -> F {
    let (mut a, mut b) = (2i128, 2i128);
    for pair in 0..64 {
        a *= 2;
        b *= 2;
        let sign = if word >> (2 * pair) & 1 == 0 { 1 } else { -1 };
        if word >> (2 * pair + 1) & 1 == 0 {
            a += sign;
        } else {
            b += sign;
        }
    }
    let signed = |n: i128| {
        let value = F::from_u128(n.unsigned_abs());
        if n < 0 { -value } else { value }
    };
    signed(a) + signed(b) * F::ZETA
}

fn transcript_identity(value: Fp) -> Result<Fp> {
    let dr = &mut Simulator::<Fp>::new();
    let mut transcript = Transcript::new(
        dr,
        Pasta::circuit_poseidon(Pasta::baked()),
        b"V07-representation",
    )?;
    Element::constant(dr, value).write(dr, &mut transcript)?;
    Ok(*transcript.challenge(dr)?.value().take())
}

#[test]
fn lossy_extraction_preserves_low_bits_and_full_transcript_identity() -> Result<()> {
    for low in [0, 1, u128::MAX, 0x0123_4567_89ab_cdef_fedc_ba98_7654_3210] {
        let base = Integer([low as u64, (low >> 64) as u64, 0, 0]);
        for high in [
            Integer::power(128),
            Integer::power(129),
            Integer::power(253),
        ] {
            let paired = Integer([base.0[0], base.0[1], high.0[2], high.0[3]]);
            let (a, b) = (base.field::<Fp>(), paired.field::<Fp>());
            assert_ne!(a, b);
            assert_ne!(a.to_repr(), b.to_repr());
            assert_ne!(transcript_identity(a)?, transcript_identity(b)?);
            for extracted in [
                extract_endoscalar(a)?,
                extract_endoscalar(b)?,
                extract_endoscalar(base.field::<Fq>())?,
                extract_endoscalar(paired.field::<Fq>())?,
            ] {
                assert_eq!(extracted, low);
                assert_eq!(lift_endoscalar::<Fp>(extracted), lift::<Fp>(low));
                assert_eq!(lift_endoscalar::<Fq>(extracted), lift::<Fq>(low));
            }
            // An oracle requiring different lifts for different complete
            // challenges is invalid: this explicit pair refutes it.
            assert_eq!(
                lift_endoscalar::<Fp>(extract_endoscalar(a)?),
                lift_endoscalar::<Fp>(extract_endoscalar(b)?)
            );
        }
        for bit in 0..128 {
            let changed = low ^ (1u128 << bit);
            assert_eq!(extract_endoscalar(Fp::from_u128(changed))?, changed);
            assert_eq!(extract_endoscalar(Fq::from_u128(changed))?, changed);
            assert_ne!(lift::<Fp>(low), lift_endoscalar::<Fp>(changed));
            assert_ne!(lift::<Fq>(low), lift_endoscalar::<Fq>(changed));
            assert_eq!(lift::<Fp>(changed), lift_endoscalar::<Fp>(changed));
            assert_eq!(lift::<Fq>(changed), lift_endoscalar::<Fq>(changed));
        }
    }
    Ok(())
}

fn extraction<'dr, D: Driver<'dr, F: PrimeFieldBits>>(
    dr: &mut D,
    value: D::F,
) -> Result<(D::Wire, Vec<D::Wire>)> {
    let source = Element::alloc(dr, &mut (), D::just(|| value))?;
    let wire = source.wire().clone();
    let challenge = EndoscalarChallenge::from_element(dr, &mut (), source)?;
    let bits = Endoscalar::extract(challenge)
        .bits()
        .map(|b| b.wire().clone())
        .collect();
    Ok((wire, bits))
}

fn check_decomposition<F: PrimeFieldBits>() -> Result<()> {
    let mut rec = Recorder::<F>::new();
    let (source, low_bits) = extraction(&mut rec, F::ONE)?;
    assert!(constraints_hold(&rec.events, &rec.values));
    let gates: Vec<_> = rec
        .events
        .iter()
        .filter_map(|event| match event {
            Event::Gate { a, b, c } if *a != source => Some((*a, *b, *c)),
            _ => None,
        })
        .collect();
    assert_eq!(
        low_bits,
        gates
            .iter()
            .take(128)
            .map(|(a, _, _)| *a)
            .collect::<Vec<_>>()
    );
    // Follow the emitted bit count during calibration; the numerical
    // acceptance assertion below must catch a relaxed length before shape.
    let binding: Vec<_> = rec
        .events
        .iter()
        .enumerate()
        .filter_map(|(i, event)| match event {
            Event::Enforce { terms }
                if terms.len() == 2 && terms.iter().any(|(wire, _)| *wire == source) =>
            {
                Some(i)
            }
            _ => None,
        })
        .collect();
    assert_eq!(binding.len(), 1);
    let remaining: Vec<_> = rec
        .events
        .iter()
        .enumerate()
        .filter(|(i, _)| !binding.contains(i))
        .map(|(_, event)| event.clone())
        .collect();
    let probe = |integer: Integer, value: F, expected: bool| -> Result<()> {
        let mut values = rec.values.clone();
        values[source] = value;
        let mut pins = vec![0, source];
        let mut recomposed = F::ZERO;
        let mut power = F::ONE;
        for (i, &(a, b, c)) in gates.iter().enumerate() {
            values[a] = F::from(u64::from(integer.bit(i)));
            values[b] = F::ONE - values[a];
            values[c] = F::ZERO;
            pins.extend([a, b, c]);
            recomposed += values[a] * power;
            power = power.double();
        }
        repair(&rec.events, &mut values, &pins);
        assert_eq!(values[source], value, "source stays fixed");
        for (i, &(a, b, c)) in gates.iter().enumerate() {
            assert_eq!(values[a], F::from(u64::from(integer.bit(i))));
            assert_eq!(values[a] + values[b], F::ONE);
            assert_eq!(values[a] * values[b], values[c]);
        }
        let exact = constraints_hold(&rec.events, &values);
        assert!(
            constraints_hold(&remaining, &values),
            "every equation except recomposition holds"
        );
        assert_eq!(exact, recomposed == value);
        let mut live = Playback::new(values);
        // Host witness remains valid; rejection cannot come from the native
        // range helper rather than malicious wire advice reaching constraints.
        extraction(&mut live, F::ONE)?;
        assert_eq!(exact, live.accepts(), "exact/live integer {integer:?}");
        assert_eq!(
            live.accepts(),
            expected,
            "canonical decomposition {integer:?}"
        );
        Ok(())
    };

    // Integer aliases p and p+1 reduce to valid sources zero and one. They
    // must never constitute a canonical bit representation of those sources.
    let modulus = Integer::modulus::<F>();
    probe(modulus, F::ZERO, false)?;
    probe(modulus.add_one(), F::ONE, false)?;
    for (integer, expected) in boundaries::<F>() {
        let value = integer.field::<F>();
        let native = extract_endoscalar(value);
        let mut honest = Recorder::new();
        let gadget = extraction(&mut honest, value);
        if expected {
            assert_eq!(native?, integer.low());
            let (_, bits) = gadget?;
            assert!(constraints_hold(&honest.events, &honest.values));
            for (i, bit) in bits.iter().enumerate() {
                assert_eq!(honest.values[*bit], F::from(u64::from(integer.bit(i))));
            }
        } else {
            assert!(
                native
                    .unwrap_err()
                    .invalid_witness_source::<EndoscalarRangeError>()
                    .is_some()
            );
            assert!(
                gadget
                    .unwrap_err()
                    .invalid_witness_source::<EndoscalarRangeError>()
                    .is_some()
            );
        }
        probe(integer, value, expected)?;
    }
    // Both low and high advice are bound to the unchanged canonical source.
    for bit in 0..254 {
        probe(Integer::power(bit), F::ZERO, false)?;
    }
    assert_eq!(gates.len(), 254);
    Ok(())
}

#[test]
fn canonical_boundaries_and_injected_decomposition_fp() -> Result<()> {
    check_decomposition::<Fp>()
}

#[test]
fn canonical_boundaries_and_injected_decomposition_fq() -> Result<()> {
    check_decomposition::<Fq>()
}

#[test]
fn malformed_root_challenges_reject_before_algebra() -> Result<()> {
    type Leaf = HeaderStep<(), (), ApplicationHeader, 0>;
    type Both = HeaderStep<ApplicationHeader, ApplicationHeader, ApplicationHeader, 1>;
    let app = ApplicationBuilder::<Pasta, R, 4>::new()
        .register(Leaf::new())?
        .register(Both::new())?
        .finalize(Pasta::baked())?;
    let mut rng = StdRng::seed_from_u64(0x8730_0708);
    let left = app.seed(&mut rng, Leaf::new(), Fp::from(19))?.0;
    let right = app.seed(&mut rng, Leaf::new(), Fp::from(43))?.0;
    let parent = app
        .fuse(&mut rng, Both::new(), Fp::from(71), left.clone(), right)?
        .0;
    for node in [left, parent] {
        let (accepted, checks) = app.verify_with_checks(&node, &mut rng)?;
        assert!(accepted && checks.unwrap().all());
        for challenge in Challenge::ALL {
            for (integer, _) in boundaries::<Fp>().into_iter().filter(|(_, valid)| !valid) {
                let mut changed = node.proof().clone();
                changed.corrupt(Corruption::Challenge(challenge, integer.field()));
                let changed = changed.carry::<ApplicationHeader>(*node.data());
                let (accepted, checks) = app.verify_with_checks(&changed, &mut rng)?;
                assert!(!accepted && checks.is_none(), "{challenge:?}: {integer:?}");
            }
        }
    }
    Ok(())
}
