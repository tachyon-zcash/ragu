//! Characterization tests for the polynomial collections
//! ([`ragu_testing::pcd::collections`]), grown by fusing singleton seeds.
//! Both fuse circuits are `O(1)` in collection size.

use ragu_arithmetic::{
    ff::Field,
    rand::{SeedableRng, rngs::StdRng},
};
use ragu_circuits::polynomials::{ProductionRank, Rank};
use ragu_core::Result;
use ragu_pasta::{Fp, Pasta};
use ragu_pcd::Pcd;
use ragu_testing::pcd::collections::{
    collections_app, merged_polynomial, sequence_polynomial, set_polynomial,
    step::{
        ConcatSequences, ConcatSequencesWitness, MergeSets, MergeSetsWitness, SeedSequence,
        SeedSequenceWitness, SeedSet, SeedSetWitness, SeqHeader, SetHeader,
    },
};

type R = ProductionRank;

/// Singleton seeds fuse into `{3, 5, 5}`; the parent verifies and the merged
/// polynomial is the expected set polynomial, root by root and by handle.
#[test]
fn seeded_singletons_fuse_into_their_merge() -> Result<()> {
    let pasta = Pasta::baked();
    let app = collections_app::<Pasta, R>(pasta)?;
    let mut rng = StdRng::seed_from_u64(31415);

    let three_poly = set_polynomial::<Fp, R>(&[Fp::from(3u64)]);
    let (three, ()) = app.seed(
        &mut rng,
        SeedSet::new(),
        SeedSetWitness {
            polynomial: three_poly,
        },
    )?;
    let five_a_poly = set_polynomial(&[Fp::from(5u64)]);
    let (five_a, ()) = app.seed(
        &mut rng,
        SeedSet::new(),
        SeedSetWitness {
            polynomial: five_a_poly,
        },
    )?;
    let five_b_poly = set_polynomial(&[Fp::from(5u64)]);
    let (five_b, ()) = app.seed(
        &mut rng,
        SeedSet::new(),
        SeedSetWitness {
            polynomial: five_b_poly,
        },
    )?;
    assert!(app.verify(&three, &mut rng)?, "a singleton seed verifies");

    let pair_product = merged_polynomial(&three.data().polynomial, &five_a.data().polynomial);
    let (pair, ()) = app.fuse(
        &mut rng,
        MergeSets::new(),
        MergeSetsWitness {
            a: three.data().polynomial.clone(),
            b: five_a.data().polynomial.clone(),
            product: pair_product,
        },
        three,
        five_a,
    )?;
    let merged_product = merged_polynomial(&pair.data().polynomial, &five_b.data().polynomial);
    let (merged, ()) = app.fuse(
        &mut rng,
        MergeSets::new(),
        MergeSetsWitness {
            a: pair.data().polynomial.clone(),
            b: five_b.data().polynomial.clone(),
            product: merged_product,
        },
        pair,
        five_b,
    )?;
    assert!(app.verify(&merged, &mut rng)?, "the merge tree verifies");

    // Longhand root checks on the carried product.
    let product = &merged.data().polynomial;
    for m in [3u64, 5] {
        assert_eq!(
            product.eval(Fp::from(m)),
            Fp::ZERO,
            "every seeded member is a root of the merge"
        );
    }
    assert_ne!(
        product.eval(Fp::from(13u64)),
        Fp::ZERO,
        "a non-member is not a root"
    );
    // 5 was seeded twice, so it is a double root: its derivative (computed
    // longhand) also vanishes there.
    let coeffs: Vec<Fp> = product.iter_coeffs().collect();
    let mut derivative_at_5 = Fp::ZERO;
    let mut power = Fp::ONE; // 5^(i-1)
    for (i, c) in coeffs.iter().enumerate().skip(1) {
        derivative_at_5 += Fp::from(i as u64) * *c * power;
        power *= Fp::from(5u64);
    }
    assert_eq!(derivative_at_5, Fp::ZERO, "5 is a double root of the merge");

    let expected = set_polynomial::<Fp, R>(&[3u64, 5, 5].map(Fp::from));
    assert_eq!(
        merged.data().handle,
        app.commit_polynomial(&expected)?,
        "the merge's commitment is the expected set's"
    );

    Ok(())
}

/// A parent whose witnessed contributing set is not the one its child's header
/// carries cannot produce a verifying proof. Assembly does not check trace
/// satisfaction, so rejection at fuse or at verify are both in-contract.
///
/// Merges the same two children honestly first, as the control.
#[test]
fn a_parent_cannot_merge_a_substituted_set() -> Result<()> {
    let pasta = Pasta::baked();
    let app = collections_app::<Pasta, R>(pasta)?;
    let mut rng = StdRng::seed_from_u64(2718);

    let three = set_polynomial::<Fp, R>(&[Fp::from(3u64)]);
    let seven = set_polynomial::<Fp, R>(&[Fp::from(7u64)]);

    let seed_pair = |rng: &mut StdRng| -> Result<_> {
        let (left, ()) = app.seed(
            &mut *rng,
            SeedSet::new(),
            SeedSetWitness {
                polynomial: three.clone(),
            },
        )?;
        let (right, ()) = app.seed(
            &mut *rng,
            SeedSet::new(),
            SeedSetWitness {
                polynomial: seven.clone(),
            },
        )?;
        Ok((left, right))
    };

    let (left, right) = seed_pair(&mut rng)?;
    let (honest, ()) = app.fuse(
        &mut rng,
        MergeSets::new(),
        MergeSetsWitness {
            product: merged_polynomial(&three, &seven),
            a: three.clone(),
            b: seven.clone(),
        },
        left,
        right,
    )?;
    assert!(
        app.verify(&honest, &mut rng)?,
        "the honest merge of these children must verify"
    );

    // Product computed honestly *for the substitute*: every claim is
    // internally consistent, so only the header tie can reject it.
    let (left, right) = seed_pair(&mut rng)?;
    let substitute = set_polynomial::<Fp, R>(&[Fp::from(11u64)]);
    let result = app.fuse(
        &mut rng,
        MergeSets::new(),
        MergeSetsWitness {
            product: merged_polynomial(&substitute, &seven),
            a: substitute,
            b: seven,
        },
        left,
        right,
    );

    let rejected = match result {
        Err(_) => true,
        Ok((merged, ())) => !app.verify(&merged, &mut rng)?,
    };
    assert!(
        rejected,
        "the in-circuit handle-vs-header equality must reject a substituted set"
    );
    Ok(())
}

/// A claimed merge that is not the product is rejected at fuse time: the
/// merged set's claim carries `a(z)·b(z)` as its claimed evaluation, and the
/// wrong polynomial does not evaluate to it.
#[test]
fn a_wrong_merge_is_rejected() -> Result<()> {
    let pasta = Pasta::baked();
    let app = collections_app::<Pasta, R>(pasta)?;
    let mut rng = StdRng::seed_from_u64(1618);

    let left_poly = set_polynomial::<Fp, R>(&[Fp::from(3u64)]);
    let (left, ()) = app.seed(
        &mut rng,
        SeedSet::new(),
        SeedSetWitness {
            polynomial: left_poly,
        },
    )?;
    let right_poly = set_polynomial(&[Fp::from(7u64)]);
    let (right, ()) = app.seed(
        &mut rng,
        SeedSet::new(),
        SeedSetWitness {
            polynomial: right_poly,
        },
    )?;

    // The claimed merge drops member 7.
    let result = app.fuse(
        &mut rng,
        MergeSets::new(),
        MergeSetsWitness {
            a: set_polynomial(&[Fp::from(3u64)]),
            b: set_polynomial(&[Fp::from(7u64)]),
            product: set_polynomial(&[Fp::from(3u64)]),
        },
        left,
        right,
    );

    assert!(
        result.is_err(),
        "a merge whose product drops a member must fail to prove"
    );
    Ok(())
}

/// Four singleton seeds fuse pairwise into `[3, 5, 5, 7]` — order and
/// duplicates preserved; the carried members and the header's polynomial match.
#[test]
fn seeded_singletons_fuse_into_their_concatenation() -> Result<()> {
    let pasta = Pasta::baked();
    let app = collections_app::<Pasta, R>(pasta)?;
    let mut rng = StdRng::seed_from_u64(1729);

    let (three, ()) = app.seed(
        &mut rng,
        SeedSequence::<Pasta, R>::new(),
        SeedSequenceWitness {
            sequence: sequence_polynomial(&[Fp::from(3u64)]),
            member: Fp::from(3u64),
        },
    )?;
    let (five_a, ()) = app.seed(
        &mut rng,
        SeedSequence::<Pasta, R>::new(),
        SeedSequenceWitness {
            sequence: sequence_polynomial(&[Fp::from(5u64)]),
            member: Fp::from(5u64),
        },
    )?;
    let (five_b, ()) = app.seed(
        &mut rng,
        SeedSequence::<Pasta, R>::new(),
        SeedSequenceWitness {
            sequence: sequence_polynomial(&[Fp::from(5u64)]),
            member: Fp::from(5u64),
        },
    )?;
    let (seven, ()) = app.seed(
        &mut rng,
        SeedSequence::<Pasta, R>::new(),
        SeedSequenceWitness {
            sequence: sequence_polynomial(&[Fp::from(7u64)]),
            member: Fp::from(7u64),
        },
    )?;
    assert!(app.verify(&three, &mut rng)?, "a singleton seed verifies");

    // [3, 5]
    let left_members: Vec<Fp> = [three.data().members.as_slice(), &five_a.data().members].concat();
    let (left, ()) = app.fuse(
        &mut rng,
        ConcatSequences::<Pasta, R>::new(),
        ConcatSequencesWitness {
            a: sequence_polynomial(&three.data().members),
            b: sequence_polynomial(&five_a.data().members),
            output: sequence_polynomial(&left_members),
        },
        three,
        five_a,
    )?;
    // [5, 7]
    let right_members: Vec<Fp> = [five_b.data().members.as_slice(), &seven.data().members].concat();
    let (right, ()) = app.fuse(
        &mut rng,
        ConcatSequences::<Pasta, R>::new(),
        ConcatSequencesWitness {
            a: sequence_polynomial(&five_b.data().members),
            b: sequence_polynomial(&seven.data().members),
            output: sequence_polynomial(&right_members),
        },
        five_b,
        seven,
    )?;
    // [3, 5, 5, 7]
    let out_members: Vec<Fp> = [left.data().members.as_slice(), &right.data().members].concat();
    let (out, ()) = app.fuse(
        &mut rng,
        ConcatSequences::<Pasta, R>::new(),
        ConcatSequencesWitness {
            a: sequence_polynomial(&left.data().members),
            b: sequence_polynomial(&right.data().members),
            output: sequence_polynomial(&out_members),
        },
        left,
        right,
    )?;
    assert!(app.verify(&out, &mut rng)?, "the concatenation verifies");

    let expected = [3u64, 5, 5, 7].map(Fp::from);
    assert_eq!(out.data().members.len(), expected.len());
    for (i, want) in expected.iter().enumerate() {
        assert_eq!(out.data().members[i], *want, "member {i} in order");
    }

    // The expected monic encoding is `[3, 5, 5, 7, 1]`.
    let expected_poly = sequence_polynomial::<Fp, R>(&expected);
    let coeffs: Vec<Fp> = expected_poly.iter_coeffs().collect();
    assert_eq!(
        coeffs[4],
        Fp::ONE,
        "the sentinel sits above the last member"
    );
    assert_eq!(
        out.data().handle,
        app.commit_polynomial(&expected_poly)?,
        "the output's commitment is the expected sequence's"
    );

    Ok(())
}

/// The sentinel makes every member value representable: `[0]` alone would be
/// the zero polynomial, indistinguishable from the empty sequence, but its
/// monic encoding `[0, 1]` is the polynomial `X`.
#[test]
fn a_zero_member_is_a_valid_sequence() -> Result<()> {
    let pasta = Pasta::baked();
    let app = collections_app::<Pasta, R>(pasta)?;
    let mut rng = StdRng::seed_from_u64(4104);

    let (zero, ()) = app.seed(
        &mut rng,
        SeedSequence::<Pasta, R>::new(),
        SeedSequenceWitness {
            sequence: sequence_polynomial(&[Fp::ZERO]),
            member: Fp::ZERO,
        },
    )?;
    let (three, ()) = app.seed(
        &mut rng,
        SeedSequence::<Pasta, R>::new(),
        SeedSequenceWitness {
            sequence: sequence_polynomial(&[Fp::from(3u64)]),
            member: Fp::from(3u64),
        },
    )?;
    let out_members: Vec<Fp> = [zero.data().members.as_slice(), &three.data().members].concat();
    let (out, ()) = app.fuse(
        &mut rng,
        ConcatSequences::<Pasta, R>::new(),
        ConcatSequencesWitness {
            a: sequence_polynomial(&zero.data().members),
            b: sequence_polynomial(&three.data().members),
            output: sequence_polynomial(&out_members),
        },
        zero,
        three,
    )?;
    assert!(app.verify(&out, &mut rng)?, "[0, 3] verifies");
    assert_eq!(out.data().members, vec![Fp::ZERO, Fp::from(3u64)]);

    Ok(())
}

/// The rank provides `2^13 = 8192` coefficients and one sits above the last
/// member, so either collection holds at most `8191` members.
#[test]
fn the_collection_ceiling_is_8191_members() {
    assert_eq!(
        <R as Rank>::num_coeffs(),
        8192,
        "the rank's coefficient capacity, spelled out"
    );

    // A ceiling-sized multiset: 4096 + 4095 members merge to degree 8191.
    let a: Vec<Fp> = (1..=4096u64).map(Fp::from).collect();
    let b: Vec<Fp> = (1..=4095u64).map(Fp::from).collect();
    let product = merged_polynomial(&set_polynomial::<Fp, R>(&a), &set_polynomial::<Fp, R>(&b));
    assert_eq!(
        product.eval(Fp::from(4096u64)),
        Fp::ZERO,
        "the ceiling-sized merge is a well-formed set polynomial"
    );

    // A ceiling-sized sequence: 8191 members and the sentinel fill all
    // 8192 coefficients.
    let full: Vec<Fp> = (1..=8191u64).map(Fp::from).collect();
    let seq = sequence_polynomial::<Fp, R>(&full);
    assert_eq!(seq.iter_coeffs().count(), 8192);
}

/// One member past the ceiling fails at construction, before any proving:
/// 8,192 members need 8,193 coefficients.
#[test]
#[should_panic(expected = "exceeds capacity")]
fn one_set_member_past_the_ceiling_fails_at_construction() {
    let members: Vec<Fp> = (1..=8192u64).map(Fp::from).collect();
    let _ = set_polynomial::<Fp, R>(&members);
}

/// The same ceiling for sequences: 8,192 members plus the sentinel need
/// 8,193 coefficients.
#[test]
#[should_panic(expected = "exceeds capacity")]
fn one_sequence_member_past_the_ceiling_fails_at_construction() {
    let members: Vec<Fp> = (1..=8192u64).map(Fp::from).collect();
    let _ = sequence_polynomial::<Fp, R>(&members);
}

/// Builds a balanced fuse tree over `n` singleton seeds (`n` a power of
/// two), printing the average seed time and per-level average fuse time.
fn characterize<H, S, F>(n: u64, mut seed: S, mut fuse: F) -> Result<Pcd<Pasta, R, H>>
where
    H: ragu_pcd::header::Header<Fp>,
    S: FnMut(u64) -> Result<Pcd<Pasta, R, H>>,
    F: FnMut(Pcd<Pasta, R, H>, Pcd<Pasta, R, H>) -> Result<Pcd<Pasta, R, H>>,
{
    let t = std::time::Instant::now();
    let mut nodes = (1..=n).map(&mut seed).collect::<Result<Vec<_>>>()?;
    println!(
        "{n:>4} seeds               | {:>9.2?} avg",
        t.elapsed() / n as u32
    );

    let mut size = 2u64;
    while nodes.len() > 1 {
        let pairs = (nodes.len() / 2) as u32;
        let t = std::time::Instant::now();
        let mut next = Vec::with_capacity(nodes.len() / 2);
        let mut iter = nodes.into_iter();
        while let (Some(a), Some(b)) = (iter.next(), iter.next()) {
            next.push(fuse(a, b)?);
        }
        println!(
            "{pairs:>4} fuses to size {size:>4} | {:>9.2?} avg",
            t.elapsed() / pairs
        );
        nodes = next;
        size *= 2;
    }
    Ok(nodes.pop().expect("n >= 1"))
}

/// Wall-clock characterization: a balanced merge tree over 32 singleton seeds.
///
/// Run: `cargo test -p ragu_pcd --release print_merge_characterization -- --ignored --nocapture`
#[test]
#[ignore = "characterization; run explicitly with --release --nocapture"]
fn print_merge_characterization() -> Result<()> {
    let pasta = Pasta::baked();
    let app = collections_app::<Pasta, R>(pasta)?;
    let rng = std::cell::RefCell::new(StdRng::seed_from_u64(1234));

    println!();
    println!("merge tree over 32 singletons");
    let merged: Pcd<Pasta, R, SetHeader<R>> = characterize(
        32,
        |m| {
            let polynomial = set_polynomial(&[Fp::from(m)]);
            let (pcd, ()) = app.seed(
                &mut *rng.borrow_mut(),
                SeedSet::new(),
                SeedSetWitness { polynomial },
            )?;
            Ok(pcd)
        },
        |a, b| {
            let product = merged_polynomial(&a.data().polynomial, &b.data().polynomial);
            let (pcd, ()) = app.fuse(
                &mut *rng.borrow_mut(),
                MergeSets::new(),
                MergeSetsWitness {
                    a: a.data().polynomial.clone(),
                    b: b.data().polynomial.clone(),
                    product,
                },
                a,
                b,
            )?;
            Ok(pcd)
        },
    )?;

    let t = std::time::Instant::now();
    assert!(app.verify(&merged, &mut *rng.borrow_mut())?);
    println!("final verify at size 32  | {:>9.2?}", t.elapsed());

    Ok(())
}

/// Wall-clock characterization: a balanced concat tree over 32 singleton
/// seeds, ending in the sequence `[1, 2, .., 32]`.
///
/// Run: `cargo test -p ragu_pcd --release print_concat_characterization -- --ignored --nocapture`
#[test]
#[ignore = "characterization; run explicitly with --release --nocapture"]
fn print_concat_characterization() -> Result<()> {
    let pasta = Pasta::baked();
    let app = collections_app::<Pasta, R>(pasta)?;
    let rng = std::cell::RefCell::new(StdRng::seed_from_u64(5678));

    println!();
    println!("concat tree over 32 singletons");
    let out: Pcd<Pasta, R, SeqHeader> = characterize(
        32,
        |m| {
            let member = Fp::from(m);
            let (pcd, ()) = app.seed(
                &mut *rng.borrow_mut(),
                SeedSequence::<Pasta, R>::new(),
                SeedSequenceWitness {
                    sequence: sequence_polynomial::<_, R>(&[member]),
                    member,
                },
            )?;
            Ok(pcd)
        },
        |a, b| {
            let members: Vec<Fp> = [a.data().members.as_slice(), &b.data().members].concat();
            let (pcd, ()) = app.fuse(
                &mut *rng.borrow_mut(),
                ConcatSequences::<Pasta, R>::new(),
                ConcatSequencesWitness {
                    a: sequence_polynomial(&a.data().members),
                    b: sequence_polynomial(&b.data().members),
                    output: sequence_polynomial(&members),
                },
                a,
                b,
            )?;
            Ok(pcd)
        },
    )?;

    let t = std::time::Instant::now();
    assert!(app.verify(&out, &mut *rng.borrow_mut())?);
    println!("final verify at size 32  | {:>9.2?}", t.elapsed());

    // `#[ignore]`d, so this runs only on request;
    // `seeded_singletons_fuse_into_their_concatenation` asserts order per member
    // in CI, over a balanced tree. Thirty-two leaves add scale, not a property.
    let expected: Vec<Fp> = (1..=32u64).map(Fp::from).collect();
    assert_eq!(out.data().members, expected, "order preserved end to end");

    Ok(())
}
