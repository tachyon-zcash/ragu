//! Device commitments against the reference backend.
//!
//! Every check compares `AcceleratedProver`, which commits on the CUDA
//! device when the `gpu` feature finds one, with `ReferenceBackend` on the
//! same polynomials and generators. On a machine without a device the
//! accelerated backend takes its CPU path and the checks still hold.

#![cfg(feature = "gpu")]

use ragu_acceleration::AcceleratedProver;
use ragu_backend::{Backend, ReferenceBackend};
use ragu_circuits::polynomials::{ProductionRank, Rank, TestRank, sparse};
use udon::{
    curve::{AffineAdapter, Pallas, PastaCurve, Point, Vesta},
    cycle::Generators,
    field::{FieldAdapter, PallasBase, PallasScalar, PastaField, PrimeModulus},
};

/// A scalar of the curve `P`, in Udon's own representation.
type Fe<P> = PastaField<<P as PastaCurve>::Scalar>;
type Poly<P, R> = sparse::Polynomial<FieldAdapter<<P as PastaCurve>::Scalar>, R>;

/// A deterministic stream of field elements with no structure the window
/// recoding could favor.
struct Stream<P: PastaCurve>(Fe<P>);

impl<P: PastaCurve> Stream<P> {
    fn new(seed: u64) -> Self {
        Self(Fe::<P>::from_u64(seed).add(&Fe::<P>::from_u64(0x9e37_79b9_7f4a_7c15)))
    }

    fn next(&mut self) -> Fe<P> {
        self.0 = self.0.square().add(&Fe::<P>::from_u64(5));
        self.0
    }
}

/// `len` generators with unknown-to-the-test relationships, kept for the
/// life of the process as `Generators` requires. With `paired`, generator
/// `2k + 1` repeats generator `2k`, so opposite scalars on a pair cancel.
fn generators<P: PastaCurve>(len: usize, seed: u64, paired: bool) -> Generators<P> {
    let mut stream = Stream::<P>::new(seed);
    let mut points = Vec::with_capacity(len);
    while points.len() < len {
        let point = Point::<P>::GENERATOR
            .mul_projective(&stream.next())
            .to_point();
        points.push(point);
        if paired && points.len() < len {
            points.push(point);
        }
    }
    let h = Point::<P>::GENERATOR
        .mul_projective(&stream.next())
        .to_point();
    Generators::new(points.leak(), h)
}

fn poly<P: PastaCurve, R: Rank>(coeffs: Vec<Fe<P>>) -> Poly<P, R> {
    sparse::Polynomial::from_coeffs(coeffs.into_iter().map(FieldAdapter::new).collect())
}

/// Scalars whose signed 8-bit digits sit on every boundary of the recoding:
/// zero digits, the largest positive digit, the smallest negative one, and
/// carries that run the whole width.
fn boundary_scalars<P: PastaCurve>() -> Vec<Fe<P>> {
    let from_bytes = |bytes: [u8; 32]| Fe::<P>::from_bytes_reduced(&bytes);
    let mut scalars = vec![
        Fe::<P>::ZERO,
        Fe::<P>::ONE,
        Fe::<P>::ONE.neg(),
        Fe::<P>::from_u64(2).neg(),
        Fe::<P>::from_u64(127),
        Fe::<P>::from_u64(128),
        Fe::<P>::from_u64(129),
        Fe::<P>::from_u64(255),
        Fe::<P>::from_u64(256),
        Fe::<P>::from_u64(u64::MAX),
        Fe::<P>::from_u128(u128::MAX),
    ];
    for byte in [0x7f, 0x80, 0x81, 0xff, 0x01] {
        let mut bytes = [byte; 32];
        // Stay below the 255-bit modulus so the pattern survives reduction.
        bytes[31] = 0x3f.min(byte);
        scalars.push(from_bytes(bytes));
        scalars.push(from_bytes(bytes).neg());
    }
    for bit in [7, 8, 63, 64, 127, 128, 247, 248, 253] {
        let mut bytes = [0u8; 32];
        bytes[bit / 8] = 1 << (bit % 8);
        let power = from_bytes(bytes);
        scalars.push(power);
        scalars.push(power.sub(&Fe::<P>::ONE));
        scalars.push(power.neg());
    }
    scalars
}

fn check_curve<P: PastaCurve>(seed: u64)
where
    Generators<P>: ragu_core::FixedGenerators<AffineAdapter<P>>,
{
    type R = ProductionRank;
    let generators = generators::<P>(R::num_coeffs(), seed, false);
    let mut stream = Stream::<P>::new(seed ^ 0xabcd);

    // Dense polynomials of full-size coefficients.
    let dense: Vec<Poly<P, R>> = (0..5)
        .map(|_| poly::<P, R>((0..R::num_coeffs()).map(|_| stream.next()).collect()))
        .collect();
    // Blocks separated by gaps, with a block ending at the last coefficient.
    let mut gapped = vec![Fe::<P>::ZERO; R::num_coeffs()];
    for range in [3..400, 1000..1001, 4096..5000, 8000..8192] {
        for coefficient in &mut gapped[range] {
            *coefficient = stream.next();
        }
    }
    // Every boundary scalar, repeated across the generators.
    let boundary = boundary_scalars::<P>();
    let cycled: Vec<_> = (0..R::num_coeffs())
        .map(|index| boundary[index % boundary.len()])
        .collect();
    // Fewer terms than the device is used for.
    let mut short = vec![Fe::<P>::ZERO; R::num_coeffs()];
    for coefficient in &mut short[10..40] {
        *coefficient = stream.next();
    }

    let mut polys = dense;
    polys.push(poly::<P, R>(gapped));
    polys.push(poly::<P, R>(cycled));
    polys.push(poly::<P, R>(short));
    polys.push(poly::<P, R>(vec![Fe::<P>::ZERO; R::num_coeffs()]));
    // Requests of the sizes the device splits differently, a term over 32,
    // 16, 8 or 4 threads, and around the size it starts at, on the last
    // generators, with boundary scalars among the terms.
    for count in [31, 32, 33, 64, 128, 129, 256, 257, 1000, 1100, 2100, 4200] {
        let mut small = vec![Fe::<P>::ZERO; R::num_coeffs()];
        let start = R::num_coeffs() - count;
        for (offset, coefficient) in small[start..].iter_mut().enumerate() {
            *coefficient = match offset % 3 {
                0 => boundary[offset % boundary.len()],
                _ => stream.next(),
            };
        }
        polys.push(poly::<P, R>(small));
    }

    for poly in &polys {
        assert_eq!(
            AcceleratedProver::sparse_commit(poly, &generators),
            ReferenceBackend::sparse_commit(poly, &generators),
        );
        assert_eq!(
            AcceleratedProver::sparse_commit_to_affine(poly, &generators),
            ReferenceBackend::sparse_commit_to_affine(poly, &generators),
        );
    }

    let refs: Vec<_> = polys.iter().collect();
    assert_eq!(
        AcceleratedProver::sparse_commit_many(&refs, &generators),
        ReferenceBackend::sparse_commit_many(&refs, &generators),
    );
    assert_eq!(
        AcceleratedProver::sparse_commit_batch([&polys[0], &polys[8], &polys[5]], &generators),
        ReferenceBackend::sparse_commit_batch([&polys[0], &polys[8], &polys[5]], &generators),
    );
    // Two full polynomials: a term over two threads.
    assert_eq!(
        AcceleratedProver::sparse_commit_batch([&polys[1], &polys[2]], &generators),
        ReferenceBackend::sparse_commit_batch([&polys[1], &polys[2]], &generators),
    );
    assert!(
        AcceleratedProver::sparse_commit_many::<AffineAdapter<P>, R, _>(&[], &generators)
            .is_empty()
    );

    // The same commitments begun and waited for later, with other requests
    // of the curve served meanwhile. A curve takes one begun request at a
    // time, and this test may share its curve with another, so a request
    // that is declined is not an error.
    let expected = ReferenceBackend::sparse_commit_many(&refs, &generators);
    if let Some(mut started) = AcceleratedProver::sparse_commit_many_start(&refs, &generators) {
        assert_eq!(
            AcceleratedProver::sparse_commit_many(&refs[..4], &generators),
            expected[..4]
        );
        while !started.ready() {
            std::hint::spin_loop();
        }
        assert_eq!(started.finish().expect("the device finishes"), expected);
    }
    // One given up leaves the device as it was.
    drop(AcceleratedProver::sparse_commit_many_start(
        &refs[..2],
        &generators,
    ));
    assert_eq!(
        AcceleratedProver::sparse_commit_many(&refs, &generators),
        expected
    );
}

/// A sum that cancels exactly leaves the device with the identity, which has
/// no affine form.
fn check_identity<P: PastaCurve>(seed: u64)
where
    Generators<P>: ragu_core::FixedGenerators<AffineAdapter<P>>,
{
    type R = ProductionRank;
    let generators = generators::<P>(R::num_coeffs(), seed, true);
    let mut stream = Stream::<P>::new(seed ^ 0x1234);
    let mut coeffs = Vec::with_capacity(R::num_coeffs());
    for _ in 0..R::num_coeffs() / 2 {
        let scalar = stream.next();
        coeffs.push(scalar);
        coeffs.push(scalar.neg());
    }
    let cancelling = poly::<P, R>(coeffs.clone());
    // The same polynomial with one pair left unbalanced.
    coeffs[4001] = coeffs[4001].add(&Fe::<P>::ONE);
    let unbalanced = poly::<P, R>(coeffs);

    let expected = ReferenceBackend::sparse_commit_many(&[&cancelling, &unbalanced], &generators);
    assert_eq!(
        expected[0],
        ReferenceBackend::sparse_commit(&poly::<P, R>(vec![]), &generators)
    );
    assert_ne!(expected[0], expected[1]);
    assert_eq!(
        AcceleratedProver::sparse_commit_many(&[&cancelling, &unbalanced], &generators),
        expected,
    );
    assert_eq!(
        AcceleratedProver::sparse_commit(&cancelling, &generators),
        expected[0]
    );
}

/// A rank whose polynomials are all below the device threshold on their own
/// reaches the device only as a batch.
fn check_small_rank<P: PastaCurve>(seed: u64)
where
    Generators<P>: ragu_core::FixedGenerators<AffineAdapter<P>>,
{
    type R = TestRank;
    let generators = generators::<P>(R::num_coeffs(), seed, false);
    let mut stream = Stream::<P>::new(seed ^ 0x77);
    let polys: Vec<Poly<P, R>> = (0..7)
        .map(|_| poly::<P, R>((0..R::num_coeffs()).map(|_| stream.next()).collect()))
        .collect();
    let refs: Vec<_> = polys.iter().collect();
    assert_eq!(
        AcceleratedProver::sparse_commit_many(&refs, &generators),
        ReferenceBackend::sparse_commit_many(&refs, &generators),
    );
    assert_eq!(
        AcceleratedProver::sparse_commit(&polys[0], &generators),
        ReferenceBackend::sparse_commit(&polys[0], &generators),
    );
}

/// Every operation of the device's polynomial store against the host
/// polynomial arithmetic it stands for.
fn check_poly_device<M: PrimeModulus>(seed: u64) {
    type R = ProductionRank;
    type Dense<M> = sparse::Polynomial<FieldAdapter<M>, R>;
    let Some(mut device) = AcceleratedProver::poly_device::<FieldAdapter<M>, R>() else {
        // No device, or its store is in use: there is nothing to compare.
        return;
    };
    // While one caller holds the store, the next computes on the host.
    assert!(AcceleratedProver::poly_device::<FieldAdapter<M>, R>().is_none());

    let mut state = PastaField::<M>::from_u64(seed).add(&PastaField::<M>::from_u64(99));
    let mut next = move || {
        state = state.square().add(&PastaField::<M>::from_u64(3));
        FieldAdapter::new(state)
    };
    let n = R::num_coeffs();
    let zero = FieldAdapter::new(PastaField::<M>::ZERO);
    let mut gapped = vec![zero; n];
    for range in [0..1, 17..900, 4095..4097, 8000..8192] {
        for coefficient in &mut gapped[range] {
            *coefficient = next();
        }
    }
    let mut short = vec![zero; n];
    short[n - 1] = next();
    let polys: Vec<Dense<M>> = vec![
        sparse::Polynomial::from_coeffs((0..n).map(|_| next()).collect()),
        sparse::Polynomial::from_coeffs((0..n).map(|_| next()).collect()),
        sparse::Polynomial::from_coeffs(gapped),
        sparse::Polynomial::from_coeffs(short),
        sparse::Polynomial::new(),
        sparse::Polynomial::from_coeffs((0..n / 2).map(|_| next()).collect()),
    ];
    let same = |a: &Dense<M>, b: &Dense<M>| a.iter_coeffs().eq(b.iter_coeffs());

    let refs: Vec<_> = polys.iter().collect();
    let slots = device.upload(&refs);
    for (poly, back) in polys.iter().zip(device.download(&slots)) {
        assert!(same(poly, &back));
    }

    // Polynomials taken in apart from the store's other work: calls that do
    // not read them go on meanwhile, and the first that does sees them
    // stored. Two such uploads in a row, then work on other slots, then a
    // product across both and a read of each.
    let apart = device.upload_apart(&refs[..3]);
    let later = device.upload_apart(&refs[3..]);
    let doubled = device.lincomb(&[vec![(
        FieldAdapter::new(PastaField::<M>::from_u64(2)),
        slots[0],
    )]]);
    let mut twice = polys[0].clone();
    twice.scale(FieldAdapter::new(PastaField::<M>::from_u64(2)));
    assert!(same(&twice, &device.download(&doubled)[0]));
    assert_eq!(
        device.revdot(&[(apart[1], later[0]), (slots[1], apart[0])]),
        [polys[1].revdot(&polys[3]), polys[1].revdot(&polys[0])]
    );
    for (poly, back) in polys.iter().zip(device.download(&[apart, later].concat())) {
        assert!(same(poly, &back));
    }

    // An upload large enough to go to the device in several pieces.
    let many: Vec<_> = refs.iter().copied().cycle().take(40).collect();
    assert!(
        many.iter()
            .map(|poly| poly.iter_coeffs().count())
            .sum::<usize>()
            > 3 << 16
    );
    let pieces = device.upload_apart(&many);
    for (poly, back) in many.iter().zip(device.download(&pieces)) {
        assert!(same(poly, &back));
    }

    // The same with the storing left to the caller: the slots are there at
    // once, and a call that reads them waits for the work, which here runs
    // on another thread.
    let (left, work) = device.upload_later(&refs);
    let work = work.expect("the device leaves the upload to its caller");
    std::thread::scope(|scope| {
        scope.spawn(work);
        for (poly, back) in polys.iter().zip(device.download(&left)) {
            assert!(same(poly, &back));
        }
    });

    let mut pairs = Vec::new();
    let mut expected = Vec::new();
    for (i, a) in polys.iter().enumerate() {
        for (j, b) in polys.iter().enumerate() {
            pairs.push((slots[i], slots[j]));
            expected.push(a.revdot(b));
        }
    }
    assert_eq!(device.revdot(&pairs), expected);

    let one = FieldAdapter::new(PastaField::<M>::ONE);
    let jobs = vec![
        vec![(next(), slots[0]), (next(), slots[1]), (next(), slots[2])],
        vec![(one, slots[3]), (one, slots[5]), (zero, slots[0])],
        vec![(next(), slots[4])],
        vec![],
    ];
    let combined = device.lincomb(&jobs);
    for (job, got) in jobs.iter().zip(device.download(&combined)) {
        let mut expected = Dense::<M>::new();
        for (scalar, slot) in job {
            let index = slots.iter().position(|s| s == slot).unwrap();
            let mut term = polys[index].clone();
            term.scale(*scalar);
            expected.add_assign(&term);
        }
        assert!(same(&expected, &got));
    }

    let z = next();
    let powers = device.powers(z);
    let dilated = device.dilate_add(
        &[
            (slots[0], slots[1]),
            (slots[2], slots[4]),
            (slots[4], slots[3]),
        ],
        powers,
        slots[5],
    );
    for ((a, s), got) in [(0, 1), (2, 4), (4, 3)]
        .into_iter()
        .zip(device.download(&dilated))
    {
        let mut expected = polys[a].clone();
        expected.dilate(z);
        expected.add_assign(&polys[s]);
        expected.add_assign(&polys[5]);
        assert!(same(&expected, &got));
    }
    // Results feed later operations.
    assert_eq!(
        device.revdot(&[(combined[0], dilated[0])]),
        vec![{
            let mut a = Dense::<M>::new();
            for (scalar, slot) in &jobs[0] {
                let index = slots.iter().position(|s| s == slot).unwrap();
                let mut term = polys[index].clone();
                term.scale(*scalar);
                a.add_assign(&term);
            }
            let mut b = polys[0].clone();
            b.dilate(z);
            b.add_assign(&polys[1]);
            b.add_assign(&polys[5]);
            a.revdot(&b)
        }]
    );

    // Evaluation as a product with a point's powers.
    let pairs: Vec<_> = slots.iter().map(|slot| (*slot, powers)).collect();
    let expected: Vec<_> = polys.iter().map(|poly| poly.eval(z)).collect();
    assert_eq!(device.dot(&pairs), expected);

    // Quotients by X - point, summed: every dividend shape, a point of
    // zero, a point of one, and a job with nothing to divide.
    let quotient_jobs = vec![
        (next(), vec![(next(), slots[0]), (next(), slots[2])]),
        (zero, vec![(one, slots[1]), (next(), slots[3])]),
        (one, vec![(next(), slots[5])]),
        (next(), vec![(one, slots[3])]),
        (next(), vec![(next(), slots[4])]),
        (next(), vec![]),
        (
            z,
            vec![
                (one, slots[0]),
                (one, slots[1]),
                (one, slots[2]),
                (one, slots[5]),
            ],
        ),
    ];
    type Jobs<M> = [(FieldAdapter<M>, Vec<(FieldAdapter<M>, ragu_backend::Slot)>)];
    let quotients_of = |jobs: &Jobs<M>| {
        let mut expected = vec![zero; n];
        for (point, terms) in jobs {
            let mut dividend = vec![zero; n];
            for (scalar, slot) in terms {
                let index = slots.iter().position(|s| s == slot).unwrap();
                for (sum, coefficient) in dividend.iter_mut().zip(polys[index].iter_coeffs()) {
                    *sum += *scalar * coefficient;
                }
            }
            let mut carry = zero;
            for k in (1..n).rev() {
                carry = carry * *point + dividend[k];
                expected[k - 1] += carry;
            }
        }
        sparse::Polynomial::from_coeffs(expected)
    };
    // The same without the point of zero, and so with fewer jobs than the
    // device sums in lanes.
    let invertible: Vec<_> = quotient_jobs
        .iter()
        .filter(|(point, _)| *point != zero)
        .cloned()
        .collect();
    assert_eq!(invertible.len() + 1, quotient_jobs.len());
    let quotient = device.quotients(&invertible);
    assert!(same(
        &quotients_of(&invertible),
        &device.download(&[quotient])[0]
    ));
    let quotient = device.quotients(&quotient_jobs);
    let expected = quotients_of(&quotient_jobs);
    assert!(same(&expected, &device.download(&[quotient])[0]));
    // The slots the divisions used are free again, and results still feed
    // later operations.
    let after = device.lincomb(&[vec![(one, quotient), (one, slots[0])]]);
    let mut sum = expected.clone();
    sum.add_assign(&polys[0]);
    assert!(same(&sum, &device.download(&after)[0]));
    assert!(same(&expected, &device.download(&[quotient])[0]));

    drop(device);
    assert!(AcceleratedProver::poly_device::<FieldAdapter<M>, R>().is_some());
}

/// The device commits to polynomials it holds as the reference commits to
/// them, and reads them back unchanged, in the one request.
fn check_device_commit<P: PastaCurve>(seed: u64)
where
    Generators<P>: ragu_core::FixedGenerators<AffineAdapter<P>>,
{
    type R = ProductionRank;
    let Some(mut device) = AcceleratedProver::poly_device::<FieldAdapter<P::Scalar>, R>() else {
        // No device, or its store is in use: there is nothing to compare.
        return;
    };
    let generators = generators::<P>(R::num_coeffs(), seed, false);
    let mut stream = Stream::<P>::new(seed ^ 0x51);
    let polys: Vec<Poly<P, R>> = vec![
        poly::<P, R>((0..R::num_coeffs()).map(|_| stream.next()).collect()),
        poly::<P, R>((0..R::num_coeffs() / 3).map(|_| stream.next()).collect()),
        poly::<P, R>(vec![]),
    ];
    let refs: Vec<_> = polys.iter().collect();
    let slots = device.upload(&refs);
    let (read, commitments) = AcceleratedProver::device_commit::<AffineAdapter<P>, R, _>(
        device.as_mut(),
        &slots,
        &generators,
    )
    .expect("the device commits to what it holds");
    assert_eq!(read.len(), polys.len());
    for (read, poly) in read.iter().zip(&polys) {
        assert!(read.iter_coeffs().eq(poly.iter_coeffs()));
    }
    assert_eq!(
        commitments,
        ReferenceBackend::sparse_commit_many(&refs, &generators)
    );
    // One slot alone, as the prover asks for a quotient.
    let (read, commitments) = AcceleratedProver::device_commit::<AffineAdapter<P>, R, _>(
        device.as_mut(),
        &slots[1..2],
        &generators,
    )
    .expect("the device commits to what it holds");
    assert!(read[0].iter_coeffs().eq(polys[1].iter_coeffs()));
    assert_eq!(
        commitments,
        [ReferenceBackend::sparse_commit(&polys[1], &generators)]
    );
    // The reference backend has no such device.
    assert!(
        ReferenceBackend::device_commit::<AffineAdapter<P>, R, _>(
            device.as_mut(),
            &slots,
            &generators
        )
        .is_none()
    );
}

#[test]
fn the_polynomial_store_matches_host_arithmetic() {
    check_poly_device::<PallasBase>(7);
    check_poly_device::<PallasScalar>(8);
    // Each curve commits from the store of its scalar field, which this
    // test has to itself.
    check_device_commit::<Pallas>(9);
    check_device_commit::<Vesta>(10);
}

#[test]
fn commitments_match_the_reference_on_pallas() {
    check_curve::<Pallas>(1);
}

#[test]
fn commitments_match_the_reference_on_vesta() {
    check_curve::<Vesta>(2);
}

#[test]
fn a_cancelling_sum_is_the_identity() {
    check_identity::<Pallas>(3);
    check_identity::<Vesta>(4);
}

#[test]
fn a_small_rank_commits_as_a_batch() {
    check_small_rank::<Pallas>(5);
    check_small_rank::<Vesta>(6);
}
