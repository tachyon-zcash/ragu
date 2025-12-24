//! Benchmark for measuring circuit constraint counts and headroom.
//!
//! This test measures the number of multiplication and linear constraints
//! for each internal staged circuit.

use internal_circuits::NativeParameters;
use ragu_circuits::{
    metrics,
    polynomials::{R, Rank},
};
use ragu_pasta::Pasta;

mod internal_circuits {
    pub use ragu_pcd::internal_circuits::*;
}

type TestRank = R<13>;
const HEADER_SIZE: usize = 4;

#[test]
fn constraint_headroom() {
    let pasta = Pasta::baked();
    let log2_circuits = 5;
    let max_muls = TestRank::n();
    let max_linear = TestRank::num_coeffs();

    println!(
        "\nConstraint Headroom (R<13>: max {} muls, {} linear)\n",
        max_muls, max_linear
    );
    println!(
        "{:12} | {:>5} | {:>6} | {:>12} | {:>15} | {:>9}",
        "Circuit", "Muls", "Linear", "Mul Headroom", "Linear Headroom", "Mul Usage"
    );
    println!("{:-<80}", "");

    {
        let circuit = internal_circuits::hashes_1::Circuit::<
            Pasta,
            TestRank,
            HEADER_SIZE,
            NativeParameters,
        >::new(pasta, log2_circuits);
        let m = metrics::eval(&circuit).expect("metrics should succeed");
        print_row(
            "Hashes1",
            m.num_multiplication_constraints,
            m.num_linear_constraints,
            max_muls,
            max_linear,
        );
    }

    {
        let circuit = internal_circuits::hashes_2::Circuit::<
            Pasta,
            TestRank,
            HEADER_SIZE,
            NativeParameters,
        >::new(pasta);
        let m = metrics::eval(&circuit).expect("metrics should succeed");
        print_row(
            "Hashes2",
            m.num_multiplication_constraints,
            m.num_linear_constraints,
            max_muls,
            max_linear,
        );
    }

    {
        let circuit = internal_circuits::fold::Circuit::<
            Pasta,
            TestRank,
            HEADER_SIZE,
            NativeParameters,
        >::new();
        let m = metrics::eval(&circuit).expect("metrics should succeed");
        print_row(
            "Fold",
            m.num_multiplication_constraints,
            m.num_linear_constraints,
            max_muls,
            max_linear,
        );
    }

    {
        let circuit = internal_circuits::compute_c::Circuit::<
            Pasta,
            TestRank,
            HEADER_SIZE,
            NativeParameters,
        >::new();
        let m = metrics::eval(&circuit).expect("metrics should succeed");
        print_row(
            "ComputeC",
            m.num_multiplication_constraints,
            m.num_linear_constraints,
            max_muls,
            max_linear,
        );
    }

    {
        let circuit = internal_circuits::compute_v::Circuit::<Pasta, TestRank, HEADER_SIZE>::new();
        let m = metrics::eval(&circuit).expect("metrics should succeed");
        print_row(
            "ComputeV",
            m.num_multiplication_constraints,
            m.num_linear_constraints,
            max_muls,
            max_linear,
        );
    }
}

fn print_row(name: &str, muls: usize, linear: usize, max_muls: usize, max_linear: usize) {
    assert!(
        muls <= max_muls,
        "{name} exceeds max multiplication constraints: {muls} > {max_muls}"
    );
    assert!(
        linear <= max_linear,
        "{name} exceeds max linear constraints: {linear} > {max_linear}"
    );

    let mul_headroom = max_muls - muls;
    let linear_headroom = max_linear - linear;
    let mul_usage = (muls as f64 / max_muls as f64) * 100.0;

    println!(
        "{:12} | {:>5} | {:>6} | {:>12} | {:>15} | {:>8.1}%",
        name, muls, linear, mul_headroom, linear_headroom, mul_usage
    );
}
