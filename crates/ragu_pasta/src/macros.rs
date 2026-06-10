/// Creates an [`Fp`](ragu_arithmetic::pasta_curves::Fp) element from a `0x`-prefixed hex
/// literal via [`Fp::from_raw`](ragu_arithmetic::pasta_curves::Fp::from_raw) (non-Montgomery
/// representation).
#[macro_export]
macro_rules! fp {
    ( $x:expr ) => {
        $crate::Fp::from_raw(ragu_arithmetic::repr256!($x))
    };
}

/// Creates an [`Fq`](ragu_arithmetic::pasta_curves::Fq) element from a `0x`-prefixed hex
/// literal via [`Fq::from_raw`](ragu_arithmetic::pasta_curves::Fq::from_raw) (non-Montgomery
/// representation).
#[macro_export]
macro_rules! fq {
    ( $x:expr ) => {
        $crate::Fq::from_raw(ragu_arithmetic::repr256!($x))
    };
}
