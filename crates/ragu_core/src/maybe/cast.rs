use super::{MaybeCast, MaybeKind, Perhaps};

impl<const N: usize, U: Send, K: MaybeKind> MaybeCast<[U; N], K> for [U; N] {
    type Output = [Perhaps<K, U>; N];

    fn empty() -> Self::Output {
        core::array::from_fn(|_| K::empty())
    }
    fn cast(self) -> Self::Output {
        // TODO(ebfull): This can be done more efficiently with unsafe{} code,
        // since the two structures have identical layouts.
        let mut iter = self.into_iter();
        core::array::from_fn(|_| K::maybe_just(|| iter.next().expect("array lengths are the same")))
    }
}

// Generate MaybeCast implementations for tuples of size 2 through 32
ragu_macros::impl_maybe_cast_tuple!(32);

#[cfg(test)]
use super::{Always, Empty, Maybe};

#[test]
fn test_2tuple() {
    let (a, b) = Always::maybe_just(|| (1usize, 2usize)).cast();
    assert_eq!(a.take(), 1);
    assert_eq!(b.take(), 2);
    let (Empty, Empty) = <Empty as Maybe<(usize, usize)>>::cast(Empty);
}

#[test]
fn test_3tuple() {
    let (a, b, c) = Always::maybe_just(|| (1usize, 2usize, 3usize)).cast();
    assert_eq!(a.take(), 1);
    assert_eq!(b.take(), 2);
    assert_eq!(c.take(), 3);
    let (Empty, Empty, Empty) = <Empty as Maybe<(usize, usize, usize)>>::cast(Empty);
}

#[test]
fn test_4tuple_full() {
    let (a, b, c, d) =
        Always::maybe_just(|| (1usize, 2usize, 3usize, 4usize)).cast::<(_, _, _, _)>();
    assert_eq!(a.take(), 1);
    assert_eq!(b.take(), 2);
    assert_eq!(c.take(), 3);
    assert_eq!(d.take(), 4);
    let (Empty, Empty, Empty, Empty) =
        <Empty as Maybe<(usize, usize, usize, usize)>>::cast::<(_, _, _, _)>(Empty);
}

#[test]
fn test_arr() {
    let [a, b, c] = Always::maybe_just(|| [1usize, 2usize, 3usize]).cast();
    assert_eq!(a.take(), 1);
    assert_eq!(b.take(), 2);
    assert_eq!(c.take(), 3);
    let [Empty, Empty, Empty] = <Empty as Maybe<[usize; 3]>>::cast(Empty);
}

#[test]
fn test_5tuple() {
    let (a, b, c, d, e) = Always::maybe_just(|| (1usize, 2usize, 3usize, 4usize, 5usize)).cast();
    assert_eq!(a.take(), 1);
    assert_eq!(b.take(), 2);
    assert_eq!(c.take(), 3);
    assert_eq!(d.take(), 4);
    assert_eq!(e.take(), 5);
    let (Empty, Empty, Empty, Empty, Empty) =
        <Empty as Maybe<(usize, usize, usize, usize, usize)>>::cast(Empty);
}
