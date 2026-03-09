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
mod tests {
    use alloc::vec;
    use alloc::vec::Vec;

    use crate::maybe::{Always, Empty, Maybe, MaybeKind};

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
        let (a, b, c, d, e) =
            Always::maybe_just(|| (1usize, 2usize, 3usize, 4usize, 5usize)).cast();
        assert_eq!(a.take(), 1);
        assert_eq!(b.take(), 2);
        assert_eq!(c.take(), 3);
        assert_eq!(d.take(), 4);
        assert_eq!(e.take(), 5);
        let (Empty, Empty, Empty, Empty, Empty) =
            <Empty as Maybe<(usize, usize, usize, usize, usize)>>::cast(Empty);
    }

    #[test]
    fn test_2tuple_mixed_types() {
        let (a, b) = Always::maybe_just(|| (1u8, 2u64)).cast();
        assert_eq!(a.take(), 1u8);
        assert_eq!(b.take(), 2u64);
        let (Empty, Empty) = <Empty as Maybe<(u8, u64)>>::cast(Empty);
    }

    #[test]
    fn test_3tuple_mixed_types() {
        let (a, b, c) = Always::maybe_just(|| (1u8, 2u16, 3u32)).cast();
        assert_eq!(a.take(), 1u8);
        assert_eq!(b.take(), 2u16);
        assert_eq!(c.take(), 3u32);
        let (Empty, Empty, Empty) = <Empty as Maybe<(u8, u16, u32)>>::cast(Empty);
    }

    #[test]
    fn test_4tuple_mixed_types() {
        let (a, b, c, d) = Always::maybe_just(|| (1u8, 2u16, 3u32, 4u64)).cast();
        assert_eq!(a.take(), 1u8);
        assert_eq!(b.take(), 2u16);
        assert_eq!(c.take(), 3u32);
        assert_eq!(d.take(), 4u64);
        let (Empty, Empty, Empty, Empty) = <Empty as Maybe<(u8, u16, u32, u64)>>::cast(Empty);
    }

    #[test]
    fn test_2tuple_with_zst() {
        let (a, b) = Always::maybe_just(|| ((), 42usize)).cast();
        a.take();
        assert_eq!(b.take(), 42);
        let (Empty, Empty) = <Empty as Maybe<((), usize)>>::cast(Empty);
    }

    #[test]
    fn test_arr_zst() {
        let arr = Always::maybe_just(|| [(); 5]).cast();
        for elem in arr {
            elem.take();
        }
        let [Empty, Empty, Empty, Empty, Empty] = <Empty as Maybe<[(); 5]>>::cast(Empty);
    }

    #[test]
    fn test_6tuple() {
        let (a, _b, _c, _d, _e, f) =
            Always::maybe_just(|| (1usize, 2usize, 3usize, 4usize, 5usize, 6usize)).cast();
        assert_eq!(a.take(), 1);
        assert_eq!(f.take(), 6);
        let (Empty, Empty, Empty, Empty, Empty, Empty) =
            <Empty as Maybe<(usize, usize, usize, usize, usize, usize)>>::cast(Empty);
    }

    #[test]
    fn test_arr_non_copy() {
        let [a, b, c] =
            Always::maybe_just(|| [vec![1, 2], vec![3, 4], vec![5, 6]]).cast::<[Vec<i32>; 3]>();
        assert_eq!(a.take(), vec![1, 2]);
        assert_eq!(b.take(), vec![3, 4]);
        assert_eq!(c.take(), vec![5, 6]);
    }
}
