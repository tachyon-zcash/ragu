/// Assigns `val` into the next slot and advances the counter.
pub const fn push<T: Copy, const N: usize>(slots: &mut [Option<T>; N], c: &mut usize, val: T) {
    slots[*c] = Some(val);
    *c += 1;
}

/// Unwraps every element of an `Option` array at compile time.
///
/// Panics (at compile time) if any slot is `None`.
pub const fn unwrap_all<T: Copy, const N: usize>(slots: [Option<T>; N]) -> [T; N] {
    // The filler is immediately overwritten for every index; it exists only
    // because `[T; N]` requires an initializer in const context.
    let mut arr = [slots[0].unwrap(); N];
    let mut i = 1;
    while i < N {
        arr[i] = slots[i].unwrap();
        i += 1;
    }
    arr
}
