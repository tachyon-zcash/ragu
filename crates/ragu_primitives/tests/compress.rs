use ragu_primitives::wire::{Compress, Decode, Encode, Limits};

// Neither Clone nor a byte codec is required of the omitted type.
#[derive(Debug)]
struct Cache;

#[derive(Compress)]
struct Working<T>
where
    T: Clone,
{
    #[ragu(provided)]
    value: T,
    #[ragu(derived)]
    cache: Cache,
    #[ragu(derived)]
    scratch: [u8; 3],
}

#[test]
fn omitted_cache_needs_no_clone_or_codec() {
    let working = Working {
        value: 42u64,
        cache: Cache,
        scratch: [0; 3],
    };
    let bytes = working.compress().to_bytes();
    let decoded = WorkingCompressed::<u64>::from_bytes(&bytes, Limits::default()).unwrap();
    assert_eq!(decoded.value, 42);
    assert_eq!(bytes, 42u64.to_bytes());
    assert_eq!(working.scratch.len(), 3);
    assert_eq!(format!("{:?}", working.cache), "Cache");
}

#[derive(Compress)]
struct Outer {
    #[ragu(provided)]
    inner: WorkingCompressed<u64>,
    #[cfg(not(test))]
    not_in_this_build: (),
    #[cfg(test)]
    #[ragu(provided)]
    tail: u16,
}

// The generated type does not automatically derive Clone; it is only needed
// here because another source struct chooses to retain it as a provided field.
impl Clone for WorkingCompressed<u64> {
    fn clone(&self) -> Self {
        Self { value: self.value }
    }
}

#[test]
fn nested_structs_have_only_one_envelope() {
    let outer = Outer {
        inner: WorkingCompressed { value: 5 },
        tail: 9,
    };
    let bytes = outer.compress().to_bytes();
    assert_eq!(bytes, [1, 5, 0, 0, 0, 0, 0, 0, 0, 9, 0]);
    let decoded = OuterCompressed::from_bytes(&bytes, Limits::default()).unwrap();
    assert_eq!(decoded.inner.value, 5);
    assert_eq!(decoded.tail, 9);
}
