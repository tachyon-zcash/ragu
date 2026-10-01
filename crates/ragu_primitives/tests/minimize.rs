use ragu_primitives::wire::{Checked, Decode, Encode, Limits, Minimize};

// Neither Clone nor a byte codec is required of the omitted type.
struct Cache;

// The derived fields exist only to be left out of the minimal type.
#[allow(dead_code)]
#[derive(Minimize)]
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
    let bytes = working.minimize().to_bytes();
    let decoded = WorkingMinimal::<u64>::from_bytes(&bytes, Limits::default()).unwrap();
    assert_eq!(decoded.value, 42);
    assert_eq!(bytes, 42u64.to_bytes());
}

#[derive(Minimize)]
struct Outer {
    #[ragu(provided)]
    inner: WorkingMinimal<u64>,
    #[cfg(not(test))]
    not_in_this_build: (),
    #[cfg(test)]
    #[ragu(provided)]
    tail: u16,
}

// The generated type does not automatically derive Clone; it is only needed
// here because another source struct chooses to retain it as a provided field.
impl Clone for WorkingMinimal<u64> {
    fn clone(&self) -> Self {
        Self { value: self.value }
    }
}

#[test]
fn nested_structs_have_only_one_envelope() {
    let outer = Outer {
        inner: WorkingMinimal { value: 5 },
        tail: 9,
    };
    let bytes = outer.minimize().to_bytes();
    assert_eq!(bytes, [1, 5, 0, 0, 0, 0, 0, 0, 0, 9, 0]);
    let decoded = OuterMinimal::from_bytes(&bytes, Limits::default()).unwrap();
    assert_eq!(decoded.inner.value, 5);
    assert_eq!(decoded.tail, 9);
}

#[derive(Minimize)]
struct Committed {
    #[ragu(provided)]
    poly: Vec<u8>,
    #[ragu(checked = poly, batch = host)]
    commitment: u64,
    #[ragu(provided)]
    other_poly: Vec<u8>,
    #[ragu(checked = other_poly, batch = nested)]
    other_commitment: u64,
}

// Sums each polynomial's bytes and records it beside the claimed commitment.
#[derive(Default)]
struct Sums(Vec<(u64, u64)>);

impl<'a> Checked<'a, Vec<u8>, u64> for Sums {
    fn check(&mut self, poly: &'a Vec<u8>, commitment: &u64) {
        self.0
            .push((poly.iter().map(|&b| u64::from(b)).sum(), *commitment));
    }
}

#[test]
fn checked_fields_ship_and_visit_their_batch() {
    let committed = Committed {
        poly: vec![1, 2, 3],
        commitment: 6,
        other_poly: vec![4],
        other_commitment: 9,
    };
    // Checked fields stay on the wire, in declaration order.
    let bytes = committed.minimize().to_bytes();
    let decoded = CommittedMinimal::from_bytes(&bytes, Limits::default()).unwrap();
    assert_eq!(decoded.commitment, 6);
    assert_eq!(decoded.other_commitment, 9);
    // Each batch visits only its own pairs.
    let mut host = Sums::default();
    committed.for_each_checked_host(&mut host);
    assert_eq!(host.0, [(6, 6)]);
    let mut nested = Sums::default();
    committed.for_each_checked_nested(&mut nested);
    assert_eq!(nested.0, [(4, 9)]);
}

#[test]
fn consuming_minimization_moves_retained_storage() {
    let values = vec![1u64, 2, 3];
    let pointer = values.as_ptr();
    let working = Working {
        value: values,
        cache: Cache,
        scratch: [0; 3],
    };
    let minimal = working.into_minimal();
    assert_eq!(minimal.value.as_ptr(), pointer);
    assert_eq!(minimal.value, [1, 2, 3]);
}
