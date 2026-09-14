use ragu_core::{
    drivers::{Driver, emulator::Emulator},
    gadgets::Gadget,
    maybe::Maybe,
};
use ragu_pasta::Fp;
use ragu_primitives::{Element, GadgetExt, io::Write, wire::Compress};

#[derive(Compress, Gadget, Write)]
struct CompressFirst<'dr, #[ragu(driver)] D: Driver<'dr>> {
    /// A field shared by both representations.
    #[ragu(gadget, provided)]
    value: Element<'dr, D>,
    #[ragu(gadget, skip, provided)]
    skipped_by_write: Element<'dr, D>,
    #[ragu(gadget, derived)]
    cache: Element<'dr, D>,
}

#[derive(Gadget, Write, Compress)]
struct WriteFirst<'dr, #[ragu(driver)] D: Driver<'dr>> {
    #[ragu(provided, gadget)]
    value: Element<'dr, D>,
    #[ragu(provided)]
    #[cfg_attr(test, ragu(gadget, skip))]
    skipped_by_write: Element<'dr, D>,
    #[ragu(derived, gadget)]
    cache: Element<'dr, D>,
}

#[test]
fn shared_namespace_preserves_each_derives_classification() {
    let mut dr = Emulator::execute();
    let source = CompressFirst {
        value: Element::constant(&mut dr, Fp::from(3)),
        skipped_by_write: Element::constant(&mut dr, Fp::from(5)),
        cache: Element::constant(&mut dr, Fp::from(7)),
    };
    let compressed = source.compress();
    assert_eq!(*compressed.value.value().take(), Fp::from(3));
    assert_eq!(*compressed.skipped_by_write.value().take(), Fp::from(5));
    let mut written = Vec::new();
    source.write(&mut dr, &mut written).unwrap();
    let values: Vec<_> = written.iter().map(|v| *v.value().take()).collect();
    assert_eq!(values, [Fp::from(3), Fp::from(7)]);
}

#[test]
fn reversed_derive_order_and_conditional_helpers_compile() {
    let mut dr = Emulator::execute();
    let source = WriteFirst {
        value: Element::constant(&mut dr, Fp::from(11)),
        skipped_by_write: Element::constant(&mut dr, Fp::from(13)),
        cache: Element::constant(&mut dr, Fp::from(17)),
    };
    let compressed = source.compress();
    assert_eq!(*compressed.value.value().take(), Fp::from(11));
    assert_eq!(*compressed.skipped_by_write.value().take(), Fp::from(13));
    let mut written = Vec::new();
    source.write(&mut dr, &mut written).unwrap();
    let values: Vec<_> = written.iter().map(|v| *v.value().take()).collect();
    assert_eq!(values, [Fp::from(11), Fp::from(17)]);
}
