//! Values that are pure functions of their types, built once and kept.

/// The value a key type names, built once and kept: under `std`, one
/// process-wide map from the [`TypeId`] of a key type, which names the
/// function and its type parameters, to the value built for it; without
/// `std`, rebuilt on each request, which costs time alone. Only a successful
/// build is kept. The build runs outside the lock, since a build may ask for
/// other kept values (a decompression schedule asks for the other side's
/// sizes, and an extension's descriptor for other profile dimensions), so
/// callers racing on a first request may each build; every one returns the
/// value kept first.
///
/// [`TypeId`]: core::any::TypeId
#[cfg(feature = "std")]
pub(crate) fn memo<Key: 'static, T: Clone + Send + Sync + 'static, E>(
    build: impl FnOnce() -> Result<T, E>,
) -> Result<T, E> {
    use core::any::{Any, TypeId};
    use std::{
        boxed::Box,
        collections::BTreeMap,
        sync::{Mutex, OnceLock, PoisonError},
    };
    static MEMO: OnceLock<Mutex<BTreeMap<TypeId, Box<dyn Any + Send + Sync>>>> = OnceLock::new();
    let memo = MEMO.get_or_init(|| Mutex::new(BTreeMap::new()));
    let key = TypeId::of::<Key>();
    let kept = memo
        .lock()
        .unwrap_or_else(PoisonError::into_inner)
        .get(&key)
        .map(|value| {
            value
                .downcast_ref::<T>()
                .expect("a key names one type")
                .clone()
        });
    if let Some(value) = kept {
        return Ok(value);
    }
    let value = build()?;
    Ok(memo
        .lock()
        .unwrap_or_else(PoisonError::into_inner)
        .entry(key)
        .or_insert_with(|| Box::new(value))
        .downcast_ref::<T>()
        .expect("a key names one type")
        .clone())
}

#[cfg(not(feature = "std"))]
#[allow(
    clippy::extra_unused_type_parameters,
    reason = "the key names the kept value, which only the std build keeps"
)]
pub(crate) fn memo<Key: 'static, T, E>(build: impl FnOnce() -> Result<T, E>) -> Result<T, E> {
    build()
}
