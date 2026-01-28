use alloc::vec::Vec;
use core::marker::PhantomData;
use ff::Field;

/// Marker trait for the different states that the [`BatchInverter`] can be in.
pub trait State: private::Sealed {}

mod private {
    pub trait Sealed {}
}

/// [`State`] of the [`BatchInverter`] where it can still receive more inversion requests.
pub struct Pending;
impl private::Sealed for Pending {}
impl State for Pending {}

/// [`State`] of the [`BatchInverter`] after batch inversion has been performed. After this point,
/// no more inversion requests can be created, but inverted values are available for retrieval.
pub struct Resolved;
impl private::Sealed for Resolved {}
impl State for Resolved {}

/// A token that represents a pending reversion request.
///
/// Upon resolution of the [`BatchInverter`], the inverted value can be retrieved using this token.
pub struct Token {
    index: usize,
}

/// A batch inverter that accumulates field elements and inverts them using Mongomery's trick.
///
/// Uses the [typestate][typestate] pattern to ensure compile-time safety:
/// - [`Pending`] state: Elements can be [added][Self::add].
/// - [`Resolved`] state: Inverted elements can be [retrieved][Self::retrieve].
///
/// [typestate]: https://cliffle.com/blog/rust-typestate/
pub struct BatchInverter<F, S: State> {
    elements: Vec<F>,
    _state: PhantomData<S>,
}

impl<F: Field> BatchInverter<F, Pending> {
    /// Creates an empty batch inverter in the default pending state.
    pub fn new() -> Self {
        Self::default()
    }

    /// Creates an empty batch inverter with the specified capacity.
    pub fn with_capacity(capacity: usize) -> Self {
        Self {
            elements: Vec::with_capacity(capacity),
            _state: PhantomData,
        }
    }

    /// Returns the number of elements pending inversion.
    pub fn len(&self) -> usize {
        self.elements.len()
    }

    /// Returns `true` if there are no elements in the batch inverter.
    pub fn is_empty(&self) -> bool {
        self.elements.is_empty()
    }

    /// Adds an element to be inverted and returns a token that can be used to retrieve the
    /// inverted value once the batch inverter is resolved.
    pub fn add(&mut self, element: F) -> Token {
        let index = self.len();
        self.elements.push(element);
        Token { index }
    }

    /// Reserves a slot for a future value while still returning a retrieval token.
    ///
    /// Before resolving the batch inverter, the reserved slot must be [filled][Self::fill].
    pub fn reserve(&mut self) -> Token {
        self.add(F::ZERO)
    }

    /// Fills a previously reserved slot with the provided element.
    pub fn fill(&mut self, token: &Token, element: F) {
        if token.index >= self.len() {
            return;
        }
        self.elements[token.index] = element;
    }

    /// Resolves all pending inversion requests.
    ///
    /// Returns:
    /// - The resolved batch inverter that supports retrieval of inverted values.
    pub fn resolve(mut self) -> BatchInverter<F, Resolved> {
        if self.elements.is_empty() {
            return BatchInverter {
                elements: Vec::new(),
                _state: PhantomData,
            };
        }

        let mut scratch = alloc::vec![F::ZERO; self.len()];
        ff::BatchInverter::invert_with_external_scratch(&mut self.elements, &mut scratch);

        BatchInverter {
            elements: self.elements,
            _state: PhantomData,
        }
    }
}

impl<F: Field> Default for BatchInverter<F, Pending> {
    fn default() -> Self {
        Self {
            elements: Vec::new(),
            _state: PhantomData,
        }
    }
}

impl<F: Field> BatchInverter<F, Resolved> {
    /// Returns a reference to the inverted value for the provided token or `None` if out of
    /// bounds.
    pub fn retrieve_ref(&self, token: &Token) -> Option<&F> {
        self.elements.get(token.index)
    }

    /// Returns the inverted value for the provided token or `None` if out of bounds.
    pub fn retrieve(&self, token: &Token) -> Option<F> {
        self.elements.get(token.index).copied()
    }
}

#[cfg(test)]
mod tests {
    use super::{BatchInverter, Pending};

    use alloc::vec::Vec;
    use ff::Field;
    use ragu_pasta::Fp;

    #[test]
    fn test_batch_inverter() {
        let mut batch_inverter = BatchInverter::<Fp, Pending>::new();
        let felts = [Fp::from(2u64), Fp::from(3u64), Fp::from(5u64)];

        // Add field elements to be inverted and collect tokens.
        let tokens: Vec<_> = felts.iter().map(|&v| batch_inverter.add(v)).collect();

        // Resolve the batch inverter.
        let resolved = batch_inverter.resolve();

        // Assert that the retrieved value is in fact the inversion of the field element.
        for (token, &felt) in tokens.iter().zip(felts.iter()) {
            let felt_inv = resolved.retrieve(token).expect("tests: not out of bounds");
            assert_eq!(felt * felt_inv, Fp::ONE);
        }
    }
}
