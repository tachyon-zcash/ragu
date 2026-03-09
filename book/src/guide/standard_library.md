# The Primitives Standard Library

The [`ragu_primitives`] crate is a **standard library for circuit
developers**. `ragu_core` defines the fundamental `Driver` abstraction
and related traits; `ragu_primitives` builds on that foundation to
provide the concrete gadgets and utilities that most circuit code
depends on:

* **Core gadgets** — [`Element`], [`Boolean`], and [`Point`] provide
  in-circuit representations of field elements, boolean values, and elliptic
  curve points respectively.
* **Cryptographic primitives** — the [Poseidon] sponge hash and
  [`Endoscalar`] challenge gadget for efficient curve arithmetic using
  endomorphisms.
* **Serialization** — the [`Write`][write-trait] trait and [`Buffer`]
  interface standardize how gadgets are serialized to field elements.
* **Containers** — [`FixedVec`] provides a length-typed vector that
  satisfies the `Gadget` trait, ensuring circuit structure is determined by
  types rather than runtime values.
* **Development tooling** — the [`Simulator`] driver executes circuit code
  in-memory for testing and debugging without generating proofs.
* **Gadget utilities** — [demotion and promotion][promotion] for stripping
  and recovering witness data, [consistency enforcement][consistent] for
  enforcing gadget constraints, and thread-safe wrappers via [`Sendable`].

Most Ragu applications will depend on `ragu_primitives` directly, and the
user guide covers its gadgets extensively in the chapters that follow.

[`ragu_primitives`]: https://docs.rs/ragu_primitives
[`Element`]: ragu_primitives::Element
[`Boolean`]: ragu_primitives::Boolean
[`Point`]: ragu_primitives::point::Point
[Poseidon]: ragu_primitives::poseidon::Sponge
[`Endoscalar`]: ragu_primitives::endoscalar::Endoscalar
[write-trait]: ragu_primitives::io::Write
[`Buffer`]: ragu_primitives::io::Buffer
[`FixedVec`]: ragu_primitives::vec::FixedVec
[`Simulator`]: ragu_primitives::Simulator
[promotion]: ragu_primitives::promotion
[consistent]: ragu_primitives::consistent::Consistent
[`Sendable`]: ragu_primitives::sendable::Sendable
