# Inputs, Outputs, and Serialization

This section describes the boundary between structured Ragu gadgets and the flat
field-level interface used by extraction.

## Input variables

The extracted operations are parameterized by symbolic inputs. At extraction
time, input wires are introduced as formal placeholders, kept distinct from
ordinary witness wires.

When an extracted expression refers to the `i`-th input wire, the
[fingerprint encoding](./fingerprint.md) maps it to a variable in the reserved
input index region (`2³² + i`), and the Lean side instantiates the
reimplementation at the matching canonical input vector. The extracted
operations do not contain concrete input values, but are a function of symbolic
inputs, exactly like ordinary `Clean` circuits.

## Example: incomplete point addition

The point-add extraction instance gives a concrete example. On the Rust side,
the instance glue code allocates five input placeholders:

```rust
let input_wires_1 = dr.alloc_input_wires(2);
let input_wires_2 = dr.alloc_input_wires(2);
let nonzero_input = dr.alloc_input_wires(1);
```

It then reuses gadget templates and deserializes those flat wires into
structured input gadgets:

```rust
let p1 = WireDeserializer::new(input_wires_1).into_gadget(&point_template)?;
let p2 = WireDeserializer::new(input_wires_2).into_gadget(&point_template)?;
let mut nonzero = WireDeserializer::new(nonzero_input).into_gadget(&element_template)?;
```

The template only supplies the gadget's *structure*; every wire it carries is
replaced. For gadgets whose public constructors emit operations (`Boolean`,
`Endoscalar`, `HoistedEndoscalar`), the private `wire_remap` module builds a
constraint-free template on Ragu's wireless emulator and replaces its dummy
wires with the symbolic inputs through the public gadget-mapping API. The
remapping emits no Boolean constraints, so each Lean instance supplies any
required `IsBool` preconditions through its `Assumptions`; likewise it emits no
product constraints for a `HoistedEndoscalar`, whose product wires are pinned
by the separately extracted `EnforceProducts` instance.

Either way, the extraction instance then calls the real gadget methods —
`Boolean::and`, `Point::conditional_negate`, and so on — instead of mirroring
their bodies, without requiring extraction-specific API in `ragu_primitives`.

So the flat input interface is composed of:

- two input wires for `P1`,
- two input wires for `P2`,
- one input wire for `nonzero`.

On the Lean side, the structured circuit input is very similar:

```lean
structure Inputs (F : Type) where
  P1 : Spec.Point F
  P2 : Spec.Point F
  nonzero : F
deriving ProvableStruct
```

The extracted operations, however, are parameterized over a flat vector of five
elements:

```lean
input_var : Var (ProvableVector field 5) (F p)
```

The user must provide a function `deserializeInput` to convert a flat vector
into the structured input of the reimplementation.

```lean
def deserializeInput (input : Var (ProvableVector field inputLen) (F p)) :
    Var Circuits.Point.AddIncomplete.Inputs (F p) :=
  {
    P1 := ⟨input.get 0, input.get 1⟩,
    P2 := ⟨input.get 2, input.get 3⟩,
    nonzero := input.get 4
  }
```

In this case, it is assumed that:

- `input.get 0` and `input.get 1` are `P1.x` and `P1.y`,
- `input.get 2` and `input.get 3` are `P2.x` and `P2.y`,
- `input.get 4` is `nonzero`.

The user must also provide a way to serialize outputs, from a structured output
`ProvableType` into a flat vector of elements.

```lean
def serializeOutput (outputs: Var Circuits.Point.AddIncomplete.Outputs (F p)) :
    Vector (Expression (F p)) 3 :=
  #v[
    outputs.P3.x,
    outputs.P3.y,
    outputs.nonzero
  ]
```

```admonish warning
The Rust serialization/deserialization code is not mature yet, but just provides
a proof-of-concept. At the moment, `Gadget`s do not expose a stable interface
for converting values to and from flat vectors of field elements. Because of
that, the current extraction code relies on ad hoc traversal where needed,
rather than on a uniform gadget-level serialization interface.
```

## Trust boundary

The correctness of serialization is currently assumed: the statements for the
extracted circuit reason about the extracted operations under the assumption
that the chosen serialization of inputs and outputs is the right one. If the
serialization is wrong, that mismatch is not ruled out by the soundness and
completeness statements.

```admonish note
It would be tempting to generate structure fields directly from Ragu gadgets,
deriving `ProvableType`. However, nothing in the `Gadget` interface gives us any
guarantees about wire ordering when mapping across drivers. Similarly,
`ProvableType` makes no assumptions about the ordering used by serialization and
deserialization. Indeed, any ordering is a valid implementation for both
interfaces.

In practice, `Gadget`s and `ProvableType`s will usually be automatically
derived, so there will heuristically be one ordering of elements, for example,
the one induced by a depth-first traversal of the structures. However, we cannot
make this assumption in general, so for now this needs to be manually handled
with care.
```
