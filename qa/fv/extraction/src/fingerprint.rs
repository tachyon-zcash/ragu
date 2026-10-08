//! Canonical fingerprints of extracted circuit traces.
//!
//! Computes the SHA-256 digest of a canonical byte encoding of a circuit's
//! extracted operation trace and output expressions. Expressions are hashed in
//! their *polynomial normal form* — a sorted map from monomials over wire
//! variables to coefficients — not in the tree shape the driver happened to
//! build them in. Two traces therefore share a digest exactly when every
//! constraint and every output denotes the same polynomial over the same
//! wires, which is the semantics a constraint system actually has: `w + w` and
//! `2 · w` are the same constraint. The Lean side normalizes the `Clean`
//! reimplementation's expressions identically, and CI compares the two: a
//! match means the reimplementation emits exactly the operations and outputs
//! of the Rust circuit.
//!
//! The byte-level encoding, the input-variable index convention, and the
//! trust assumptions of the check are specified in the FV book
//! (`book/src/fv/circuits/fingerprint.md`); this module and
//! `qa/fv/Ragu/Fingerprint.lean` implement that spec and must stay in
//! lockstep.

use std::{
    collections::{BTreeMap, HashMap, btree_map::Entry},
    sync::Arc,
};

use udon::field::Field;

use crate::{
    expr::{Expr, Op},
    sha256::sha256,
};

/// Wire index at which encoded input variables start (`2³²`).
pub const INPUT_VAR_OFFSET: u64 = 1 << 32;

/// Domain separator prefixed to every digest preimage.
const DOMAIN_TAG: &[u8] = b"ragu-fv-fingerprint-v2";

/// A monomial: the variable indices it multiplies, sorted ascending, with
/// multiplicity (`[3, 3]` is `x₃²`). The empty monomial is the constant term.
pub type Monomial = Vec<u64>;

/// A polynomial over wire variables in canonical form: monomials in
/// lexicographic order (a proper prefix sorts first), no zero coefficients.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Poly<F: Field>(BTreeMap<Monomial, F>);

impl<F: Field> Poly<F> {
    fn zero() -> Self {
        Poly(BTreeMap::new())
    }

    fn term(monomial: Monomial, coeff: F) -> Self {
        let mut poly = Poly::zero();
        poly.add_term(monomial, coeff);
        poly
    }

    fn add_term(&mut self, monomial: Monomial, coeff: F) {
        if coeff.is_zero() {
            return;
        }
        match self.0.entry(monomial) {
            Entry::Vacant(entry) => {
                entry.insert(coeff);
            }
            Entry::Occupied(mut entry) => {
                let sum = *entry.get() + coeff;
                if sum.is_zero() {
                    entry.remove();
                } else {
                    *entry.get_mut() = sum;
                }
            }
        }
    }

    fn add_assign(&mut self, other: &Poly<F>) {
        for (monomial, coeff) in &other.0 {
            self.add_term(monomial.clone(), *coeff);
        }
    }

    fn mul(&self, other: &Poly<F>) -> Poly<F> {
        let mut out = Poly::zero();
        for (m1, c1) in &self.0 {
            for (m2, c2) in &other.0 {
                let mut monomial = Vec::with_capacity(m1.len() + m2.len());
                monomial.extend_from_slice(m1);
                monomial.extend_from_slice(m2);
                monomial.sort_unstable();
                out.add_term(monomial, *c1 * *c2);
            }
        }
        out
    }

    /// The terms in canonical (encoding) order.
    pub fn terms(&self) -> impl Iterator<Item = (&Monomial, &F)> {
        self.0.iter()
    }
}

/// Memo of already-normalized shared sub-expressions, keyed by node address.
///
/// Expressions are DAGs (see [`Expr`]); memoizing by pointer makes
/// normalization linear in the number of distinct nodes, so a gadget that
/// feeds its symbolic output back into itself 64 times (`Endoscalar::lift`)
/// normalizes in 64 steps rather than 2⁶⁴. Every [`Arc`] stays alive for the
/// duration of the memo's use (the trace owns them), so addresses are stable.
type Memo<F> = HashMap<*const Expr<F>, Arc<Poly<F>>>;

/// Normalizes an expression into its canonical polynomial.
#[cfg(test)]
pub fn normalize<F: Field>(expr: &Expr<F>) -> Poly<F> {
    normalize_with(expr, &mut Memo::new())
}

fn normalize_with<F: Field>(expr: &Expr<F>, memo: &mut Memo<F>) -> Poly<F> {
    match expr {
        Expr::Var(index) => {
            let index = *index as u64;
            assert!(
                index < INPUT_VAR_OFFSET,
                "wire index {index} collides with the input variable region"
            );
            Poly::term(vec![index], F::ONE)
        }
        Expr::InputVar(index) => {
            let index = *index as u64;
            assert!(
                index < INPUT_VAR_OFFSET,
                "input variable index {index} overflows the input variable region"
            );
            Poly::term(vec![INPUT_VAR_OFFSET + index], F::ONE)
        }
        Expr::Const(coeff) => Poly::term(Vec::new(), coeff.value()),
        Expr::Add(left, right) => {
            let mut poly = (*normalize_shared(left, memo)).clone();
            poly.add_assign(&normalize_shared(right, memo));
            poly
        }
        Expr::Mul(left, right) => normalize_shared(left, memo).mul(&normalize_shared(right, memo)),
    }
}

fn normalize_shared<F: Field>(node: &Arc<Expr<F>>, memo: &mut Memo<F>) -> Arc<Poly<F>> {
    let key = Arc::as_ptr(node);
    if let Some(poly) = memo.get(&key) {
        return poly.clone();
    }
    let poly = Arc::new(normalize_with(node, memo));
    memo.insert(key, poly.clone());
    poly
}

fn push_u64(buf: &mut Vec<u8>, n: u64) {
    buf.extend_from_slice(&n.to_le_bytes());
}

/// Append the canonical 32-byte little-endian representation of `value`.
fn push_field_element<F: Field>(buf: &mut Vec<u8>, value: F) {
    let repr = value.to_bytes();
    let bytes = repr.as_ref();
    assert_eq!(bytes.len(), 32, "expected a 32-byte field representation");
    buf.extend_from_slice(bytes);
}

/// Append [`Field::MODULUS`] as 32 little-endian bytes.
fn push_modulus<F: Field>(buf: &mut Vec<u8>) {
    let hex = modulus_hex::<F>();
    assert_eq!(hex.len(), 64, "expected a 256-bit modulus");
    let mut bytes = [0u8; 32];
    for (i, byte) in bytes.iter_mut().rev().enumerate() {
        *byte = u8::from_str_radix(&hex[2 * i..2 * i + 2], 16).expect("modulus is valid hex");
    }
    buf.extend_from_slice(&bytes);
}

/// Append a polynomial: its term count, then each term as the monomial's
/// degree, the monomial's variable indices, and the coefficient.
fn push_poly<F: Field>(buf: &mut Vec<u8>, poly: &Poly<F>) {
    push_u64(buf, poly.0.len() as u64);
    for (monomial, coeff) in poly.terms() {
        push_u64(buf, monomial.len() as u64);
        for var in monomial {
            push_u64(buf, *var);
        }
        push_field_element(buf, *coeff);
    }
}

fn push_op<F: Field>(buf: &mut Vec<u8>, op: &Op<F>, memo: &mut Memo<F>) {
    match op {
        Op::Witness { count } => {
            buf.push(0x01);
            push_u64(buf, *count as u64);
        }
        Op::Assert(expr) => {
            buf.push(0x02);
            push_poly(buf, &normalize_with(expr, memo));
        }
    }
}

/// Build the canonical digest preimage for an extracted trace.
fn encode_trace<F: Field>(input_len: usize, ops: &[Op<F>], outputs: &[Expr<F>]) -> Vec<u8> {
    let mut memo = Memo::new();
    let mut buf = Vec::new();
    buf.extend_from_slice(DOMAIN_TAG);
    push_modulus::<F>(&mut buf);
    push_u64(&mut buf, input_len as u64);
    push_u64(&mut buf, outputs.len() as u64);
    push_u64(&mut buf, ops.len() as u64);
    for op in ops {
        push_op(&mut buf, op, &mut memo);
    }
    for output in outputs {
        push_poly(&mut buf, &normalize_with(output, &mut memo));
    }
    buf
}

/// Compute the canonical fingerprint of an extracted trace, as a lowercase
/// hex digest.
pub fn digest_hex<F: Field>(input_len: usize, ops: &[Op<F>], outputs: &[Expr<F>]) -> String {
    let buf = encode_trace(input_len, ops, outputs);
    sha256(&buf).iter().map(|b| format!("{b:02x}")).collect()
}

/// The field modulus as 64 lowercase hex digits, most significant first.
fn modulus_hex<F: Field>() -> String {
    F::MODULUS
        .as_ref()
        .iter()
        .rev()
        .map(|limb| format!("{limb:016x}"))
        .collect()
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use ragu_core::{
        Coeff,
        pasta::{Fp, Fq},
    };
    use udon::field::Field;

    use super::{INPUT_VAR_OFFSET, Poly, encode_trace, normalize};
    use crate::{
        expr::{Expr, Op},
        instance::CircuitInstance,
    };

    /// Structural mirror of the encoded trace, recovered by [`decode_trace`].
    #[derive(Debug, PartialEq)]
    struct AstPoly(Vec<(Vec<u64>, [u8; 32])>);

    #[derive(Debug, PartialEq)]
    enum AstOp {
        Witness(u64),
        Assert(AstPoly),
    }

    #[derive(Debug, PartialEq)]
    struct AstTrace {
        modulus: [u8; 32],
        input_len: u64,
        ops: Vec<AstOp>,
        outputs: Vec<AstPoly>,
    }

    /// Strict cursor over the digest preimage; panics on malformed input.
    struct Parser<'a> {
        bytes: &'a [u8],
        pos: usize,
    }

    impl<'a> Parser<'a> {
        fn take(&mut self, n: usize) -> &'a [u8] {
            let slice = &self.bytes[self.pos..self.pos + n];
            self.pos += n;
            slice
        }

        fn byte(&mut self) -> u8 {
            self.take(1)[0]
        }

        fn u64(&mut self) -> u64 {
            u64::from_le_bytes(self.take(8).try_into().unwrap())
        }

        fn bytes32(&mut self) -> [u8; 32] {
            self.take(32).try_into().unwrap()
        }
    }

    fn decode_poly(p: &mut Parser) -> AstPoly {
        let terms = p.u64();
        AstPoly(
            (0..terms)
                .map(|_| {
                    let degree = p.u64();
                    let monomial = (0..degree).map(|_| p.u64()).collect();
                    (monomial, p.bytes32())
                })
                .collect(),
        )
    }

    /// Decode a digest preimage produced by [`encode_trace`], asserting that
    /// every byte is consumed.
    fn decode_trace(bytes: &[u8]) -> AstTrace {
        let mut p = Parser { bytes, pos: 0 };
        assert_eq!(p.take(super::DOMAIN_TAG.len()), super::DOMAIN_TAG);
        let modulus = p.bytes32();
        let input_len = p.u64();
        let output_len = p.u64();
        let op_count = p.u64();
        let ops = (0..op_count)
            .map(|_| match p.byte() {
                0x01 => AstOp::Witness(p.u64()),
                0x02 => AstOp::Assert(decode_poly(&mut p)),
                tag => panic!("unknown operation tag {tag:#x}"),
            })
            .collect();
        let outputs = (0..output_len).map(|_| decode_poly(&mut p)).collect();
        assert_eq!(p.pos, bytes.len(), "trailing bytes after outputs");
        AstTrace {
            modulus,
            input_len,
            ops,
            outputs,
        }
    }

    /// Build the AST the decoder is expected to recover from a normalized
    /// polynomial.
    fn expected_poly<F: Field>(poly: &Poly<F>) -> AstPoly {
        AstPoly(
            poly.terms()
                .map(|(monomial, coeff)| {
                    let mut buf = Vec::new();
                    super::push_field_element(&mut buf, *coeff);
                    (monomial.clone(), buf.try_into().unwrap())
                })
                .collect(),
        )
    }

    /// Encode an instance's trace and decode it back, asserting the decoder
    /// recovers exactly the normalized trace. This demonstrates that the
    /// encoding is uniquely decodable — and therefore injective on normal
    /// forms — over the exported corpus.
    fn assert_roundtrip<I: CircuitInstance>() {
        let trace = I::extracted_trace();
        let decoded = decode_trace(&encode_trace::<I::Field>(
            trace.input_len,
            &trace.ops,
            &trace.outputs,
        ));

        let mut modulus = Vec::new();
        super::push_modulus::<I::Field>(&mut modulus);
        let expected = AstTrace {
            modulus: modulus.try_into().unwrap(),
            input_len: trace.input_len as u64,
            ops: trace
                .ops
                .iter()
                .map(|op| match op {
                    Op::Witness { count } => AstOp::Witness(*count as u64),
                    Op::Assert(expr) => AstOp::Assert(expected_poly(&normalize(expr))),
                })
                .collect(),
            outputs: trace
                .outputs
                .iter()
                .map(|expr| expected_poly(&normalize(expr)))
                .collect(),
        };
        assert_eq!(decoded, expected);
    }

    #[test]
    fn encoding_roundtrips_for_every_instance() {
        use crate::instances::{
            boolean_alloc::BooleanAllocInstance,
            boolean_and::BooleanAndInstance,
            boolean_conditional_enforce_equal::BooleanConditionalEnforceEqualInstance,
            boolean_conditional_select::BooleanConditionalSelectInstance,
            boolean_consistent::BooleanConsistentInstance,
            core_mul::CoreMulInstance,
            element_alloc::ElementAllocInstance,
            element_alloc_square::ElementAllocSquareInstance,
            element_div_nonzero::ElementDivNonzeroInstance,
            element_enforce_invertible::ElementEnforceInvertibleInstance,
            element_enforce_nonzero::ElementEnforceNonzeroInstance,
            element_enforce_root_of_unity::{
                ElementEnforceRootOfUnityInstanceK2, ElementEnforceRootOfUnityInstanceK5,
            },
            element_enforce_zero::ElementEnforceZeroInstance,
            element_fold::{
                ElementFoldInstanceN2, ElementFoldInstanceN3, ElementFoldInstanceN7,
                ElementFoldInstanceN19,
            },
            element_invert::ElementInvertInstance,
            element_invert_with::ElementInvertWithInstance,
            element_invertible::ElementInvertibleInstance,
            element_invertible_consistent::ElementInvertibleConsistentInstance,
            element_is_equal::ElementIsEqualInstance,
            element_is_zero::ElementIsZeroInstance,
            element_mul::ElementMulInstance,
            element_square::ElementSquareInstance,
            endoscalar_alloc::EndoscalarAllocInstance,
            endoscalar_extract::EndoscalarExtractInstance,
            endoscalar_group_scale::EndoscalarGroupScaleInstance,
            endoscalar_lift::EndoscalarLiftInstance,
            hoisted_endoscalar_alloc::HoistedEndoscalarAllocInstance,
            hoisted_endoscalar_enforce_products::HoistedEndoscalarEnforceProductsInstance,
            hoisted_endoscalar_group_scale::HoistedEndoscalarGroupScaleInstance,
            hoisted_endoscalar_lift::HoistedEndoscalarLiftInstance,
            horner::{HornerInstanceN3, HornerInstanceN7, HornerInstanceN19, HornerKyInstanceN3},
            nonzero_bank_scope::{
                NonzeroBankScopeInstanceK0, NonzeroBankScopeInstanceK1, NonzeroBankScopeInstanceK2,
            },
            point_add_incomplete::PointAddIncompleteInstance,
            point_alloc::{PointAllocInstanceFp, PointAllocInstanceFq},
            point_conditional_endo::PointConditionalEndoInstance,
            point_conditional_negate::PointConditionalNegateInstance,
            point_consistent::{PointConsistentInstanceFp, PointConsistentInstanceFq},
            point_double::PointDoubleInstance,
            point_double_and_add_incomplete::PointDoubleAndAddIncompleteInstance,
            poseidon_sponge::{
                PoseidonBlocks1Tail2InstanceFp, PoseidonBlocks2Squeeze3InstanceFp,
                PoseidonHash1InstanceFp, PoseidonHash1InstanceFq, PoseidonHash4InstanceFp,
                PoseidonInterleavedInstanceFp, PoseidonSaveResumeInstanceFp,
            },
        };

        macro_rules! assert_registered_roundtrips {
            ($($name:literal => $instance:ty),+ $(,)?) => {{
                $(assert_roundtrip::<$instance>();)+
                [$($name),+]
            }};
        }

        let tested_names = assert_registered_roundtrips! {
            "Ragu.Instances.Point.AllocFp" => PointAllocInstanceFp,
            "Ragu.Instances.Point.AllocFq" => PointAllocInstanceFq,
            "Ragu.Instances.Point.Double" => PointDoubleInstance,
            "Ragu.Instances.Point.DoubleAndAddIncomplete" => PointDoubleAndAddIncompleteInstance,
            "Ragu.Instances.Point.AddIncomplete" => PointAddIncompleteInstance,
            "Ragu.Instances.Point.ConditionalEndo" => PointConditionalEndoInstance,
            "Ragu.Instances.Point.ConditionalNegate" => PointConditionalNegateInstance,
            "Ragu.Instances.Point.ConsistentFp" => PointConsistentInstanceFp,
            "Ragu.Instances.Point.ConsistentFq" => PointConsistentInstanceFq,
            "Ragu.Instances.Element.Mul" => ElementMulInstance,
            "Ragu.Instances.Element.Square" => ElementSquareInstance,
            "Ragu.Instances.Element.Alloc" => ElementAllocInstance,
            "Ragu.Instances.Element.AllocSquare" => ElementAllocSquareInstance,
            "Ragu.Instances.Element.DivNonzero" => ElementDivNonzeroInstance,
            "Ragu.Instances.Element.FoldN2" => ElementFoldInstanceN2,
            "Ragu.Instances.Element.FoldN3" => ElementFoldInstanceN3,
            "Ragu.Instances.Element.FoldN7" => ElementFoldInstanceN7,
            "Ragu.Instances.Element.FoldN19" => ElementFoldInstanceN19,
            "Ragu.Instances.Element.EnforceRootOfUnityK2" => ElementEnforceRootOfUnityInstanceK2,
            "Ragu.Instances.Element.EnforceRootOfUnityK5" => ElementEnforceRootOfUnityInstanceK5,
            "Ragu.Instances.Element.EnforceZero" => ElementEnforceZeroInstance,
            "Ragu.Instances.Element.EnforceInvertible" => ElementEnforceInvertibleInstance,
            "Ragu.Instances.Element.Invertible" => ElementInvertibleInstance,
            "Ragu.Instances.Element.InvertibleConsistent" => ElementInvertibleConsistentInstance,
            "Ragu.Instances.Element.Invert" => ElementInvertInstance,
            "Ragu.Instances.Element.InvertWith" => ElementInvertWithInstance,
            "Ragu.Instances.Element.EnforceNonzero" => ElementEnforceNonzeroInstance,
            "Ragu.Instances.NonzeroBank.ScopeK0" => NonzeroBankScopeInstanceK0,
            "Ragu.Instances.NonzeroBank.ScopeK1" => NonzeroBankScopeInstanceK1,
            "Ragu.Instances.NonzeroBank.ScopeK2" => NonzeroBankScopeInstanceK2,
            "Ragu.Instances.Element.IsEqual" => ElementIsEqualInstance,
            "Ragu.Instances.Element.IsZero" => ElementIsZeroInstance,
            "Ragu.Instances.Core.Mul" => CoreMulInstance,
            "Ragu.Instances.Boolean.Alloc" => BooleanAllocInstance,
            "Ragu.Instances.Boolean.And" => BooleanAndInstance,
            "Ragu.Instances.Boolean.ConditionalSelect" => BooleanConditionalSelectInstance,
            "Ragu.Instances.Boolean.Consistent" => BooleanConsistentInstance,
            "Ragu.Instances.Boolean.ConditionalEnforceEqual" => BooleanConditionalEnforceEqualInstance,
            "Ragu.Instances.Endoscalar.Alloc" => EndoscalarAllocInstance,
            "Ragu.Instances.Endoscalar.Extract" => EndoscalarExtractInstance,
            "Ragu.Instances.Endoscalar.GroupScale" => EndoscalarGroupScaleInstance,
            "Ragu.Instances.Endoscalar.Lift" => EndoscalarLiftInstance,
            "Ragu.Instances.Endoscalar.HoistedAlloc" => HoistedEndoscalarAllocInstance,
            "Ragu.Instances.Endoscalar.HoistedGroupScale" => HoistedEndoscalarGroupScaleInstance,
            "Ragu.Instances.Endoscalar.HoistedLift" => HoistedEndoscalarLiftInstance,
            "Ragu.Instances.Endoscalar.EnforceProducts" => HoistedEndoscalarEnforceProductsInstance,
            "Ragu.Instances.Horner.N3" => HornerInstanceN3,
            "Ragu.Instances.Horner.N7" => HornerInstanceN7,
            "Ragu.Instances.Horner.N19" => HornerInstanceN19,
            "Ragu.Instances.Horner.KyN3" => HornerKyInstanceN3,
            "Ragu.Instances.Poseidon.Hash1Fp" => PoseidonHash1InstanceFp,
            "Ragu.Instances.Poseidon.Hash4Fp" => PoseidonHash4InstanceFp,
            "Ragu.Instances.Poseidon.Hash1Fq" => PoseidonHash1InstanceFq,
            "Ragu.Instances.Poseidon.Blocks2Squeeze3Fp" => PoseidonBlocks2Squeeze3InstanceFp,
            "Ragu.Instances.Poseidon.Hash1SaveResumeFp" => PoseidonSaveResumeInstanceFp,
            "Ragu.Instances.Poseidon.InterleavedFp" => PoseidonInterleavedInstanceFp,
            "Ragu.Instances.Poseidon.Blocks1Tail2Squeeze2Fp" => PoseidonBlocks1Tail2InstanceFp,
        };
        let registered_names = crate::EXPORT_TARGETS
            .iter()
            .map(|target| target.name)
            .collect::<Vec<_>>();

        assert_eq!(tested_names.as_slice(), registered_names.as_slice());
    }

    /// The modulus encoding must round-trip through the canonical field
    /// element representation: `-1` is `modulus - 1`.
    #[test]
    fn modulus_matches_repr() {
        fn check<F: Field>() {
            let mut modulus = Vec::new();
            super::push_modulus::<F>(&mut modulus);

            let mut minus_one = Vec::new();
            super::push_field_element(&mut minus_one, -F::ONE);

            // minus_one + 1 == modulus, as 256-bit little-endian integers
            let mut carry = 1u16;
            for byte in &mut minus_one {
                let sum = *byte as u16 + carry;
                *byte = (sum & 0xff) as u8;
                carry = sum >> 8;
            }
            assert_eq!(minus_one, modulus);
        }
        check::<Fp>();
        check::<Fq>();
    }

    fn var(i: usize) -> Arc<Expr<Fp>> {
        Arc::new(Expr::Var(i))
    }

    fn constant(c: Fp) -> Arc<Expr<Fp>> {
        Arc::new(Expr::Const(Coeff::Arbitrary(c)))
    }

    /// The normal form identifies expressions that denote the same polynomial
    /// regardless of how the driver built them.
    #[test]
    fn normal_form_ignores_tree_shape() {
        let x = var(7);
        // w + w  ==  2 · w
        let doubled = Expr::Add(x.clone(), x.clone());
        let scaled = Expr::Mul(constant(Fp::from(2)), x.clone());
        assert_eq!(normalize(&doubled), normalize(&scaled));

        // (a + b) + c  ==  a + (b + c), and multiplication distributes.
        let (a, b, c) = (var(1), var(2), var(3));
        let left = Expr::Add(Arc::new(Expr::Add(a.clone(), b.clone())), c.clone());
        let right = Expr::Add(a.clone(), Arc::new(Expr::Add(b.clone(), c.clone())));
        assert_eq!(normalize(&left), normalize(&right));
        let distributed = Expr::Add(
            Arc::new(Expr::Mul(constant(Fp::from(3)), a.clone())),
            Arc::new(Expr::Mul(constant(Fp::from(3)), b.clone())),
        );
        let factored = Expr::Mul(
            constant(Fp::from(3)),
            Arc::new(Expr::Add(a.clone(), b.clone())),
        );
        assert_eq!(normalize(&distributed), normalize(&factored));

        // Cancelling terms vanish, and the constant zero is the empty polynomial.
        let cancels = Expr::Add(
            x.clone(),
            Arc::new(Expr::Mul(constant(-Fp::ONE), x.clone())),
        );
        assert_eq!(
            normalize(&cancels),
            normalize(&Expr::<Fp>::Const(Coeff::Zero))
        );
        assert_eq!(normalize(&cancels).terms().count(), 0);

        // Monomials are sorted, so the gate's `a · b` is order-independent.
        let ab = Expr::Mul(var(5), var(3));
        let ba = Expr::Mul(var(3), var(5));
        assert_eq!(normalize(&ab), normalize(&ba));
        assert_eq!(
            normalize(&ab)
                .terms()
                .map(|(m, _)| m.clone())
                .collect::<Vec<_>>(),
            vec![vec![3, 5]]
        );

        // Input variables live in their own index region.
        let input = Expr::<Fp>::InputVar(4);
        assert_eq!(
            normalize(&input)
                .terms()
                .map(|(m, _)| m.clone())
                .collect::<Vec<_>>(),
            vec![vec![INPUT_VAR_OFFSET + 4]]
        );
    }

    /// A shared doubling chain — the shape `Endoscalar::lift` records for its
    /// accumulator — normalizes in time linear in its depth, not `2^depth`.
    #[test]
    fn shared_chain_normalizes_linearly() {
        let mut acc: Arc<Expr<Fp>> = Arc::new(Expr::Var(0));
        for _ in 0..64 {
            acc = Arc::new(Expr::Add(acc.clone(), acc.clone()));
        }
        let poly = normalize(&acc);
        let terms: Vec<_> = poly.terms().collect();
        assert_eq!(terms.len(), 1);
        assert_eq!(terms[0].0, &vec![0]);
        assert_eq!(*terms[0].1, Fp::from(2).pow_u64(64));
    }
}
