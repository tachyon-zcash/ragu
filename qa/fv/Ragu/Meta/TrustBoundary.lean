import Ragu.Meta.EndpointCensus
import Ragu.Core
import Ragu.Foundation.AlgebraicRelation
import Ragu.Foundation.IPA
import Ragu.Foundation.Pasta.Basic
import Ragu.Foundation.Polynomial
import Ragu.Foundation.Oracle
import Ragu.Foundation.Probability
import Ragu.Foundation.RelationWitness
import Ragu.Fingerprint.Instances
import Ragu.PolynomialFingerprint
import Ragu.Circuits.Boolean.Alloc
import Ragu.Circuits.Boolean.And
import Ragu.Circuits.Boolean.ConditionalEnforceEqual
import Ragu.Circuits.Boolean.ConditionalSelect
import Ragu.Circuits.Boolean.Consistent
import Ragu.Circuits.Boolean.Decompose
import Ragu.Circuits.Core.Mul
import Ragu.Circuits.Element.Alloc
import Ragu.Circuits.Element.AllocSquare
import Ragu.Circuits.Element.Divide
import Ragu.Circuits.Element.DivNonzero
import Ragu.Circuits.Element.EnforceInvertible
import Ragu.Circuits.Element.EnforceNonzero
import Ragu.Circuits.Element.EnforceRootOfUnity
import Ragu.Circuits.Element.EnforceZero
import Ragu.Circuits.Element.Fold
import Ragu.Circuits.Element.Invert
import Ragu.Circuits.Element.Invertible
import Ragu.Circuits.Element.InvertibleConsistent
import Ragu.Circuits.Element.InvertWith
import Ragu.Circuits.Element.IsEqual
import Ragu.Circuits.Element.IsZero
import Ragu.Circuits.Element.Mul
import Ragu.Circuits.Element.Square
import Ragu.Circuits.Endoscalar.Alloc
import Ragu.Circuits.Endoscalar.EnforceProducts
import Ragu.Circuits.Endoscalar.Extract
import Ragu.Circuits.Endoscalar.GroupScale
import Ragu.Circuits.Endoscalar.HoistedAlloc
import Ragu.Circuits.Endoscalar.HoistedGroupScale
import Ragu.Circuits.Endoscalar.HoistedLift
import Ragu.Circuits.Endoscalar.Initial
import Ragu.Circuits.Endoscalar.Lift
import Ragu.Circuits.Endoscalar.Walk
import Ragu.Circuits.Horner.Ky
import Ragu.Circuits.NonzeroBank.Scope
import Ragu.Circuits.Point.AddIncomplete
import Ragu.Circuits.Point.AddIncompleteUnchecked
import Ragu.Circuits.Point.Alloc
import Ragu.Circuits.Point.ConditionalEndo
import Ragu.Circuits.Point.ConditionalNegate
import Ragu.Circuits.Point.Consistent
import Ragu.Circuits.Point.Denormalize
import Ragu.Circuits.Point.Double
import Ragu.Circuits.Point.DoubleAndAddIncomplete
import Ragu.Circuits.Point.DoubleAndAddIncompleteUnchecked
import Ragu.Circuits.Point.Normalize
import Ragu.Circuits.Point.Spec
import Ragu.Circuits.Point.TripleAndAddIncompleteUnchecked
import Ragu.Circuits.Poseidon.Linear
import Ragu.Circuits.Poseidon.ParamsFp
import Ragu.Circuits.Poseidon.ParamsFq
import Ragu.Circuits.Poseidon.Permutation
import Ragu.Circuits.Poseidon.Round
import Ragu.Circuits.Poseidon.Sbox
import Ragu.Circuits.Poseidon.Sponge

/-!
# Ragu formal-verification trust boundary

Every deliverable `soundness` and `completeness` theorem is pinned directly with
`census_axioms`, which bounds its transitive kernel axioms to Lean's standard theorem tier and
rejects undisclosed compiler trust. The two randomized-fingerprint `_prob_le` arithmetic
endpoints and the two Pasta primality theorems are pinned at the same tier. Other protocol-level
markers such as `_error_bound`, `_finite_security`, and `_capstone` remain reserved for verifier
and soundness layers added later.

The exact and randomized fingerprint functions and generated instance registry are executable
boundary artifacts, so they use `census_computable`: each must remain a safe, computable
definition with the tighter computable axiom budget. These checks do not prove that the trusted
fingerprint encoders or serialization assign the intended semantics, and they do not connect this
gadget layer to an unfinished Ragu verifier. Those remain separate manual and future refinement
obligations.

The relation-witness traversal combinators are also pinned as computed data. They preserve explicit
break branches while composing future reductions; their companion theorem is pinned at the standard
theorem tier.

The entries below are intentionally fully qualified and direct. Transitive coverage disappears
when a consumer is refactored and therefore does not satisfy the endpoint census.
-/

/-! ## Computed-break foundation -/

census_computable Ragu.Foundation.bindOrRelationWitness
census_computable Ragu.Foundation.finForallOrRelationWitness
census_computable Ragu.Foundation.finForallOption
census_axioms Ragu.Foundation.finForallOption_isSome_of
census_computable Ragu.Foundation.boundedForallOrRelationWitness
census_computable Ragu.Foundation.listForallOrRelationWitness

/-! ## Pasta cycle foundation -/

census_axioms Ragu.Foundation.Pasta.p_eq_pallasBaseCard
census_axioms Ragu.Foundation.Pasta.q_eq_pallasScalarCard
census_axioms Ragu.Foundation.Pasta.pallas_base_prime
census_axioms Ragu.Foundation.Pasta.pallas_scalar_prime
census_axioms Ragu.Foundation.Pasta.pallas_group_order +native(
  CompElliptic.Curves.Pasta.Pallas.q_nsmul_Gpt)
census_axioms Ragu.Foundation.Pasta.vesta_group_order +native(
  CompElliptic.Curves.Pasta.Vesta.p_nsmul_Gpt)
census_axioms Ragu.Foundation.Pasta.pallas_no_two_torsion
census_axioms Ragu.Foundation.Pasta.vesta_no_two_torsion

/-! ## Probability foundation -/

census_axioms Ragu.Foundation.Probability.uniformOfFintype_toOuterMeasure_finset
census_axioms Ragu.Foundation.Probability.map_uniformOfFintype_equiv
census_axioms Ragu.Foundation.Probability.uniformOfFintype_prod_fiber_bound
census_axioms Ragu.Foundation.Probability.uniformOfFintype_prod_fiber_bound_right
census_axioms Ragu.Foundation.Probability.uniformOfFintype_fresh_read_bound
census_axioms Ragu.Foundation.Probability.sum_point_mem_measure_le
census_axioms Ragu.Foundation.Probability.uniformOfFintype_point_mem_blind_le
census_axioms Ragu.Foundation.Probability.PMFEventBiasLE
census_axioms Ragu.Foundation.Probability.PMFWeightedBiasLE
census_axioms Ragu.Foundation.Probability.PMFWeightedBiasLE.eventBiasLE
census_axioms Ragu.Foundation.Probability.PMFEventBiasLE.weightedBiasLE
census_axioms Ragu.Foundation.Probability.PMFEventBiasLE.trans
census_axioms Ragu.Foundation.Probability.PMFEventBiasLE.bind_same
census_axioms Ragu.Foundation.Probability.PMFEventBiasLE.bind_average
census_axioms Ragu.Foundation.Probability.event_measure_le_of_bias
census_axioms Ragu.Foundation.Probability.tendsto_toOuterMeasure_of_eventBiasLE

/-! ## Oracle foundation -/

census_axioms Ragu.Foundation.Oracle.OracleComp.queries_queryList
census_axioms Ragu.Foundation.Oracle.OracleComp.queries_bind
census_axioms Ragu.Foundation.Oracle.OracleComp.mem_queries_completing
census_computable Ragu.Foundation.Oracle.OracleComp.restrictSum
census_computable Ragu.Foundation.Oracle.OracleComp.reachSet +choice
census_axioms Ragu.Foundation.Oracle.OracleComp.run_congr_reachSet
census_computable Ragu.Foundation.Oracle.OracleComp.restrictTo +choice
census_computable Ragu.Foundation.Oracle.OracleComp.splitDomain +choice
census_axioms Ragu.Foundation.Oracle.OracleComp.run_congr_of_agree
census_computable Ragu.Foundation.Oracle.queryCharge
census_axioms Ragu.Foundation.Oracle.queryCharge_sum_mul_le
census_axioms Ragu.Foundation.Oracle.queryCharge_sum_mul_le_table_budget
census_axioms Ragu.Foundation.Oracle.le_queryCharge_of_mem_queries
census_axioms Ragu.Foundation.Oracle.mem_queries_dedup
census_axioms Ragu.Foundation.Oracle.applyUpdates_apply_mem_nodup
census_axioms Ragu.Foundation.Oracle.steeredCharge_context_sum_mul_le
census_axioms Ragu.Foundation.Oracle.steeredCharge_context_sum_mul_le_table_budget
census_axioms Ragu.Foundation.Oracle.steeredCharge_sum_mul_le
census_axioms Ragu.Foundation.Oracle.escapesDuringC_measure_le
census_axioms Ragu.Foundation.Oracle.escapesDuringC_measure_le'
census_axioms Ragu.Foundation.Oracle.OracleComp.runFreshPMF
census_axioms Ragu.Foundation.Oracle.OracleComp.runFreshPMF_eventBiasLE
census_computable Ragu.Foundation.Oracle.LabeledOracleComp.erase
census_computable Ragu.Foundation.Oracle.LabeledOracleComp.runWithAnnotations
census_computable Ragu.Foundation.Oracle.LabeledOracleComp.findLabel
census_axioms Ragu.Foundation.Oracle.LabeledOracleComp.finalBadWithoutRelation_measure_le
census_axioms Ragu.Foundation.Oracle.LabeledOracleComp.firstLabelOrFallbackBad_measure_le
census_computable Ragu.Foundation.Oracle.MultiOracleComp.runTables
census_computable Ragu.Foundation.Oracle.MultiOracleComp.mapQuery
census_axioms Ragu.Foundation.Oracle.MultiOracleComp.runTables_mapQuery
census_axioms Ragu.Foundation.Oracle.MultiOracleComp.queryBound_mapQuery
census_axioms Ragu.Foundation.Oracle.MultiOracleComp.runFreshPMF
census_axioms Ragu.Foundation.Oracle.MultiOracleComp.runFreshPMF_eventBiasLE
census_computable Ragu.Foundation.Oracle.OracleComp.readFin
census_computable Ragu.Foundation.Oracle.OracleComp.withReads
census_axioms Ragu.Foundation.Oracle.OracleComp.run_withReads
census_axioms Ragu.Foundation.Oracle.OracleComp.queryBound_withReads

/-! ## Algebraic-relation and DLOG foundation -/

census_computable Ragu.Foundation.AlgebraicRelation.commitGen +choice
census_computable Ragu.Foundation.AlgebraicRelation.representationEval
census_computable Ragu.Foundation.AlgebraicRelation.AlgebraicRelationWitness.toGroupRepresentation
census_computable Ragu.Foundation.AlgebraicRelation.AlgebraicRelationWitness.toAlgebraicPoint
census_computable Ragu.Foundation.AlgebraicRelation.NontrivialRelation.ofCombinationCollision +choice
census_computable Ragu.Foundation.AlgebraicRelation.discreteLogOfBasis_of_relation +choice
census_computable Ragu.Foundation.AlgebraicRelation.discreteLogOfChallenge_of_relation +choice
census_computable Ragu.Foundation.AlgebraicRelation.programmedExtractOrMiss +choice
census_computable Ragu.Foundation.AlgebraicRelation.AugmentedRelationWitness.toAlgebraicRelationWitness +choice
census_computable Ragu.Foundation.AlgebraicRelation.discreteLogOfAugmentedRelationAtChallenge +choice
census_computable Ragu.Foundation.AlgebraicRelation.discreteLogOfU_of_augmentedRelation +choice
census_computable Ragu.Foundation.AlgebraicRelation.discreteLogOfW_of_augmentedRelation +choice
census_axioms Ragu.Foundation.AlgebraicRelation.AlgebraicRelationWitness.augment
census_axioms Ragu.Foundation.AlgebraicRelation.programmedRelSet_card
census_axioms Ragu.Foundation.AlgebraicRelation.programmedRelSet_subset_win_union_miss
census_axioms Ragu.Foundation.AlgebraicRelation.missSet_card_le
census_axioms Ragu.Foundation.AlgebraicRelation.relation_prob_le_of_textbookDL
census_axioms Ragu.Foundation.AlgebraicRelation.independentProductPMF
census_axioms Ragu.Foundation.AlgebraicRelation.independentProductPMF_map_left
census_axioms Ragu.Foundation.AlgebraicRelation.independentProductPMF_uniform
census_axioms Ragu.Foundation.AlgebraicRelation.programmedRelSetWithCoins_card
census_axioms Ragu.Foundation.AlgebraicRelation.programmedRelSetWithCoins_subset_win_union_miss
census_axioms Ragu.Foundation.AlgebraicRelation.missSetWithCoins_card_le
census_axioms Ragu.Foundation.AlgebraicRelation.relationWithCoins_prob_le_of_textbookDL
census_axioms Ragu.Foundation.AlgebraicRelation.truncateRelationFinder
census_axioms Ragu.Foundation.AlgebraicRelation.truncatedRelationFinderCalls
census_axioms Ragu.Foundation.AlgebraicRelation.truncatedRelationFinderCalls_le
census_axioms Ragu.Foundation.AlgebraicRelation.TextbookDLWithCoinsFixedCallsAdvantageLE
census_axioms Ragu.Foundation.AlgebraicRelation.TextbookDLWithCoinsTruncatedAdvantageLE
census_axioms Ragu.Foundation.AlgebraicRelation.textbookDLWithCoinsTruncatedAdvantageLE_iff
census_axioms Ragu.Foundation.AlgebraicRelation.RelationFinderExpectedCallsLE
census_axioms Ragu.Foundation.AlgebraicRelation.relationFinderCallTail
census_axioms Ragu.Foundation.AlgebraicRelation.relSetWithCoins_subset_truncate_union_tail
census_axioms Ragu.Foundation.AlgebraicRelation.relationFinderCallTail_prob_le
census_axioms Ragu.Foundation.AlgebraicRelation.relationWithCoins_prob_le_of_truncated_textbookDL

/-! ## Polynomial foundation -/

census_computable CompPoly.CPolynomial.map +choice
census_computable CompPoly.CPolynomial.mapRingHom +choice
census_computable CompPoly.CPolynomial.comp +choice
census_computable CompPoly.CPolynomial.rootsBy +choice
census_axioms CompPoly.CPolynomial.eq_zero_of_natDegree_lt_card_of_eval_eq_zero
census_axioms CompPoly.CPolynomial.rootsBy_eq_toFinset
census_axioms CompPoly.CPolynomial.card_rootsBy_le
census_axioms Ragu.Foundation.Polynomial.schwartz_zippel_fin
census_axioms Ragu.Foundation.Polynomial.schwartz_zippel_index

/-! ## IPA algebra foundation -/

census_computable Ragu.Foundation.IPA.commit +choice
census_computable Ragu.Foundation.IPA.evalVector
census_computable Ragu.Foundation.IPA.innerProduct +choice
census_axioms Ragu.Foundation.IPA.IpaRelation
census_computable Ragu.Foundation.IPA.foldVec
census_computable Ragu.Foundation.IPA.loHalf
census_computable Ragu.Foundation.IPA.hiHalf
census_computable Ragu.Foundation.IPA.append
census_axioms Ragu.Foundation.IPA.append_loHalf_hiHalf
census_axioms Ragu.Foundation.IPA.ipaRelation_unshift
census_axioms Ragu.Foundation.IPA.ipaRelation_unblind
census_axioms Ragu.Foundation.IPA.commit_eq_commitGen
census_axioms Ragu.Foundation.IPA.commitGen_round
census_axioms Ragu.Foundation.IPA.accepting_fold_eq_foldVec
census_computable Ragu.Foundation.IPA.NontrivialDLRelation.ofCollision +choice
census_computable Ragu.Foundation.IPA.NontrivialDLRelation.ofIpaOpenings +choice
census_computable Ragu.Foundation.IPA.foldGens +choice
census_axioms Ragu.Foundation.IPA.commitGen_split
census_axioms Ragu.Foundation.IPA.commitGen_append
census_axioms Ragu.Foundation.IPA.commitGen_sum

/-! ## Boolean circuits -/

census_axioms Ragu.Circuits.Boolean.Alloc.soundness
census_axioms Ragu.Circuits.Boolean.Alloc.completeness
census_axioms Ragu.Circuits.Boolean.And.soundness
census_axioms Ragu.Circuits.Boolean.And.completeness
census_axioms Ragu.Circuits.Boolean.ConditionalEnforceEqual.soundness
census_axioms Ragu.Circuits.Boolean.ConditionalEnforceEqual.completeness
census_axioms Ragu.Circuits.Boolean.ConditionalSelect.soundness
census_axioms Ragu.Circuits.Boolean.ConditionalSelect.completeness
census_axioms Ragu.Circuits.Boolean.Consistent.soundness
census_axioms Ragu.Circuits.Boolean.Consistent.completeness
census_axioms Ragu.Circuits.Boolean.Decompose.soundness
census_axioms Ragu.Circuits.Boolean.Decompose.completeness

/-! ## Core and element circuits -/

census_axioms Ragu.Circuits.Core.Mul.soundness
census_axioms Ragu.Circuits.Core.Mul.completeness
census_axioms Ragu.Circuits.Element.Alloc.soundness
census_axioms Ragu.Circuits.Element.Alloc.completeness
census_axioms Ragu.Circuits.Element.AllocSquare.soundness
census_axioms Ragu.Circuits.Element.AllocSquare.completeness
census_axioms Ragu.Circuits.Element.DivNonzero.soundness
census_axioms Ragu.Circuits.Element.DivNonzero.completeness
census_axioms Ragu.Circuits.Element.Divide.soundness
census_axioms Ragu.Circuits.Element.Divide.completeness
census_axioms Ragu.Circuits.Element.EnforceInvertible.soundness
census_axioms Ragu.Circuits.Element.EnforceInvertible.completeness
census_axioms Ragu.Circuits.Element.EnforceNonzero.soundness
census_axioms Ragu.Circuits.Element.EnforceNonzero.completeness
census_axioms Ragu.Circuits.Element.EnforceRootOfUnity.soundness
census_axioms Ragu.Circuits.Element.EnforceRootOfUnity.completeness
census_axioms Ragu.Circuits.Element.EnforceZero.soundness
census_axioms Ragu.Circuits.Element.EnforceZero.completeness
census_axioms Ragu.Circuits.Element.Fold.soundness
census_axioms Ragu.Circuits.Element.Fold.completeness
census_axioms Ragu.Circuits.Element.Invert.soundness
census_axioms Ragu.Circuits.Element.Invert.completeness
census_axioms Ragu.Circuits.Element.InvertWith.soundness
census_axioms Ragu.Circuits.Element.InvertWith.completeness
census_axioms Ragu.Circuits.Element.Invertible.soundness
census_axioms Ragu.Circuits.Element.Invertible.completeness
census_axioms Ragu.Circuits.Element.InvertibleConsistent.soundness
census_axioms Ragu.Circuits.Element.InvertibleConsistent.completeness
census_axioms Ragu.Circuits.Element.IsEqual.soundness
census_axioms Ragu.Circuits.Element.IsEqual.completeness
census_axioms Ragu.Circuits.Element.IsZero.soundness
census_axioms Ragu.Circuits.Element.IsZero.completeness
census_axioms Ragu.Circuits.Element.Mul.soundness
census_axioms Ragu.Circuits.Element.Mul.completeness
census_axioms Ragu.Circuits.Element.Square.soundness
census_axioms Ragu.Circuits.Element.Square.completeness

/-! ## Endoscalar, Horner, and nonzero-bank circuits -/

census_axioms Ragu.Circuits.Endoscalar.Alloc.soundness
census_axioms Ragu.Circuits.Endoscalar.Alloc.completeness
census_axioms Ragu.Circuits.Endoscalar.EnforceProducts.Digit.soundness
census_axioms Ragu.Circuits.Endoscalar.EnforceProducts.Digit.completeness
census_axioms Ragu.Circuits.Endoscalar.EnforceProducts.soundness
census_axioms Ragu.Circuits.Endoscalar.EnforceProducts.completeness
census_axioms Ragu.Circuits.Endoscalar.Extract.soundness
census_axioms Ragu.Circuits.Endoscalar.Extract.completeness
census_axioms Ragu.Circuits.Endoscalar.GroupScale.Step.soundness
census_axioms Ragu.Circuits.Endoscalar.GroupScale.Step.completeness
census_axioms Ragu.Circuits.Endoscalar.GroupScale.soundness
census_axioms Ragu.Circuits.Endoscalar.GroupScale.completeness
census_axioms Ragu.Circuits.Endoscalar.HoistedAlloc.soundness
census_axioms Ragu.Circuits.Endoscalar.HoistedAlloc.completeness
census_axioms Ragu.Circuits.Endoscalar.HoistedGroupScale.Step.soundness
census_axioms Ragu.Circuits.Endoscalar.HoistedGroupScale.Step.completeness
census_axioms Ragu.Circuits.Endoscalar.HoistedGroupScale.soundness
census_axioms Ragu.Circuits.Endoscalar.HoistedGroupScale.completeness
census_axioms Ragu.Circuits.Endoscalar.HoistedLift.Digit.soundness
census_axioms Ragu.Circuits.Endoscalar.HoistedLift.Digit.completeness
census_axioms Ragu.Circuits.Endoscalar.HoistedLift.soundness
census_axioms Ragu.Circuits.Endoscalar.HoistedLift.completeness
census_axioms Ragu.Circuits.Endoscalar.Initial.soundness
census_axioms Ragu.Circuits.Endoscalar.Initial.completeness
census_axioms Ragu.Circuits.Endoscalar.Lift.Digit.soundness
census_axioms Ragu.Circuits.Endoscalar.Lift.Digit.completeness
census_axioms Ragu.Circuits.Endoscalar.Lift.soundness
census_axioms Ragu.Circuits.Endoscalar.Lift.completeness
census_axioms Ragu.Circuits.Horner.Ky.soundness
census_axioms Ragu.Circuits.Horner.Ky.completeness
census_axioms Ragu.Circuits.NonzeroBank.Scope.soundness
census_axioms Ragu.Circuits.NonzeroBank.Scope.completeness

/-! ## Point circuits -/

census_axioms Ragu.Circuits.Point.AddIncomplete.soundness
census_axioms Ragu.Circuits.Point.AddIncomplete.completeness
census_axioms Ragu.Circuits.Point.AddIncompleteUnchecked.soundness
census_axioms Ragu.Circuits.Point.AddIncompleteUnchecked.completeness
census_axioms Ragu.Circuits.Point.Alloc.soundness
census_axioms Ragu.Circuits.Point.Alloc.completeness
census_axioms Ragu.Circuits.Point.ConditionalEndo.soundness
census_axioms Ragu.Circuits.Point.ConditionalEndo.completeness
census_axioms Ragu.Circuits.Point.ConditionalNegate.soundness
census_axioms Ragu.Circuits.Point.ConditionalNegate.completeness
census_axioms Ragu.Circuits.Point.Consistent.soundness
census_axioms Ragu.Circuits.Point.Consistent.completeness
census_axioms Ragu.Circuits.Point.Denormalize.soundness
census_axioms Ragu.Circuits.Point.Denormalize.completeness
census_axioms Ragu.Circuits.Point.Double.soundness
census_axioms Ragu.Circuits.Point.Double.completeness
census_axioms Ragu.Circuits.Point.DoubleAndAddIncomplete.soundness
census_axioms Ragu.Circuits.Point.DoubleAndAddIncomplete.completeness
census_axioms Ragu.Circuits.Point.DoubleAndAddIncompleteUnchecked.soundness
census_axioms Ragu.Circuits.Point.DoubleAndAddIncompleteUnchecked.completeness
census_axioms Ragu.Circuits.Point.Normalize.soundness
census_axioms Ragu.Circuits.Point.Normalize.completeness
census_axioms Ragu.Circuits.Point.TripleAndAddIncompleteUnchecked.soundness
census_axioms Ragu.Circuits.Point.TripleAndAddIncompleteUnchecked.completeness

/-! ## Poseidon circuits -/

census_axioms Ragu.Circuits.Poseidon.Permutation.AnyRound.soundness
census_axioms Ragu.Circuits.Poseidon.Permutation.AnyRound.completeness
census_axioms Ragu.Circuits.Poseidon.Permutation.soundness
census_axioms Ragu.Circuits.Poseidon.Permutation.completeness
census_axioms Ragu.Circuits.Poseidon.Round.Full.soundness
census_axioms Ragu.Circuits.Poseidon.Round.Full.completeness
census_axioms Ragu.Circuits.Poseidon.Round.Partial.soundness
census_axioms Ragu.Circuits.Poseidon.Round.Partial.completeness
census_axioms Ragu.Circuits.Poseidon.Sbox.soundness
census_axioms Ragu.Circuits.Poseidon.Sbox.completeness
census_axioms Ragu.Circuits.Poseidon.Sponge.Hash1.soundness
census_axioms Ragu.Circuits.Poseidon.Sponge.Hash1.completeness
census_axioms Ragu.Circuits.Poseidon.Sponge.Blocks.loop_soundness
census_axioms Ragu.Circuits.Poseidon.Sponge.Blocks.loop_completeness
census_axioms Ragu.Circuits.Poseidon.Sponge.Blocks.soundness
census_axioms Ragu.Circuits.Poseidon.Sponge.Blocks.completeness
census_axioms Ragu.Circuits.Poseidon.Sponge.Squeeze.soundness
census_axioms Ragu.Circuits.Poseidon.Sponge.Squeeze.completeness
census_axioms Ragu.Circuits.Poseidon.Sponge.Ragged.soundness
census_axioms Ragu.Circuits.Poseidon.Sponge.Ragged.completeness

/-! ## Prime-field and executable fingerprint boundary -/

census_axioms Ragu.Core.Primes.p_prime
census_axioms Ragu.Core.Primes.q_prime
census_axioms Ragu.PolynomialFingerprint.pastaFp_two_point_prob_le
census_axioms Ragu.PolynomialFingerprint.pastaFq_two_point_prob_le
census_computable Ragu.Core.Statements.FormalInstance.fingerprint +choice
census_computable Ragu.Core.Statements.FormalInstance.polynomialFingerprint +choice
census_computable Ragu.Fingerprint.instances +choice
