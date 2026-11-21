//! Prover operations on a compressed instance.
use alloc::vec::Vec;

use ragu_circuits::{
    polynomials::Rank,
    staging::{StageReader, stage_wire_indices, wires_of},
};
use ragu_core::Result;

use crate::{
    Proof,
    compress::{
        instance::*,
        revdot::{native_components, nested_components},
    },
    profile::ProfiledCycle,
    protocol::{native, nested},
};
impl<C: ProfiledCycle> Instance<C> {
    /// The instance of `proof`, with the values the decider derives computed
    /// from its polynomials and the wires read off its stages.
    pub(crate) fn of<R: Rank, const HEADER_SIZE: usize>(proof: &Proof<C, R>) -> Result<Self> {
        let preamble = StageReader::<C::CircuitField, R>::new(&proof[native::RxIndex::Preamble]);
        let child = stage_wire_indices::<_, R, NativePreamble<C, R, HEADER_SIZE>>(|out| {
            let mut wires = Vec::new();
            for child in [&out.left, &out.right] {
                wires.extend(wires_of(&child.unified.x)?);
                wires.extend(wires_of(&child.unified.y)?);
                wires.extend(wires_of(&child.circuit_id)?);
            }
            Ok(wires)
        })?;
        let child: Vec<_> = child.iter().map(|&i| preamble.read(i)).collect();
        let [lx, ly, lid, rx, ry, rid] = child.try_into().expect("six child values");

        let eval = StageReader::<C::CircuitField, R>::new(&proof[native::RxIndex::Eval]);
        let ab = stage_wire_indices::<_, R, NativeEval<C, R, HEADER_SIZE>>(|out| {
            let mut wires = wires_of(&out.evaluations.a_poly)?;
            wires.extend(wires_of(&out.evaluations.b_poly)?);
            Ok(wires)
        })?;
        let [a_at_u, b_at_u] = [eval.read(ab[0]), eval.read(ab[1])];

        let bridge_preamble =
            StageReader::<C::ScalarField, R>::new(&proof[nested::RxIndex::BridgePreamble]);
        let nested_child = stage_wire_indices::<_, R, NestedPreamble<C, R>>(|out| {
            let mut wires = Vec::new();
            for child in [&out.left, &out.right] {
                wires.extend(wires_of(&child.nested.x)?);
                wires.extend(wires_of(&child.nested.y)?);
            }
            Ok(wires)
        })?;
        let nested_child: Vec<_> = nested_child
            .iter()
            .map(|&i| bridge_preamble.read(i))
            .collect();
        let [left_x, left_y, right_x, right_y] =
            nested_child.try_into().expect("four child values");

        let bridge_eval =
            StageReader::<C::ScalarField, R>::new(&proof[nested::RxIndex::BridgeEval]);
        let nested_ab = stage_wire_indices::<_, R, NestedEval<C, R>>(|out| {
            let mut wires = wires_of(&out.nested.a_poly)?;
            wires.extend(wires_of(&out.nested.b_poly)?);
            Ok(wires)
        })?;
        let [nested_a_at_u, nested_b_at_u] = [
            bridge_eval.read(nested_ab[0]),
            bridge_eval.read(nested_ab[1]),
        ];

        Ok(Instance {
            circuit_id: proof.circuit_id(),
            left_header: proof.left_header().to_vec(),
            right_header: proof.right_header().to_vec(),
            online: *proof.online_openings(),
            native: native_components::<C::Profile>()
                .map(|component| proof.native_commitment(component))
                .collect(),
            native_registry_xy: proof.native_registry_xy_commitment(),
            native_p: proof.native_p_commitment(),
            online_commitments: proof.online_commitments(),
            nested: nested_components::<C::Profile>()
                .map(|component| match component {
                    nested::RxComponent::AbA => proof.nested_a_commitment(),
                    nested::RxComponent::AbB => proof.nested_b_commitment(),
                    nested::RxComponent::Rx(index) => proof.nested_rx_commitment(index),
                })
                .collect(),
            nested_registry_xy: proof.nested_registry_xy_commitment(),
            nested_p: proof.nested_p_commitment(),
            nested_challenges_partial: proof.nested_challenges_partial(),
            bridge_alpha: proof.bridge_alpha,
            c: proof.native_c(),
            v: proof.v(),
            nested_c: proof.nested_c(),
            nested_v: proof.nested_v()?,
            left: Child {
                x: lx,
                y: ly,
                id: lid,
            },
            right: Child {
                x: rx,
                y: ry,
                id: rid,
            },
            a_at_u,
            b_at_u,
            nested_left: NestedChild {
                x: left_x,
                y: left_y,
            },
            nested_right: NestedChild {
                x: right_x,
                y: right_y,
            },
            nested_a_at_u,
            nested_b_at_u,
        })
    }
}
