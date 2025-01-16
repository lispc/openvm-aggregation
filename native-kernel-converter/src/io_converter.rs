use openvm_instructions::{instruction::Instruction, VmOpcode};
use openvm_native_compiler::{asm::A0, CastfOpcode, NativeLoadStoreOpcode};
use openvm_rv32im_transpiler::{BaseAluOpcode, Rv32LoadStoreOpcode};
use openvm_stark_sdk::p3_baby_bear::BabyBear as F;
use p3_field::{FieldAlgebra, PrimeField32};

use crate::asm_builder::*;

//////////////// convert `hint_read`` and `publish` ///////////////////

pub fn convert_hintread(op: Instruction<F>) -> Vec<Instruction<F>> {
    // x28
    // x30: value

    let native_addr = op.c.as_canonical_u32() as usize;
    let offset = op.b.as_canonical_u32() as usize;
    let tmp_slot = A0 - 4;
    // VmOpcode(260) 0 0 16777150 5 5 0 0    // StoreHintWord
    vec![Instruction::<F> {
        opcode: VmOpcode::with_default_offset(Rv32LoadStoreOpcode::LOADW),
        a: F::from_canonical_usize(X30 * 4),
        b: F::from_canonical_usize(X28 * 4),
        c: F::from_canonical_usize(0),
        d: as_register(),
        e: as_mem(),
        f: F::from_canonical_usize(0),
        g: F::from_canonical_usize(0),
    }]
    .into_iter()
    .chain(load_register_to_native(tmp_slot as usize, X30).into_iter())
    .chain(
        vec![
            Instruction::<F> {
                opcode: VmOpcode::with_default_offset(NativeLoadStoreOpcode::STOREW),
                a: F::from_canonical_usize(tmp_slot as usize),
                b: F::from_canonical_usize(offset),
                c: F::from_canonical_usize(native_addr),
                d: as_native(),
                e: as_native(),
                f: F::from_canonical_usize(0),
                g: F::from_canonical_usize(0),
            },
            Instruction::<F> {
                opcode: VmOpcode::with_default_offset(BaseAluOpcode::ADD),
                a: F::from_canonical_usize(X28 * 4),
                b: F::from_canonical_usize(X28 * 4),
                c: F::from_canonical_usize(4),
                d: as_register(),
                e: as_imm(),
                f: F::from_canonical_usize(0),
                g: F::from_canonical_usize(0),
            },
        ]
        .into_iter(),
    )
    .collect::<Vec<_>>()
}

pub fn convert_publish(op: Instruction<F>) -> Vec<Instruction<F>> {
    // VmOpcode(288) 0 16776149 16776511 0 5 5 0

    let pi_value_addr = op.b;
    let pi_idx_addr = op.c;
    // x28: input, const
    // x29: output, const
    // x30: the pi value | hint value
    // x31: the pi index
    vec![
        Instruction::<F> {
            opcode: VmOpcode::with_default_offset(CastfOpcode::CASTF),
            a: F::from_canonical_usize(X30 * 4),
            b: pi_value_addr,
            c: F::from_canonical_usize(0),
            d: as_register(),
            e: as_native(),
            f: F::from_canonical_usize(0),
            g: F::from_canonical_usize(0),
        },
        Instruction::<F> {
            opcode: VmOpcode::with_default_offset(CastfOpcode::CASTF),
            a: F::from_canonical_usize(X31 * 4),
            b: pi_idx_addr,
            c: F::from_canonical_usize(0),
            d: as_register(),
            e: as_native(),
            f: F::from_canonical_usize(0),
            g: F::from_canonical_usize(0),
        },
        // we need x31*=4
        // here i add itself twice
        // TODO: shift left by 2 bits?
        Instruction::<F> {
            opcode: VmOpcode::with_default_offset(BaseAluOpcode::ADD),
            a: F::from_canonical_usize(X31 * 4),
            b: F::from_canonical_usize(X31 * 4),
            c: F::from_canonical_usize(X31 * 4),
            d: as_register(),
            e: as_register(),
            f: F::from_canonical_usize(0),
            g: F::from_canonical_usize(0),
        },
        Instruction::<F> {
            opcode: VmOpcode::with_default_offset(BaseAluOpcode::ADD),
            a: F::from_canonical_usize(X31 * 4),
            b: F::from_canonical_usize(X31 * 4),
            c: F::from_canonical_usize(X31 * 4),
            d: as_register(),
            e: as_register(),
            f: F::from_canonical_usize(0),
            g: F::from_canonical_usize(0),
        },
        Instruction::<F> {
            opcode: VmOpcode::with_default_offset(BaseAluOpcode::ADD),
            a: F::from_canonical_usize(X31 * 4),
            b: F::from_canonical_usize(X31 * 4),
            c: F::from_canonical_usize(X29 * 4),
            d: as_register(),
            e: as_register(),
            f: F::from_canonical_usize(0),
            g: F::from_canonical_usize(0),
        },
        Instruction::<F> {
            opcode: VmOpcode::with_default_offset(Rv32LoadStoreOpcode::STOREW),
            a: F::from_canonical_usize(X30 * 4),
            b: F::from_canonical_usize(X31 * 4),
            c: F::from_canonical_usize(0),
            d: as_register(),
            e: as_mem(),
            f: F::from_canonical_usize(0),
            g: F::from_canonical_usize(0),
        },
    ]
}
