use std::fmt::format;
use std::sync::Arc;

use openvm_instructions::instruction::DebugInfo;
use openvm_instructions::program::Program;
use openvm_instructions::{
    instruction::{self, Instruction},
    PhantomDiscriminant, PublishOpcode,
    SystemOpcode::{PHANTOM, TERMINATE},
    VmOpcode,
};
use openvm_native_recursion::hints::Hintable;
use openvm_native_compiler::{asm::A0, CastfOpcode, NativeBranchEqualOpcode, NativeJalOpcode, NativeLoadStoreOpcode, NativePhantom};
use openvm_rv32im_transpiler::{BaseAluOpcode, Rv32LoadStoreOpcode, MulOpcode, BranchEqualOpcode};
use openvm_sdk::fs::read_root_proof_from_file;
use openvm_sdk::{
    prover::RootVerifierLocalProver,
    prover::vm::SingleSegmentVmProver,
    fs::read_root_pk_from_file,
    verifier::root::types::RootVmVerifierInput,
};
use openvm_stark_sdk::{
    config::baby_bear_poseidon2::BabyBearPoseidon2Config,
    p3_baby_bear::BabyBear as F,
};
use p3_field::{FieldAlgebra, PrimeField32};
use serde::{Deserialize, Serialize};
use snark_verifier_sdk::{
    halo2::aggregation::AggregationCircuit,
    snark_verifier::system::halo2::{compile, Config},
    CircuitExt,
};

pub const DEFAULT_ROOT_PK_PATH: &str = concat!(env!("HOME"), "/.openvm/root.pk");

mod asm_builder;
use asm_builder::*;
mod io_converter;
use io_converter::*;
mod asm_writer;
use asm_writer::*;


// VmOpcode(1) 0 0 17 0 0 0 0    // HintInputVec
// VmOpcode(260) 0 0 16777150 5 5 0 0    // StoreHintWord
// VmOpcode(256) 16777143 0 16777150 5 5 0 0    // LoadV

fn load_root_program() -> Program<F> {
// load from root_exe.bin if exist, otherwise load from pk
let root_exe = {
    let agg_stark_pk = read_root_pk_from_file(DEFAULT_ROOT_PK_PATH).expect("invalid pk file");
    let root_exe = &agg_stark_pk.root_verifier_pk.root_committed_exe;
    let root_exe = &root_exe.exe;
    root_exe.clone()
};

//println!("root program: {}", root_program.program);
let program = root_exe.program.clone();
println!(
    "total ins count: {}, {}",
    program.instructions_and_debug_infos.len(),
    program.defined_instructions().len(),
);
program
}

fn op_publish() -> usize {
    VmOpcode::with_default_offset(PublishOpcode::PUBLISH).as_usize()
}

fn op_hintstore() -> usize {
    VmOpcode::with_default_offset(NativeLoadStoreOpcode::HINT_STOREW).as_usize()
}

fn op_phantom() -> usize {
    VmOpcode::with_default_offset(PHANTOM).as_usize()
}

fn op_jal() -> usize {
    VmOpcode::with_default_offset(NativeJalOpcode::JAL).as_usize()
}

fn op_beq() -> usize {
    VmOpcode::with_default_offset(NativeBranchEqualOpcode(BranchEqualOpcode::BEQ)).as_usize()
}

fn op_bne() -> usize {
    VmOpcode::with_default_offset(NativeBranchEqualOpcode(BranchEqualOpcode::BNE)).as_usize()
}

fn dump_root_program() {
    
    let mut program = load_root_program();

    let mut new_instructions_and_debug_infos: Vec<(Option<(Instruction<F>, Option<openvm_instructions::instruction::DebugInfo>)>, usize)> = vec![];
    let mut hint_bits_mode = false;
    let mut hint_bits_counter_limit = 0;
    let mut hint_bits_counter = 0;
    for (idx, op_elem) in program.instructions_and_debug_infos.iter().enumerate() {
        if let Some(op) = op_elem.as_ref() {
            if op.0.opcode.as_usize() == op_publish() {
                let instructions = convert_publish(op.0.clone());
                new_instructions_and_debug_infos.extend(
                    instructions.iter().map(|x| 
                            (Some((x.clone(), None)), idx * 4)
                        ),
                );
                continue;
            }
            if op.0.opcode.as_usize() == op_phantom() {
                if op.0.c.as_canonical_u32() as usize == NativePhantom::HintInput as usize {
                    // as nop
                    let instructions = print_native(F::from_canonical_usize(A0 as usize));
                    new_instructions_and_debug_infos.extend(
                        instructions.iter().map(|x| (Some((x.clone(), None)), idx * 4))
                    );
                    continue;
                }
                if op.0.c.as_canonical_u32() as usize == ((AS_NATIVE as usize) << 16 | (NativePhantom::HintBits as usize)) {
                    hint_bits_mode = true;
                    hint_bits_counter = 0;
                    hint_bits_counter_limit = op.0.b.as_canonical_u32() as usize;
                    new_instructions_and_debug_infos.push((op_elem.clone(), idx * 4));
                    continue;
                }
            }
            if op.0.opcode.as_usize() == op_hintstore() {
                if hint_bits_mode {
                    new_instructions_and_debug_infos.push((op_elem.clone(), idx * 4));
                    hint_bits_counter += 1;
                    //println!("in hint bits mode, counter: {}, limit {}", hint_bits_counter, hint_bits_counter_limit);
                    if hint_bits_counter >= hint_bits_counter_limit {
                        hint_bits_mode = false;
                        hint_bits_counter = 0;
                        hint_bits_counter_limit = 0;
                    }
                    continue;
                } else {
                    let instructions = convert_hintread(op.0.clone());
                    new_instructions_and_debug_infos.extend(
                        instructions.iter().map(|x| (Some((x.clone(), None)), idx * 4))
                    );
                    continue;
                }
            }
        };
        new_instructions_and_debug_infos.push((op_elem.clone(), idx * 4));
    }


    fix_pc(&mut new_instructions_and_debug_infos);

    program.instructions_and_debug_infos = new_instructions_and_debug_infos.into_iter().map(|x| x.0).collect();

    if let Some(0) = program.instructions_and_debug_infos.last().unwrap()
    .as_ref()
    .map(|x| x.0.opcode.as_usize()) {
        program.instructions_and_debug_infos.pop();
    }

    
    let output_file = "root.u32s";
    post_process_and_write(program, output_file);
    println!("written to {}", output_file);
}


fn fix_pc(new_instructions_and_debug_infos: &mut Vec<(Option<(Instruction<F>, Option<DebugInfo>)>, usize)>) {

    // 
    // fix jump and pc
    // step1: for all jal, collect the old_pc=>new_pc mapping

    // idx=>correct pc
    let mut pc_rewrite = vec![];
    for (idx, op_elem) in new_instructions_and_debug_infos.iter().enumerate() {
        if let Some(op) = &op_elem.0 {
            if op.0.opcode.as_usize() == op_jal()  ||
                op.0.opcode.as_usize() == op_beq() ||
                op.0.opcode.as_usize() == op_bne()
            {
                let old_pc_diff = if op.0.opcode.as_usize() == op_jal() {
                    op.0.b.as_canonical_u32() as usize
                } else {
                    op.0.c.as_canonical_u32() as usize
                };
                let babybear = 2013265921;
                let old_pc_target = (op_elem.1 + old_pc_diff) % babybear;
                //println!("old pc: {}", old_pc);
                // find the idx of new_instructions_and_debug_infos where element.1 == old_pc
                let new_idx = new_instructions_and_debug_infos.iter().enumerate().find(|(_, x)| x.1 == old_pc_target).map(|x| x.0);
                //if !new_pc.map(|x| x == old_pc).unwrap_or(false) {
                //    println!("WARN: new pc == old pc {}", old_pc);
                //}
                match new_idx {
                    Some(new_idx) => {
                        let new_pc = new_idx * 4;
                        let new_pc_diff = (new_pc + babybear - idx * 4) % babybear;
                        if new_pc_diff != old_pc_diff {
                            let display = |f: i32| {
                                if f < 1_000_000 {
                                    f
                                } else {
                                    f- babybear as i32
                                }
                            };
                            //println!("pc rewrite idx {idx}, {}=>{:?}",display(old_pc_diff as i32), display(new_pc_diff as i32));
                            pc_rewrite.push((idx, new_pc_diff, if op.0.opcode.as_usize() == op_jal() {
                                1 // b
                            } else {
                                2 // c
                            }));
                        }
                    }
                    None => {
                        println!("WARN: fail to find new pc for old pc {}", old_pc_target);
                    }
                }
            }
        }
    }
    for (idx, new_pc_diff, op_idx) in pc_rewrite {
                if op_idx == 1 {
                    new_instructions_and_debug_infos[idx].0.as_mut().unwrap().0.b = F::from_canonical_usize(new_pc_diff);
                } else if op_idx == 2 {
                    new_instructions_and_debug_infos[idx].0.as_mut().unwrap().0.c = F::from_canonical_usize(new_pc_diff);
                } else {
                    panic!("invalid op_idx");
                }
    }
}

fn parse_root_proof() {
    let root_proof_bytes: RootVmVerifierInput<BabyBearPoseidon2Config> = read_root_proof_from_file("factor-example/openvm/root.proof").expect("fail to read proof");
    let steams = root_proof_bytes.write();
    //let input_stream: std::collections::VecDeque<Vec<F>> = bitcode::deserialize(&[]).expect("decode");

    let mut flatten_input: Vec<u32> = Vec::new();
    for (idx, x) in steams.into_iter().enumerate() {
        flatten_input.push(x.len() as u32);
        if idx < 30 {
        println!("len is {}", x.len());
        }
        for f in x {
            flatten_input.push(f.as_canonical_u32());
        }
    }
    // dump flatten_input to flatten.input
    let flatten_input_bytes = bitcode::serialize(&flatten_input).unwrap();
    std::fs::write("flatten.input", flatten_input_bytes).expect("fail to write");
}
fn main() {
    //dump_root_program();
    parse_root_proof();
}
