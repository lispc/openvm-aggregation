use std::fmt::format;
use std::sync::Arc;

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
use openvm_sdk::{
    prover::RootVerifierLocalProver,
    prover::vm::SingleSegmentVmProver,
    commit::babybear_digest_to_bn254, fs::read_agg_pk_from_file,
    verifier::root::types::RootVmVerifierInput, F,
};
use openvm_stark_sdk::config::baby_bear_poseidon2::BabyBearPoseidon2Config;
use p3_field::{FieldAlgebra, PrimeField32};
use serde::{Deserialize, Serialize};
use snark_verifier_sdk::{
    halo2::aggregation::AggregationCircuit,
    snark_verifier::system::halo2::{compile, Config},
    CircuitExt,
};

pub const DEFAULT_AGG_PK_PATH: &str = concat!(env!("HOME"), "/.openvm/agg.pk");


const X0: usize = 0; // x0
const X10: usize = 10; // a0
const X28: usize = 28; // t3
const X29: usize = 29; // t4
const X30: usize = 30; // t5
const X31: usize = 31; // t6

// process hint read
// before conversion:
//
// VmOpcode(1) 0 0 17 0 0 0 0    // HintInputVec
// VmOpcode(260) 0 0 16777150 5 5 0 0    // StoreHintWord
// VmOpcode(256) 16777143 0 16777150 5 5 0 0    // LoadV

fn print_native(mem_addr: F) -> Vec<Instruction<F>> {
    vec![Instruction::<F>::phantom(
        PhantomDiscriminant(0x10 as u16), // print
        mem_addr,
        F::from_canonical_usize(0),
        5,
    )]
}
fn print_mem(mem_addr: F) -> Vec<Instruction<F>> {
    vec![Instruction::<F>::phantom(
        PhantomDiscriminant(0x10 as u16), // print
        mem_addr,
        F::from_canonical_usize(0),
        2,
    )]
}
fn print_register(register_idx: usize) -> Vec<Instruction<F>> {
    vec![
        Instruction::<F>::phantom(
            PhantomDiscriminant(0x10 as u16),
            F::from_canonical_usize(4 * register_idx),
            F::from_canonical_usize(0),
            1,
        ),
        Instruction::<F>::phantom(
            PhantomDiscriminant(0x10 as u16),
            F::from_canonical_usize(4 * register_idx + 1),
            F::from_canonical_usize(0),
            1,
        ),
        Instruction::<F>::phantom(
            PhantomDiscriminant(0x10 as u16),
            F::from_canonical_usize(4 * register_idx + 2),
            F::from_canonical_usize(0),
            1,
        ),
        Instruction::<F>::phantom(
            PhantomDiscriminant(0x10 as u16),
            F::from_canonical_usize(4 * register_idx + 3),
            F::from_canonical_usize(0),
            1,
        ),
    ]
}

fn load_register_to_native(native_addr: usize, register_idx: usize) -> Vec<Instruction<F>> {
    let as_imm = F::from_canonical_usize(0);
    let as_native = F::from_canonical_usize(5);
    let as_register = F::from_canonical_usize(1);

    let dst = F::from_canonical_usize(native_addr);
    let zero = F::from_canonical_usize(0);

    let op_add = VmOpcode::from_usize(0x130);
    let op_mul = VmOpcode::from_usize(0x132);

    let add_op = |(b, as_b), (c, as_c)| Instruction::<F> {
        opcode: op_add,
        a: dst,
        b: b,
        c: F::from_canonical_usize(c),
        d: as_native,
        e: as_b,
        f: as_c,
        g: F::from_canonical_usize(0),
    };
    let shift_op = || Instruction::<F> {
        opcode: op_mul,
        a: dst,
        b: dst,
        c: F::from_canonical_usize(256),
        d: as_native,
        e: as_native,
        f: as_imm,
        g: F::from_canonical_usize(0),
    };
    let mut result = vec![];
    //result.extend(print_native(F::from_canonical_usize(A0 as usize)));
    result.extend([
        add_op((zero, as_imm), (4 * register_idx + 3, as_register)),
        shift_op(),
        add_op((dst, as_native), (4 * register_idx + 2, as_register)),
        shift_op(),
        add_op((dst, as_native), (4 * register_idx + 1, as_register)),
        shift_op(),
        add_op((dst, as_native), (4 * register_idx, as_register)),
    ]);
    result
}

fn handle_pc_diff(program: &mut Program<F>) -> usize {
    let mut pc_diff = 2;
    for op in &program.defined_instructions() {
        pc_diff += 1 + 1 + 7; // don't skip unused operands
    }
    pc_diff += 9; // for next jal
    let jal = Instruction::<F> {
        opcode: VmOpcode::from_usize(0x115),
        a: F::from_canonical_usize(1 << 24 - 8), // A0
        b: F::from_canonical_usize(4 * (pc_diff + 1)),
        c: F::from_canonical_usize(0),
        d: F::from_canonical_usize(5), // native_as
        e: F::from_canonical_usize(0),
        f: F::from_canonical_usize(0),
        g: F::from_canonical_usize(0),
    };
    program.push_instruction(jal);
    pc_diff
}

fn u32_to_directive(x: u32) -> String {
    let opcode = x & 0b1111111;
    let funct3 = (x >> 12) & 0b111;
    let rd = (x >> 7) & 0b11111;
    let rs1 = (x >> 15) & 0b11111;
    let mut simm12 = (x >> 20) as i32;
    if simm12 >= 1 << 11 {
        simm12 -= 1 << 12;
    }
    format!(
        ".insn i {}, {}, x{}, x{}, {}",
        opcode, funct3, rd, rs1, simm12
    )
}

const OPCODE: u32 = 0x0b;
const FUNCT3: u32 = 0b111;
pub const LONG_FORM_INSTRUCTION_INDICATOR: u32 = (FUNCT3 << 12) + OPCODE;
pub const GAP_INDICATOR: u32 = (1 << 25) + (FUNCT3 << 12) + OPCODE;

fn convert_program_to_u32s(program: &Program<F>, pc_diff: usize) -> Vec<(Vec<u32>, String)> {
    program
        .defined_instructions()
        .iter()
        .map(|ins| {
            (
                vec![
                    LONG_FORM_INSTRUCTION_INDICATOR,
                    7,
                    ins.opcode.as_usize() as u32,
                    ins.a.as_canonical_u32(),
                    ins.b.as_canonical_u32(),
                    ins.c.as_canonical_u32(),
                    ins.d.as_canonical_u32(),
                    ins.e.as_canonical_u32(),
                    ins.f.as_canonical_u32(),
                    ins.g.as_canonical_u32(),
                ],
                format!("{:?}", ins.opcode),
            )
        })
        .chain(std::iter::once((
            vec![GAP_INDICATOR, pc_diff as u32],
            "GAP_INDICATOR".to_string(),
        )))
        .collect()
}

fn convert_hintread(op :Instruction<F>) -> Vec<Instruction<F>> {
    // x28
    // x30: value
    let as_register = F::from_canonical_usize(1);
    let as_imm = F::from_canonical_usize(0);
    let as_mem = F::from_canonical_usize(2);
    let as_native = F::from_canonical_usize(5);

    let native_addr = op.c.as_canonical_u32() as usize;
    let offset = op.b.as_canonical_u32() as usize;
    let tmp_slot = A0 - 4;
    // VmOpcode(260) 0 0 16777150 5 5 0 0    // StoreHintWord

    let mut ins = vec![

    Instruction::<F> {
        opcode: VmOpcode::with_default_offset(Rv32LoadStoreOpcode::LOADW),
        a: F::from_canonical_usize(X30 * 4),
        b: F::from_canonical_usize(X28 * 4),
        c: F::from_canonical_usize(0),
        d: as_register,
        e: as_mem,
        f: F::from_canonical_usize(0),
        g: F::from_canonical_usize(0),
    }];
    // 8 0s
    //ins.extend(print_register(X28)); // print x28
    //ins.extend(print_register(X30)); // print x30
    //ins.extend(print_native(F::from_canonical_usize(A0 as usize)));
    ins.extend(load_register_to_native(tmp_slot as usize, X30)); // print30
    ins.extend(print_native(F::from_canonical_usize(tmp_slot as usize)));
    ins.extend(print_native(F::from_canonical_usize(native_addr)));
    ins.push(
        Instruction::<F> {
            opcode: VmOpcode::with_default_offset(NativeLoadStoreOpcode::STOREW),
            a: F::from_canonical_usize(tmp_slot as usize),
            b: F::from_canonical_usize(offset),
            c: F::from_canonical_usize(native_addr),
            d: as_native,
            e: as_native,
            f: F::from_canonical_usize(0),
            g: F::from_canonical_usize(0),
        }
    );
    ins.push(Instruction::<F> {
        opcode: VmOpcode::with_default_offset(BaseAluOpcode::ADD),
        a: F::from_canonical_usize(X28 * 4),
        b: F::from_canonical_usize(X28 * 4),
        c: F::from_canonical_usize(4),
        d: as_register,
        e: as_imm,
        f: F::from_canonical_usize(0),
        g: F::from_canonical_usize(0),
    });
    //ins.extend(print_register(X28)); // print x28
    /* 
    ins.push(Instruction::<F> {
        opcode: VmOpcode::with_default_offset(SystemOpcode:),
        a: F::from_canonical_usize(X28 * 4),
        b: F::from_canonical_usize(X28 * 4),
        c: F::from_canonical_usize(4),
        d: as_register,
        e: as_imm,
        f: F::from_canonical_usize(0),
        g: F::from_canonical_usize(0),
    }
    );
    */
    ins
}

fn convert_publish(op: Instruction<F>) -> Vec<Instruction<F>> {
    // VmOpcode(288) 0 16776149 16776511 0 5 5 0
    let as_imm = F::from_canonical_usize(0);
    let as_native = F::from_canonical_usize(5);
    let as_register = F::from_canonical_usize(1);
    let as_mem = F::from_canonical_usize(2);

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
            d: as_register,
            e: as_native,
            f: F::from_canonical_usize(0),
            g: F::from_canonical_usize(0),
        },
        Instruction::<F> {
            opcode: VmOpcode::with_default_offset(CastfOpcode::CASTF),
            a: F::from_canonical_usize(X31 * 4),
            b: pi_idx_addr,
            c: F::from_canonical_usize(0),
            d: as_register,
            e: as_native,
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
            d: as_register,
            e: as_register,
            f: F::from_canonical_usize(0),
            g: F::from_canonical_usize(0),
        },
        Instruction::<F> {
            opcode: VmOpcode::with_default_offset(BaseAluOpcode::ADD),
            a: F::from_canonical_usize(X31 * 4),
            b: F::from_canonical_usize(X31 * 4),
            c: F::from_canonical_usize(X31 * 4),
            d: as_register,
            e: as_register,
            f: F::from_canonical_usize(0),
            g: F::from_canonical_usize(0),
        },
        Instruction::<F> {
            opcode: VmOpcode::with_default_offset(BaseAluOpcode::ADD),
            a: F::from_canonical_usize(X31 * 4),
            b: F::from_canonical_usize(X31 * 4),
            c: F::from_canonical_usize(X29 * 4),
            d: as_register,
            e: as_register,
            f: F::from_canonical_usize(0),
            g: F::from_canonical_usize(0),
        },
        Instruction::<F> {
            opcode: VmOpcode::with_default_offset(Rv32LoadStoreOpcode::STOREW),
            a: F::from_canonical_usize(X30 * 4),
            b: F::from_canonical_usize(X31 * 4),
            c: F::from_canonical_usize(0),
            d: as_register,
            e: as_mem,
            f: F::from_canonical_usize(0),
            g: F::from_canonical_usize(0),
        },
    ]
}

fn verify_root() {
    let agg_pk = read_agg_pk_from_file(DEFAULT_AGG_PK_PATH).expect("invalid pk file");
        
    let prover = RootVerifierLocalProver::new(agg_pk.agg_stark_pk.root_verifier_pk);

    let path = "/home/ubuntu/zzhang/openvm-aggregation/factor-example/root_input.in";
    let bytes = std::fs::read(path).unwrap();
    let input: RootVmVerifierInput<BabyBearPoseidon2Config> = bitcode::deserialize(&bytes).unwrap();
    //input.proofs[0].commitments.
    println!("height {:?}", prover.execute_for_air_heights(input.clone()));
    let proof = SingleSegmentVmProver::prove(&prover, input.write());
}

fn dump_root_program() {
    // load from root_exe.bin if exist, otherwise load from pk
    let path  = "/home/ubuntu/zzhang/openvm-aggregation/program.bin";
    let load_from_pk = std::fs::metadata(path).is_err();
    let root_exe = if load_from_pk {
        println!("reading pk from {:?}, need minutes", DEFAULT_AGG_PK_PATH);
        let agg_pk = read_agg_pk_from_file(DEFAULT_AGG_PK_PATH).expect("invalid pk file");
        //let leaf_commitment = &agg_pk.agg_stark_pk.leaf_vm_pk.vm_pk.;
        let root_exe = &agg_pk.agg_stark_pk.root_verifier_pk.root_committed_exe;
        let root_exe = &root_exe.exe;//.program;
        //let bytes = bitcode::serialize(&root_exe).expect("serialize");
        //std::fs::write("root_exe.bin", bytes).expect("fail to write");
        root_exe.clone()
    } else {
        let data = std::fs::read(path).unwrap();
        bitcode::deserialize(&data).unwrap()
    };

    //println!("root program: {}", root_program.program);
    let mut program = root_exe.program.clone();
    println!(
        "total ins count: {}, {}",
        program.instructions_and_debug_infos.len(),
        program.defined_instructions().len(),
    );
    std::fs::write("program.txt", format!("{}", program)).expect("fail to write");
    
    let as_native = F::from_canonical_usize(5);

    let op_publish = VmOpcode::with_default_offset(PublishOpcode::PUBLISH).as_usize();
    let op_hintstore = VmOpcode::with_default_offset(NativeLoadStoreOpcode::SHINTW).as_usize();
    let op_phantom = VmOpcode::with_default_offset(PHANTOM).as_usize();
    let op_jal = VmOpcode::with_default_offset(NativeJalOpcode::JAL).as_usize();
    let op_beq = VmOpcode::with_default_offset(NativeBranchEqualOpcode(BranchEqualOpcode::BEQ)).as_usize();
    let op_bne = VmOpcode::with_default_offset(NativeBranchEqualOpcode(BranchEqualOpcode::BNE)).as_usize();

    let mut new_instructions_and_debug_infos: Vec<(Option<(Instruction<F>, Option<openvm_instructions::instruction::DebugInfo>)>, usize)> = vec![];
    let mut hint_bits_mode = false;
    let mut hint_bits_counter_limit = 0;
    let mut hint_bits_counter = 0;
    for (idx, op_elem) in program.instructions_and_debug_infos.iter().enumerate() {
        if let Some(op) = op_elem.as_ref() {
            if op.0.opcode.as_usize() == op_publish {
                let instructions = convert_publish(op.0.clone());
                new_instructions_and_debug_infos.extend(
                    instructions.iter().enumerate().map(|(inner_idx,x)| 
                            (Some((x.clone(), None)), idx * 4)
                        ),
                );
                continue;
            }
            if op.0.opcode.as_usize() == op_phantom {
                if op.0.c.as_canonical_u32() as usize == NativePhantom::HintInput as usize {
                    // as nop
                    let instructions = print_native(F::from_canonical_usize(A0 as usize));
                    new_instructions_and_debug_infos.extend(
                        instructions.iter().map(|x| (Some((x.clone(), None)), idx * 4))
                    );
                    continue;
                }
                if op.0.c.as_canonical_u32() as usize == ((as_native.as_canonical_u32() as usize) << 16 | (NativePhantom::HintBits as usize)) {
                    hint_bits_mode = true;
                    hint_bits_counter = 0;
                    hint_bits_counter_limit = op.0.b.as_canonical_u32() as usize;
                    new_instructions_and_debug_infos.push((op_elem.clone(), idx * 4));
                    continue;
                }
            }
            if op.0.opcode.as_usize() == op_hintstore {
                if hint_bits_mode {
                    new_instructions_and_debug_infos.push((op_elem.clone(), idx * 4));
                    hint_bits_counter += 1;
                    println!("in hint bits mode, counter: {}, limit {}", hint_bits_counter, hint_bits_counter_limit);
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

    // 
    // fix jump and pc
    // step1: for all jal, collect the old_pc=>new_pc mapping

    // idx=>correct pc
    let mut pc_rewrite = vec![];
    for (idx, op_elem) in new_instructions_and_debug_infos.iter().enumerate() {
        if let Some(op) = &op_elem.0 {
            if op.0.opcode.as_usize() == op_jal  ||
                op.0.opcode.as_usize() == op_beq ||
                op.0.opcode.as_usize() == op_bne
            {
                let old_pc_diff = if op.0.opcode.as_usize() == op_jal {
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
                            pc_rewrite.push((idx, new_pc_diff, if op.0.opcode.as_usize() == op_jal {
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

    program.instructions_and_debug_infos = new_instructions_and_debug_infos.into_iter().map(|x| x.0).collect();

    if let Some(0) = program.instructions_and_debug_infos.last().unwrap()
    .as_ref()
    .map(|x| x.0.opcode.as_usize()) {
        program.instructions_and_debug_infos.pop();
    }

    
    std::fs::write("program2.txt", format!("{}", program)).expect("fail to write");
    
    post_process_and_write(program, "root.u32s");
    println!("write root.u32s done");
}


fn post_process_and_write(mut program: Program<F>, path: &str) {
    let pc_diff = handle_pc_diff(&mut program);
    let assembly_and_comments = convert_program_to_u32s(&program, pc_diff);
    let mut asm_output = String::new();
    for (u32s, comment) in &assembly_and_comments {
        for (idx, x) in u32s.iter().enumerate() {
            asm_output.push_str(&u32_to_directive(*x));
            if idx == 0 {
                asm_output.push_str(" // ");
                asm_output.push_str(comment);
            }
            asm_output.push_str("\n");
        }
    }
    std::fs::write(path, asm_output).expect("fail to write");
}
/*
fn dump_protocol() {
    use openvm_native_recursion::halo2::{
    utils::Halo2ParamsReader, CacheHalo2ParamsReader, Halo2Params,
};
    println!("reading pk from {:?}, need minutes", DEFAULT_AGG_PK_PATH);
    let agg_pk = read_agg_pk_from_file(DEFAULT_AGG_PK_PATH).expect("invalid pk file");

    let wrapper_k = agg_pk.halo2_pk.wrapper.pinning.metadata.config_params.k;
    let num_instance = agg_pk.halo2_pk.wrapper.pinning.metadata.num_pvs.clone();
    println!("wrapper_k: {:?}", wrapper_k);

    let params_reader = CacheHalo2ParamsReader::new(DEFAULT_PARAMS_DIR);
    let params = params_reader.read_params(wrapper_k);
    println!("read params done");
    let params: &Halo2Params = &params;
    let protocol = compile(
        params,
        agg_pk.halo2_pk.wrapper.pinning.pk.get_vk(),
        Config::kzg()
            .with_num_instance(num_instance)
            .with_accumulator_indices(AggregationCircuit::accumulator_indices()),
    );
    let bytes = bitcode::serialize(&protocol).expect("serialize");
    std::fs::write("protocol.bin", bytes).expect("fail to write");
    println!("protocol compiled and saved to protocol.bin");
}
*/

#[derive(Clone, Deserialize, Serialize)]
pub struct EvmProof {
    pub instances: Vec<Vec<Fr>>,
    pub proof: Vec<u8>,
}
use halo2curves_axiom::bn256::Fr;
fn parse_root_proof() {
    let input_stream: std::collections::VecDeque<Vec<F>> = bitcode::deserialize(include_bytes!("/home/ubuntu/zzhang/openvm-aggregation/input.stream")).expect("decode");

    let mut flatten_input: Vec<u32> = Vec::new();
    for (idx, x) in input_stream.into_iter().enumerate() {
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
fn parse_evm_proof() {
    let evm_proof_bytes =
        std::fs::read("/home/ubuntu/zzhang/openvm-aggregation/factor-example/openvm/evm.proof")
            .unwrap();
    let proof: EvmProof = bitcode::deserialize(&evm_proof_bytes).expect("decode proof");

    println!("instance[0][12] {:?}", proof.instances[0][12]); // exe commit
    println!("instance[0][13] {:?}", proof.instances[0][13]); // app_pk commit
    println!("instance[0][14] {:?}", proof.instances[0][14]); // first real public input

    let commitments = [
        833353020u32,
        442029907,
        658416486,
        1809536565,
        186991987,
        736248086,
        1811913050,
        939375660,
    ]
    .map(F::from_canonical_u32);
    let comm2 = [
        977564024u32,
        866334407,
        987273333,
        1264821797,
        1791688428,
        80262598,
        1774555478,
        1236902767,
    ]
    .map(F::from_canonical_u32);
    println!("commitments {:?}", babybear_digest_to_bn254(&commitments));
    println!("commitments2 {:?}", babybear_digest_to_bn254(&comm2));
}
fn main() {
    //verify_root();
    dump_root_program();
    //parse_root_proof();
}
