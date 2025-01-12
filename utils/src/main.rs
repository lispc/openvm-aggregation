use std::sync::Arc;

use openvm_instructions::program::Program;
use openvm_instructions::{
    instruction::{self, Instruction},
    PhantomDiscriminant, VmOpcode,
};
use openvm_sdk::{
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
    // print x11
    vec![
    Instruction::<F>::phantom(
        PhantomDiscriminant(0x10 as u16),
        F::from_canonical_usize(4*register_idx),
        F::from_canonical_usize(0),
        1,
    ),
    Instruction::<F>::phantom(
        PhantomDiscriminant(0x10 as u16),
        F::from_canonical_usize(4*register_idx+1),
        F::from_canonical_usize(0),
        1,
    ),
    Instruction::<F>::phantom(
        PhantomDiscriminant(0x10 as u16),
        F::from_canonical_usize(4*register_idx+2),
        F::from_canonical_usize(0),
        1,
    ),
    Instruction::<F>::phantom(
        PhantomDiscriminant(0x10 as u16),
        F::from_canonical_usize(4*register_idx+3),
        F::from_canonical_usize(0),
        1,
    )]
}

fn load_a0_to_native(edsl_fp: usize) -> Vec<Instruction<F>> {
    let as_imm = F::from_canonical_usize(0);
    let as_native = F::from_canonical_usize(5);
    let as_register = F::from_canonical_usize(1);

    let dst = F::from_canonical_usize(edsl_fp);
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
    // assign x10 to dst
    // little endian
    let x10 = 40; // x10 is a0
    [
        add_op((zero, as_imm), (x10 + 3, as_register)),
        shift_op(),
        add_op((dst, as_native), (x10 + 2, as_register)),
        shift_op(),
        add_op((dst, as_native), (x10 + 1, as_register)),
        shift_op(),
        add_op((dst, as_native), (x10, as_register)),
    ]
    .into()
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
        ".insn i {}, {}, x{}, x{}, {} // {}",
        opcode, funct3, rd, rs1, simm12, x
    )
}

const OPCODE: u32 = 0x0b;
const FUNCT3: u32 = 0b111;
pub const LONG_FORM_INSTRUCTION_INDICATOR: u32 = (FUNCT3 << 12) + OPCODE;
pub const GAP_INDICATOR: u32 = (1 << 25) + (FUNCT3 << 12) + OPCODE;

fn convert_program_to_u32s(program: &Program<F>, pc_diff: usize) -> Vec<u32> {
    let mut u32s = Vec::new();
    for ins in &program.defined_instructions() {
        u32s.push(LONG_FORM_INSTRUCTION_INDICATOR);
        u32s.push(7);
        u32s.push(ins.opcode.as_usize() as u32);
        u32s.push(ins.a.as_canonical_u32());
        u32s.push(ins.b.as_canonical_u32());
        u32s.push(ins.c.as_canonical_u32());
        u32s.push(ins.d.as_canonical_u32());
        u32s.push(ins.e.as_canonical_u32());
        u32s.push(ins.f.as_canonical_u32());
        u32s.push(ins.g.as_canonical_u32());
    }
    u32s.push(GAP_INDICATOR);
    u32s.push(pc_diff as u32);
    u32s
}

fn dump_simple_program() {
    let as_imm = F::from_canonical_usize(0);
    let as_native = F::from_canonical_usize(5);
    let as_register = F::from_canonical_usize(1);
    let as_mem = F::from_canonical_usize(2);

    // output_buf[0] = output_buf as u32;
    // copy x10 into native[addr1]
    let native_addr = F::from_canonical_usize(16776511usize);
    let mut instructions = Vec::new();
    let mut part1 = load_a0_to_native(native_addr.as_canonical_u32() as usize);
    instructions.append(&mut part1);
    // then copy the value inside x10 back to mem[x10]
    let mut part2 = vec![
        // castf native[native_addr] to x11
        Instruction::<F> {
            opcode: VmOpcode::from_usize(0x125), // 293, castf
            a: F::from_canonical_usize(44),
            b: native_addr,
            c: F::from_canonical_usize(0),
            d: as_register,
            e: as_native,
            f: F::from_canonical_usize(0),
            g: F::from_canonical_usize(0),
        },
        Instruction::<F> {
            opcode: VmOpcode::from_usize(0x125), // 293, castf
            a: F::from_canonical_usize(48),
            b: native_addr,
            c: F::from_canonical_usize(0),
            d: as_register,
            e: as_native,
            f: F::from_canonical_usize(0),
            g: F::from_canonical_usize(0),
        },
        Instruction::<F> {
            opcode: VmOpcode::from_usize(0x213), // riscv, storew
            a: F::from_canonical_usize(44),
            b: F::from_canonical_usize(48),
            // another method, instead of inc "mem_addr", is that we set c to 0,1,2,..48?
            c: F::from_canonical_usize(0),
            d: as_register,
            e: as_mem,
            f: F::from_canonical_usize(0),
            g: F::from_canonical_usize(0),
        },
    ];
    instructions.append(&mut part2);
    let mut program = Program::<F>::from_instructions(&instructions);
    post_process_and_write(program, "simple.u32s");
}

fn dump_root_program() {
    // load from root_exe.bin if exist, otherwise load from pk
    let load_from_pk = std::fs::metadata("root_exe.bin").is_err();
    let root_exe = if load_from_pk {
        println!("reading pk from {:?}, need minutes", DEFAULT_AGG_PK_PATH);
        let agg_pk = read_agg_pk_from_file(DEFAULT_AGG_PK_PATH).expect("invalid pk file");
        //let leaf_commitment = &agg_pk.agg_stark_pk.leaf_vm_pk.vm_pk.;
        let root_exe = &agg_pk.agg_stark_pk.root_verifier_pk.root_committed_exe;
        let root_exe = &root_exe.exe;
        let bytes = bitcode::serialize(&root_exe).expect("serialize");
        std::fs::write("root_exe.bin", bytes).expect("fail to write");
        root_exe.clone()
    } else {
        let path = "root_exe.bin";
        let data = std::fs::read(path).unwrap();
        bitcode::deserialize(&data).unwrap()
    };

    //println!("root program: {}", root_program.program);
    let mut program = root_exe.program.clone();
    println!(
        "total ins count: {}",
        program.instructions_and_debug_infos.len()
    );

    /* 
    let predicate_check_publish = |op: &Instruction<F>| match op.opcode.as_usize() {
        288 => true,
        _ => false,
    };

    // remove all instructions inside program until `predicate_check_publish` is true
    // FIXME
    while !program.instructions_and_debug_infos.is_empty() {
        if let Some(op) = program.instructions_and_debug_infos[1].as_ref() {
            if predicate_check_publish(&op.0) {
                break;
            }
        }
        program.instructions_and_debug_infos.remove(0);
    }
    */

    let mut idx = 0;
    while idx < program.instructions_and_debug_infos.len() {
        if let Some(op) = program.instructions_and_debug_infos[idx].as_ref() {
            if op.0.opcode.as_usize() == 288 {
                // 288 is publish
                idx -= 1; // IMM
                break;
            }
        }
        idx += 1;
    }
    println!("idx: {}", idx);
    println!("op {:?}", program.instructions_and_debug_infos[idx]);

    // remove program.instructions_and_debug_infos[0..idx]
    //program.instructions_and_debug_infos.drain(0..idx);
    //idx = 0;
    assert_eq!(
        program.instructions_and_debug_infos[idx]
            .as_ref()
            .unwrap()
            .0
            .opcode
            .as_usize(),
        257 // imm
    );
    let fp = program.instructions_and_debug_infos[idx]
        .as_ref()
        .unwrap()
        .0
        .c;
    println!("fp {}", fp);
    let mut instructions = load_a0_to_native(fp.as_canonical_u32() as usize);
    //instructions.clear();
    // replace program.instructions_and_debug_infos[idx] with instructions
    program.instructions_and_debug_infos.splice(
        idx..idx + 1,
        instructions.iter().map(|x| Some((x.clone(), None))),
    );
    idx += instructions.len();
    
    assert_eq!(
        program.instructions_and_debug_infos[idx]
            .as_ref()
            .unwrap()
            .0
            .opcode
            .as_usize(),
        288 // publish
    );
    let debug = false;
    let mut add_cnt = 0;
    while idx < program.instructions_and_debug_infos.len() {
        if let Some(op) = program.instructions_and_debug_infos[idx].as_ref() {
            match op.0.opcode.as_usize() {
                304 => {
                    // ADD
                    let mut op = program.instructions_and_debug_infos[idx].clone().unwrap();
                    op.0.c = F::from_canonical_usize(4);
                    let mut to_replace = vec![op.0];
                    //to_replace.clear();
                    program
                        .instructions_and_debug_infos
                        .splice(idx..idx + 1, to_replace.iter().map(|x| Some((x.clone(), None))));
                    //idx -= 1; // FIXME
                    add_cnt += 1;
                    if add_cnt >= 3  {
                        //break;
                    }
                }
                288 => {
                    // VmOpcode(288) 0 16776149 16776511 0 5 5 0
                    let as_imm = F::from_canonical_usize(0);
                    let as_native = F::from_canonical_usize(5);
                    let as_register = F::from_canonical_usize(1);
                    let as_mem = F::from_canonical_usize(2);
                    let x11 = 44; // x11 is a1

                    let mem_addr = op.0.c;
                    assert_eq!(mem_addr, fp);
                    let instructions = vec![
                        // castf native[op.0.b] to x11
                        Instruction::<F> {
                            opcode: VmOpcode::from_usize(0x125), // 293, castf
                            a: F::from_canonical_usize(x11),
                            b: op.0.b,
                            c: F::from_canonical_usize(0),
                            d: as_register,
                            e: as_native,
                            f: F::from_canonical_usize(0),
                            g: F::from_canonical_usize(0),
                        },
                        // copy "mem_addr" to x12
                        
                        Instruction::<F> {
                            opcode: VmOpcode::from_usize(0x125), // 293, castf
                            a: F::from_canonical_usize(48),
                            b: mem_addr,
                            c: F::from_canonical_usize(0),
                            d: as_register,
                            e: as_native,
                            f: F::from_canonical_usize(0),
                            g: F::from_canonical_usize(0),
                        },
                        
                        // storew x11 to mem[x12]
                        
                        Instruction::<F> {
                            opcode: VmOpcode::from_usize(0x213), // riscv, storew
                            a: F::from_canonical_usize(x11),
                            b: F::from_canonical_usize(48),
                            // another method, instead of inc "mem_addr", is that we set c to 0,1,2,..48?
                            c: F::from_canonical_usize(0),
                            d: as_register,
                            e: as_mem,
                            f: F::from_canonical_usize(0),
                            g: F::from_canonical_usize(0),
                        },
                        
                    ];
                    program.instructions_and_debug_infos.splice(
                        idx..idx + 1,
                        instructions.iter().map(|x| Some((x.clone(), None))),
                    );
                    // TODO: better fix the idx
                }
                _ => {}
            }
        }
        idx += 1;
    }
    let adhoc = false;
    if !adhoc {
        idx -= 1; // switch to HALT
        // halt
        assert_eq!(
            program.instructions_and_debug_infos[idx]
                .as_ref()
                .map(|x| x.0.opcode.as_usize()),
            Some(0)
        );
        // remove last elem of program.instructions_and_debug_infos
        program.instructions_and_debug_infos.pop();
    } else {
        // discard all instructions after idx
        program.instructions_and_debug_infos.truncate(idx + 1);
        //program.instructions_and_debug_infos.remove(0);
        /* 
        assert_eq!(
            program.instructions_and_debug_infos[idx]
                .as_ref()
                .map(|x| x.0.opcode.as_usize()),
            Some(304)
        );
        */
        //assert_eq!(program.instructions_and_debug_infos.len(), 19);
        // delete program.instructions_and_debug_infos[12..=15]
        //program.instructions_and_debug_infos.drain(12..16);
    }

    //println!("program {}", program);
    post_process_and_write(program, "root.u32s");
}

fn test_bug_program() {
    let ins = 
        Instruction::<F> {
            opcode: VmOpcode::from_usize(0x125), // 293, castf
            a: F::from_canonical_usize(44),
            b: F::from_canonical_usize(16775748),
            c: F::from_canonical_usize(0),
            d: F::from_canonical_usize(1),
            e: F::from_canonical_usize(5),
            f: F::from_canonical_usize(0),
            g: F::from_canonical_usize(0),
        };
    let repeat_n = 2;
    let ins_vec = vec![ins; repeat_n];
    let program = Program::<F>::from_instructions(&ins_vec);
    println!("program {}", program);
    post_process_and_write(program, "bug.u32s");
}

fn post_process_and_write(mut program: Program<F>, path: &str) {
    let pc_diff = handle_pc_diff(&mut program);
    let u32s = convert_program_to_u32s(&program, pc_diff);
    let mut u32s_str = String::new();
    for x in u32s {
        u32s_str.push_str(&u32_to_directive(x));
        u32s_str.push_str("\n");
    }
    std::fs::write(path, u32s_str).expect("fail to write");
    // let us do the jal and pc diff trick
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
fn parse_proof() {
    let path = "/home/ubuntu/zzhang/openvm-aggregation/factor-example/root_input.in";
    let bytes = std::fs::read(path).unwrap();
    let input: RootVmVerifierInput<BabyBearPoseidon2Config> = bitcode::deserialize(&bytes).unwrap();
    //input.proofs[0].commitments.
    println!("pi {:?}", input.public_values);

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
    //dump_simple_program();
    dump_root_program();
    //test_bug_program();
    //parse_proof();
}
