use std::fmt::format;
use std::sync::Arc;

use openvm_instructions::program::Program;
use openvm_instructions::{
    instruction::{self, Instruction},
    PhantomDiscriminant, PublishOpcode,
    SystemOpcode::{PHANTOM, TERMINATE},
    VmOpcode,
};
use openvm_native_compiler::{CastfOpcode, NativeJalOpcode};
use openvm_rv32im_transpiler::{BaseAluOpcode, Rv32LoadStoreOpcode, MulOpcode};
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
    [
        add_op((zero, as_imm), (4 * register_idx + 3, as_register)),
        shift_op(),
        add_op((dst, as_native), (4 * register_idx + 2, as_register)),
        shift_op(),
        add_op((dst, as_native), (4 * register_idx + 1, as_register)),
        shift_op(),
        add_op((dst, as_native), (4 * register_idx, as_register)),
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
    // x30: the pi value
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
        "total ins count: {}, {}",
        program.instructions_and_debug_infos.len(),
        program.defined_instructions().len(),
    );
    std::fs::write("program.txt", format!("{}", program)).expect("fail to write");
    
    let mut idx = 0;

    let op_publish = VmOpcode::with_default_offset(PublishOpcode::PUBLISH).as_usize();
    while idx < program.instructions_and_debug_infos.len() {
        if let Some(op) = program.instructions_and_debug_infos[idx].as_ref() {
            if op.0.opcode.as_usize() == op_publish {
                let instructions = convert_publish(op.0.clone());
                program.instructions_and_debug_infos.splice(
                    idx..idx + 1,
                    instructions.iter().map(|x| Some((x.clone(), None))),
                );
                idx += instructions.len() - 1;
            }
        };
        idx += 1;
    }

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

    //println!("program {}", program);
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
    dump_root_program();
    //parse_proof();
}
