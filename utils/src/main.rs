
use std::sync::Arc;

use openvm_sdk::{fs::read_agg_pk_from_file, F, 
    commit::babybear_digest_to_bn254,
    verifier::root::types::RootVmVerifierInput};
use snark_verifier_sdk::{
    halo2::aggregation::AggregationCircuit,
    snark_verifier::system::halo2::{compile, Config},
    CircuitExt,
};
use serde::{Deserialize, Serialize};
use openvm_stark_sdk::{
    config::{
        baby_bear_poseidon2::{BabyBearPoseidon2Config}}};
use p3_field::{PrimeField32,FieldAlgebra};
use openvm_instructions::{VmOpcode, instruction::Instruction, PhantomDiscriminant};
use openvm_instructions::program::Program;

pub const DEFAULT_AGG_PK_PATH: &str = concat!(env!("HOME"), "/.openvm/agg.pk");
fn load_a0_to_native(edsl_fp: usize) -> Vec<Instruction<F>> {


    let as_imm = F::from_canonical_usize(0);
    let as_native = F::from_canonical_usize(5);
    let as_register = F::from_canonical_usize(1);

    let dst = F::from_canonical_usize(edsl_fp);
    let zero = F::from_canonical_usize(0);

    let op_add = VmOpcode::from_usize(0x130);
    let op_mul = VmOpcode::from_usize(0x132);

    let add_op = |(b, as_b), (c, as_c)| {
            Instruction::<F> {
                opcode: op_add,
                a: dst,
                b: b,
                c: F::from_canonical_usize(c),
                d: as_native,
                e: as_b,
                f: as_c,
                g: F::from_canonical_usize(0),
            }
    };
    let shift_op = || {
            Instruction::<F> {
                opcode: op_mul,
                a: dst,
                b: dst,
                c: F::from_canonical_usize(256),
                d: as_native,
                e: as_native,
                f: as_imm,
                g: F::from_canonical_usize(0),
            }
    };
    // assign x10 to dst
    // little endian
    let x10 = 40; // x10 is a0
    [

    Instruction::<F>::phantom(
        PhantomDiscriminant(0x10 as u16), // print
        F::from_canonical_usize(40), // x10
        F::from_canonical_usize(0),
        1,
    ),
    Instruction::<F>::phantom(
        PhantomDiscriminant(0x10 as u16), // print
        dst,
        F::from_canonical_usize(0),
        5,
    ),
        add_op((zero, as_imm), (x10 + 3, as_register)),
        Instruction::<F>::phantom(
            PhantomDiscriminant(0x10 as u16), // print
            dst,
            F::from_canonical_usize(0),
            5,
        ),
        shift_op(),
        Instruction::<F>::phantom(
            PhantomDiscriminant(0x10 as u16), // print
            dst,
            F::from_canonical_usize(0),
            5,
        ),
        Instruction::<F>::phantom(
            PhantomDiscriminant(0x10 as u16), // print
            F::from_canonical_usize(41), // x10
            F::from_canonical_usize(0),
            1,
        ),
        add_op((dst, as_native), (x10 + 2, as_register)),

        Instruction::<F>::phantom(
            PhantomDiscriminant(0x10 as u16), // print
            dst,
            F::from_canonical_usize(0),
            5,
        ),
        shift_op(),
        Instruction::<F>::phantom(
            PhantomDiscriminant(0x10 as u16), // print
            dst,
            F::from_canonical_usize(0),
            5,
        ),
        add_op((dst, as_native), (x10 + 1, as_register)),
        Instruction::<F>::phantom(
            PhantomDiscriminant(0x10 as u16), // print
            dst,
            F::from_canonical_usize(0),
            5,
        ),
        shift_op(),
        Instruction::<F>::phantom(
            PhantomDiscriminant(0x10 as u16), // print
            dst,
            F::from_canonical_usize(0),
            5,
        ),
        add_op((dst, as_native), (x10, as_register)),
        Instruction::<F>::phantom(
            PhantomDiscriminant(0x10 as u16), // print
            dst,
            F::from_canonical_usize(0),
            5,
        ),
    ].into()
}

fn handle_pc_diff(program: &mut Program<F>) -> usize { 
    let mut pc_diff = 2;
    for op in &program.defined_instructions() {
        pc_diff += 1 + 1 + 7; // don't skip unused operands
    }
    pc_diff += 9; // for next jal
    let jal = Instruction::<F> {
        opcode: VmOpcode::from_usize(0x115),
        a: F::from_canonical_usize(1<<24 - 8), // A0
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

fn dump_root_program() {
    let load_from_pk = true;
    let root_program = if load_from_pk {
        println!("reading pk from {:?}, need minutes", DEFAULT_AGG_PK_PATH);
        let agg_pk = read_agg_pk_from_file(DEFAULT_AGG_PK_PATH).expect("invalid pk file");
        //let leaf_commitment = &agg_pk.agg_stark_pk.leaf_vm_pk.vm_pk.;
        let root_exe = &agg_pk.agg_stark_pk.root_verifier_pk.root_committed_exe;
        let root_program = &root_exe.exe;
        let bytes = bitcode::serialize(&root_program).expect("serialize");
        std::fs::write("root.program", bytes).expect("fail to write");
        root_program.clone()
    } else {
        let path = "/home/ubuntu/zzhang/openvm-aggregation/factor-example/root_committed_exe.bin";
        let data = std::fs::read(path).unwrap();
        bitcode::deserialize(&data).unwrap()
    };

    //println!("root program: {}", root_program.program);
    let mut program = root_program.program.clone();
    println!("total ins count: {}", program.instructions_and_debug_infos.len());
    let mut idx = 0;
    while idx < program.instructions_and_debug_infos.len() {
        if let Some(op) = program.instructions_and_debug_infos[idx].as_ref() {
            if op.0.opcode.as_usize() == 288 { // 288 is publish
                idx -= 1; // IMM
                break; 
            }
        }
        idx += 1;
    }
    println!("idx: {}", idx);
    println!("op {:?}", program.instructions_and_debug_infos[idx]);
    let fp = program.instructions_and_debug_infos[idx].as_ref().unwrap().0.c;
    println!("fp {}", fp);
    let mut instructions = load_a0_to_native(fp.as_canonical_u32() as usize);
    // replace program.instructions_and_debug_infos[idx] with instructions
    program.instructions_and_debug_infos.splice(idx..idx+1, instructions.iter().map(|x| Some((x.clone(), None))));
    idx += instructions.len();
    assert_eq!(program.instructions_and_debug_infos[idx].as_ref().unwrap().0.opcode.as_usize(), 288);
    while idx < program.instructions_and_debug_infos.len() {
        if let Some(op) = program.instructions_and_debug_infos[idx].as_ref() {
            match op.0.opcode.as_usize()
             {
                304 => {

                // ADD
                let mut op = program.instructions_and_debug_infos[idx].clone().unwrap();
                op.0.c = F::from_canonical_usize(4);
                program.instructions_and_debug_infos.splice(idx..idx+1, [op.0].iter().map(|x| Some((x.clone(), None))));
            },
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
                    Instruction::<F>::phantom(
                        PhantomDiscriminant(0x10 as u16), // print
                        mem_addr,
                        F::from_canonical_usize(0),
                        5,
                    ),
                    // print x11
                    Instruction::<F>::phantom(
                        PhantomDiscriminant(0x10 as u16), 
                        F::from_canonical_usize(x11),
                        F::from_canonical_usize(0),
                        1,
                    ),
                    Instruction::<F>::phantom(
                        PhantomDiscriminant(0x10 as u16), 
                        F::from_canonical_usize(45),
                        F::from_canonical_usize(0),
                        1,
                    ),
                    Instruction::<F>::phantom(
                        PhantomDiscriminant(0x10 as u16), 
                        F::from_canonical_usize(46),
                        F::from_canonical_usize(0),
                        1,
                    ),
                    Instruction::<F>::phantom(
                        PhantomDiscriminant(0x10 as u16), 
                        F::from_canonical_usize(47),
                        F::from_canonical_usize(0),
                        1,
                    ),
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
                    Instruction::<F>::phantom(
                        PhantomDiscriminant(0x10 as u16), 
                        F::from_canonical_usize(48),
                        F::from_canonical_usize(0),
                        1,
                    ),
                    Instruction::<F>::phantom(
                        PhantomDiscriminant(0x10 as u16), 
                        F::from_canonical_usize(49),
                        F::from_canonical_usize(0),
                        1,
                    ),
                    Instruction::<F>::phantom(
                        PhantomDiscriminant(0x10 as u16), 
                        F::from_canonical_usize(50),
                        F::from_canonical_usize(0),
                        1,
                    ),
                    Instruction::<F>::phantom(
                        PhantomDiscriminant(0x10 as u16), 
                        F::from_canonical_usize(51),
                        F::from_canonical_usize(0),
                        1,
                    ),
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
                    Instruction::<F>::phantom(
                        PhantomDiscriminant(0x10 as u16), // print
                        F::from_canonical_usize(2097800), // the slot..
                        F::from_canonical_usize(0),
                        2,
                    ),
                    // print mem
                    //Instruction::<F>::phantom(
                    //    PhantomDiscriminant(0x10 as u16), 
                    //    F::from_canonical_usize(x11),
                    //    F::from_canonical_usize(0),
                    //    1,
                    //)
                    ];
                    program.instructions_and_debug_infos.splice(idx..idx+1, instructions.iter().map(|x| Some((x.clone(), None))));
    
            }
            _ => {},
        }
    }
        idx += 1;
    }
    idx -= 1;
    // halt
    assert_eq!(program.instructions_and_debug_infos[idx].as_ref().map(|x| x.0.opcode.as_usize()), Some(0));
    // remove last elem of program.instructions_and_debug_infos
    program.instructions_and_debug_infos.pop();

    let pc_diff = handle_pc_diff(&mut program);
    let u32s = convert_program_to_u32s(&program, pc_diff);
    let mut u32s_str = String::new();
    for x in u32s {
        u32s_str.push_str(&u32_to_directive(x));
        u32s_str.push_str("\n");
    }
    std::fs::write("root.u32s", u32s_str).expect("fail to write");
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
use halo2curves_axiom::bn256::{Fr};
fn parse_proof() {

    let path = "/home/ubuntu/zzhang/openvm-aggregation/factor-example/root_input.in";
    let bytes = std::fs::read(path).unwrap();
    let input: RootVmVerifierInput<BabyBearPoseidon2Config>  = bitcode::deserialize(&bytes).unwrap();
    //input.proofs[0].commitments.
    println!("pi {:?}", input.public_values);


    let evm_proof_bytes = std::fs::read("/home/ubuntu/zzhang/openvm-aggregation/factor-example/openvm/evm.proof").unwrap();
    let proof: EvmProof =
        bitcode::deserialize(&evm_proof_bytes)
            .expect("decode proof");

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
        939375660
    ].map(F::from_canonical_u32);
    let comm2 = [977564024u32
    , 866334407
    , 987273333
    , 1264821797
    , 1791688428
    , 80262598
    , 1774555478
    , 1236902767].map(F::from_canonical_u32);
    println!("commitments {:?}", babybear_digest_to_bn254(&commitments));
    println!("commitments2 {:?}", babybear_digest_to_bn254(&comm2));

}
fn main() {
    dump_root_program();
    //parse_proof();
}
