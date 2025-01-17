use halo2curves_axiom::bn256::Fr as Bn254Fr;
use openvm::io::{read, read_vec, reveal};

openvm::entry!(main);


// will terminate inside if fail
fn exec_kernel(input: &[u32], expect_output: &[u32]) {
    let mut input_ptr: *const u32 = input.as_ptr();
    let mut output_ptr: *const u32 = expect_output.as_ptr();
    let mut buf1: u32 = 0;
    let mut buf2: u32 = 0;
    #[cfg(all(target_os = "zkvm", target_arch = "riscv32"))]
    unsafe {
        std::arch::asm!(
            include_str!("../../../root_verifier.asm"),
            inout("x28") input_ptr,
            inout("x29") output_ptr,
            inout("x30") buf1,
            inout("x31") buf2,
        )
    }
}


#[derive(serde::Deserialize)]
struct Input {
    flatten_proof: Vec<u32>,
    public_values: Vec<u32>,
}

fn main() {
    let raw_input: Vec<u8> = read_vec();
    let input: Input = bitcode::deserialize(&raw_input).expect("decode");

    println!("input.flatten_proof[..30]: {:?}", &input.flatten_proof[..30]);
    println!("input.public_values[..30]: {:?}", &input.public_values[..30]);
    let default_pi_len = 48;
    assert_eq!(input.public_values.len(), default_pi_len);
    exec_kernel(&input.flatten_proof, &input.public_values);

    // not needed. Just for display
    {
        let pi = &input.public_values;
        for i in 0..48 {
            println!("pi byte {}: {}", i, pi[i]);
        }
        let in1: [u32; 8] = pi[..8].try_into().unwrap();
        let in2: [u32; 8] = pi[8..16].try_into().unwrap();
        let digest1 = babybear_digest_to_bn254(&in1);
        let digest2 = babybear_digest_to_bn254(&in2);
        println!("digest1: {:?}", digest1);
        println!("digest2: {:?}", digest2);
    }
}


pub fn babybear_digest_to_bn254(digest: &[u32; 8]) -> Bn254Fr {
    let mut ret = Bn254Fr::from(0u64);

    let order = Bn254Fr::from(15u64 * (1 << 27) + 1);
    let mut base = Bn254Fr::from(1u64);
    digest.iter().for_each(|&x| {
        ret += base * Bn254Fr::from(x as u64);
        base *= order;
    });
    ret
}