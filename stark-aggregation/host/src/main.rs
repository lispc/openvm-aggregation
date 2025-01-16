use openvm_sdk::{
    config::{AppConfig, SdkVmConfig},
    fs::{read_exe_from_file, read_root_proof_from_file},
    verifier::root::types::RootVmVerifierInput,
    Sdk, StdIn,
};

use openvm_native_recursion::hints::Hintable;

use openvm_stark_sdk::config::baby_bear_poseidon2::BabyBearPoseidon2Config;
use openvm_stark_sdk::openvm_stark_backend::p3_field::PrimeField32;

fn run_test() {
    let exe = read_exe_from_file("./stark-aggregation/guest/openvm/app.vmexe").unwrap();
    let toml = std::fs::read_to_string("./stark-aggregation/guest/openvm.toml").unwrap();
    let app_config: AppConfig<SdkVmConfig> = toml::from_str(&toml).unwrap();

    let stdin = {
        let root_proof_bytes: RootVmVerifierInput<BabyBearPoseidon2Config> =
            read_root_proof_from_file("factor-example/openvm/root.proof")
                .expect("fail to read proof");
        let steams = root_proof_bytes.write();

        let mut flatten_input: Vec<u32> = Vec::new();
        for x in &steams {
            flatten_input.push(x.len() as u32);
            for f in x {
                flatten_input.push(f.as_canonical_u32());
            }
        }
        let flatten_input_bytes = bitcode::serialize(&flatten_input).unwrap();

        std::fs::write(
            "factor-example/openvm/flatten-root.proof",
            flatten_input_bytes.clone(),
        )
        .expect("fail to write");
        StdIn::from_bytes(&flatten_input_bytes)
    };
    let output = Sdk.execute(exe, app_config.app_vm_config, stdin).unwrap();
    println!("Execution output: {:?}", output);
}

fn main() {
    run_test();
}
