use openvm_sdk::{
    commit::AppExecutionCommit, config::{AppConfig, SdkVmConfig}, fs::{read_app_pk_from_file, read_exe_from_file, read_root_proof_from_file}, keygen::AppProvingKey, verifier::root::types::RootVmVerifierInput, Sdk, StdIn
};

use openvm_native_recursion::hints::Hintable;

use openvm_stark_sdk::config::baby_bear_poseidon2::BabyBearPoseidon2Config;
use openvm_stark_sdk::openvm_stark_backend::p3_field::PrimeField32;

fn run_test() {
    let assets_dir = "./stark-aggregation/guest/openvm";
    let exe = read_exe_from_file(format!("{assets_dir}/app.vmexe")).unwrap();
    let exe_commitments = {

        let app_pk: AppProvingKey<SdkVmConfig> = read_app_pk_from_file(format!("{assets_dir}/app.pk")).unwrap();
        let committed_exe = Sdk.commit_app_exe(app_pk.app_fri_params(), exe.clone()).unwrap();

        let commits = AppExecutionCommit::compute(
            &app_pk.app_vm_pk.vm_config,
            &committed_exe,
            &app_pk.leaf_committed_exe,
        );
        println!("app_pk commit: {:?}", commits.app_config_commit_to_bn254());
        println!("exe commit: {:?}", commits.exe_commit_to_bn254());
        commits
    };
    let toml = std::fs::read_to_string("./stark-aggregation/guest/openvm.toml").unwrap();
    let app_config: AppConfig<SdkVmConfig> = toml::from_str(&toml).unwrap();

    let stdin = {
        #[derive(serde::Serialize)]
        struct Input {
            flatten_proof: Vec<u32>,
            public_values: Vec<u32>,
        }
        let root_proof_bytes: RootVmVerifierInput<BabyBearPoseidon2Config> =
            read_root_proof_from_file("factor-example/openvm/root.proof")
                .expect("fail to read proof");
        let full_proof_steams = root_proof_bytes.write();
        
        let mut flatten_input: Vec<u32> = Vec::new();
        for x in &full_proof_steams {
            flatten_input.push(x.len() as u32);
            for f in x {
                flatten_input.push(f.as_canonical_u32());
            }
        }
        let mut public_values = vec![];
        public_values.extend(exe_commitments.exe_commit.map(|x| x.as_canonical_u32()));
        public_values.extend(exe_commitments.leaf_vm_verifier_commit.map(|x| x.as_canonical_u32()));
        public_values.extend(root_proof_bytes.public_values.iter().map(|x| x.as_canonical_u32()));
        let input = Input {
            flatten_proof: flatten_input,
            public_values: public_values,
        };
        let flatten_input_bytes = bitcode::serialize(&input).unwrap();

        std::fs::write(
            "factor-example/openvm/flatten-input.proof",
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
