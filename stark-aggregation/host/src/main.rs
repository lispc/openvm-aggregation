use openvm_sdk::{
    commit::AppExecutionCommit,
    config::{AppConfig, SdkVmConfig},
    fs::{read_app_pk_from_file, read_exe_from_file, read_root_proof_from_file},
    keygen::AppProvingKey,
    verifier::root::types::RootVmVerifierInput,
    Sdk, StdIn,
};

use openvm_native_recursion::hints::Hintable;

use openvm_stark_sdk::{
    p3_baby_bear::BabyBear as F,
    config::baby_bear_poseidon2::BabyBearPoseidon2Config
};
use openvm_stark_sdk::openvm_stark_backend::p3_field::PrimeField32;

#[derive(serde::Serialize)]
struct FlattenRootProof {
    flatten_proof: Vec<u32>,
    public_values: Vec<u32>,
}

fn flatten_root_vm_verifier_input(root_proof: &RootVmVerifierInput<BabyBearPoseidon2Config>, exe_commit: [F; 8], leaf_commit: [F; 8]) -> FlattenRootProof {
    let full_proof_steams = root_proof.write();

        let mut flatten_input: Vec<u32> = Vec::new();
        for x in &full_proof_steams {
            flatten_input.push(x.len() as u32);
            for f in x {
                flatten_input.push(f.as_canonical_u32());
            }
        }
        let mut public_values = vec![];
        public_values.extend(exe_commit.map(|x| x.as_canonical_u32()));
        public_values.extend(
                leaf_commit
                .map(|x| x.as_canonical_u32()),
        );
        public_values.extend(
            root_proof
                .public_values
                .iter()
                .map(|x| x.as_canonical_u32()),
        );
        FlattenRootProof {
            flatten_proof: flatten_input,
            public_values: public_values,
        }
}

fn run_test() {
    let guest_dir = "./factor-example/"; 
    let guest_dir = "/home/ubuntu/zzhang/sproll-evm/openvm/program/";

    let exe_commitments = {
        let exe = read_exe_from_file(format!("{guest_dir}/openvm/app.vmexe")).unwrap();
        let app_pk: AppProvingKey<SdkVmConfig> =
            read_app_pk_from_file(format!("{guest_dir}/openvm/app.pk")).unwrap();
        let committed_exe = Sdk
            .commit_app_exe(app_pk.app_fri_params(), exe.clone())
            .unwrap();

        let commits = AppExecutionCommit::compute(
            &app_pk.app_vm_pk.vm_config,
            &committed_exe,
            &app_pk.leaf_committed_exe,
        );
        println!("exe commit: {:?}", commits.exe_commit_to_bn254());
        println!("app_pk commit: {:?}", commits.app_config_commit_to_bn254());
        commits
    };

    let flatten_proof_bytes = {
        let root_proof: RootVmVerifierInput<BabyBearPoseidon2Config> =
            read_root_proof_from_file(format!("{guest_dir}/openvm/root.proof"))
                .expect("fail to read proof");
        let flatten_root_proof = flatten_root_vm_verifier_input(
            &root_proof,
            exe_commitments.exe_commit,
            exe_commitments.leaf_vm_verifier_commit,
        );
        bitcode::serialize(&flatten_root_proof).unwrap()
    };


    let agg_guest_dir = "./stark-aggregation/guest/";
    let stdin = {
        std::fs::write(
            format!("{agg_guest_dir}/flatten-proof.bin"),
            flatten_proof_bytes.clone(),
        )
        .expect("fail to write");
        StdIn::from_bytes(&flatten_proof_bytes)
    };
    
    let toml = std::fs::read_to_string(format!("{agg_guest_dir}/openvm.toml")).unwrap();
    let app_config: AppConfig<SdkVmConfig> = toml::from_str(&toml).unwrap();
    let exe = read_exe_from_file(format!("{agg_guest_dir}/openvm/app.vmexe")).unwrap();
    let output = Sdk.execute(exe, app_config.app_vm_config, stdin).unwrap();
    println!("Execution output: {:?}", output);
}

fn main() {
    run_test();
}
