use openvm_native_recursion::halo2::{
    utils::Halo2ParamsReader, CacheHalo2ParamsReader, Halo2Params,
};
use openvm_sdk::fs::read_agg_pk_from_file;
use snark_verifier_sdk::{
    halo2::aggregation::AggregationCircuit,
    snark_verifier::system::halo2::{compile, Config},
    CircuitExt,
};

pub const DEFAULT_AGG_PK_PATH: &str = concat!(env!("HOME"), "/.openvm/agg.pk");
pub const DEFAULT_PARAMS_DIR: &str = concat!(env!("HOME"), "/.openvm/params/");

fn main() {
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
