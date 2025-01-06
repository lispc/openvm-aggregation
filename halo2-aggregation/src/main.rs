use halo2curves_axiom::bn256::{Bn256, Fr, G1Affine};
use openvm_snark_verifier::{
    loader::{OpenVmLoader, LOADER},
    traits::OpenVmScalar,
    transcript::OpenVmTranscript,
};
use serde::{Deserialize, Serialize};
use snark_verifier_sdk::snark_verifier::{
    pcs::{kzg::KzgDecidingKey, AccumulationDecider},
    verifier::{
        plonk::{PlonkProof, PlonkProtocol},
        SnarkVerifier,
    },
};
use snark_verifier_sdk::{PlonkSuccinctVerifier, PlonkVerifier, SHPLONK};

#[allow(unused_imports, clippy::single_component_path_imports)]
use {
    openvm_bigint_guest, // trigger extern u256 (this may be unneeded)
    openvm_ecc_guest::k256::Secp256k1Coord,
    openvm_keccak256_guest, // trigger extern native-keccak256
    openvm_pairing_guest::bn254::Bn254Fp,
};

openvm_algebra_guest::moduli_setup::moduli_init! {
    "0x30644e72e131a029b85045b68181585d97816a916871ca8d3c208c16d87cfd47", // Bn254Fp Coordinate field
    "0x30644e72e131a029b85045b68181585d2833e84879b9709143e1f593f0000001", // Bn254 Scalar
    "0xFFFFFFFF FFFFFFFF FFFFFFFF FFFFFFFF FFFFFFFF FFFFFFFF FFFFFFFE FFFFFC2F", // secp256k1 Coordinate field
    "0xFFFFFFFF FFFFFFFF FFFFFFFF FFFFFFFE BAAEDCE6 AF48A03B BFD25E8C D0364141" // secp256k1 Scalar field
}
openvm_ecc_guest::sw_setup::sw_init! {
    Secp256k1Coord,
    Bn254Fp
}
openvm_algebra_complex_macros::complex_init! {
    Bn254Fp2 { mod_idx = 0 },
}

openvm::entry!(main);

#[derive(Clone, Deserialize, Serialize)]
pub struct EvmProof {
    pub instances: Vec<Vec<Fr>>,
    pub proof: Vec<u8>,
}

fn verify_halo2_proof() {
    let proof: EvmProof =
        bitcode::deserialize(include_bytes!("../../factor-example/openvm/evm.proof"))
            .expect("decode proof");
    let protocol: PlonkProtocol<G1Affine> =
        bitcode::deserialize(include_bytes!("../../utils/protocol.bin")).expect("decode protocol");

    // openvm/extensions/native/recursion/src/halo2/utils.rs
    let dk: KzgDecidingKey<Bn256> = serde_json::from_str(r#"
    {
    "_marker": null,
    "g2": "edf692d95cbdde46ddda5ef7d422436779445c5e66006a42761e1f12efde0018c212f3aeb785e49712e7a9353349aaf1255dfb31b7bf60723a480d9293938e19",
    "s_g2": "0016e2a0605f771222637bae45148c8faebb4598ee98f30f20f790a0c3c8e02a7bf78bf67c4aac19dcc690b9ca0abef445d9a576c92ad6041e6ef1413ca92a17",
    "svk": {
        "g": "0100000000000000000000000000000000000000000000000000000000000000"
    }
    }
    "#).unwrap();

    /*
    app_pk commit: 0x0043707da073e28b0cbf8c18d1a22052ae59a59e2a443d4fe872ddfc52fc4598
    exe commit: 0x004746ddef0bd9871691039c2c8acb7f08bcd379eeb3d9c421486adb7a23a239
    */
    //println!("{:?}", proof.instances);
    println!("instance[0][12] {:?}", proof.instances[0][12]); // exe commit
    println!("instance[0][13] {:?}", proof.instances[0][13]); // app_pk commit
    println!("instance[0][14] {:?}", proof.instances[0][14]); // first real public input

    let mut transcript = OpenVmTranscript::<G1Affine, _, _>::new(proof.proof.as_slice());

    let instances: Vec<
        Vec<OpenVmScalar<halo2curves_axiom::bn256::Fr, openvm_pairing_guest::bn254::Scalar>>,
    > = proof
        .instances
        .into_iter()
        .map(|x| {
            x.into_iter()
                .map(|x| {
                    use openvm_ecc_guest::algebra::IntMod;
                    let value = openvm_pairing_guest::bn254::Scalar::from_le_bytes(&x.to_bytes());
                    OpenVmScalar::new(value)
                })
                .collect()
        })
        .collect::<Vec<_>>();

    println!("transcript done");

    let loader = &LOADER;
    let protocol: PlonkProtocol<G1Affine, OpenVmLoader> = protocol.loaded(loader);
    println!("protocol loaded");
    let loaded_proof: PlonkProof<G1Affine, OpenVmLoader, SHPLONK> =
        PlonkVerifier::<SHPLONK>::read_proof(&dk, &protocol, &instances[..], &mut transcript)
            .unwrap();

    println!("loaded_proof done");
    let accumulators = PlonkSuccinctVerifier::<SHPLONK>::verify(
        dk.as_ref(),
        &protocol,
        &instances[..],
        &loaded_proof,
    )
    .unwrap();
    println!("before pairing, pairing num {}", accumulators.len());

    SHPLONK::decide_all(&dk, accumulators).unwrap();

    println!("plonk verify done");
}

fn main() {
    setup_all_moduli();
    setup_all_curves();
    setup_all_complex_extensions();

    verify_halo2_proof();
}
