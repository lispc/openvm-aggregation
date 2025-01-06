Example codes to verify proof inside openvm.

It is like `sp1_zkvm::lib::verify::verify_sp1_proof`.

# verify halo2 proof inside openvm

```
cd factor-example
cargo openvm build
cargo openvm setup
cargo openvm prove evm --input 0x0300000000000000  # to dump the evm.proof file
cd ..

cd utils
cargo run # to dump the protocol.bin file
cd ..

cd halo-aggregation
cargo openvm build
cargo openvm run
cargo openvm prove [app|evm]

```

# verify stark proof inside openvm 

WIP
