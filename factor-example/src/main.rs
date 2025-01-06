use openvm::io::{read, reveal};

openvm::entry!(main);

fn main() {
    let n: u32 = read();
    println!("n is {n}");
    assert_eq!(15 % n, 0);
    reveal(n, 0);
}
