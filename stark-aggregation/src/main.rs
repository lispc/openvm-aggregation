use openvm::io::{read, reveal};
use std::arch::asm;

openvm::entry!(main);

fn exec_kernel(buf_ptr: *mut u32) {
    unsafe {
        asm!(
            include_str!("../../root.u32s"),
            in("a0") buf_ptr,
        )
    }
}

fn main() {
    let mut buf= [0u32; 48];
    unsafe { let ptr = buf.as_mut_ptr(); 
        println!("AAA ptr {:?}", ptr);
        exec_kernel(ptr);
     }
    for i in 0..48 {
        println!("AAA {}, {}", i, buf[i]);
    }
}
