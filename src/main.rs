use std::{env, fs};

mod parser;

fn main() {
    let path = env::args().nth(1).expect("You didn't provide an argument!");
    let data = fs::read(path).expect("Failed to read input file");
    let obj = parser::elf(&data);

    println!("ELF header:\n{:?}", obj.header);
    println!("Sections:");
    for sec in obj.sections {
        println!("- {sec:?}");
    }
    assert!(obj.segments.is_empty());
}
