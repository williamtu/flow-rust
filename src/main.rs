#![allow(dead_code,
         unused_variables,
         unused_assignments,
         non_camel_case_types,
         unused_mut)]

pub mod dp_packet;
pub mod miniflow;
pub mod parser;

fn main() {
    println!("Hello, world!");

    let x = dp_packet::dp_packet {};
    let y = miniflow::miniflow {};
    let z = parser::parser {};
}
