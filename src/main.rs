#![allow(dead_code,
         unused_variables,
         unused_assignments,
         non_camel_case_types,
         unused_mut)]

#![feature(stmt_expr_attributes)]

pub mod dp_packet;
pub mod miniflow;
pub mod parser;
pub mod flow;

pub struct test_macro {
    pub m1: u32,
    pub m2: u32,
}
fn main() {
    println!("Hello, world!");

    let x = dp_packet::dp_packet::new(128);
    let y = miniflow::Miniflow::new();
    let z = parser::parser {};

    member_sizeof!(test_macro, m1);
}
