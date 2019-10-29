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

fn main() {
    println!("Hello, world!");

    let x = dp_packet::Dp_packet::new(128);
    let y = miniflow::Miniflow::new();
    let z = parser::Parser {};

}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::miniflow::*;

    pub struct test_macro {
        pub m1: u32,
        pub m2: u32,
    }

    #[test]
    fn marcos() {
        member_sizeof!(test_macro, m1);

        let mut mf: Miniflow =Miniflow::new();
        let mut mfx = &mut mf_ctx::from_mf(mf.map, &mut mf.values);
        miniflow_push_uint32!(mfx, recirc_id, 0xa);
        miniflow_push_uint8!(mfx, ct_state, 0xb);
        miniflow_push_uint8!(mfx, ct_nw_proto, 0xc);
        miniflow_push_uint16!(mfx, ct_zone, 0xd);

        assert_eq!(mfx.map.bits, [0x100000, 0]);
        let expected: &mut [u64] =
            &mut [0xd0c0b0000000a, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0];
        assert_eq!(mfx.data, expected);
    }
}
