#![allow(dead_code,
         unused_variables,
         unused_assignments,
         non_camel_case_types,
         unused_mut)]

#![feature(stmt_expr_attributes)]

pub mod dp_packet;
pub mod flow;
pub mod miniflow;
pub mod packet;
pub mod parser;
pub mod tun_metadata;
pub mod types;

use crate::dp_packet::*;
use crate::miniflow::*;
use crate::parser::*;
use std::slice;

#[no_mangle]
pub extern "C" fn rust_miniflow_extract(packet: *mut Dp_packet,
                                        dst: *mut Miniflow) {
    println!("Hello from rust miniflow extract!");

    let mut mf: Miniflow = Miniflow::new();
    let mut mfx = &mut mf_ctx::from_mf(mf.map, &mut mf.values);

    unsafe {
        let md = &(*packet).data_.md;
        let data = (*packet).dp_packet_data();
        let packet_type_be =  (*packet).packet_type;

        parse_metadata(md, packet_type_be, mfx);
        (*packet).reset_offset();

        let result = parse_l2(data, mfx, packet_type_be);
        if result.is_err() {
            // XXX: goto
            (*dst).map = mfx.map;
            return ;
        } else {
            let (offset, l2_5_ofs) = result.unwrap();
            (*packet).l2_5_ofs = l2_5_ofs;
            (*packet).l3_ofs = offset as u16;
        }
    }
}

#[no_mangle]
pub extern "C" fn test_data(data: *const libc::c_void) {
    println!("Hello from rust test_data!");

    unsafe {
        let slice = slice::from_raw_parts(data.offset(3) as *const u8, 5);

        println!("data[0] = {}, data[3] = {}", slice[0], slice[3]);
    }
}
