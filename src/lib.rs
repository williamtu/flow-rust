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
    let mut map: flowmap = flowmap::new();

    unsafe {
        let mut mfx = &mut mf_ctx::from_mf(map, &mut (*dst).values);
        let md = &(*packet).data_.md;
        let data = (*packet).dp_packet_data();
        let packet_type_be =  (*packet).packet_type;

        let ct_nw_proto_data_ofs = parse_metadata(md, packet_type_be, mfx);
        (*packet).reset_offset();

        let (offset, l2_5_ofs, dl_type) = match parse_l2(data, mfx, packet_type_be) {
            Ok(success_val) => success_val,
            Err(err) => {
                (*dst).map = mfx.map;
                match err {
                    ParseError::Skip => (),
                    _ => println!("failed to parse L2 {:?}", err),
                };
                return ;
            },
        };

        (*packet).l2_5_ofs = l2_5_ofs;
        (*packet).l3_ofs = offset as u16;

        let (offset2, l2_pad_size, total_size, nw_frag, nw_proto, ct_tp_src_be, ct_tp_dst_be) =
            match parse_l3(&data[offset..], mfx, md, dl_type, ct_nw_proto_data_ofs) {
            Ok(success_val) => success_val,
            Err(err) => {
                (*dst).map = mfx.map;
                match err {
                    ParseError::Skip => (),
                    _ => (), //println!("failed to parse L3 {:?}", err),
                };
                return ;
            }
        };

        (*packet).l2_pad_size = l2_pad_size;
        (*packet).l4_ofs = (offset + offset2) as u16;

        let result = parse_l4(&data[(offset + offset2)..],  mfx, md, nw_proto, nw_frag, ct_tp_src_be, ct_tp_dst_be);

        (*dst).map = mfx.map;
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
