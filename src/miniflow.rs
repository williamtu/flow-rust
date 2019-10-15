use std::usize;
use crate::flow::*;
use std::convert::TryInto;

// use std::fmt::{Debug, Formatter};

// Rust's pointer types must always point to a valid location;
// there are no "null" pointers. Instead, Rust has optional pointers,
// like the optional owned box

#[macro_export]
macro_rules! offsetOf
{
    ($structType:ty, $field:ident) =>
    {
        #[allow(trivial_casts)]
        unsafe
        {
            &(*(0 as *const $structType)).$field as *const _ as isize
        }
    }
}

#[derive(Debug)]
pub struct flowmap {
    bits: [u64; FLOWMAP_UNITS],
}

pub const FLOWMAP_UNITS:usize = 2;
pub const MAP_T_BITS:usize = 64;
pub const FLOW_U64S:usize = 84;

impl flowmap {
    pub fn new() -> flowmap {
        flowmap {
            bits: [0; FLOWMAP_UNITS],
        }
    }
    //pub fn flowmap_init
    pub fn flowmap_set(&mut self, mut idx: usize, n_bits: usize) {

        let n_bits_mask = (1 << n_bits) - 1;
        let unit: usize = idx / MAP_T_BITS;
        idx %= MAP_T_BITS;

        self.bits[unit] |= n_bits_mask << idx;

        if unit + 1 < FLOWMAP_UNITS && idx + n_bits > MAP_T_BITS {
            self.bits[unit + 1] |= n_bits_mask >> (MAP_T_BITS - idx);
        }
    }

    pub fn flowmap_equal(fm1: &flowmap, fm2: &flowmap) -> bool {
        if fm1.bits == fm2.bits {
            return true;
        } else {
            return false;
        }
    }

    //pub fn flowmap_and
    //pub fn flowmap_clear

}

pub struct miniflow {
    pub map: flowmap,
    pub values: [u64; 20],
}

impl miniflow {
    pub fn new() -> miniflow {
        miniflow {
            map: flowmap::new(),
            values: [0; 20],
        }
    }
}

/* Context for pushing data to a miniflow. */
struct mf_ctx<'a> {
    pub map: flowmap,
    pub data_ofs: usize,
    pub data: &'a mut [u64],
    //data: std::slice::IterMut,
    //end: &'a mut [u64], // cause multiple mutable borrow
}

impl<'a> mf_ctx<'a> {
    pub fn from_mf(map_: flowmap, data_: &'a mut [u64]) -> mf_ctx<'a> {
        mf_ctx {
            map: map_,
            data_ofs: 0,
            data: data_,
        }
    }

    pub fn miniflow_set_maps(&mut self, ofs: usize, n_words: usize) {
        self.map.flowmap_set(ofs, n_words);
    }

    pub fn miniflow_set_map(&mut self, ofs: usize) {
        self.map.flowmap_set(ofs, 1);
    }

    pub fn miniflow_push_uint32_(&mut self, ofs: usize, value: u32) {
        let data_ofs = self.data_ofs;
        if ofs % 8 == 0 {
            self.miniflow_set_map(ofs / 8);
            self.data[data_ofs] = value as u64;
        } else if ofs % 8 == 4 {
            self.data[data_ofs] |= (value as u64) << 32;
            self.data_ofs += 1;
        }
    }

    pub fn miniflow_push_uint64_(&mut self, ofs: usize, value: u64) {
        let data_ofs = self.data_ofs;
        self.miniflow_set_map(ofs / 8);
        self.data[data_ofs] = value;
        self.data_ofs += 1;
    }

    // see https://doc.rust-lang.org/std/primitive.u64.html#method.from_le_bytes
    pub fn miniflow_push_macs_(&mut self, ofs: usize, valuep: &[u8; 12]) {
        let data_ofs = self.data_ofs;
        self.miniflow_set_maps(ofs / 8, 2);

        let (v, rest) = valuep.split_at(std::mem::size_of::<u64>());
        self.data[data_ofs] = u64::from_le_bytes(v.try_into().unwrap());

        println!("{:x?}", self.data[data_ofs]);
        let (v2, rest2) = rest.split_at(std::mem::size_of::<u32>());
        self.data[data_ofs + 1] = u32::from_le_bytes(v2.try_into().unwrap()) as u64;
        self.data_ofs += 2;
    }

    pub fn miniflow_push_be16_(&mut self, ofs: usize, value: u16) {
        let offset = self.data_ofs;

        if ofs % 8 == 0 {
            self.miniflow_set_map(ofs / 8);
            self.data[offset] = value as u64;
        } else if ofs % 8 == 2 {
            // miniflow_assert_in_map
            self.data[offset] |= (value as u64) << 16;
        } else if ofs % 8 == 4 {
            self.data[offset] |= (value as u64) << 32;
        } else if ofs % 8 == 6 {
            self.data[offset] |= (value as u64) << 48;
            self.data_ofs += 1;
        }
    }
}

// Arrays are stack allocated
//        println!("array occupies {} bytes", mem::size_of_val(&xs));
#[macro_export]
macro_rules! miniflow_push_uint32 {
    ($MFX: expr, $FIELD: ident, $VALUE:expr) => ({
        let ofs = offsetOf!(flow, $FIELD) as usize;
        $MFX.miniflow_push_uint32_(ofs, $VALUE)
    });
}

#[macro_export]
macro_rules! miniflow_push_uint64 {
    ($MFX: expr, $FIELD: ident, $VALUE:expr) => ({
        let ofs = offsetOf!(flow, $FIELD) as usize;
        $MFX.miniflow_push_uint64_(ofs, $VALUE)
    });
}

#[macro_export]
macro_rules! miniflow_push_macs {
    ($MFX: expr, $FIELD: ident, $VALUE:expr) => ({
        let ofs = offsetOf!(flow, $FIELD) as usize;
        $MFX.miniflow_push_macs_(ofs, $VALUE)
    });
}

#[macro_export]
macro_rules! miniflow_push_be16 {
    ($MFX: expr, $FIELD: ident, $VALUE:expr) => ({
        let ofs = offsetOf!(flow, $FIELD) as usize;
        $MFX.miniflow_push_be16_(ofs, $VALUE)
    });
}

#[test]
fn test_push() {

    let mut mf: miniflow = miniflow::new();
    let mut mfx = &mut mf_ctx::from_mf(mf.map, &mut mf.values);
    let ofs = 0;

    mfx.miniflow_push_uint64_(ofs, 1);
    assert_eq!(mfx.map.bits, [1, 0]);
    mfx.miniflow_push_uint64_(ofs + 8, 2);
    assert_eq!(mfx.map.bits, [3, 0]);
    mfx.miniflow_push_uint64_(ofs + 16, 3);
    assert_eq!(mfx.map.bits, [7, 0]);
    assert_eq!(mfx.data, [1, 2, 3, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]);

    mfx.miniflow_push_uint32_(ofs + 24, 0xffff);
    mfx.miniflow_push_uint32_(ofs + 24 + 4, 0xeeee);
    let expected: &mut [u64] =
        &mut [1, 2, 3, 0xeeee0000ffff, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0];

    assert_eq!(mfx.data, expected);
    assert_eq!(mfx.map.bits, [0xf, 0]);

    let macs = [0x00, 0x23, 0x54, 0x07, 0x93, 0x6c, /* dest MAC */
                0x00, 0x1b, 0x21, 0x0f, 0x91, 0x9b /* src MAC */
                ];
    mfx.miniflow_push_macs_(ofs + 32, &macs);
    let expected: &mut [u64] =
        &mut [1, 2, 3, 0xeeee0000ffff, 0x1b006c9307542300, 0x9b910f21, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0];
    assert_eq!(mfx.data, expected);
    assert_eq!(mfx.map.bits, [0x3f, 0]);
//    panic!("{:x?}", mfx.map.bits);
}

#[test]
fn test_macro_push() {

    let mut mf: miniflow = miniflow::new();
    let mut mfx = &mut mf_ctx::from_mf(mf.map, &mut mf.values);

    let macs = [0x00, 0x23, 0x54, 0x07, 0x93, 0x6c, /* dest MAC */
                0x00, 0x1b, 0x21, 0x0f, 0x91, 0x9b /* src MAC */
                ];

    miniflow_push_macs!(mfx, dl_dst, &macs);

    let expected: &mut [u64] =
        &mut [0x1b006c9307542300, 0x9b910f21, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0];
    assert_eq!(mfx.data, expected);
    assert_eq!(mfx.map.bits, [0x6000000, 0]);

    let ethertype = 0x0800;

    miniflow_push_be16!(mfx, dl_type, ethertype);
    assert_eq!(mfx.map.bits, [0x6000000, 0]);

    /* Push nw_src and nw_dst */
    /* 240 / 8 = 30, 1 << 30 = 0x40000000 */
    miniflow_push_uint32!(mfx, nw_src, 4);
    assert_eq!(mfx.map.bits, [0x46000000, 0]);

    miniflow_push_uint32!(mfx, nw_dst, 2);
    assert_eq!(mfx.map.bits, [0x46000000, 0]);

//    let expected: &mut [u64] =
//        &mut [0x200000004, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0];
//    assert_eq!(mfx.data, expected);

//    panic!("{:?}", offsetOf!(flow, metadata)); //72
//    panic!("{:?}", offsetOf!(flow, pkt_mark)); //148
//    panic!("{:x?}", mfx.map.bits);
}

#[test]
fn test_offsetof() {

    /* test macro offsetOf */
    let fff = flow::default();

    assert_eq!(offsetOf!(flow, pkt_mark), 148);
    assert_eq!(offsetOf!(flow, dp_hash), 152);
    assert_eq!(offsetOf!(flow, nw_src), 240);
}

