extern crate bitvec;
use std::usize;
use std::convert::TryInto;
use bitvec::prelude::*;

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
            &(*(0 as *const $structType)).$field as *const _ as usize
        }
    }
}

/* Yields the size of MEMBER within STRUCT. */
//#define MEMBER_SIZEOF(STRUCT, MEMBER) (sizeof(((STRUCT *) NULL)->MEMBER))
#[macro_export]
macro_rules! member_sizeof {
    ($structType:ty, $field:ident) =>
    {
        #[allow(trivial_casts)]
        unsafe
        {
            std::mem::size_of_val(&(*(0 as *const $structType)).$field)
        }
    }
}

/* Yields the offset of the end of MEMBER within STRUCT. */
#[macro_export]
macro_rules! OFFSETOFEND {
    ($structType:ty, $field:ident) =>
    {
        offsetOf!($structType, $field) + member_sizeof!($structType, $field)
    }
}

#[macro_export]
macro_rules! DIV_ROUND_UP {
    ($n: expr, $d: expr) => ((($n) + ($d) - 1) / ($d))
}


#[derive(Debug,Copy,Clone)]
pub struct flowmap {
    pub bits: [u64; FLOWMAP_UNITS],
    //bv: BitVec,
}

pub const FLOWMAP_UNITS:usize = 2;
pub const MAP_T_BITS:usize = 64;
pub const FLOW_U64S:usize = 84;
pub const MAP_1:u64 = 1;
pub const MAP_MAX:u64 = u64::max_value();

impl flowmap {
    pub fn new() -> flowmap {
        flowmap {
            bits: [0; FLOWMAP_UNITS],
            //bv: BitVec::with_capacity(128),
        }
    }
    //pub fn flowmap_init
    pub fn flowmap_set(&mut self, mut idx: usize, n_bits: usize) {
        let mut bv = self.bits.as_mut_bitslice::<LittleEndian>();
        let mut n = n_bits;

        while n > 0 {
            bv.set(idx, true);
            idx += 1;
            n -= 1;
        }
    }

    pub fn flowmap_equal(fm1: &flowmap, fm2: &flowmap) -> bool {
        if fm1.bits == fm2.bits {
            return true;
        } else {
            return false;
        }
    }

    pub fn flowmap_is_set(&self, idx: usize) -> bool {
        let base = self.bits;
        let bv = base.as_bitslice::<LittleEndian>();
        return bv[idx];
    }

    pub fn assert_flowmap_not_set(&self, idx: usize) {
        let base = self.bits;
        let bv = base.as_bitslice::<LittleEndian>();
        assert_eq!(bv[idx], false);
    }
    // consider use:
    //  https://docs.rs/bitvec/0.2.0/bitvec/trait.Bits.html
    pub fn flowmap_n_1bits(&self) -> usize {
        let base = self.bits;
        let bv = base.as_bitslice::<LittleEndian>();
        assert_eq!(bv.len(), 128);

        return bv.count_ones();
    }

}

pub struct Miniflow {
    pub map: flowmap,
    pub values: [u64; 20],
}

impl Miniflow {
    pub fn new() -> Miniflow {
        Miniflow {
            map: flowmap::new(),
            values: [0; 20],
        }
    }
    pub fn miniflow_values(&self) -> &[u64] {
        return &self.values;
    }

    pub fn miniflow_get_values(&mut self) -> &mut [u64] {
        return &mut self.values;
    }

    //pub fn miniflow_n_values(&self) -> usize {
        //return self.map.flowmap_n_1bits();
    //}

}

/* Context for pushing data to a miniflow. */
pub struct mf_ctx<'a> {
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

    pub fn miniflow_assert_in_map(&self, ofs: usize) {
        assert!(self.map.flowmap_is_set(ofs));
        self.map.assert_flowmap_not_set(ofs + 1);
    }

    pub fn miniflow_push_uint32_(&mut self, ofs: usize, value: u32) {
        let data_ofs = self.data_ofs;
        if ofs % 8 == 0 {
            self.miniflow_set_map(ofs / 8);
            self.data[data_ofs] = value as u64;
        } else if ofs % 8 == 4 {
            self.miniflow_assert_in_map(ofs / 8);
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

    pub fn miniflow_push_words_(&mut self, ofs: usize, valuep: &[u64], n_words: usize) {
        assert_eq!(ofs % 8, 0);
        let mut data_ofs = self.data_ofs;
        let mut words_to_write = n_words;
        let mut i = 0;
        self.miniflow_set_maps(ofs/8, n_words);

        while words_to_write > 0 {
            self.data[data_ofs] = valuep[i];
            words_to_write -= 1;
            data_ofs += 1;
            i += 1;
        }
        self.data_ofs += n_words;
    }

    /* Push 32-bit words padded to 64-bits. */
    pub fn miniflow_push_words_32_(&mut self, ofs: usize, valuep: &[u32], n_words: usize) {
        let mut data_ofs = self.data_ofs;
        let mut words_to_write = n_words / 2;
        let mut i = 0;
        self.miniflow_set_maps(ofs / 8, DIV_ROUND_UP!(n_words, 2));

        let mut rest: &[u32] = valuep;
        while words_to_write > 0 {
            self.data[data_ofs] = (rest[1] as u64) << 32 | rest[0] as u64;
            words_to_write -= 1;
            data_ofs += 1;
            i += 1;
            rest = &valuep[(i * 2)..];
        }

        if n_words % 2 != 0 {
              self.data[data_ofs] = rest[0] as u64;
        }
        self.data_ofs += DIV_ROUND_UP!(n_words, 2);
    }

    // see https://doc.rust-lang.org/std/primitive.u64.html#method.from_le_bytes
    pub fn miniflow_push_macs_(&mut self, ofs: usize, valuep: &[u8]) {
        let data_ofs = self.data_ofs;
        self.miniflow_set_maps(ofs / 8, 2);

        let mut rest: &[u8] = valuep;
        let (v, rest) = rest.split_at(std::mem::size_of::<u64>());
        self.data[data_ofs] = u64::from_le_bytes(v.try_into().unwrap());

        println!("{:x?}", self.data[data_ofs]);
        let (v2, rest2) = rest.split_at(std::mem::size_of::<u32>());
        self.data[data_ofs + 1] = u32::from_le_bytes(v2.try_into().unwrap()) as u64;
        self.data_ofs += 1;
    }

    pub fn miniflow_push_uint16_(&mut self, ofs: usize, value: u16) {
        let offset = self.data_ofs;

        if ofs % 8 == 0 {
            self.miniflow_set_map(ofs / 8);
            self.data[offset] = value as u64;
        } else if ofs % 8 == 2 {
            self.miniflow_assert_in_map(ofs / 8);
            self.data[offset] |= (value as u64) << 16;
        } else if ofs % 8 == 4 {
            self.miniflow_assert_in_map(ofs / 8);
            self.data[offset] |= (value as u64) << 32;
        } else if ofs % 8 == 6 {
            self.miniflow_assert_in_map(ofs / 8);
            self.data[offset] |= (value as u64) << 48;
            self.data_ofs += 1;
        }
    }

    pub fn miniflow_push_uint8_(&mut self, ofs: usize, value: u8) {
        let offset = self.data_ofs;

        if ofs % 8 == 0 {
            self.miniflow_set_map(ofs / 8);
            self.data[offset] = value as u64;
        } else if ofs % 8 == 7 {
            self.miniflow_assert_in_map(ofs / 8);
            self.data[offset] |= (value as u64) << 56;
            self.data_ofs += 1;
        } else {
            self.miniflow_assert_in_map(ofs / 8);
            let shft = (ofs % 8) * 8;
            self.data[offset] |= (value as u64) << shft;
        }
    }

    pub fn miniflow_pad_to_64_(&mut self, ofs: usize) {
        assert_ne!(ofs % 8, 0);
        let offset = self.data_ofs;

        self.miniflow_assert_in_map(ofs / 8);
        let bit = (ofs % 8) * 8;
        let mask = ((1 as u64) << bit) - 1;
        self.data[offset] &= mask;
        self.data_ofs += 1;
    }

    pub fn miniflow_pad_from_64_(&mut self, ofs: usize) {
        assert_ne!(ofs % 8, 0);

        let offset = self.data_ofs;
        self.miniflow_set_map(ofs / 8);
        let bit = (ofs % 8) * 8;
        let mask = !((1_u64 << bit) - 1);
        self.data[offset] &= mask;
    }

    pub fn miniflow_push_ct_nw_proto(&mut self, offset: usize, value: u8) {
        let ofs = offsetOf!(crate::flow::Flow, ct_nw_proto);
        self.miniflow_assert_in_map(ofs / 8);
        let shft = (ofs % 8) * 8;
        self.data[offset] |= (value as u64) << shft;
    }
}

// Arrays are stack allocated
//        println!("array occupies {} bytes", mem::size_of_val(&xs));
// about macro: https://doc.rust-lang.org/1.7.0/book/macros.html

// I follow the sequences in lib/flow.c
#[macro_export]
macro_rules! miniflow_push_uint32 {
    ($MFX: expr, $FIELD: ident, $VALUE:expr) => ({
        let ofs = offsetOf!(crate::flow::Flow, $FIELD) as usize;
        $MFX.miniflow_push_uint32_(ofs, $VALUE)
    });
}

#[macro_export]
macro_rules! miniflow_push_be32 {
    ($MFX: expr, $FIELD: ident, $VALUE:expr) => ({
        let ofs = offsetOf!(crate::flow::Flow, $FIELD) as usize;
        $MFX.miniflow_push_uint32_(ofs, $VALUE)
    });
}

#[macro_export]
macro_rules! miniflow_push_uint16 {
    ($MFX: expr, $FIELD: ident, $VALUE:expr) => ({
        let ofs = offsetOf!(crate::flow::Flow, $FIELD) as usize;
        $MFX.miniflow_push_uint16_(ofs, $VALUE)
    });
}

#[macro_export]
macro_rules! miniflow_push_be16 {
    ($MFX: expr, $FIELD: ident, $VALUE:expr) => ({
        let ofs = offsetOf!(crate::flow::Flow, $FIELD) as usize;
        $MFX.miniflow_push_uint16_(ofs, $VALUE)
    });
}

#[macro_export]
macro_rules! miniflow_push_uint8 {
    ($MFX: expr, $FIELD: ident, $VALUE:expr) => ({
        let ofs = offsetOf!(crate::flow::Flow, $FIELD) as usize;
        $MFX.miniflow_push_uint8_(ofs, $VALUE)
    });
}

#[macro_export]
macro_rules! miniflow_pad_to_64 {
    ($MFX: expr, $FIELD: ident) => ({
        let ofs = OFFSETOFEND!(crate::flow::Flow, $FIELD) as usize;
        $MFX.miniflow_pad_to_64_(ofs)
    });
}

#[macro_export]
macro_rules! miniflow_pad_from_64 {
    ($MFX: expr, $FIELD: ident) => ({
        let ofs = offsetOf!(crate::flow::Flow, $FIELD) as usize;
        $MFX.miniflow_pad_from_64_(ofs)
    });
}

#[macro_export]
macro_rules! miniflow_push_uint64 {
    ($MFX: expr, $FIELD: ident, $VALUE:expr) => ({
        let ofs = offsetOf!(crate::flow::Flow, $FIELD) as usize;
        $MFX.miniflow_push_uint64_(ofs, $VALUE)
    });
}

#[macro_export]
macro_rules! miniflow_push_words {
    ($MFX: expr, $FIELD: ident, $VALUEP:expr, $N_WORDS:expr) => ({
        let ofs = offsetOf!(crate::flow::Flow, $FIELD) as usize;
        $MFX.miniflow_push_words_(ofs, $VALUEP, $N_WORDS)
    });
}

#[macro_export]
macro_rules! miniflow_push_words_32 {
    ($MFX: expr, $FIELD: ident, $VALUE:expr, $N_WORDS:expr) => ({
        let ofs = offsetOf!(crate::flow::Flow, $FIELD) as usize;
        $MFX.miniflow_push_words_32_(ofs, $VALUE, $N_WORDS)
    });
}

#[macro_export]
macro_rules! miniflow_push_macs {
    ($MFX: expr, $FIELD: ident, $VALUE:expr) => ({
        let ofs = offsetOf!(crate::flow::Flow, $FIELD) as usize;
        $MFX.miniflow_push_macs_(ofs, $VALUE)
    });
}

#[cfg(test)]
mod tests {
    use crate::flow::*;
    use super::*;

    #[test]
    fn test_push() {

        let mut mf: Miniflow = Miniflow::new();
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

        mfx.miniflow_pad_to_64_(ofs + 44);

        let v = 0x1;
        mfx.miniflow_push_uint8_(ofs + 48, v);
        assert_eq!(mfx.map.bits, [0x7f, 0]);
        mfx.miniflow_push_uint8_(ofs + 49, v + 1);
        mfx.miniflow_push_uint8_(ofs + 50, v + 2);
        mfx.miniflow_push_uint8_(ofs + 55, v + 3);
        assert_eq!(mfx.map.bits, [0x7f, 0]);

        let expected: &mut [u64] =
            &mut [1, 2, 3, 0xeeee0000ffff, 0x1b006c9307542300, 0x9b910f21, 0x400000000030201, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0];
        assert_eq!(mfx.data, expected);

        // Push 3 words
        let words: [u64; 3]  = [0x807060504030201, 0x100f0e0d0c0b0a09, 0x1817161514131211];
        mfx.miniflow_push_words_(ofs + 56, &words, 3);
        let expected: &mut [u64] =
            &mut [1, 2, 3, 0xeeee0000ffff, 0x1b006c9307542300, 0x9b910f21, 0x400000000030201, 0x807060504030201, 0x100f0e0d0c0b0a09, 0x1817161514131211, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0];
        assert_eq!(mfx.data, expected);
        assert_eq!(mfx.map.bits, [0x3ff, 0]);

        let words_32: [u32; 5]  = [0x4030201, 0x8070605, 0xc0b0a09, 0xf0e0d, 0x14131211];
        mfx.miniflow_push_words_32_(ofs + 80, &words_32, 5);
        let expected: &mut [u64] =
            &mut [1, 2, 3, 0xeeee0000ffff, 0x1b006c9307542300, 0x9b910f21, 0x400000000030201, 0x807060504030201, 0x100f0e0d0c0b0a09, 0x1817161514131211, 0x807060504030201, 0xf0e0d0c0b0a09, 0x14131211, 0, 0, 0, 0, 0, 0, 0];
        assert_eq!(mfx.data, expected);
        assert_eq!(mfx.map.bits, [0x1fff, 0]);
    }

    #[test]
    fn test_macro_push() {

        let mut mf: Miniflow = Miniflow::new();
        let mut mfx = &mut mf_ctx::from_mf(mf.map, &mut mf.values);

        /* Push */
        miniflow_push_uint32!(mfx, recirc_id, 0xa);
        miniflow_push_uint8!(mfx, ct_state, 0xb);
        miniflow_push_uint8!(mfx, ct_nw_proto, 0xc);
        miniflow_push_uint16!(mfx, ct_zone, 0xd);

        /* recird_id offset = 432. 432 / 8 = 54. */
        assert_eq!(mfx.map.bits, [0x40000000000000, 0]);
        let expected: &mut [u64] =
            &mut [0xd0c0b0000000a, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0];
        assert_eq!(mfx.data, expected);

        let macs = [0x00, 0x23, 0x54, 0x07, 0x93, 0x6c, /* dest MAC */
                    0x00, 0x1b, 0x21, 0x0f, 0x91, 0x9b /* src MAC */
                    ];

        miniflow_push_macs!(mfx, dl_dst, &macs);

        let expected: &mut [u64] =
            &mut [0xd0c0b0000000a, 0x1b006c9307542300, 0x9b910f21, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0];
        assert_eq!(mfx.data, expected);
        assert_eq!(mfx.map.bits, [0x1840000000000000, 0]);

        let ethertype = 0x0800;
        miniflow_push_be16!(mfx, dl_type, ethertype);
        assert_eq!(mfx.map.bits, [0x1840000000000000, 0]);
        let expected: &mut [u64] =
            &mut [0xd0c0b0000000a, 0x1b006c9307542300, 0x8009b910f21, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0];
        assert_eq!(mfx.data, expected);

        miniflow_pad_to_64!(mfx, dl_type);
        /* Push nw_src and nw_dst */
        /* 512 / 8 = 64 */
        miniflow_push_uint32!(mfx, nw_src, 4);
        assert_eq!(mfx.map.bits, [0x1840000000000000, 1]);
        miniflow_push_uint32!(mfx, nw_dst, 2);
        assert_eq!(mfx.map.bits, [0x1840000000000000, 1]);
        let expected: &mut [u64] =
            &mut [0xd0c0b0000000a, 0x1b006c9307542300, 0x8009b910f21, 0x200000004, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0];
        assert_eq!(mfx.data, expected);

        let words: [u64; 2]  = [0x807060504030201, 0x100f0e0d0c0b0a09];
        miniflow_push_words!(mfx, ct_label, &words, 2);
        let expected: &mut [u64] =
            &mut [0xd0c0b0000000a, 0x1b006c9307542300, 0x8009b910f21, 0x200000004, 0x807060504030201, 0x100f0e0d0c0b0a09, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0];
        assert_eq!(mfx.data, expected);

        /* One mpls_lse has 4-byte, assume 3 mpls  */
        let words_32: [u32; 3]  = [0x4030201, 0x8070605, 0xc0b0a09];
        miniflow_push_words_32!(mfx, mpls_lse, &words_32, 3);
        let expected: &mut [u64] =
            &mut [0xd0c0b0000000a, 0x1b006c9307542300, 0x8009b910f21, 0x200000004, 0x807060504030201, 0x100f0e0d0c0b0a09, 0x807060504030201, 0xc0b0a09, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0];
        assert_eq!(mfx.data, expected);

//        panic!("{:x?}", mfx.data);
    }

    #[test]
    fn test_offsetof() {

        /* test macro offsetOf */
        let fff = Flow::default();

        assert_eq!(offsetOf!(Flow, metadata), 344);
        assert_eq!(offsetOf!(Flow, pkt_mark), 420);
        assert_eq!(offsetOf!(Flow, dp_hash), 424);
        assert_eq!(offsetOf!(Flow, nw_src), 512);
        assert_eq!(offsetOf!(Flow, dl_dst), 472);

        assert_eq!(member_sizeof!(Flow, dl_dst), 6);
        assert_eq!(member_sizeof!(Flow, arp_sha), 6);
        assert_eq!(member_sizeof!(Flow, nw_src), 4);
        assert_eq!(member_sizeof!(Flow, nw_tos), 1);
        assert_eq!(member_sizeof!(Flow, ct_state), 1);

        assert_eq!(OFFSETOFEND!(Flow, nw_src), 516);

        //panic!("{:?}", OFFSETOFEND!(flow, nw_src));
    }
    #[test]
    fn test_div_round_up() {
        let x = 5;
        assert_eq!(DIV_ROUND_UP!(5, 2), 3);
    }
}

