use std::usize;
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
}

#[macro_export]
macro_rules! miniflow_push_uint32 {
    ($MFX: expr, $FIELD: ident, $VALUE:expr) => ({
        let ofs = offsetOf!(miniflow, $FIELD) as usize;
        $MFX.miniflow_push_uint32_(ofs, $VALUE)
    });
}

#[test]
fn test() {
    println!("Hello, world!");

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
    let expected: &mut [u64] = &mut [1, 2, 3, 0xeeee0000ffff, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0];

    assert_eq!(mfx.data, expected);
    assert_eq!(mfx.map.bits, [0xf, 0]);
//    panic!("{:x?}", mfx.map.bits);
}

