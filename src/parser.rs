use byteorder::*;
use crate::packet::*;
use std::mem;
use super::*;

pub struct Parser {}

#[derive(PartialEq, Debug)]
pub enum ParseError {
    BadLength,
    DefaultError,
}

fn is_vlan(eth_type: u16) -> bool {
    if (eth_type == EtherType::Vlan8021Q as u16) || (eth_type == EtherType::Vlan8021AD as u16) {
        return true;
    }
    return false;
}

fn is_mpls(eth_type: u16) -> bool {
    if (eth_type  == EtherType::Mpls as u16) || (eth_type == EtherType::MplsMcast as u16) {
        return true;
    }
    return false;
}

fn parse_mpls <'a>(data: &'a[u8], mpls_labels: &mut [u32; MAX_MPLS_LABELS]) -> (&'a[u8], usize) {
    let mut count: usize = 0;
    let mut offset: usize = 0;

    while (data.len() - offset) >= MPLS_HEADER_SIZE {
        let mpls_header = MplsHeader {
            mpls_lse_hi_be: NativeEndian::read_u16(&data[offset..offset+2]),
            mpls_lse_lo_be: NativeEndian::read_u16(&data[offset+2..offset+4]),
        };
        offset += 4;

        if count < MAX_MPLS_LABELS {
            mpls_labels[count] = unsafe {
                mem::transmute_copy::<MplsHeader, u32>(&mpls_header)
            };
        }
        count += 1;

        if (mpls_header.mpls_lse_lo_be & (1_u16 << MPLS_BOS_SHIFT).to_be()) != 0  {
            break;
        }
    }

    return (&data[offset..], std::cmp::min(count, MAX_MPLS_LABELS));
}

fn parse_ethertype<'a>(data: &'a[u8]) -> (&'a[u8], u16) {
    let mut offset: usize = 0;

    let eth_type = BigEndian::read_u16(data);
    offset += ETH_TYPE_SIZE;

    if eth_type >= EtherType::Min as u16 {
        return (&data[offset..], eth_type);
    }

    if data[offset..].len() < LLC_SNAP_HEADER_SIZE {
        return (&data[offset..], EtherType::NotEth as u16);
    }

    let mut rest_data  = &data[offset..];
    let mut llc: LlcSnapHeader = Default::default();
    llc.llc_header.llc_dsap = rest_data[0];
    llc.llc_header.llc_ssap = rest_data[1];
    llc.llc_header.llc_cntl = rest_data[2];
    llc.snap_header.snap_org[0] = rest_data[3];
    llc.snap_header.snap_org[1] = rest_data[4];
    llc.snap_header.snap_org[2] = rest_data[5];
    llc.snap_header.snap_type = BigEndian::read_u16(&rest_data[6..8]);

    if llc.llc_header.llc_dsap != LLC_DSAP_SNAP
        || llc.llc_header.llc_ssap != LLC_SSAP_SNAP
        || llc.llc_header.llc_cntl != LLC_CNTL_SNAP
        || llc.snap_header.snap_org[0] != 0
        || llc.snap_header.snap_org[1] != 0
        || llc.snap_header.snap_org[2] != 0 {
        return (&data[offset..], EtherType::NotEth as u16);
    }

    rest_data = &rest_data[LLC_SNAP_HEADER_SIZE..];
    if llc.snap_header.snap_type >= EtherType::Min as u16 {
        return (&rest_data, llc.snap_header.snap_type);
    }

    return (&rest_data, EtherType::NotEth as u16);
}

fn parse_vlan<'a>(data: &'a[u8], vlan_hdrs: &mut [u32; MAX_VLAN_HEADERS]) -> (&'a[u8], usize) {
    let mut eth_type = BigEndian::read_u16(data);
    let mut offset : usize = 0;
    let mut n : usize = 0;

    while  is_vlan(eth_type) && n < MAX_VLAN_HEADERS {
        if data.len() < ETH_TYPE_SIZE + VLAN_HEADER_SIZE {
            break;
        }

        let mut vlan_hdr = VlanHeader { qtag_be: 0 };
        vlan_hdr.qtag2.tpid_be = NativeEndian::read_u16(&data[offset..offset+2]);
        offset += 2;
        vlan_hdr.qtag2.tci_be = NativeEndian::read_u16(&data[offset..offset+2]);
        offset += 2;

        unsafe {
            vlan_hdrs[n] = vlan_hdr.qtag_be;
        }
        eth_type = BigEndian::read_u16(&data[offset..offset+2]);
        n += 1;
    }
    return (&data[offset..], n);
}

fn parse_dp_packet<'a>(data: &'a[u8], mf: &mut miniflow::mf_ctx) -> Result<&'a[u8], ParseError> {
    let mut offset: usize = 0;
    let mut dl_type: u16 = 0xFFFF;

    // TODO: metadata

    // L2, ethernet
    // TODO: L3 packet without L2 header packet_type != PT_ETH
    if data.len() < ETH_HEADER_SIZE {
        return Err(ParseError::BadLength);
    }

    miniflow_push_macs!(mf, dl_dst, &data);
    offset += 2 * ETH_ADDR_SIZE;

    /* Parse VLAN */
    let mut vlan_hdrs: [u32; MAX_VLAN_HEADERS] = [0; MAX_VLAN_HEADERS];
    let (mut rest, n_vlans) = parse_vlan(&data[offset..], &mut vlan_hdrs);

    /* Parse ether type, LLC + SNAP. */
    let (rest, dl_type) = parse_ethertype(rest);
    miniflow_push_be16!(mf, dl_type, dl_type.to_be());
    miniflow_pad_to_64!(mf, dl_type);

    if n_vlans > 0 {
        miniflow_push_words_32!(mf, vlans, &vlan_hdrs , n_vlans);
    }

    /* Parse MPLS */
    if is_mpls(dl_type) {
        // TODO: set l2_5_ofs
        let mut mpls_labels: [u32; MAX_MPLS_LABELS] = [0; MAX_MPLS_LABELS];
        let (rest, count) = parse_mpls(rest, &mut mpls_labels);
        miniflow_push_words_32!(mf, mpls_lse, &mpls_labels, count);
    }

    // TODO:L3
    // TODO:L4
    Ok(&data[offset..])
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::miniflow::*;

    #[test]
    fn l2_bad_length() {
        let mut mf: Miniflow = Miniflow::new();
        let mut mfx = &mut mf_ctx::from_mf(mf.map, &mut mf.values);

        let data = [0x00, 0x01, 0x02, 0x03];
        assert_eq!(parse_dp_packet(&data, &mut mfx).err(), Some(ParseError::BadLength));
    }

    #[test]
    fn l2_ethernet() {
        let mut mf: miniflow::Miniflow = miniflow::Miniflow::new();
        let mut mfx = &mut mf_ctx::from_mf(mf.map, &mut mf.values);

        let data = [0x00, 0x11, 0x22, 0x33, 0x44, 0x55, /* dst MAC */
                    0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, /* src MAC */
                    0x08, 0x00];                        /* EtherType */
        assert_eq!(parse_dp_packet(&data, &mut mfx).is_ok(), true);

        let expected: &mut [u64] =
            &mut [0x7766554433221100, 0x0008bbaa9988, 0, 0, 0, 0, 0, 0, 0, 0,
                    0, 0, 0, 0, 0, 0, 0, 0, 0, 0];
        assert_eq!(mfx.data, expected);
        assert_eq!(mfx.map.bits, [0x6000000, 0]);
    }

    #[test]
    fn l2_vlan() {
        let mut mf: miniflow::Miniflow = miniflow::Miniflow::new();
        let mut mfx = &mut mf_ctx::from_mf(mf.map, &mut mf.values);

        let data = [0x00, 0x11, 0x22, 0x33, 0x44, 0x55, /* dst MAC */
                    0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, /* src MAC */
                    0x81, 0x00,                         /* vlan: TPID */
                    0x01, 0xFF,                         /* vlan: TCI */
                    0x08, 0x00];                        /* EtherType */
        assert_eq!(parse_dp_packet(&data, &mut mfx).is_ok(), true);

        let expected: &mut [u64] =
            &mut [0x7766554433221100, 0x0008bbaa9988, 0xFF010081, 0, 0, 0, 0, 0, 0, 0,
                    0, 0, 0, 0, 0, 0, 0, 0, 0, 0];
        assert_eq!(mfx.data, expected);
    }

    #[test]
    fn l2_vlan_double_tagging() {
        let mut mf: miniflow::Miniflow = miniflow::Miniflow::new();
        let mut mfx = &mut mf_ctx::from_mf(mf.map, &mut mf.values);

        let data = [0x00, 0x11, 0x22, 0x33, 0x44, 0x55, /* dst MAC */
                    0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, /* src MAC */
                    0x88, 0xA8,                         /* vlan: TPID */
                    0x01, 0xFF,                         /* vlan: TCI */
                    0x81, 0x00,                         /* vlan: TPID */
                    0x02, 0xFF,                         /* vlan: TCI */
                    0x08, 0x00];                        /* EtherType */
        assert_eq!(parse_dp_packet(&data, &mut mfx).is_ok(), true);

        let expected: &mut [u64] =
            &mut [0x7766554433221100, 0x0008bbaa9988, 0xFF020081FF01A888, 0, 0, 0, 0, 0, 0, 0,
                    0, 0, 0, 0, 0, 0, 0, 0, 0, 0];
        assert_eq!(mfx.data, expected);
    }

    #[test]
    fn l2_mpls() {
        let mut mf: miniflow::Miniflow = miniflow::Miniflow::new();
        let mut mfx = &mut mf_ctx::from_mf(mf.map, &mut mf.values);

        let data = [0x00, 0x11, 0x22, 0x33, 0x44, 0x55, /* dst MAC */
                    0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, /* src MAC */
                    0x88, 0x47,                         /* EtherType (MPLS) */
                    0x00, 0x11, 0x00, 0x22,
                    0x00, 0x11, 0x00, 0x33,
                    0x00, 0x11, 0x00, 0x44,
                    0x00, 0x11, 0x01, 0x55];
        assert_eq!(parse_dp_packet(&data, &mut mfx).is_ok(), true);

        let expected: &mut [u64] =
            &mut [0x7766554433221100, 0x4788bbaa9988, 0x3300110022001100, 0x44001100,
                    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0];
        assert_eq!(mfx.data, expected);
    }

    #[test]
    fn l2_llc_snap() {
        let mut mf: miniflow::Miniflow = miniflow::Miniflow::new();
        let mut mfx = &mut mf_ctx::from_mf(mf.map, &mut mf.values);

        let data = [0x00, 0x11, 0x22, 0x33, 0x44, 0x55, /* dst MAC */
                    0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, /* src MAC */
                    0x00, 0x10,                         /* Length */
                    0xaa, 0xaa, 0x03,                   /* LLC */
                    0x00, 0x00, 0x00, 0x09, 0x00,       /* SNAP */
                    0x00, 0x11, 0x00, 0x44,
                    0x00, 0x11, 0x01, 0x55];
        assert_eq!(parse_dp_packet(&data, &mut mfx).is_ok(), true);

        let expected: &mut [u64] =
            &mut [0x7766554433221100, 0x0009bbaa9988, 0, 0,
                    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0];
        assert_eq!(mfx.data, expected);
    }

}
