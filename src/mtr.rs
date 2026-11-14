fn icmp_matches_udp_port(buf: &[u8], src_port: u16, dst_port: u16, is_v6: bool) -> bool {
    if is_v6 {
        if buf.len() < 52 || buf[0] != 3 {
            return false;
        }
        let s_port = u16::from_be_bytes([buf[48], buf[49]]);
        let d_port = u16::from_be_bytes([buf[50], buf[51]]);
        s_port == src_port && d_port == dst_port
    } else {
        if buf.len() < 52 {
            return false;
        }
        let ihl = ((buf[0] & 0x0F) as usize) * 4;
        if buf.len() < ihl + 8 + 20 + 4 || buf[ihl] != 11 {
            return false;
        }
        let inner_ip_start = ihl + 8;
        let inner_ihl = ((buf[inner_ip_start] & 0x0F) as usize) * 4;
        let udp_start = inner_ip_start + inner_ihl;
        if buf.len() < udp_start + 4 {
            return false;
        }
        let s_port = u16::from_be_bytes([buf[udp_start], buf[udp_start + 1]]);
        let d_port = u16::from_be_bytes([buf[udp_start + 2], buf[udp_start + 3]]);
        s_port == src_port && d_port == dst_port
    }
}