// dhcp.rs — парсер DHCP пакетов (RFC 2131 + опции RFC 2132)
// Аналог ospf.rs

/// Тип DHCP сообщения (Option 53)
#[derive(Debug, Clone, PartialEq)]
pub enum DhcpMessageType {
    Discover,
    Offer,
    Request,
    Decline,
    Ack,
    Nak,
    Release,
    Inform,
    Unknown(u8),
}

impl DhcpMessageType {
    pub fn as_str(&self) -> &'static str {
        match self {
            DhcpMessageType::Discover    => "DHCPDISCOVER",
            DhcpMessageType::Offer       => "DHCPOFFER",
            DhcpMessageType::Request     => "DHCPREQUEST",
            DhcpMessageType::Decline     => "DHCPDECLINE",
            DhcpMessageType::Ack         => "DHCPACK",
            DhcpMessageType::Nak         => "DHCPNAK",
            DhcpMessageType::Release     => "DHCPRELEASE",
            DhcpMessageType::Inform      => "DHCPINFORM",
            DhcpMessageType::Unknown(_)  => "UNKNOWN",
        }
    }
}

/// Распарсенный DHCP пакет
#[derive(Debug, Clone)]
pub struct DhcpPacket {
    /// op: 1=BOOTREQUEST, 2=BOOTREPLY
    pub op: u8,
    /// Transaction ID
    pub xid: u32,
    /// Client MAC (chaddr, первые 6 байт)
    pub client_mac: [u8; 6],
    /// Client IP (ciaddr)
    pub ciaddr: [u8; 4],
    /// Your IP (yiaddr) — в Offer/ACK
    pub yiaddr: [u8; 4],
    /// Server IP (siaddr)
    pub siaddr: [u8; 4],
    /// Gateway IP (giaddr) — relay agent
    pub giaddr: [u8; 4],
    /// Тип сообщения из Option 53
    pub msg_type: DhcpMessageType,
    /// Requested IP (Option 50)
    pub requested_ip: Option<[u8; 4]>,
    /// Server Identifier (Option 54)
    pub server_id: Option<[u8; 4]>,
    /// Lease Time (Option 51)
    pub lease_time: Option<u32>,
}

impl DhcpPacket {
    pub fn client_mac_str(&self) -> String {
        format!("{:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}",
            self.client_mac[0], self.client_mac[1], self.client_mac[2],
            self.client_mac[3], self.client_mac[4], self.client_mac[5])
    }

    pub fn yiaddr_str(&self) -> String { bytes_to_ip(&self.yiaddr) }
    pub fn ciaddr_str(&self) -> String { bytes_to_ip(&self.ciaddr) }
    pub fn siaddr_str(&self) -> String { bytes_to_ip(&self.siaddr) }
    pub fn giaddr_str(&self) -> String { bytes_to_ip(&self.giaddr) }

    pub fn requested_ip_str(&self) -> Option<String> {
        self.requested_ip.map(|ip| bytes_to_ip(&ip))
    }
    pub fn server_id_str(&self) -> Option<String> {
        self.server_id.map(|ip| bytes_to_ip(&ip))
    }
}

pub fn bytes_to_ip(b: &[u8; 4]) -> String {
    format!("{}.{}.{}.{}", b[0], b[1], b[2], b[3])
}

const DHCP_MAGIC: [u8; 4] = [99, 130, 83, 99];

/// Парсим DHCP пакет из UDP payload
pub fn parse_dhcp(data: &[u8]) -> Option<DhcpPacket> {
    // Минимальный размер DHCP: 236 байт фиксированный заголовок + 4 байта magic
    if data.len() < 240 { return None; }

    let op  = data[0];
    // htype = data[1], hlen = data[2], hops = data[3]
    let xid = u32::from_be_bytes([data[4], data[5], data[6], data[7]]);
    // secs = data[8..10], flags = data[10..12]

    let ciaddr: [u8; 4] = data[12..16].try_into().ok()?;
    let yiaddr: [u8; 4] = data[16..20].try_into().ok()?;
    let siaddr: [u8; 4] = data[20..24].try_into().ok()?;
    let giaddr: [u8; 4] = data[24..28].try_into().ok()?;

    // chaddr: 16 байт, берём первые 6
    let client_mac: [u8; 6] = data[28..34].try_into().ok()?;

    // Проверяем DHCP magic cookie на offset 236
    if &data[236..240] != &DHCP_MAGIC { return None; }

    // Парсим опции
    let options = &data[240..];
    let (msg_type, requested_ip, server_id, lease_time) = parse_options(options);

    Some(DhcpPacket {
        op,
        xid,
        client_mac,
        ciaddr,
        yiaddr,
        siaddr,
        giaddr,
        msg_type,
        requested_ip,
        server_id,
        lease_time,
    })
}

fn parse_options(data: &[u8]) -> (DhcpMessageType, Option<[u8; 4]>, Option<[u8; 4]>, Option<u32>) {
    let mut msg_type    = DhcpMessageType::Unknown(0);
    let mut requested_ip = None;
    let mut server_id    = None;
    let mut lease_time   = None;

    let mut i = 0;
    while i < data.len() {
        let opt = data[i];
        match opt {
            255 => break,                   // End
            0   => { i += 1; continue; }    // Pad
            _ => {
                if i + 1 >= data.len() { break; }
                let len = data[i + 1] as usize;
                if i + 2 + len > data.len() { break; }
                let val = &data[i + 2..i + 2 + len];

                match opt {
                    53 if len == 1 => {
                        msg_type = match val[0] {
                            1 => DhcpMessageType::Discover,
                            2 => DhcpMessageType::Offer,
                            3 => DhcpMessageType::Request,
                            4 => DhcpMessageType::Decline,
                            5 => DhcpMessageType::Ack,
                            6 => DhcpMessageType::Nak,
                            7 => DhcpMessageType::Release,
                            8 => DhcpMessageType::Inform,
                            n => DhcpMessageType::Unknown(n),
                        };
                    }
                    50 if len == 4 => {
                        requested_ip = Some([val[0], val[1], val[2], val[3]]);
                    }
                    54 if len == 4 => {
                        server_id = Some([val[0], val[1], val[2], val[3]]);
                    }
                    51 if len == 4 => {
                        lease_time = Some(u32::from_be_bytes([val[0], val[1], val[2], val[3]]));
                    }
                    _ => {}
                }
                i += 2 + len;
            }
        }
    }

    (msg_type, requested_ip, server_id, lease_time)
}

#[cfg(test)]
mod tests {
    use super::*;

    const MAGIC: [u8; 4] = [99, 130, 83, 99];

    fn make_dhcp_packet(options: &[u8]) -> Vec<u8> {
        let mut pkt = vec![0u8; 240];
        pkt[0] = 1;
        pkt[4..8].copy_from_slice(&[0xde, 0xad, 0xbe, 0xef]);
        pkt[28..34].copy_from_slice(&[0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff]);
        pkt[12..16].copy_from_slice(&[192, 168, 1, 10]);
        pkt[16..20].copy_from_slice(&[192, 168, 1, 20]);
        pkt[236..240].copy_from_slice(&MAGIC);
        pkt.extend_from_slice(options);
        pkt
    }

    fn opt53(t: u8)     -> Vec<u8> { vec![53, 1, t] }
    fn opt50(ip: [u8;4])-> Vec<u8> { let mut v = vec![50, 4]; v.extend_from_slice(&ip); v }
    fn opt54(ip: [u8;4])-> Vec<u8> { let mut v = vec![54, 4]; v.extend_from_slice(&ip); v }
    fn opt51(s: u32)    -> Vec<u8> { let mut v = vec![51, 4]; v.extend_from_slice(&s.to_be_bytes()); v }
    fn end()            -> Vec<u8> { vec![255] }

    #[test]
    fn test_parse_discover() {
        let mut opts = opt53(1); opts.extend(end());
        let result = parse_dhcp(&make_dhcp_packet(&opts)).expect("should parse");
        assert_eq!(result.msg_type, DhcpMessageType::Discover);
        assert_eq!(result.xid, 0xdeadbeef);
        assert_eq!(result.op, 1);
    }

    #[test]
    fn test_parse_offer_with_server_id_and_lease() {
        let mut opts = opt53(2);
        opts.extend(opt54([192, 168, 1, 1]));
        opts.extend(opt51(86400));
        opts.extend(end());
        let result = parse_dhcp(&make_dhcp_packet(&opts)).unwrap();
        assert_eq!(result.msg_type, DhcpMessageType::Offer);
        assert_eq!(result.server_id, Some([192, 168, 1, 1]));
        assert_eq!(result.lease_time, Some(86400));
    }

    #[test]
    fn test_parse_request_with_requested_ip() {
        let mut opts = opt53(3);
        opts.extend(opt50([10, 0, 0, 100]));
        opts.extend(opt54([10, 0, 0, 1]));
        opts.extend(end());
        let result = parse_dhcp(&make_dhcp_packet(&opts)).unwrap();
        assert_eq!(result.msg_type, DhcpMessageType::Request);
        assert_eq!(result.requested_ip, Some([10, 0, 0, 100]));
        assert_eq!(result.server_id,    Some([10, 0, 0, 1]));
    }

    #[test]
    fn test_parse_ack()     { let mut o = opt53(5); o.extend(end()); assert_eq!(parse_dhcp(&make_dhcp_packet(&o)).unwrap().msg_type, DhcpMessageType::Ack); }
    #[test]
    fn test_parse_nak()     { let mut o = opt53(6); o.extend(end()); assert_eq!(parse_dhcp(&make_dhcp_packet(&o)).unwrap().msg_type, DhcpMessageType::Nak); }
    #[test]
    fn test_parse_release() { let mut o = opt53(7); o.extend(end()); assert_eq!(parse_dhcp(&make_dhcp_packet(&o)).unwrap().msg_type, DhcpMessageType::Release); }
    #[test]
    fn test_parse_decline() { let mut o = opt53(4); o.extend(end()); assert_eq!(parse_dhcp(&make_dhcp_packet(&o)).unwrap().msg_type, DhcpMessageType::Decline); }
    #[test]
    fn test_parse_inform()  { let mut o = opt53(8); o.extend(end()); assert_eq!(parse_dhcp(&make_dhcp_packet(&o)).unwrap().msg_type, DhcpMessageType::Inform); }

    #[test]
    fn test_unknown_msg_type() {
        let mut o = opt53(99); o.extend(end());
        assert!(matches!(parse_dhcp(&make_dhcp_packet(&o)).unwrap().msg_type, DhcpMessageType::Unknown(99)));
    }

    #[test]
    fn test_too_short_returns_none() {
        assert!(parse_dhcp(&vec![0u8; 200]).is_none());
    }

    #[test]
    fn test_wrong_magic_returns_none() {
        let mut pkt = make_dhcp_packet(&end());
        pkt[236] = 0xde;
        assert!(parse_dhcp(&pkt).is_none());
    }

    #[test]
    fn test_no_options_returns_unknown() {
        assert!(matches!(parse_dhcp(&make_dhcp_packet(&end())).unwrap().msg_type, DhcpMessageType::Unknown(0)));
    }

    #[test]
    fn test_pad_bytes_skipped() {
        let mut opts = vec![0u8, 0u8];
        opts.extend(opt53(1));
        opts.extend(end());
        assert_eq!(parse_dhcp(&make_dhcp_packet(&opts)).unwrap().msg_type, DhcpMessageType::Discover);
    }

    #[test]
    fn test_options_order_independent() {
        let mut opts = opt51(3600);
        opts.extend(opt54([172, 16, 0, 1]));
        opts.extend(opt50([172, 16, 0, 50]));
        opts.extend(opt53(3));
        opts.extend(end());
        let result = parse_dhcp(&make_dhcp_packet(&opts)).unwrap();
        assert_eq!(result.msg_type,     DhcpMessageType::Request);
        assert_eq!(result.lease_time,   Some(3600));
        assert_eq!(result.server_id,    Some([172, 16, 0, 1]));
        assert_eq!(result.requested_ip, Some([172, 16, 0, 50]));
    }

    #[test]
    fn test_truncated_option_no_panic() {
        let _ = parse_dhcp(&make_dhcp_packet(&vec![53, 4, 1, 2]));
    }

    #[test]
    fn test_client_mac_str() {
        assert_eq!(parse_dhcp(&make_dhcp_packet(&end())).unwrap().client_mac_str(), "aa:bb:cc:dd:ee:ff");
    }

    #[test]
    fn test_yiaddr_and_ciaddr() {
        let result = parse_dhcp(&make_dhcp_packet(&end())).unwrap();
        assert_eq!(result.yiaddr_str(), "192.168.1.20");
        assert_eq!(result.ciaddr_str(), "192.168.1.10");
    }

    #[test]
    fn test_xid_big_endian() {
        assert_eq!(parse_dhcp(&make_dhcp_packet(&end())).unwrap().xid, 0xdeadbeef);
    }

    #[test]
    fn test_server_id_str() {
        let mut opts = opt53(2); opts.extend(opt54([10, 1, 1, 1])); opts.extend(end());
        assert_eq!(parse_dhcp(&make_dhcp_packet(&opts)).unwrap().server_id_str(), Some("10.1.1.1".to_string()));
    }

    #[test]
    fn test_requested_ip_str() {
        let mut opts = opt53(3); opts.extend(opt50([192, 168, 100, 50])); opts.extend(end());
        assert_eq!(parse_dhcp(&make_dhcp_packet(&opts)).unwrap().requested_ip_str(), Some("192.168.100.50".to_string()));
    }

    #[test]
    fn test_bytes_to_ip() {
        assert_eq!(bytes_to_ip(&[192, 168, 1, 1]),       "192.168.1.1");
        assert_eq!(bytes_to_ip(&[0, 0, 0, 0]),           "0.0.0.0");
        assert_eq!(bytes_to_ip(&[255, 255, 255, 255]),   "255.255.255.255");
    }

    #[test]
    fn test_msg_type_as_str() {
        assert_eq!(DhcpMessageType::Discover.as_str(), "DHCPDISCOVER");
        assert_eq!(DhcpMessageType::Offer.as_str(),    "DHCPOFFER");
        assert_eq!(DhcpMessageType::Ack.as_str(),      "DHCPACK");
        assert_eq!(DhcpMessageType::Nak.as_str(),      "DHCPNAK");
        assert_eq!(DhcpMessageType::Unknown(42).as_str(), "UNKNOWN");
    }
}
