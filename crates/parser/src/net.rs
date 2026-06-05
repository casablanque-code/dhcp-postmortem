// net.rs — Ethernet → IP → protocol dispatch

use nom::{bytes::complete::take, number::complete::{be_u8, be_u16, be_u32}, IResult};

pub const PROTO_OSPF: u8 = 89;
pub const PROTO_UDP:  u8 = 17;
pub const ETHERTYPE_IP: u16 = 0x0800;

pub const DHCP_SERVER_PORT: u16 = 67;
pub const DHCP_CLIENT_PORT: u16 = 68;
pub const ETHERTYPE_8021Q: u16 = 0x8100;
pub const ETHERTYPE_8021AD: u16 = 0x88a8; // Q-in-Q outer tag

#[derive(Debug, Clone)]
pub struct IpHeader {
    pub src: [u8; 4],
    pub dst: [u8; 4],
    pub protocol: u8,
    pub ttl: u8,
}

impl IpHeader {
    pub fn src_str(&self) -> String {
        format!("{}.{}.{}.{}", self.src[0], self.src[1], self.src[2], self.src[3])
    }
    pub fn dst_str(&self) -> String {
        format!("{}.{}.{}.{}", self.dst[0], self.dst[1], self.dst[2], self.dst[3])
    }
}

/// Снимаем Ethernet хедер, возвращаем IP payload
pub fn strip_ethernet(input: &[u8]) -> Option<&[u8]> {
    if input.len() < 14 {
        return None;
    }
    // dst MAC (6) + src MAC (6) = 12 байт
    let ethertype_bytes = &input[12..14];
    let ethertype = u16::from_be_bytes([ethertype_bytes[0], ethertype_bytes[1]]);

    match ethertype {
        e if e == ETHERTYPE_IP => Some(&input[14..]),
        e if e == ETHERTYPE_8021Q => {
            // 802.1Q: 4 байта VLAN tag, потом снова ethertype
            if input.len() < 18 {
                return None;
            }
            let inner_et = u16::from_be_bytes([input[16], input[17]]);
            if inner_et == ETHERTYPE_IP {
                Some(&input[18..])
            } else {
                None
            }
        }
        _ => None,
    }
}

fn parse_ip_header(input: &[u8]) -> IResult<&[u8], (IpHeader, &[u8])> {
    let (input, ver_ihl) = be_u8(input)?;
    let ihl = ((ver_ihl & 0x0f) * 4) as usize;

    if ihl < 20 {
        return Err(nom::Err::Error(nom::error::Error::new(
            input,
            nom::error::ErrorKind::Verify,
        )));
    }

    let (input, _dscp_ecn) = be_u8(input)?;
    let (input, total_len) = be_u16(input)?;
    let (input, _ident) = be_u16(input)?;
    let (input, _flags_frag) = be_u16(input)?;
    let (input, ttl) = be_u8(input)?;
    let (input, protocol) = be_u8(input)?;
    let (input, _checksum) = be_u16(input)?;
    let (input, src_raw) = take(4usize)(input)?;
    let (input, dst_raw) = take(4usize)(input)?;

    let src = [src_raw[0], src_raw[1], src_raw[2], src_raw[3]];
    let dst = [dst_raw[0], dst_raw[1], dst_raw[2], dst_raw[3]];

    // Пропускаем IP options если есть
    let options_len = ihl - 20;
    let (input, _) = take(options_len)(input)?;

    // Payload = total_len - ihl
    let payload_len = (total_len as usize).saturating_sub(ihl);
    let (input, payload) = take(payload_len)(input)?;

    Ok((input, (IpHeader { src, dst, protocol, ttl }, payload)))
}

/// Главная функция — из сырого Ethernet-фрейма достаём IP хедер и payload
pub fn extract_ip(frame: &[u8]) -> Option<(IpHeader, &[u8])> {
    let ip_data = strip_ethernet(frame)?;
    parse_ip_header(ip_data).ok().map(|(_, result)| result)
}

/// Из IP payload (proto=UDP) достаём (src_port, dst_port, udp_payload)
pub fn extract_udp(payload: &[u8]) -> Option<(u16, u16, &[u8])> {
    if payload.len() < 8 { return None; }
    let src_port = u16::from_be_bytes([payload[0], payload[1]]);
    let dst_port = u16::from_be_bytes([payload[2], payload[3]]);
    let length   = u16::from_be_bytes([payload[4], payload[5]]) as usize;
    // length включает 8-байтный заголовок UDP
    if length < 8 || length > payload.len() { return None; }
    let udp_payload = &payload[8..length];
    Some((src_port, dst_port, udp_payload))
}

/// Проверяем что порты соответствуют DHCP трафику
pub fn is_dhcp_port(src: u16, dst: u16) -> bool {
    matches!(
        (src, dst),
        (DHCP_CLIENT_PORT, DHCP_SERVER_PORT) | // Discover/Request от клиента
        (DHCP_SERVER_PORT, DHCP_CLIENT_PORT) | // Offer/ACK/NAK от сервера
        (DHCP_SERVER_PORT, DHCP_SERVER_PORT)   // relay agent → server
    )
}
