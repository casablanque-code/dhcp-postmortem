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
