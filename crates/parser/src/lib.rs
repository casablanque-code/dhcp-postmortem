#![allow(dead_code, unused_imports, unused_variables)]

mod pcap;
mod pcapng;
mod net;
mod dhcp;
mod analyzer;
mod root_cause;

use wasm_bindgen::prelude::*;
use analyzer::{Analyzer, TimedEvent, ReportSummary, classify_event, Severity};
use net::{PROTO_UDP, DHCP_SERVER_PORT, DHCP_CLIENT_PORT};

#[wasm_bindgen]
extern "C" {
    #[wasm_bindgen(js_namespace = console)]
    fn log(s: &str);
}

macro_rules! console_log {
    ($($t:tt)*) => (log(&format_args!($($t)*).to_string()))
}

#[wasm_bindgen]
pub fn analyze_pcap(data: &[u8]) -> Result<JsValue, JsValue> {
    let is_pcapng = data.len() >= 4 &&
        u32::from_le_bytes([data[0], data[1], data[2], data[3]]) == 0x0A0D0D0Au32;

    let unified: Vec<(u32, u32, Vec<u8>)> = if is_pcapng {
        console_log!("Detected PCAPng format");
        pcapng::parse_pcapng(data)
            .map_err(|e| JsValue::from_str(e.as_str()))?
    } else {
        console_log!("Detected legacy PCAP format");
        let (_, pkts) = pcap::iter_packets(data)
            .map_err(|e| JsValue::from_str(e.as_str()))?;
        pkts.iter().map(|p| (p.ts_sec, p.ts_usec, p.data.to_vec())).collect()
    };

    console_log!("Parsed: {} packets", unified.len());

    let mut analyzer = Analyzer::new();
    let mut events: Vec<TimedEvent> = Vec::new();
    let mut dhcp_count = 0usize;
    let mut last_ts = analyzer::Timestamp { sec: 0, usec: 0 };

    let first_ts = unified.first()
        .map(|(s, u, _)| *s as f64 + *u as f64 / 1e6)
        .unwrap_or(0.0);

    for (ts_sec, ts_usec, pkt_data) in &unified {
        let ts = analyzer::Timestamp { sec: *ts_sec, usec: *ts_usec };
        last_ts = ts;

        let Some((ip, payload)) = net::extract_ip(pkt_data) else { continue };
        if ip.protocol != PROTO_UDP { continue; }

        let Some((src_port, dst_port, udp_payload)) = net::extract_udp(payload) else { continue };
        if !net::is_dhcp_port(src_port, dst_port) { continue; }

        let Some(dhcp_pkt) = dhcp::parse_dhcp(udp_payload) else { continue };
        dhcp_count += 1;

        let src = ip.src_str();
        let dst = ip.dst_str();

        let new_events = analyzer.process(&dhcp_pkt, &src, &dst, ts);
        for ev in new_events {
            let severity = classify_event(&ev);
            events.push(TimedEvent { ts: ts.to_f64(), event: ev, severity });
        }
    }

    let final_events = analyzer.finalize(last_ts);
    for ev in final_events {
        let severity = classify_event(&ev);
        events.push(TimedEvent { ts: last_ts.to_f64(), event: ev, severity });
    }

    let root_cause = root_cause::correlate(&events);

    let anomalies = events.iter().filter(|e|
        matches!(e.severity, Severity::Warning | Severity::Critical)
    ).count();

    let leases_acquired = events.iter().filter(|e|
        matches!(e.event, analyzer::DhcpEvent::LeaseAcquired { .. })
    ).count();

    let rogue_servers = events.iter().filter(|e|
        matches!(e.event, analyzer::DhcpEvent::RogueServerDetected { .. })
    ).count();

    let nak_count = events.iter().filter(|e|
        matches!(e.event, analyzer::DhcpEvent::NakReceived { .. })
    ).count();

    let timeouts = events.iter().filter(|e|
        matches!(e.event, analyzer::DhcpEvent::LeaseTimeout { .. })
    ).count();

    let conflicts = events.iter().filter(|e|
        matches!(e.event, analyzer::DhcpEvent::IpConflict { .. } | analyzer::DhcpEvent::LeaseConflict { .. })
    ).count();

    let clients_seen = {
        let mut macs = std::collections::HashSet::new();
        for te in &events {
            match &te.event {
                analyzer::DhcpEvent::ClientDiscovered { client_mac, .. } => { macs.insert(client_mac.clone()); }
                _ => {}
            }
        }
        macs.len()
    };

    let report = FullReport {
        total_packets: unified.len(),
        dhcp_packets: dhcp_count,
        duration_sec: last_ts.to_f64() - first_ts,
        events,
        summary: ReportSummary {
            clients_seen,
            leases_acquired,
            anomalies,
            rogue_servers,
            nak_count,
            timeouts,
            conflicts,
        },
        root_cause,
    };

    serde_wasm_bindgen::to_value(&report).map_err(|e| JsValue::from_str(&e.to_string()))
}

#[derive(serde::Serialize)]
struct FullReport {
    total_packets: usize,
    dhcp_packets: usize,
    duration_sec: f64,
    events: Vec<TimedEvent>,
    summary: ReportSummary,
    root_cause: root_cause::RootCauseReport,
}

pub use analyzer::Timestamp;
