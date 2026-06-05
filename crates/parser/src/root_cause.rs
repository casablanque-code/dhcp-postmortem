// root_cause.rs — корреляция событий в причинно-следственные цепочки
// Структура 1:1 с ospf-postmortem, детекторы DHCP-специфичные

#![allow(unused_imports, unused_variables, dead_code)]

use std::collections::HashMap;
use serde::{Serialize, Deserialize};
use crate::analyzer::{TimedEvent, DhcpEvent, Severity};

// ── Типы — идентичны ospf-postmortem ─────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum RootCauseKind {
    RogueServer,
    Starvation,
    LeaseConflict,
    NakStorm,
    ServerUnreachable,
    IpConflict,
    Clean,
}

impl RootCauseKind {
    pub fn title(&self) -> &'static str {
        match self {
            RootCauseKind::RogueServer       => "Rogue DHCP Server",
            RootCauseKind::Starvation        => "DHCP Starvation Attack",
            RootCauseKind::LeaseConflict     => "Lease Conflict",
            RootCauseKind::NakStorm          => "NAK Storm",
            RootCauseKind::ServerUnreachable => "Server Unreachable",
            RootCauseKind::IpConflict        => "IP Address Conflict",
            RootCauseKind::Clean             => "No Issues Detected",
        }
    }
}

/// Один шаг в причинно-следственной цепочке — 1:1 с ospf-postmortem
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ChainStep {
    pub ts: f64,
    pub event_type: String,
    pub description: String,
    pub role: ChainRole,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum ChainRole {
    Cause,
    Effect,
    Context,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, PartialOrd)]
pub enum RootCauseSeverity {
    Info,
    Warning,
    Critical,
}

/// Ссылка на событие в timeline — 1:1 с ospf-postmortem
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EvidenceRef {
    pub ts: f64,
    pub event_type: String,
    pub description: String,
}

/// Одна первопричина — 1:1 с ospf-postmortem
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RootCause {
    pub kind: RootCauseKind,
    pub severity: RootCauseSeverity,
    pub headline: String,
    pub impact: String,
    pub remediation: String,
    pub evidence: Vec<EvidenceRef>,
    pub secondary_effects: Vec<String>,
    pub affected_clients: Vec<String>,
    pub first_seen: f64,
    pub last_seen: f64,
    pub confidence: u8,
    pub confidence_reason: String,
    pub causal_chain: Vec<ChainStep>,
}

/// Итоговый отчёт — 1:1 с ospf-postmortem
#[derive(Debug, Serialize, Deserialize)]
pub struct RootCauseReport {
    pub causes: Vec<RootCause>,
    pub verdict: String,
    pub stable: bool,       // аналог converged
    pub action_plan: Vec<String>,
}

// ── Correlator ────────────────────────────────────────────────────────────────

pub fn correlate(events: &[TimedEvent]) -> RootCauseReport {
    let mut causes: Vec<RootCause> = Vec::new();

    if let Some(c) = detect_rogue_server(events)      { causes.push(c); }
    if let Some(c) = detect_starvation(events)         { causes.push(c); }
    if let Some(c) = detect_lease_conflict(events)     { causes.push(c); }
    if let Some(c) = detect_nak_storm(events)          { causes.push(c); }
    if let Some(c) = detect_server_unreachable(events) { causes.push(c); }
    if let Some(c) = detect_ip_conflict(events)        { causes.push(c); }

    causes.sort_by(|a, b| b.severity.partial_cmp(&a.severity).unwrap());

    let stable      = assess_stability(events);
    let verdict     = build_verdict(&causes, stable);
    let action_plan = build_action_plan(&causes);

    if causes.is_empty() {
        causes.push(RootCause {
            kind: RootCauseKind::Clean,
            severity: RootCauseSeverity::Info,
            headline: "DHCP operating normally".into(),
            impact: "All leases acquired via clean DORA exchange. No anomalies detected.".into(),
            remediation: "No action required.".into(),
            evidence: Vec::new(),
            secondary_effects: Vec::new(),
            affected_clients: Vec::new(),
            first_seen: 0.0,
            last_seen: 0.0,
            confidence: 90,
            confidence_reason: "No anomalous patterns detected across full capture window.".into(),
            causal_chain: Vec::new(),
        });
    }

    RootCauseReport { causes, verdict, stable, action_plan }
}

// ── Детекторы ─────────────────────────────────────────────────────────────────

fn detect_rogue_server(events: &[TimedEvent]) -> Option<RootCause> {
    let rogue_events: Vec<&TimedEvent> = events.iter()
        .filter(|e| matches!(e.event, DhcpEvent::RogueServerDetected { .. }))
        .collect();

    if rogue_events.is_empty() { return None; }

    let first_seen = rogue_events.first().unwrap().ts;
    let last_seen  = rogue_events.last().unwrap().ts;

    let mut affected_clients = Vec::new();
    let mut evidence = Vec::new();

    for te in &rogue_events {
        if let DhcpEvent::RogueServerDetected { client_mac, rogue_server, legitimate_server, xid, .. } = &te.event {
            if !affected_clients.contains(client_mac) {
                affected_clients.push(client_mac.clone());
            }
            evidence.push(EvidenceRef {
                ts: te.ts,
                event_type: "RogueServerDetected".into(),
                description: format!(
                    "xid=0x{:08x} client={} — rogue {} vs legitimate {}",
                    xid, client_mac, rogue_server, legitimate_server
                ),
            });
        }
    }

    // Строим causal chain из первого инцидента
    let mut chain = Vec::new();
    if let DhcpEvent::RogueServerDetected { xid, client_mac, legitimate_server, rogue_server, .. } =
        &rogue_events[0].event
    {
        chain.push(ChainStep {
            ts: first_seen,
            event_type: "ClientDiscovered".into(),
            description: format!("Client {} sent DHCPDISCOVER (xid=0x{:08x})", client_mac, xid),
            role: ChainRole::Context,
        });
        chain.push(ChainStep {
            ts: first_seen,
            event_type: "RogueServerDetected".into(),
            description: format!(
                "Rogue server {} sent competing OFFER (legitimate: {})",
                rogue_server, legitimate_server
            ),
            role: ChainRole::Cause,
        });
        chain.push(ChainStep {
            ts: last_seen,
            event_type: "SecurityRisk".into(),
            description: "Client may receive incorrect gateway/DNS — traffic interception risk".into(),
            role: ChainRole::Effect,
        });
    }

    Some(RootCause {
        kind: RootCauseKind::RogueServer,
        severity: RootCauseSeverity::Critical,
        headline: format!(
            "Rogue DHCP server detected — {} client(s) affected",
            affected_clients.len()
        ),
        impact: "Clients may be assigned attacker-controlled gateway/DNS, enabling MITM attacks and traffic interception.".into(),
        remediation: "Enable DHCP snooping on all access-layer switches. Locate rogue server by MAC/port — run `show ip dhcp snooping binding`. Isolate the port immediately.".into(),
        evidence,
        secondary_effects: vec![
            "Incorrect default gateway assigned".into(),
            "DNS hijacking possible".into(),
            "Traffic interception via ARP poisoning".into(),
        ],
        affected_clients,
        first_seen,
        last_seen,
        confidence: 95,
        confidence_reason: "Direct observation of two OFFER responses to identical xid from different servers.".into(),
        causal_chain: chain,
    })
}

fn detect_starvation(events: &[TimedEvent]) -> Option<RootCause> {
    let flood_events: Vec<&TimedEvent> = events.iter()
        .filter(|e| matches!(e.event, DhcpEvent::DiscoverFlood { .. }))
        .collect();

    if flood_events.is_empty() { return None; }

    let first_seen = flood_events.first().unwrap().ts;
    let last_seen  = flood_events.last().unwrap().ts;

    let mut max_count = 0usize;
    let mut max_macs  = 0usize;
    let mut evidence  = Vec::new();

    for te in &flood_events {
        if let DhcpEvent::DiscoverFlood { discover_count, unique_macs, window_ms, .. } = &te.event {
            if *discover_count > max_count { max_count = *discover_count; }
            if *unique_macs > max_macs     { max_macs  = *unique_macs; }
            evidence.push(EvidenceRef {
                ts: te.ts,
                event_type: "DiscoverFlood".into(),
                description: format!(
                    "{} DISCOVER in {:.0}ms window from {} unique MACs",
                    discover_count, window_ms, unique_macs
                ),
            });
        }
    }

    // Также добавляем timeout события как подтверждение (легит клиенты не получили lease)
    for te in events.iter().filter(|e| matches!(e.event, DhcpEvent::LeaseTimeout { .. })) {
        if let DhcpEvent::LeaseTimeout { client_mac, elapsed_ms, .. } = &te.event {
            evidence.push(EvidenceRef {
                ts: te.ts,
                event_type: "LeaseTimeout".into(),
                description: format!(
                    "Client {} failed to get lease after {:.0}ms — pool likely exhausted",
                    client_mac, elapsed_ms
                ),
            });
        }
    }

    let confidence = if max_macs > 10 { 90u8 } else { 70u8 };
    let confidence_reason = if max_macs > 10 {
        format!("{} unique MACs in flood window strongly indicates spoofed MAC starvation attack", max_macs)
    } else {
        format!("Flood pattern detected but only {} unique MACs — may be misconfigured client", max_macs)
    };

    let chain = vec![
        ChainStep {
            ts: first_seen,
            event_type: "DiscoverFlood".into(),
            description: format!("Attacker sends {} DISCOVER with spoofed MACs", max_count),
            role: ChainRole::Cause,
        },
        ChainStep {
            ts: first_seen + 0.1,
            event_type: "PoolExhaustion".into(),
            description: "DHCP server pool exhausted — no addresses available for legitimate clients".into(),
            role: ChainRole::Effect,
        },
        ChainStep {
            ts: last_seen,
            event_type: "LeaseTimeout".into(),
            description: "Legitimate clients fail to obtain IP — network access denied (DoS)".into(),
            role: ChainRole::Effect,
        },
    ];

    Some(RootCause {
        kind: RootCauseKind::Starvation,
        severity: RootCauseSeverity::Critical,
        headline: format!(
            "DHCP starvation attack — {} DISCOVER/5s from {} MACs",
            max_count, max_macs
        ),
        impact: "DHCP pool exhausted. Legitimate clients cannot obtain IP addresses (Denial of Service).".into(),
        remediation: "Enable DHCP snooping + rate limiting: `ip dhcp snooping limit rate 10` on access ports. Investigate source port via MAC table.".into(),
        evidence,
        secondary_effects: vec![
            "New clients cannot join network".into(),
            "DHCP pool fully consumed".into(),
        ],
        affected_clients: Vec::new(), // атакующий MAC спуфит, конкретных клиентов нет
        first_seen,
        last_seen,
        confidence,
        confidence_reason,
        causal_chain: chain,
    })
}

fn detect_lease_conflict(events: &[TimedEvent]) -> Option<RootCause> {
    let conflict_events: Vec<&TimedEvent> = events.iter()
        .filter(|e| matches!(e.event, DhcpEvent::LeaseConflict { .. }))
        .collect();

    if conflict_events.is_empty() { return None; }

    let first_seen = conflict_events.first().unwrap().ts;
    let last_seen  = conflict_events.last().unwrap().ts;

    let mut affected_clients = Vec::new();
    let mut evidence = Vec::new();

    for te in &conflict_events {
        if let DhcpEvent::LeaseConflict { client_mac, conflicting_ip, xid, .. } = &te.event {
            if !affected_clients.contains(client_mac) {
                affected_clients.push(client_mac.clone());
            }
            evidence.push(EvidenceRef {
                ts: te.ts,
                event_type: "LeaseConflict".into(),
                description: format!(
                    "xid=0x{:08x} client={} — ACK for {} which is already leased",
                    xid, client_mac, conflicting_ip
                ),
            });
        }
    }

    Some(RootCause {
        kind: RootCauseKind::LeaseConflict,
        severity: RootCauseSeverity::Warning,
        headline: format!(
            "Lease conflict on {} address(es) — server pool inconsistency",
            conflict_events.len()
        ),
        impact: "Multiple clients assigned the same IP. Will cause ARP conflicts and intermittent connectivity loss.".into(),
        remediation: "Run `clear ip dhcp conflict *` on server. Check for static IPs overlapping the DHCP pool. Review pool exclusions.".into(),
        evidence,
        secondary_effects: vec![
            "ARP table instability".into(),
            "Intermittent packet loss for affected clients".into(),
        ],
        affected_clients,
        first_seen,
        last_seen,
        confidence: 85,
        confidence_reason: "ACK observed for IP already tracked as active lease in this capture window.".into(),
        causal_chain: Vec::new(),
    })
}

fn detect_nak_storm(events: &[TimedEvent]) -> Option<RootCause> {
    // Группируем NAK по client_mac, ищем клиентов с 3+ NAK
    let mut nak_by_mac: HashMap<String, Vec<f64>> = HashMap::new();

    for te in events.iter().filter(|e| matches!(e.event, DhcpEvent::NakReceived { .. })) {
        if let DhcpEvent::NakReceived { client_mac, .. } = &te.event {
            nak_by_mac.entry(client_mac.clone()).or_default().push(te.ts);
        }
    }

    let storm_clients: Vec<(String, Vec<f64>)> = nak_by_mac
        .into_iter()
        .filter(|(_, ts_list)| ts_list.len() >= 3)
        .collect();

    if storm_clients.is_empty() { return None; }

    let first_seen = storm_clients.iter()
        .flat_map(|(_, ts_list)| ts_list.iter())
        .cloned()
        .fold(f64::MAX, f64::min);
    let last_seen = storm_clients.iter()
        .flat_map(|(_, ts_list)| ts_list.iter())
        .cloned()
        .fold(f64::MIN, f64::max);

    let affected_clients: Vec<String> = storm_clients.iter()
        .map(|(mac, _)| mac.clone())
        .collect();

    let mut evidence = Vec::new();
    for (mac, ts_list) in &storm_clients {
        evidence.push(EvidenceRef {
            ts: ts_list[0],
            event_type: "NakStorm".into(),
            description: format!(
                "Client {} received {} NAK responses — stuck in Discover→Request→NAK loop",
                mac, ts_list.len()
            ),
        });
    }

    Some(RootCause {
        kind: RootCauseKind::NakStorm,
        severity: RootCauseSeverity::Warning,
        headline: format!(
            "NAK storm — {} client(s) in repetitive NAK loop",
            affected_clients.len()
        ),
        impact: "Clients cannot obtain IP. Repeated NAK causes exponential backoff, degrading responsiveness.".into(),
        remediation: "Check if client is requesting IP from wrong subnet (after network change). Verify server pool range. Check for stale lease entries on server.".into(),
        evidence,
        secondary_effects: vec![
            "Client connectivity loss".into(),
            "Increased DHCP broadcast traffic".into(),
        ],
        affected_clients,
        first_seen,
        last_seen,
        confidence: 80,
        confidence_reason: "3+ consecutive NAK responses to same client MAC observed.".into(),
        causal_chain: Vec::new(),
    })
}

fn detect_server_unreachable(events: &[TimedEvent]) -> Option<RootCause> {
    let timeout_events: Vec<&TimedEvent> = events.iter()
        .filter(|e| matches!(e.event, DhcpEvent::LeaseTimeout { .. }))
        .collect();

    if timeout_events.is_empty() { return None; }

    // Только учитываем timeout без предшествующего flood (flood — отдельная причина)
    let has_flood = events.iter().any(|e| matches!(e.event, DhcpEvent::DiscoverFlood { .. }));

    let first_seen = timeout_events.first().unwrap().ts;
    let last_seen  = timeout_events.last().unwrap().ts;

    let mut affected_clients = Vec::new();
    let mut evidence = Vec::new();
    let mut max_elapsed = 0.0f64;

    for te in &timeout_events {
        if let DhcpEvent::LeaseTimeout { client_mac, elapsed_ms, discover_ts, .. } = &te.event {
            if !affected_clients.contains(client_mac) {
                affected_clients.push(client_mac.clone());
            }
            if *elapsed_ms > max_elapsed { max_elapsed = *elapsed_ms; }
            evidence.push(EvidenceRef {
                ts: te.ts,
                event_type: "LeaseTimeout".into(),
                description: format!(
                    "Client {} — no OFFER received after {:.0}ms (discover at {:.3}s)",
                    client_mac, elapsed_ms, discover_ts
                ),
            });
        }
    }

    let (severity, confidence, reason) = if has_flood {
        (
            RootCauseSeverity::Warning,
            60u8,
            "Timeout co-occurs with flood — likely pool exhaustion rather than server failure".into(),
        )
    } else {
        (
            RootCauseSeverity::Critical,
            85u8,
            format!("No OFFER received by any client in {:.0}ms — consistent with server/relay failure", max_elapsed),
        )
    };

    Some(RootCause {
        kind: RootCauseKind::ServerUnreachable,
        severity,
        headline: format!(
            "DHCP server unreachable — {} client(s) timed out without OFFER",
            affected_clients.len()
        ),
        impact: "Clients cannot obtain IP address. Network access fully denied.".into(),
        remediation: "Check DHCP server process (Windows: `Get-Service DHCPServer`, Linux: `systemctl status isc-dhcp-server`). Verify UDP 67/68 reachability. Check `ip helper-address` on router interfaces.".into(),
        evidence,
        secondary_effects: vec![
            "All new clients fail to join network".into(),
            "APIPA addresses assigned (169.254.x.x)".into(),
        ],
        affected_clients,
        first_seen,
        last_seen,
        confidence,
        confidence_reason: reason,
        causal_chain: Vec::new(),
    })
}

fn detect_ip_conflict(events: &[TimedEvent]) -> Option<RootCause> {
    let conflict_events: Vec<&TimedEvent> = events.iter()
        .filter(|e| matches!(e.event, DhcpEvent::IpConflict { .. }))
        .collect();

    if conflict_events.is_empty() { return None; }

    let first_seen = conflict_events.first().unwrap().ts;
    let last_seen  = conflict_events.last().unwrap().ts;

    let mut conflicting_ips: Vec<String> = Vec::new();
    let mut evidence = Vec::new();

    for te in &conflict_events {
        if let DhcpEvent::IpConflict { conflicting_ip, mac_a, mac_b, server_ip, .. } = &te.event {
            if !conflicting_ips.contains(conflicting_ip) {
                conflicting_ips.push(conflicting_ip.clone());
            }
            evidence.push(EvidenceRef {
                ts: te.ts,
                event_type: "IpConflict".into(),
                description: format!(
                    "IP {} assigned to both {} and {} by server {}",
                    conflicting_ip, mac_a, mac_b, server_ip
                ),
            });
        }
    }

    Some(RootCause {
        kind: RootCauseKind::IpConflict,
        severity: RootCauseSeverity::Critical,
        headline: format!(
            "IP address conflict — {} address(es) assigned to multiple clients",
            conflicting_ips.len()
        ),
        impact: "Duplicate IP causes ARP conflicts. Both clients lose connectivity intermittently. May corrupt ARP caches network-wide.".into(),
        remediation: "Run `show ip dhcp conflict` on server to see flagged addresses. Clear with `clear ip dhcp conflict <ip>`. Check for static assignments overlapping pool. Review pool ranges and exclusions.".into(),
        evidence,
        secondary_effects: vec![
            "ARP cache poisoning on local segment".into(),
            "Packet loss for both conflicting clients".into(),
            "Intermittent connectivity for entire subnet".into(),
        ],
        affected_clients: conflicting_ips,
        first_seen,
        last_seen,
        confidence: 95,
        confidence_reason: "Server sent ACK for same IP to two different MAC addresses within capture window.".into(),
        causal_chain: Vec::new(),
    })
}

// ── Helpers — аналогичны ospf-postmortem ─────────────────────────────────────

fn assess_stability(events: &[TimedEvent]) -> bool {
    if events.is_empty() { return true; }
    let first = events.first().unwrap().ts;
    let last  = events.last().unwrap().ts;
    let window_start = first + (last - first) * 0.8;
    let late_anomalies = events.iter().filter(|e|
        e.ts >= window_start &&
        matches!(e.severity, Severity::Warning | Severity::Critical)
    ).count();
    late_anomalies == 0
}

fn build_verdict(causes: &[RootCause], stable: bool) -> String {
    if causes.is_empty() {
        return "DHCP operating normally. No anomalies detected.".into();
    }
    let critical: Vec<_> = causes.iter().filter(|c| c.severity == RootCauseSeverity::Critical).collect();
    let warnings: Vec<_> = causes.iter().filter(|c| c.severity == RootCauseSeverity::Warning).collect();

    if !critical.is_empty() {
        let titles: Vec<_> = critical.iter().map(|c| c.kind.title()).collect();
        format!(
            "{} critical issue(s) detected: {}. {}",
            critical.len(),
            titles.join(", "),
            if stable { "DHCP may have recovered by end of capture." }
            else { "DHCP had NOT stabilized by end of capture." }
        )
    } else {
        let titles: Vec<_> = warnings.iter().map(|c| c.kind.title()).collect();
        format!(
            "{} warning(s): {}. {}",
            warnings.len(),
            titles.join(", "),
            if stable { "Network stable." } else { "Instability persisted." }
        )
    }
}

fn build_action_plan(causes: &[RootCause]) -> Vec<String> {
    let mut plan = Vec::new();
    for cause in causes {
        match cause.kind {
            RootCauseKind::RogueServer => {
                plan.push("1. URGENT: Locate and isolate rogue DHCP server — check `show ip dhcp server statistics` on all switches, enable DHCP snooping".into());
            }
            RootCauseKind::Starvation => {
                plan.push("2. URGENT: DHCP starvation detected — enable DHCP snooping + rate limiting on access ports, investigate source MAC".into());
            }
            RootCauseKind::IpConflict => {
                plan.push("3. Fix IP conflict — check DHCP pool for duplicate static assignments, verify exclusion ranges".into());
            }
            RootCauseKind::LeaseConflict => {
                plan.push("4. Fix lease conflict — clear conflicting leases, check for static IP assignments overlapping DHCP pool".into());
            }
            RootCauseKind::NakStorm => {
                plan.push("5. Investigate NAK storm — check client is requesting valid IP, verify server pool configuration".into());
            }
            RootCauseKind::ServerUnreachable => {
                plan.push("6. Check DHCP server availability — verify UDP 67/68 reachability, check helper-address config on routers".into());
            }
            RootCauseKind::Clean => {}
        }
    }
    if plan.is_empty() {
        plan.push("No action required.".into());
    }
    plan
}
