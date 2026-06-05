// analyzer.rs — DHCP FSM + детекция аномалий
// Структура аналогична ospf-postmortem/analyzer.rs

use std::collections::HashMap;
use crate::dhcp::DhcpPacket;
use serde::{Serialize, Deserialize};

// ── Timestamp — 1:1 с ospf-postmortem ────────────────────────────────────────

#[derive(Debug, Clone, Copy)]
pub struct Timestamp {
    pub sec: u32,
    pub usec: u32,
}

impl Timestamp {
    pub fn to_f64(&self) -> f64 {
        self.sec as f64 + self.usec as f64 / 1_000_000.0
    }
    pub fn diff_ms(&self, other: &Timestamp) -> f64 {
        (self.to_f64() - other.to_f64()) * 1000.0
    }
}

// ── События — DHCP аналог OspfEvent ──────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type")]
pub enum DhcpEvent {
    /// Клиент начал DORA (Discover)
    ClientDiscovered {
        ts: f64,
        xid: u32,
        client_mac: String,
        src_ip: String,
    },
    /// Сервер ответил Offer
    OfferReceived {
        ts: f64,
        xid: u32,
        client_mac: String,
        offered_ip: String,
        server_ip: String,
    },
    /// Клиент отправил Request
    RequestSent {
        ts: f64,
        xid: u32,
        client_mac: String,
        requested_ip: String,
        server_ip: String,
    },
    /// Сервер подтвердил — lease выдан
    LeaseAcquired {
        ts: f64,
        xid: u32,
        client_mac: String,
        assigned_ip: String,
        server_ip: String,
        lease_time: u32,
    },
    /// Сервер отказал
    NakReceived {
        ts: f64,
        xid: u32,
        client_mac: String,
        server_ip: String,
    },
    /// Два Offer на один xid от разных серверов → rogue
    RogueServerDetected {
        ts: f64,
        xid: u32,
        client_mac: String,
        legitimate_server: String,
        rogue_server: String,
    },
    /// Discover flood — признак starvation атаки
    DiscoverFlood {
        ts: f64,
        discover_count: usize,
        window_ms: f64,
        unique_macs: usize,
    },
    /// IP конфликт — один IP выдан двум разным MAC
    IpConflict {
        ts: f64,
        conflicting_ip: String,
        mac_a: String,
        mac_b: String,
        server_ip: String,
    },
    /// Lease конфликт — ACK на IP уже в активной аренде
    LeaseConflict {
        ts: f64,
        xid: u32,
        client_mac: String,
        conflicting_ip: String,
    },
    /// Клиент не получил Offer (server unreachable)
    LeaseTimeout {
        ts: f64,
        xid: u32,
        client_mac: String,
        discover_ts: f64,
        elapsed_ms: f64,
    },
    /// FSM переход
    StateTransition {
        ts: f64,
        xid: u32,
        client_mac: String,
        from_state: String,
        to_state: String,
    },
}

// ── FSM состояния клиента (RFC 2131) ─────────────────────────────────────────

#[derive(Debug, Clone, PartialEq)]
pub enum DhcpClientState {
    Init,
    Selecting,
    Requesting,
    Bound,
    Renewing,
    Rebinding,
    Expired,
}

impl DhcpClientState {
    pub fn as_str(&self) -> &'static str {
        match self {
            DhcpClientState::Init       => "Init",
            DhcpClientState::Selecting  => "Selecting",
            DhcpClientState::Requesting => "Requesting",
            DhcpClientState::Bound      => "Bound",
            DhcpClientState::Renewing   => "Renewing",
            DhcpClientState::Rebinding  => "Rebinding",
            DhcpClientState::Expired    => "Expired",
        }
    }
}

// ── Состояние одной транзакции (xid) ─────────────────────────────────────────

#[derive(Debug, Clone)]
struct TransactionState {
    xid: u32,
    client_mac: String,
    fsm_state: DhcpClientState,
    discover_ts: Timestamp,
    offers: Vec<String>,        // src_ip серверов приславших Offer
    requested_ip: Option<String>,
    assigned_ip: Option<String>,
    server_ip: Option<String>,
    nak_count: u8,
    last_ts: Timestamp,
}

// ── Трекер Discover flood ─────────────────────────────────────────────────────

#[derive(Debug, Clone)]
struct DiscoverTracker {
    window_start: Timestamp,
    count: usize,
    unique_macs: std::collections::HashSet<String>,
}

// ── Основной анализатор ───────────────────────────────────────────────────────

pub struct Analyzer {
    /// xid → состояние транзакции
    transactions: HashMap<u32, TransactionState>,
    /// assigned_ip → client_mac (для детекции IP конфликтов)
    active_leases: HashMap<String, String>,
    /// flood трекер
    discover_tracker: DiscoverTracker,
    /// порог Discover flood (пакетов за 5 секунд)
    flood_threshold: usize,
    /// xid уже сгенеривших flood событие
    flood_reported: std::collections::HashSet<String>,
}

impl Analyzer {
    pub fn new() -> Self {
        Analyzer {
            transactions: HashMap::new(),
            active_leases: HashMap::new(),
            discover_tracker: DiscoverTracker {
                window_start: Timestamp { sec: 0, usec: 0 },
                count: 0,
                unique_macs: std::collections::HashSet::new(),
            },
            flood_threshold: 20,
            flood_reported: std::collections::HashSet::new(),
        }
    }

    /// Обрабатываем один DHCP пакет, возвращаем список событий
    pub fn process(&mut self, pkt: &DhcpPacket, src_ip: &str, _dst_ip: &str, ts: Timestamp) -> Vec<DhcpEvent> {
        use crate::dhcp::DhcpMessageType::*;
        let mut events = Vec::new();

        match pkt.msg_type {
            // ── DISCOVER ─────────────────────────────────────────────────────
            Discover => {
                let client_mac = pkt.client_mac_str();

                // Flood детектор: скользящее окно 5 секунд
                let window_ms = 5_000.0;
                let elapsed = ts.diff_ms(&self.discover_tracker.window_start);
                if elapsed > window_ms {
                    // Сбрасываем окно
                    self.discover_tracker.window_start = ts;
                    self.discover_tracker.count = 0;
                    self.discover_tracker.unique_macs.clear();
                }
                self.discover_tracker.count += 1;
                self.discover_tracker.unique_macs.insert(client_mac.clone());

                if self.discover_tracker.count >= self.flood_threshold {
                    let window_key = format!("{}", self.discover_tracker.window_start.sec);
                    if !self.flood_reported.contains(&window_key) {
                        self.flood_reported.insert(window_key);
                        events.push(DhcpEvent::DiscoverFlood {
                            ts: ts.to_f64(),
                            discover_count: self.discover_tracker.count,
                            window_ms,
                            unique_macs: self.discover_tracker.unique_macs.len(),
                        });
                    }
                }

                // Если транзакция с этим xid уже есть — клиент ретрансмитит,
                // обновляем timestamp но не создаём новое событие Discovered
                if self.transactions.contains_key(&pkt.xid) {
                    if let Some(tx) = self.transactions.get_mut(&pkt.xid) {
                        tx.last_ts = ts;
                    }
                    return events;
                }

                // Новая транзакция
                self.transactions.insert(pkt.xid, TransactionState {
                    xid: pkt.xid,
                    client_mac: client_mac.clone(),
                    fsm_state: DhcpClientState::Selecting,
                    discover_ts: ts,
                    offers: Vec::new(),
                    requested_ip: None,
                    assigned_ip: None,
                    server_ip: None,
                    nak_count: 0,
                    last_ts: ts,
                });

                events.push(DhcpEvent::ClientDiscovered {
                    ts: ts.to_f64(),
                    xid: pkt.xid,
                    client_mac,
                    src_ip: src_ip.to_string(),
                });
            }

            // ── OFFER ────────────────────────────────────────────────────────
            Offer => {
                let offered_ip = pkt.yiaddr_str();
                let server_ip  = pkt.server_id_str()
                    .unwrap_or_else(|| src_ip.to_string());

                let tx = self.transactions.entry(pkt.xid).or_insert_with(|| {
                    // Offer без Discover в capture (начало захвата посередине сессии)
                    TransactionState {
                        xid: pkt.xid,
                        client_mac: pkt.client_mac_str(),
                        fsm_state: DhcpClientState::Selecting,
                        discover_ts: ts,
                        offers: Vec::new(),
                        requested_ip: None,
                        assigned_ip: None,
                        server_ip: None,
                        nak_count: 0,
                        last_ts: ts,
                    }
                });

                // Rogue server: уже был Offer от другого сервера на тот же xid
                if !tx.offers.is_empty() && !tx.offers.contains(&server_ip) {
                    let legitimate = tx.offers[0].clone();
                    events.push(DhcpEvent::RogueServerDetected {
                        ts: ts.to_f64(),
                        xid: pkt.xid,
                        client_mac: tx.client_mac.clone(),
                        legitimate_server: legitimate,
                        rogue_server: server_ip.clone(),
                    });
                }

                if !tx.offers.contains(&server_ip) {
                    tx.offers.push(server_ip.clone());
                }

                // FSM: Selecting → Selecting (ждём ещё Offer или Request клиента)
                tx.last_ts = ts;

                events.push(DhcpEvent::OfferReceived {
                    ts: ts.to_f64(),
                    xid: pkt.xid,
                    client_mac: tx.client_mac.clone(),
                    offered_ip,
                    server_ip,
                });
            }

            // ── REQUEST ──────────────────────────────────────────────────────
            Request => {
                let client_mac   = pkt.client_mac_str();
                let requested_ip = pkt.requested_ip_str()
                    .or_else(|| {
                        // В Renew/Rebind requested_ip не заполнен, берём ciaddr
                        let ci = pkt.ciaddr_str();
                        if ci == "0.0.0.0" { None } else { Some(ci) }
                    })
                    .unwrap_or_else(|| "0.0.0.0".to_string());
                let server_ip = pkt.server_id_str()
                    .unwrap_or_else(|| "0.0.0.0".to_string());

                let tx = self.transactions.entry(pkt.xid).or_insert_with(|| {
                    TransactionState {
                        xid: pkt.xid,
                        client_mac: client_mac.clone(),
                        fsm_state: DhcpClientState::Selecting,
                        discover_ts: ts,
                        offers: Vec::new(),
                        requested_ip: None,
                        assigned_ip: None,
                        server_ip: None,
                        nak_count: 0,
                        last_ts: ts,
                    }
                });

                let from = tx.fsm_state.as_str().to_string();
                tx.fsm_state = DhcpClientState::Requesting;
                tx.requested_ip = Some(requested_ip.clone());
                tx.server_ip = Some(server_ip.clone());
                tx.last_ts = ts;

                events.push(DhcpEvent::StateTransition {
                    ts: ts.to_f64(),
                    xid: pkt.xid,
                    client_mac: tx.client_mac.clone(),
                    from_state: from,
                    to_state: "Requesting".to_string(),
                });

                events.push(DhcpEvent::RequestSent {
                    ts: ts.to_f64(),
                    xid: pkt.xid,
                    client_mac: tx.client_mac.clone(),
                    requested_ip,
                    server_ip,
                });
            }

            // ── ACK ──────────────────────────────────────────────────────────
            Ack => {
                let assigned_ip = pkt.yiaddr_str();
                let server_ip   = pkt.server_id_str()
                    .unwrap_or_else(|| src_ip.to_string());
                let lease_time  = pkt.lease_time.unwrap_or(86400);

                let tx = self.transactions.entry(pkt.xid).or_insert_with(|| {
                    TransactionState {
                        xid: pkt.xid,
                        client_mac: pkt.client_mac_str(),
                        fsm_state: DhcpClientState::Requesting,
                        discover_ts: ts,
                        offers: Vec::new(),
                        requested_ip: None,
                        assigned_ip: None,
                        server_ip: None,
                        nak_count: 0,
                        last_ts: ts,
                    }
                });

                // IP конфликт: этот IP уже выдан другому MAC
                if assigned_ip != "0.0.0.0" {
                    if let Some(existing_mac) = self.active_leases.get(&assigned_ip) {
                        if *existing_mac != tx.client_mac {
                            // Lease conflict: сервер выдаёт уже занятый адрес
                            events.push(DhcpEvent::LeaseConflict {
                                ts: ts.to_f64(),
                                xid: pkt.xid,
                                client_mac: tx.client_mac.clone(),
                                conflicting_ip: assigned_ip.clone(),
                            });
                            // Если это второй ACK на тот же IP разным клиентам — IP конфликт
                            events.push(DhcpEvent::IpConflict {
                                ts: ts.to_f64(),
                                conflicting_ip: assigned_ip.clone(),
                                mac_a: existing_mac.clone(),
                                mac_b: tx.client_mac.clone(),
                                server_ip: server_ip.clone(),
                            });
                        }
                    }

                    // Обновляем таблицу активных lease
                    self.active_leases.insert(assigned_ip.clone(), tx.client_mac.clone());
                }

                let from = tx.fsm_state.as_str().to_string();
                tx.fsm_state = DhcpClientState::Bound;
                tx.assigned_ip = Some(assigned_ip.clone());
                tx.last_ts = ts;

                events.push(DhcpEvent::StateTransition {
                    ts: ts.to_f64(),
                    xid: pkt.xid,
                    client_mac: tx.client_mac.clone(),
                    from_state: from,
                    to_state: "Bound".to_string(),
                });

                events.push(DhcpEvent::LeaseAcquired {
                    ts: ts.to_f64(),
                    xid: pkt.xid,
                    client_mac: tx.client_mac.clone(),
                    assigned_ip,
                    server_ip,
                    lease_time,
                });
            }

            // ── NAK ──────────────────────────────────────────────────────────
            Nak => {
                let server_ip = pkt.server_id_str()
                    .unwrap_or_else(|| src_ip.to_string());

                let tx = self.transactions.entry(pkt.xid).or_insert_with(|| {
                    TransactionState {
                        xid: pkt.xid,
                        client_mac: pkt.client_mac_str(),
                        fsm_state: DhcpClientState::Requesting,
                        discover_ts: ts,
                        offers: Vec::new(),
                        requested_ip: None,
                        assigned_ip: None,
                        server_ip: None,
                        nak_count: 0,
                        last_ts: ts,
                    }
                });

                tx.nak_count += 1;
                tx.fsm_state = DhcpClientState::Init; // клиент уйдёт в новый Discover
                tx.last_ts = ts;

                events.push(DhcpEvent::NakReceived {
                    ts: ts.to_f64(),
                    xid: pkt.xid,
                    client_mac: tx.client_mac.clone(),
                    server_ip,
                });
            }

            // ── RELEASE ──────────────────────────────────────────────────────
            Release => {
                let released_ip = pkt.ciaddr_str();
                // Удаляем из активных lease
                self.active_leases.remove(&released_ip);
                if let Some(tx) = self.transactions.get_mut(&pkt.xid) {
                    tx.fsm_state = DhcpClientState::Init;
                    tx.last_ts = ts;
                }
                // Release — info, отдельного события нет, StateTransition достаточно
                events.push(DhcpEvent::StateTransition {
                    ts: ts.to_f64(),
                    xid: pkt.xid,
                    client_mac: pkt.client_mac_str(),
                    from_state: "Bound".to_string(),
                    to_state: "Init".to_string(),
                });
            }

            // ── DECLINE / INFORM / Unknown — пропускаем ──────────────────────
            _ => {}
        }

        events
    }

    /// Финализация — проверяем незавершённые транзакции
    pub fn finalize(&mut self, last_ts: Timestamp) -> Vec<DhcpEvent> {
        let mut events = Vec::new();
        // 10 секунд без Offer → server unreachable
        let timeout_ms = 10_000.0;

        for (_xid, tx) in &self.transactions {
            if tx.fsm_state == DhcpClientState::Selecting {
                let elapsed = last_ts.diff_ms(&tx.discover_ts);
                if elapsed > timeout_ms {
                    events.push(DhcpEvent::LeaseTimeout {
                        ts: last_ts.to_f64(),
                        xid: tx.xid,
                        client_mac: tx.client_mac.clone(),
                        discover_ts: tx.discover_ts.to_f64(),
                        elapsed_ms: elapsed,
                    });
                }
            }
        }
        events
    }
}

// ── Отчёт — аналог ospf-postmortem ───────────────────────────────────────────

#[derive(Debug, Serialize, Deserialize)]
pub struct TimedEvent {
    pub ts: f64,
    pub event: DhcpEvent,
    pub severity: Severity,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum Severity {
    Info,
    Warning,
    Critical,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct ReportSummary {
    pub clients_seen: usize,
    pub leases_acquired: usize,
    pub anomalies: usize,
    pub rogue_servers: usize,
    pub nak_count: usize,
    pub timeouts: usize,
    pub conflicts: usize,
}

pub fn classify_event(event: &DhcpEvent) -> Severity {
    match event {
        DhcpEvent::RogueServerDetected { .. } => Severity::Critical,
        DhcpEvent::IpConflict { .. }          => Severity::Critical,
        DhcpEvent::DiscoverFlood { .. }       => Severity::Critical,
        DhcpEvent::LeaseConflict { .. }       => Severity::Warning,
        DhcpEvent::NakReceived { .. }         => Severity::Warning,
        DhcpEvent::LeaseTimeout { .. }        => Severity::Warning,
        _                                     => Severity::Info,
    }
}
