#!/usr/bin/env python3
"""
dhcp-postmortem dataset generator
Requires: scapy (pip install scapy)

Generates 6 pcap scenarios covering common DHCP failure modes.
"""

from scapy.all import *
from scapy.layers.dhcp import DHCP, BOOTP
from scapy.layers.l2 import Ether
from scapy.layers.inet import IP, UDP
import os, random, struct

OUT = "dataset"
os.makedirs(OUT, exist_ok=True)

def mac(s): return s
def xid(): return random.randint(0x10000000, 0xFFFFFFFF)

def dhcp_discover(client_mac, transaction_id, ts):
    return (
        Ether(src=client_mac, dst="ff:ff:ff:ff:ff:ff") /
        IP(src="0.0.0.0", dst="255.255.255.255") /
        UDP(sport=68, dport=67) /
        BOOTP(chaddr=bytes.fromhex(client_mac.replace(":", "")), xid=transaction_id, flags=0x8000) /
        DHCP(options=[("message-type", "discover"), "end"])
    )

def dhcp_offer(server_mac, server_ip, client_mac, transaction_id, offered_ip, lease_time=86400):
    return (
        Ether(src=server_mac, dst=client_mac) /
        IP(src=server_ip, dst="255.255.255.255") /
        UDP(sport=67, dport=68) /
        BOOTP(op=2, chaddr=bytes.fromhex(client_mac.replace(":", "")),
              xid=transaction_id, yiaddr=offered_ip, siaddr=server_ip) /
        DHCP(options=[
            ("message-type", "offer"),
            ("server_id", server_ip),
            ("lease_time", lease_time),
            "end"
        ])
    )

def dhcp_request(client_mac, transaction_id, requested_ip, server_ip):
    return (
        Ether(src=client_mac, dst="ff:ff:ff:ff:ff:ff") /
        IP(src="0.0.0.0", dst="255.255.255.255") /
        UDP(sport=68, dport=67) /
        BOOTP(chaddr=bytes.fromhex(client_mac.replace(":", "")), xid=transaction_id, flags=0x8000) /
        DHCP(options=[
            ("message-type", "request"),
            ("requested_addr", requested_ip),
            ("server_id", server_ip),
            "end"
        ])
    )

def dhcp_ack(server_mac, server_ip, client_mac, transaction_id, assigned_ip, lease_time=86400):
    return (
        Ether(src=server_mac, dst=client_mac) /
        IP(src=server_ip, dst="255.255.255.255") /
        UDP(sport=67, dport=68) /
        BOOTP(op=2, chaddr=bytes.fromhex(client_mac.replace(":", "")),
              xid=transaction_id, yiaddr=assigned_ip, siaddr=server_ip) /
        DHCP(options=[
            ("message-type", "ack"),
            ("server_id", server_ip),
            ("lease_time", lease_time),
            "end"
        ])
    )

def dhcp_nak(server_mac, server_ip, client_mac, transaction_id):
    return (
        Ether(src=server_mac, dst=client_mac) /
        IP(src=server_ip, dst="255.255.255.255") /
        UDP(sport=67, dport=68) /
        BOOTP(op=2, chaddr=bytes.fromhex(client_mac.replace(":", "")), xid=transaction_id) /
        DHCP(options=[("message-type", "nak"), ("server_id", server_ip), "end"])
    )

# ── Scenario 1: Clean DORA ────────────────────────────────────────────────────
def scenario_01():
    pkts = []
    t = 0.0
    for i in range(3):
        cmac = f"aa:bb:cc:dd:ee:{i+1:02x}"
        tx = xid()
        ip = f"192.168.1.{10+i}"
        pkts.append(dhcp_discover(cmac, tx, t))
        t += 0.1
        pkts.append(dhcp_offer("00:11:22:33:44:55", "192.168.1.1", cmac, tx, ip))
        t += 0.05
        pkts.append(dhcp_request(cmac, tx, ip, "192.168.1.1"))
        t += 0.05
        pkts.append(dhcp_ack("00:11:22:33:44:55", "192.168.1.1", cmac, tx, ip))
        t += 0.5
    path = f"{OUT}/01-clean-dora"
    os.makedirs(path, exist_ok=True)
    wrpcap(f"{path}/capture.pcap", pkts)
    print(f"[+] 01-clean-dora: {len(pkts)} packets")

# ── Scenario 2: Rogue DHCP Server ────────────────────────────────────────────
def scenario_02():
    pkts = []
    cmac = "aa:bb:cc:dd:ee:01"
    tx = xid()
    pkts.append(dhcp_discover(cmac, tx, 0.0))
    # Легитимный сервер
    pkts.append(dhcp_offer("00:11:22:33:44:55", "192.168.1.1", cmac, tx, "192.168.1.10"))
    # Rogue сервер отвечает тоже
    pkts.append(dhcp_offer("de:ad:be:ef:00:01", "10.0.0.1", cmac, tx, "10.0.0.100"))
    pkts.append(dhcp_request(cmac, tx, "192.168.1.10", "192.168.1.1"))
    pkts.append(dhcp_ack("00:11:22:33:44:55", "192.168.1.1", cmac, tx, "192.168.1.10"))
    path = f"{OUT}/02-rogue-server"
    os.makedirs(path, exist_ok=True)
    wrpcap(f"{path}/capture.pcap", pkts)
    print(f"[+] 02-rogue-server: {len(pkts)} packets")

# ── Scenario 3: DHCP Starvation ───────────────────────────────────────────────
def scenario_03():
    pkts = []
    # Attacker floods Discover с разными MAC
    for i in range(50):
        cmac = f"aa:bb:cc:{i//256:02x}:{i%256:02x}:ff"
        tx = xid()
        pkts.append(dhcp_discover(cmac, tx, i * 0.05))
    # Легитимный клиент — сервер уже не отвечает (pool exhausted)
    cmac_legit = "11:22:33:44:55:66"
    tx_legit = xid()
    for _ in range(3):  # ретранзмиты
        pkts.append(dhcp_discover(cmac_legit, tx_legit, 3.0))
    path = f"{OUT}/03-starvation"
    os.makedirs(path, exist_ok=True)
    wrpcap(f"{path}/capture.pcap", pkts)
    print(f"[+] 03-starvation: {len(pkts)} packets")

# ── Scenario 4: NAK Storm ─────────────────────────────────────────────────────
def scenario_04():
    pkts = []
    cmac = "aa:bb:cc:dd:ee:01"
    srv_mac = "00:11:22:33:44:55"
    srv_ip = "192.168.1.1"
    # Клиент просит IP из неправильной подсети — получает NAK в цикле
    for i in range(5):
        tx = xid()
        pkts.append(dhcp_discover(cmac, tx, i * 1.0))
        pkts.append(dhcp_offer(srv_mac, srv_ip, cmac, tx, "192.168.1.10"))
        pkts.append(dhcp_request(cmac, tx, "10.0.0.50", srv_ip))  # неверный IP
        pkts.append(dhcp_nak(srv_mac, srv_ip, cmac, tx))
    path = f"{OUT}/04-nak-storm"
    os.makedirs(path, exist_ok=True)
    wrpcap(f"{path}/capture.pcap", pkts)
    print(f"[+] 04-nak-storm: {len(pkts)} packets")

# ── Scenario 5: Server Unreachable ───────────────────────────────────────────
def scenario_05():
    from scapy.utils import PcapWriter
    # Client sends Discover, no one replies (retransmits at 2, 6, 14 sec)
    # Use PcapWriter to preserve real timestamps
    timed = []
    base = 1700000000.0
    for cmac in ["aa:bb:cc:dd:ee:01", "aa:bb:cc:dd:ee:02"]:
        tx = xid()
        for delay in [0.0, 2.0, 6.0, 14.0]:
            pkt = dhcp_discover(cmac, tx, delay)
            timed.append((base + delay, pkt))

    path = f"{OUT}/05-server-unreachable"
    os.makedirs(path, exist_ok=True)
    fpath = f"{path}/capture.pcap"
    with PcapWriter(fpath, sync=True) as pw:
        for ts, pkt in timed:
            pkt.time = ts
            pw.write(pkt)
    print(f"[+] 05-server-unreachable: {len(timed)} packets")

# ── Scenario 6: IP Conflict ───────────────────────────────────────────────────
def scenario_06():
    pkts = []
    srv_mac = "00:11:22:33:44:55"
    srv_ip  = "192.168.1.1"
    # Два клиента получают один и тот же IP (баг в пуле сервера)
    for i, cmac in enumerate(["aa:bb:cc:dd:ee:01", "aa:bb:cc:dd:ee:02"]):
        tx = xid()
        pkts.append(dhcp_discover(cmac, tx, i * 0.1))
        pkts.append(dhcp_offer(srv_mac, srv_ip, cmac, tx, "192.168.1.50"))
        pkts.append(dhcp_request(cmac, tx, "192.168.1.50", srv_ip))
        pkts.append(dhcp_ack(srv_mac, srv_ip, cmac, tx, "192.168.1.50"))
    path = f"{OUT}/06-ip-conflict"
    os.makedirs(path, exist_ok=True)
    wrpcap(f"{path}/capture.pcap", pkts)
    print(f"[+] 06-ip-conflict: {len(pkts)} packets")

if __name__ == "__main__":
    scenario_01()
    scenario_02()
    scenario_03()
    scenario_04()
    scenario_05()
    scenario_06()
    print("\n[✓] All datasets generated in ./dataset/")
