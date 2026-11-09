"""สร้าง synthetic traffic "ปกติ" สำหรับเทรนโมเดลใน demo (ไม่ต้องดัก traffic จริง)

จำลองบ้านที่มีเครื่อง LAN ไม่กี่เครื่อง: HTTPS เป็นหลัก, HTTP, DNS, QUIC, mDNS/SSDP เล็กน้อย
และ ICMP เฉพาะ error (dest unreachable / time exceeded) -- **ไม่มี ICMP echo (ping)**
เพื่อให้ ping ถูกมองว่าแปลก

ผลลัพธ์:
  data/normal_packets.csv   metadata ดิบ (คอลัมน์เดียวกับที่ capture-service โหมด csv บันทึก)
  data/normal_features.csv  feature ที่คำนวณผ่าน shared/features.py

รัน:  python training/generate_data.py [--n 8000] [--seed 42]
"""
from __future__ import annotations

import argparse
import csv
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / "system"))  # shared/, services/ อยู่ใน system/

import numpy as np  # noqa: E402

from shared.config import load_config, resolve_path  # noqa: E402
from shared.features import FEATURE_NAMES, PACKET_FIELDS, FeatureExtractor  # noqa: E402
from shared.utils import force_utf8  # noqa: E402
from collections import Counter  # noqa: E402

GATEWAY = "192.168.1.1"
# เครื่องในบ้าน: (ip, ttl เริ่มต้น, ช่วง ephemeral port ของ OS)
LAN_CLIENTS = [
    ("192.168.1.10", 128, (49152, 65535)),   # Windows
    ("192.168.1.11", 128, (49152, 65535)),   # Windows
    ("192.168.1.12", 64, (32768, 60999)),    # Linux / Android
    ("192.168.1.15", 64, (49152, 65535)),    # macOS / iOS
    ("192.168.1.20", 64, (49152, 65535)),    # มือถือ
    ("192.168.1.23", 64, (32768, 60999)),    # IoT / TV
]
IFACE = "eth0"


class Gen:
    """ตัวสร้าง packet — เก็บ packet ทั้งหมดไว้ใน self.pkts แล้วค่อย sort ตามเวลา"""

    def __init__(self, seed: int):
        self.rng = np.random.default_rng(seed)
        self.pkts: list[dict] = []
        # เซิร์ฟเวอร์ภายนอกสมมติ (CDN / เว็บ) + จำนวน hop ที่ต่างกัน
        self.servers = []
        for _ in range(40):
            ip = ".".join(str(int(x)) for x in (self.rng.choice([13, 23, 34, 52, 104, 142, 151, 172, 185]),
                                                 self.rng.integers(1, 255), self.rng.integers(1, 255),
                                                 self.rng.integers(1, 255)))
            base = int(self.rng.choice([64, 128, 255], p=[0.7, 0.2, 0.1]))
            self.servers.append((ip, base, int(self.rng.integers(6, 18))))

    # ---------- ตัวช่วย ----------
    def add(self, ts, src, dst, sport, dport, proto, length, ttl, flags=None, itype=None, icode=None):
        self.pkts.append({
            "ts": float(ts), "iface": IFACE, "src_ip": src, "dst_ip": dst,
            "src_port": sport, "dst_port": dport, "proto": proto, "length": int(length),
            "ttl": int(ttl), "tcp_flags": flags, "icmp_type": itype, "icmp_code": icode,
        })

    def client(self):
        return LAN_CLIENTS[int(self.rng.integers(len(LAN_CLIENTS)))]

    def server(self):
        return self.servers[int(self.rng.integers(len(self.servers)))]

    def eph(self, rng_ports):
        return int(self.rng.integers(rng_ports[0], rng_ports[1] + 1))

    def gap(self, mean=0.004):
        return float(self.rng.exponential(mean))

    # ---------- TCP session (HTTPS / HTTP / อื่นๆ) ----------
    def tcp_session(self, t0, client, server, dport, n_exchanges=None):
        cip, cttl, cports = client
        sip, sbase, hops = server
        sttl = sbase - hops                       # TTL ของ server ที่เห็นที่ฝั่งเรา
        sport = self.eph(cports)
        rng = self.rng
        t = t0
        syn_len = int(rng.choice([52, 60, 64], p=[0.5, 0.35, 0.15]))
        # three-way handshake
        self.add(t, cip, sip, sport, dport, "TCP", syn_len, cttl, 0x02)
        t += float(rng.uniform(0.008, 0.06))
        self.add(t, sip, cip, dport, sport, "TCP", int(rng.choice([52, 60])), sttl, 0x12)
        t += self.gap(0.001)
        self.add(t, cip, sip, sport, dport, "TCP", int(rng.choice([40, 52])), cttl, 0x10)

        n_ex = n_exchanges if n_exchanges is not None else int(rng.integers(1, 5))
        for _ in range(n_ex):
            t += float(rng.exponential(0.15)) + 0.002
            # client ส่ง request (ClientHello / HTTP GET / ข้อมูลใน TLS)
            req_len = int(np.clip(rng.lognormal(5.6, 0.7), 60, 1500))
            self.add(t, cip, sip, sport, dport, "TCP", req_len, cttl, 0x18)
            t += float(rng.uniform(0.01, 0.08))
            self.add(t, sip, cip, dport, sport, "TCP", int(rng.choice([40, 52])), sttl, 0x10)
            # server ตอบกลับเป็นหลาย segment (ส่วนใหญ่เต็ม MTU)
            n_seg = int(min(rng.geometric(0.25), 25))
            for i in range(n_seg):
                t += self.gap(0.0015)
                last = i == n_seg - 1
                ln = int(rng.integers(80, 1500)) if last else int(rng.choice([1500, 1492, 1448 + 52], p=[0.85, 0.1, 0.05]))
                self.add(t, sip, cip, dport, sport, "TCP", ln, sttl, 0x18 if last or rng.random() < 0.3 else 0x10)
                if i % 2 == 1 or last:
                    self.add(t + self.gap(0.0008) + 0.0003, cip, sip, sport, dport, "TCP",
                             int(rng.choice([40, 52])), cttl, 0x10)

        # ปิด connection: ส่วนใหญ่ FIN ปกติ, บางครั้ง RST
        t += float(rng.exponential(0.1)) + 0.002
        if rng.random() < 0.04:
            self.add(t, cip, sip, sport, dport, "TCP", 40, cttl, 0x14)
        else:
            self.add(t, cip, sip, sport, dport, "TCP", int(rng.choice([40, 52])), cttl, 0x11)
            t += float(rng.uniform(0.01, 0.05))
            self.add(t, sip, cip, dport, sport, "TCP", int(rng.choice([40, 52])), sttl, 0x11)
            t += self.gap(0.001)
            self.add(t, cip, sip, sport, dport, "TCP", int(rng.choice([40, 52])), cttl, 0x10)

    def page_load(self, t0):
        """เปิดเว็บ 1 หน้า = หลาย connection ขนานกันไปหลาย server (เหมือน browser จริง)"""
        client = self.client()
        k = int(min(self.rng.geometric(0.3), 12))
        for _ in range(k):
            dport = 443 if self.rng.random() < 0.9 else 80
            self.tcp_session(t0 + float(self.rng.uniform(0, 1.2)), client, self.server(), dport)

    # ---------- UDP ----------
    def dns(self, t0):
        cip, cttl, cports = self.client()
        sport = self.eph(cports)
        self.add(t0, cip, GATEWAY, sport, 53, "UDP", int(self.rng.integers(58, 90)), cttl)
        self.add(t0 + float(self.rng.uniform(0.002, 0.04)), GATEWAY, cip, 53, sport, "UDP",
                 int(self.rng.integers(76, 320)), 64)

    def mdns(self, t0):
        cip, _, _ = self.client()
        self.add(t0, cip, "224.0.0.251", 5353, 5353, "UDP", int(self.rng.integers(70, 220)), 255)

    def ssdp(self, t0):
        cip, _, cports = self.client()
        self.add(t0, cip, "239.255.255.250", self.eph(cports), 1900, "UDP", int(self.rng.integers(170, 400)), 4)

    def quic(self, t0):
        cip, cttl, cports = self.client()
        sip, sbase, hops = self.server()
        sport = self.eph(cports)
        t = t0
        for i in range(int(min(self.rng.geometric(0.15), 40))):
            if self.rng.random() < 0.4:
                self.add(t, cip, sip, sport, 443, "UDP",
                         1280 if i == 0 else int(self.rng.integers(60, 1280)), cttl)
            else:
                self.add(t, sip, cip, 443, sport, "UDP", int(self.rng.choice([1280, 1250, 80, 120])), sbase - hops)
            t += self.gap(0.003)

    def ntp(self, t0):
        cip, cttl, cports = self.client()
        sip, sbase, hops = self.server()
        sport = self.eph(cports)
        self.add(t0, cip, sip, sport, 123, "UDP", 76, cttl)
        self.add(t0 + float(self.rng.uniform(0.01, 0.08)), sip, cip, 123, sport, "UDP", 76, sbase - hops)

    def udp_misc(self, t0):
        """UDP พอร์ตสูง (VPN / เกม / video call) เล็กน้อย"""
        cip, cttl, cports = self.client()
        sip, sbase, hops = self.server()
        sport, dport = self.eph(cports), int(self.rng.integers(3478, 50000))
        t = t0
        for _ in range(int(min(self.rng.geometric(0.2), 20))):
            if self.rng.random() < 0.5:
                self.add(t, cip, sip, sport, dport, "UDP", int(self.rng.integers(80, 1400)), cttl)
            else:
                self.add(t, sip, cip, dport, sport, "UDP", int(self.rng.integers(80, 1400)), sbase - hops)
            t += self.gap(0.01)

    def tcp_other(self, t0):
        port = int(self.rng.choice([8080, 8443, 5228, 993, 587, 5222, 22]))
        self.tcp_session(t0, self.client(), self.server(), port, n_exchanges=int(self.rng.integers(1, 3)))

    # ---------- ICMP error (ไม่ใช่ echo) ----------
    def icmp_error(self, t0):
        """ICMP port unreachable (type 3) จากเกตเวย์ -- เจอน้อยมากใน traffic บ้านปกติ
        ต้องมีอย่างน้อยเล็กน้อย ไม่งั้นค่า proto_icmp/icmp_type จะคงที่ใน training แล้ว tree ไม่ใช้ feature นี้เลย"""
        cip, cttl, _ = self.client()
        self.add(t0, GATEWAY, cip, None, None, "ICMP", 576, 64, None, 3, 3)


# น้ำหนักต่อ "เหตุการณ์" (ไม่ใช่ต่อ packet) -- TCP session ยาวหลายสิบ packet จึงต้องมีน้อยเหตุการณ์
# เพื่อให้สัดส่วนต่อ packet ออกมาประมาณ: TCP ~80%, UDP ~20%, ICMP error ~0.3%
EVENT_MIX = [
    ("page_load", 0.075), ("tcp_http", 0.016), ("tcp_other", 0.02), ("dns", 0.56),
    ("quic", 0.065), ("mdns", 0.13), ("ssdp", 0.05), ("ntp", 0.013),
    ("udp_misc", 0.04), ("icmp_error", 0.03),
]


def generate(n_packets: int = 8000, seed: int = 42) -> list[dict]:
    """สร้าง traffic ปกติ n_packets ตัว คืน list ของ metadata dict เรียงตามเวลา (คีย์ตาม PACKET_FIELDS)"""
    g = Gen(seed)
    names = [n for n, _ in EVENT_MIX]
    probs = np.array([w for _, w in EVENT_MIX], dtype=float)
    probs /= probs.sum()
    t = 1_700_000_000.0
    while len(g.pkts) < n_packets * 1.05:
        t += float(g.rng.exponential(0.12))
        ev = names[int(g.rng.choice(len(names), p=probs))]
        if ev == "tcp_http":
            g.tcp_session(t, g.client(), g.server(), 80)
        else:
            getattr(g, ev)(t)
    pkts = sorted(g.pkts, key=lambda p: p["ts"])   # sorted เป็น stable
    return pkts[:n_packets]


def save_packets_csv(pkts: list[dict], path: Path) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with open(path, "w", newline="", encoding="utf-8") as f:
        w = csv.DictWriter(f, fieldnames=PACKET_FIELDS)
        w.writeheader()
        for p in pkts:
            w.writerow({k: ("" if p.get(k) is None else p[k]) for k in PACKET_FIELDS})


def load_packets_csv(path: Path) -> list[dict]:
    """อ่าน CSV metadata (ทั้งของ synthetic และที่ capture-service บันทึก) -> list[dict] พร้อมแปลงชนิดข้อมูล"""
    int_cols = ("src_port", "dst_port", "length", "ttl", "tcp_flags", "icmp_type", "icmp_code")
    out = []
    with open(path, newline="", encoding="utf-8") as f:
        for row in csv.DictReader(f):
            d = {"ts": float(row["ts"]), "iface": row["iface"], "src_ip": row["src_ip"],
                 "dst_ip": row["dst_ip"], "proto": row["proto"]}
            for c in int_cols:
                v = row.get(c, "")
                d[c] = None if v in ("", None) else int(float(v))
            out.append(d)
    return out


def save_features_csv(pkts: list[dict], X: np.ndarray, path: Path) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with open(path, "w", newline="", encoding="utf-8") as f:
        w = csv.writer(f)
        w.writerow(["ts", "src_ip", "dst_ip", *FEATURE_NAMES])
        for p, row in zip(pkts, X):
            w.writerow([p["ts"], p["src_ip"], p["dst_ip"], *[f"{v:g}" for v in row]])


def main() -> None:
    force_utf8()
    cfg = load_config()
    tcfg = cfg["training"]
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--n", type=int, default=tcfg["n_packets"], help="จำนวน packet")
    ap.add_argument("--seed", type=int, default=tcfg["seed"])
    args = ap.parse_args()

    pkts = generate(args.n, args.seed)
    # คำนวณ feature ผ่าน shared/features.py (ตัวเดียวกับ feature-service)
    X = FeatureExtractor(cfg["feature"]["window_sec"]).extract_many(pkts)

    p_csv = resolve_path(tcfg["packets_csv"])
    f_csv = resolve_path(tcfg["features_csv"])
    save_packets_csv(pkts, p_csv)
    save_features_csv(pkts, X, f_csv)

    n = len(pkts)
    print(f"สร้าง {n} packets (seed={args.seed})")
    print(f"  -> {p_csv}\n  -> {f_csv}")
    protos = Counter(p["proto"] for p in pkts)
    print("สัดส่วน protocol:", {k: round(v / n, 3) for k, v in protos.items()})
    dports = Counter(p["dst_port"] for p in pkts if p["dst_port"] is not None)
    print("dst port ยอดนิยม:", dict(dports.most_common(6)))
    echo = sum(1 for p in pkts if p["proto"] == "ICMP" and p["icmp_type"] in (0, 8))
    print("ICMP echo ในข้อมูล:", echo, "(ต้องเป็น 0)")


if __name__ == "__main__":
    main()
