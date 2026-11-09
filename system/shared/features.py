"""แปลง packet metadata -> feature vector

ไฟล์นี้ใช้ร่วมกันทั้งตอนเทรน (training/) และตอนรันจริง (feature-service)
ห้ามแก้ลำดับ/ความหมายของ feature โดยไม่เทรนโมเดลใหม่ (เพิ่ม FEATURE_VERSION ด้วย)

feature ต่อ packet:
  - protocol one-hot (TCP / UDP / ICMP)
  - length, TTL
  - TCP flags แยกเป็นบิต (FIN SYN RST PSH ACK URG ECE CWR)
  - ICMP type
  - dst port bucket (well-known 0-1023 / registered 1024-49151 / dynamic 49152+ / none = ไม่มี port เช่น ICMP)
feature บริบท (sliding window ต่อ src IP, ค่าเริ่มต้น 5 วินาที):
  - จำนวน packet ที่ src นี้ส่ง, จำนวน dst port ไม่ซ้ำ, จำนวน dst IP ไม่ซ้ำ
  - ctx_low_ports = จำนวน dst port ไม่ซ้ำ "เฉพาะ port ที่ต่ำกว่า 49152" (port ของ service จริง)
    เพราะ server/gateway ที่ตอบกลับหลาย client จะมี dst port สูงๆ (ephemeral) เยอะตามปกติ ไม่ใช่การสแกน
    แต่ตัวสแกน (nmap) จะไล่ยิง port ของ service ต่ำๆ จำนวนมาก
"""
from __future__ import annotations

from collections import Counter, deque

import numpy as np

FEATURE_VERSION = 2

# คอลัมน์ metadata ดิบ (ตรงกับ PacketMsg และไฟล์ CSV ที่ capture-service บันทึก)
PACKET_FIELDS = [
    "ts", "iface", "src_ip", "dst_ip", "src_port", "dst_port",
    "proto", "length", "ttl", "tcp_flags", "icmp_type", "icmp_code",
]

TCP_FLAG_BITS = (
    ("fin", 0x01), ("syn", 0x02), ("rst", 0x04), ("psh", 0x08),
    ("ack", 0x10), ("urg", 0x20), ("ece", 0x40), ("cwr", 0x80),
)

FEATURE_NAMES = [
    "proto_tcp", "proto_udp", "proto_icmp",
    "length", "ttl",
    *[f"flag_{n}" for n, _ in TCP_FLAG_BITS],
    "icmp_type",
    "port_none", "port_wellknown", "port_registered", "port_dynamic",
    "ctx_pkts", "ctx_dst_ports", "ctx_dst_ips", "ctx_low_ports", "ctx_ip_ratio",
]
N_FEATURES = len(FEATURE_NAMES)


EPHEMERAL_START = 49152


def port_bucket(port) -> int:
    """0 = ไม่มี port, 1 = well-known, 2 = registered, 3 = dynamic"""
    if port is None:
        return 0
    port = int(port)
    if port < 1024:
        return 1
    if port < EPHEMERAL_START:
        return 2
    return 3


def _num(v, default=0):
    """ค่าจาก CSV/JSON อาจเป็น None หรือ NaN -> ใช้ default"""
    if v is None:
        return default
    try:
        if v != v:  # NaN
            return default
    except TypeError:
        return default
    return v


def packet_features(meta: dict) -> list[float]:
    """feature ต่อ packet (ส่วนที่ไม่ต้องใช้ state)"""
    proto = meta.get("proto")
    flags = int(_num(meta.get("tcp_flags"), 0))
    bucket = port_bucket(_num(meta.get("dst_port"), None))
    return [
        1.0 if proto == "TCP" else 0.0,
        1.0 if proto == "UDP" else 0.0,
        1.0 if proto == "ICMP" else 0.0,
        float(_num(meta.get("length"), 0)),
        float(_num(meta.get("ttl"), 0)),
        *[1.0 if flags & bit else 0.0 for _, bit in TCP_FLAG_BITS],
        float(_num(meta.get("icmp_type"), 0)) if proto == "ICMP" else 0.0,
        1.0 if bucket == 0 else 0.0,
        1.0 if bucket == 1 else 0.0,
        1.0 if bucket == 2 else 0.0,
        1.0 if bucket == 3 else 0.0,
    ]


class _SrcState:
    """สถานะของ src IP หนึ่งตัวใน window"""
    __slots__ = ("events", "ports", "ips", "last", "low")

    def __init__(self):
        self.events: deque = deque()   # (ts, dst_ip, dst_port)
        self.ports: Counter = Counter()
        self.ips: Counter = Counter()
        self.last = 0.0
        self.low = 0                   # จำนวน dst port ไม่ซ้ำที่ < 49152


class ContextTracker:
    """นับพฤติกรรมของ src IP ในช่วง window_sec ที่ผ่านมา (sliding window ในหน่วยความจำ)
    ใช้ Counter เพิ่ม/ลดทีละรายการ -> แต่ละ packet ใช้เวลา O(1) แม้ src ส่งถี่มาก"""

    def __init__(self, window_sec: float = 5.0, cleanup_every: int = 2000):
        self.window = float(window_sec)
        self._srcs: dict[str, _SrcState] = {}
        self._cleanup_every = cleanup_every
        self._n = 0

    def update(self, ts: float, src_ip: str, dst_ip: str, dst_port) -> tuple[int, int, int, int]:
        st = self._srcs.get(src_ip)
        if st is None:
            st = self._srcs[src_ip] = _SrcState()
        # ถ้า timestamp ย้อนหลังเล็กน้อย (จากหลาย interface) ให้ถือว่าเป็น "ตอนนี้" ของ src นั้น
        now = ts if ts > st.last else st.last
        st.last = now

        st.events.append((now, dst_ip, dst_port))
        st.ips[dst_ip] += 1
        if dst_port is not None:
            st.ports[dst_port] += 1
            if st.ports[dst_port] == 1 and dst_port < EPHEMERAL_START:
                st.low += 1

        # ตัด event ที่เก่ากว่า window ออก
        limit = now - self.window
        ev = st.events
        while ev and ev[0][0] < limit:
            _, old_ip, old_port = ev.popleft()
            st.ips[old_ip] -= 1
            if st.ips[old_ip] <= 0:
                del st.ips[old_ip]
            if old_port is not None:
                st.ports[old_port] -= 1
                if st.ports[old_port] <= 0:
                    del st.ports[old_port]
                    if old_port < EPHEMERAL_START:
                        st.low -= 1

        self._n += 1
        if self._n % self._cleanup_every == 0:
            self._cleanup(now)
        return len(ev), len(st.ports), len(st.ips), st.low

    def _cleanup(self, now: float) -> None:
        """ลบ src ที่เงียบไปนานแล้วออก กัน memory โตไม่จำกัด"""
        stale = [k for k, s in self._srcs.items() if s.last < now - self.window * 2]
        for k in stale:
            del self._srcs[k]


class FeatureExtractor:
    """ตัวแปลง packet metadata (dict) -> feature vector — มี state ของ window ในตัว
    ต้องป้อน packet ตามลำดับเวลา"""

    def __init__(self, window_sec: float = 5.0):
        self.ctx = ContextTracker(window_sec)

    def extract(self, meta: dict) -> list[float]:
        # แยก context ตาม (src IP, interface): เครื่องที่ถูกดักหลาย interface (เช่น สแกนตัวเองผ่าน loopback
        # ขณะที่ traffic ปกติวิ่งบน Wi-Fi) จะได้ไม่ปนกัน
        pkts, ports, ips, low = self.ctx.update(
            float(meta["ts"]), f"{meta['src_ip']}|{meta.get('iface')}", meta["dst_ip"],
            None if _num(meta.get("dst_port"), None) is None else int(meta["dst_port"]),
        )
        # ctx_ip_ratio = IP ปลายทางไม่ซ้ำ / packet: ใกล้ 1 เมื่อ src ยิง 1 packet ต่อ 1 host (ไล่สแกน host)
        return packet_features(meta) + [float(pkts), float(ports), float(ips), float(low), ips / pkts]

    def extract_many(self, metas) -> np.ndarray:
        rows = [self.extract(m) for m in metas]
        return np.asarray(rows, dtype=float).reshape(-1, N_FEATURES)
