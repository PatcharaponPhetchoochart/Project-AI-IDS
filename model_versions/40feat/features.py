"""แปลง packet metadata -> feature vector

ไฟล์นี้ใช้ร่วมกันทั้งตอนเทรน (training/) และตอนรันจริง (feature-service)
ห้ามแก้ลำดับ/ความหมายของ feature โดยไม่เทรนโมเดลใหม่ (เพิ่ม FEATURE_VERSION ด้วย)

feature ต่อ packet:
  - protocol one-hot (TCP / UDP / ICMP)
  - length, TTL
  - TCP flags แยกเป็นบิต (FIN SYN RST PSH ACK URG ECE CWR)
  - ICMP type
  - dst port bucket (well-known 0-1023 / registered 1024-49151 / dynamic 49152+ / none = ไม่มี port เช่น ICMP)
  - dns_qlen = ความยาวชื่อ DNS query (เฉพาะ packet UDP:53 ที่มี DNS question) ใช้จับ DNS tunneling (v4)
feature บริบท (sliding window ต่อ src IP, ค่าเริ่มต้น 5 วินาที):
  - จำนวน packet ที่ src นี้ส่ง, จำนวน dst port ไม่ซ้ำ, จำนวน dst IP ไม่ซ้ำ
  - ctx_low_ports = จำนวน dst port ไม่ซ้ำ "เฉพาะ port ที่ต่ำกว่า 49152" (port ของ service จริง)
    เพราะ server/gateway ที่ตอบกลับหลาย client จะมี dst port สูงๆ (ephemeral) เยอะตามปกติ ไม่ใช่การสแกน
    แต่ตัวสแกน (nmap) จะไล่ยิง port ของ service ต่ำๆ จำนวนมาก
feature การยิงที่ไม่ได้รับการตอบรับ (v3, ต้องเห็น packet ทั้งสองทิศทาง):
  - ctx_unans_ports / ctx_unans_ports_long = จำนวน dst port ไม่ซ้ำที่ src นี้ "เปิดการเชื่อมต่อใหม่" ไป
    (TCP SYN ไม่มี ACK หรือ UDP ที่ไม่ใช่การตอบกลับ) แล้วยังไม่ได้รับการตอบรับ ใน window สั้น / ยาว
    ตอบรับ = มี packet ย้อนกลับจาก port นั้น (UDP หรือ TCP ที่ไม่ใช่ RST); RST / ICMP unreachable / เงียบ = ไม่ตอบรับ
    การสแกนยิงไปหลายสิบ-หลายร้อย port แล้วไม่มีใครตอบ ส่วน traffic ปกติ (เว็บ เกม Discord DNS)
    ได้รับการตอบกลับเกือบทุกครั้ง และ server ที่ตอบหลาย client ก็ไม่นับ เพราะเป็น "การตอบกลับ" ไม่ใช่การยิงใหม่

feature v4 (A-F): เพิ่มเพื่อจับการโจมตีระดับแอป/พฤติกรรมที่ v3 ยังไม่ครอบ (brute force, slowloris, flood,
C2 beacon, DNS tunneling) -- ทุกตัวคำนวณจาก header + จังหวะ/ปริมาณเท่านั้น ไม่อ่าน payload เว็บ (SQLi/XSS ฯลฯ
ยังอยู่นอกขอบเขตของ NIDS นี้ ต้องใช้ WAF/DPI แยกต่างหาก):
  (A) ctx_same_endpoint  = จำนวน packet ที่ src นี้ส่งไปยัง (dst_ip, dst_port) "เดิม" ใน window
                           -> brute force login / dir-enum ที่ยิงรัวไป endpoint เดียวซ้ำๆ (ไม่ใช่สแกนหลาย port)
  (B) ctx_half_open      = จำนวน TCP connection ของ src นี้ที่ handshake เสร็จแล้ว (เห็น ACK) แต่ยังไม่ปิด
                           (ไม่มี FIN/RST) ค้างนานเกิน min_age -> slowloris / DoS ที่เปิด connection ค้างไว้เยอะๆ
  (C) ctx_bytes          = ผลรวม length (byte) ของ packet จาก src นี้ใน window -> flood / data exfiltration burst
  (D) ctx_beacon_cv      = ความแปรปรวนของจังหวะเวลา (coefficient of variation) ที่ src ส่งไปยัง dst เดิม
                           ค่าต่ำ = จังหวะสม่ำเสมอมาก (น่าสงสัย, คล้าย C2 beacon เรียกบ้านเป็นช่วงเวลาคงที่)
                           ข้อมูลไม่พอ (< 3 ช่วงเวลา) -> คืนค่าเริ่มต้น BeaconTracker.DEFAULT_CV (ถือว่าปกติไว้ก่อน)
  (E) dns_qlen / ctx_dns_qrate = ความยาวชื่อ DNS query ของ packet นี้ + อัตรา DNS query ของ src ใน window
                           -> DNS tunneling (query ชื่อยาวผิดปกติ, ยิง query ถี่ผิดปกติ)
  (F) ctx_resp_ports     = จำนวน src port ต่ำ (<49152) ที่ src นี้ "ใช้ตอบกลับ" (src_port ต่ำ, dst_port สูง)
                           ไม่ซ้ำกัน แยกออกจาก ctx_low_ports (ทิศทางตรงข้าม) ให้โมเดลเห็นพฤติกรรมสองทิศทางแยกกัน

feature v5 (G-I): ดึงรายละเอียดจาก header ลึกขึ้น (มาจาก full .pcap capture) เพื่อแยก "traffic ปกติหนักๆ"
(เช่น HTTPS/QUIC ไป CDN ใหญ่) ออกจาก noise ที่ทำให้ feature A/B (v4) alert ผิด -- ยังไม่แตะ payload ที่เข้ารหัส
(TLS/QUIC application data อ่านไม่ได้อยู่ดี) ดึงเฉพาะส่วนที่เป็น header/handshake ที่ไม่เข้ารหัส:
  (G) tcp_window/tcp_mss/tcp_wscale/tcp_sack_ok/tcp_ts_present = ลายนิ้วมือ TCP handshake (เฉพาะ option
      ที่ส่งมาจริงใน packet นั้น, ส่วนใหญ่มีแค่ตอน SYN/SYN-ACK) -- OS/browser จริงตั้งค่าชุดนี้สม่ำเสมอตามสแตก
      เครือข่าย ส่วนเครื่องมือสแกน/สคริปต์เขียนเองมักขาด/ผิดจากที่ stack จริงตั้ง ช่วยแยกได้แม้ port/flag เหมือนกัน
  (H) dns_qtype/dns_rcode = ชนิด DNS query (A/AAAA/...) + ผลลัพธ์ (NOERROR/NXDOMAIN/...) เสริม dns_qlen เดิม
      ให้เห็นภาพกว้างขึ้นว่า query นี้ "ได้คำตอบปกติ" หรือไม่ (DNS tunneling มักตั้ง type แปลกๆ/ไม่ได้คำตอบ)
  (I) tls_sni_known = ปลายทาง TLS ClientHello (SNI) ตรงกับโดเมนของผู้ให้บริการใหญ่ที่รู้จัก (CDN/cloud) หรือไม่
      -- อ่านได้เฉพาะ TCP (ส่วน handshake เริ่มต้นของ TLS ไม่เข้ารหัส) QUIC/UDP ยังอ่านไม่ได้ (เข้ารหัสทั้งเฟรม)
      เก็บแค่ "รู้จักหรือไม่" (0/1) ไม่เก็บชื่อโดเมนจริงลง CSV (ตามแนวเดียวกับ dns_qlen ที่ไม่เก็บชื่อจริง)
"""
from __future__ import annotations

from collections import Counter, deque

import numpy as np

FEATURE_VERSION = 5

# คอลัมน์ metadata ดิบ (ตรงกับ PacketMsg และไฟล์ CSV ที่ capture-service บันทึก)
PACKET_FIELDS = [
    "ts", "iface", "src_ip", "dst_ip", "src_port", "dst_port",
    "proto", "length", "ttl", "tcp_flags", "icmp_type", "icmp_code",
    "dns_qlen",   # v4 (feature E): ความยาวชื่อ DNS query (เฉพาะ packet DNS) -- None สำหรับ packet อื่น
    # v5 (feature G): ลายนิ้วมือ TCP handshake -- None เมื่อไม่ใช่ TCP หรือ option นั้นไม่ได้ส่งมาใน packet นี้
    "tcp_window", "tcp_mss", "tcp_wscale", "tcp_sack_ok", "tcp_ts_present",
    # v5 (feature H): ชนิด/ผลลัพธ์ DNS -- None สำหรับ packet ที่ไม่ใช่ DNS
    "dns_qtype", "dns_rcode",
    # v5 (feature I): ปลายทาง TLS ClientHello ตรงกับโดเมนที่รู้จักหรือไม่ (1/0) -- None เมื่อไม่ใช่ TLS ClientHello
    "tls_sni_known",
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
    "ctx_unans_ports", "ctx_unans_ports_long",
    # v4 (A-F)
    "ctx_same_endpoint", "ctx_bytes", "ctx_half_open", "ctx_beacon_cv",
    "dns_qlen", "ctx_dns_qrate", "ctx_resp_ports",
    # v5 (G-I)
    "tcp_window", "tcp_mss", "tcp_wscale", "tcp_sack_ok", "tcp_ts_present",
    "dns_qtype", "dns_rcode", "tls_sni_known",
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


def header_detail_features(meta: dict) -> list[float]:
    """feature v5 (G-I) ต่อ packet (ไม่ต้องใช้ state) -- แยกจาก packet_features() เดิมเพื่อให้ชัดว่าเป็นกลุ่มที่
    เพิ่มทีหลัง ต่อท้ายใน FEATURE_NAMES เสมอ (ห้ามแทรกกลาง ไม่งั้น index จะเพี้ยนกับกลุ่ม ctx_* ที่ตามมา)
    ไม่ได้ส่งมาใน packet นี้ (None) ถือว่าเหมือน "ไม่ตั้งค่า" (0) เพราะเครื่องมือสแกน/สคริปต์มักไม่ตั้ง option
    พวกนี้ให้ครบเหมือน stack จริงอยู่แล้ว"""
    return [
        float(_num(meta.get("tcp_window"), 0)),
        float(_num(meta.get("tcp_mss"), 0)),
        float(_num(meta.get("tcp_wscale"), 0)),
        float(_num(meta.get("tcp_sack_ok"), 0)),
        float(_num(meta.get("tcp_ts_present"), 0)),
        float(_num(meta.get("dns_qtype"), 0)),
        float(_num(meta.get("dns_rcode"), 0)),
        float(_num(meta.get("tls_sni_known"), 0)),
    ]


class _SrcState:
    """สถานะของ src IP หนึ่งตัวใน window"""
    __slots__ = ("events", "ports", "ips", "endpoints", "resp_ports", "dns_times",
                "last", "low", "resp_low", "bytes_sum")

    def __init__(self):
        self.events: deque = deque()   # (ts, dst_ip, dst_port, endpoint, length, resp_port)
        self.ports: Counter = Counter()
        self.ips: Counter = Counter()
        self.endpoints: Counter = Counter()      # (dst_ip, dst_port) -> count (feature A: same-endpoint rate)
        self.resp_ports: Counter = Counter()     # src_port ต่ำที่ใช้ตอบกลับ (feature F)
        self.dns_times: deque = deque()          # เวลาของ DNS query (feature E: ctx_dns_qrate)
        self.last = 0.0
        self.low = 0                   # จำนวน dst port ไม่ซ้ำที่ < 49152
        self.resp_low = 0              # จำนวน src port (ตอบกลับ) ไม่ซ้ำที่ < 49152 (feature F)
        self.bytes_sum = 0.0           # ผลรวม length ใน window (feature C)


class ContextTracker:
    """นับพฤติกรรมของ src IP ในช่วง window_sec ที่ผ่านมา (sliding window ในหน่วยความจำ)
    ใช้ Counter เพิ่ม/ลดทีละรายการ -> แต่ละ packet ใช้เวลา O(1) แม้ src ส่งถี่มาก"""

    def __init__(self, window_sec: float = 5.0, cleanup_every: int = 2000):
        self.window = float(window_sec)
        self._srcs: dict[str, _SrcState] = {}
        self._cleanup_every = cleanup_every
        self._n = 0

    def update(self, ts: float, src_ip: str, dst_ip: str, dst_port, src_port, length: float,
              is_dns_query: bool) -> tuple[int, int, int, int, int, float, int, int]:
        st = self._srcs.get(src_ip)
        if st is None:
            st = self._srcs[src_ip] = _SrcState()
        # ถ้า timestamp ย้อนหลังเล็กน้อย (จากหลาย interface) ให้ถือว่าเป็น "ตอนนี้" ของ src นั้น
        now = ts if ts > st.last else st.last
        st.last = now

        endpoint = (dst_ip, dst_port) if dst_port is not None else None
        # feature F: ทิศทาง "ตอบกลับ" = src ใช้ port ต่ำ คุยไปหา dst port สูง (เรามักเป็นฝ่ายให้บริการ/ตอบ)
        # ตรงข้ามกับ ctx_low_ports ที่นับทิศทาง "เปิดการเชื่อมต่อใหม่ไปหา service"
        is_resp = (src_port is not None and src_port < EPHEMERAL_START
                   and dst_port is not None and dst_port >= EPHEMERAL_START)
        resp_port = src_port if is_resp else None

        st.events.append((now, dst_ip, dst_port, endpoint, float(length), resp_port))
        st.ips[dst_ip] += 1
        st.bytes_sum += float(length)
        if dst_port is not None:
            st.ports[dst_port] += 1
            if st.ports[dst_port] == 1 and dst_port < EPHEMERAL_START:
                st.low += 1
        if endpoint is not None:
            st.endpoints[endpoint] += 1
        if resp_port is not None:
            st.resp_ports[resp_port] += 1
            if st.resp_ports[resp_port] == 1 and resp_port < EPHEMERAL_START:
                st.resp_low += 1
        if is_dns_query:
            st.dns_times.append(now)

        # ตัด event ที่เก่ากว่า window ออก
        limit = now - self.window
        ev = st.events
        while ev and ev[0][0] < limit:
            _, old_ip, old_port, old_ep, old_len, old_resp = ev.popleft()
            st.ips[old_ip] -= 1
            if st.ips[old_ip] <= 0:
                del st.ips[old_ip]
            st.bytes_sum -= old_len
            if old_port is not None:
                st.ports[old_port] -= 1
                if st.ports[old_port] <= 0:
                    del st.ports[old_port]
                    if old_port < EPHEMERAL_START:
                        st.low -= 1
            if old_ep is not None:
                st.endpoints[old_ep] -= 1
                if st.endpoints[old_ep] <= 0:
                    del st.endpoints[old_ep]
            if old_resp is not None:
                st.resp_ports[old_resp] -= 1
                if st.resp_ports[old_resp] <= 0:
                    del st.resp_ports[old_resp]
                    if old_resp < EPHEMERAL_START:
                        st.resp_low -= 1
        dns_times = st.dns_times
        while dns_times and dns_times[0] < limit:
            dns_times.popleft()

        self._n += 1
        if self._n % self._cleanup_every == 0:
            self._cleanup(now)
        same_endpoint = st.endpoints.get(endpoint, 0) if endpoint is not None else 0
        return (len(ev), len(st.ports), len(st.ips), st.low,
                same_endpoint, st.bytes_sum, st.resp_low, len(dns_times))

    def _cleanup(self, now: float) -> None:
        """ลบ src ที่เงียบไปนานแล้วออก กัน memory โตไม่จำกัด"""
        stale = [k for k, s in self._srcs.items() if s.last < now - self.window * 2]
        for k in stale:
            del self._srcs[k]


class ProbeTracker:
    """นับ dst port ที่ src เปิดการเชื่อมต่อใหม่ไปแล้วยังไม่ได้รับการตอบรับ (ดู docstring ต้นไฟล์)"""

    def __init__(self, windows=(5.0, 60.0), flow_ttl: float = 120.0, purge_every_sec: float = 30.0):
        self.windows = tuple(float(w) for w in windows)
        self.keep = max(self.windows)
        self.flow_ttl = float(flow_ttl)
        self.purge_every = float(purge_every_sec)
        self._flows: dict[tuple, float] = {}               # (src, sport, dst, dport, proto) -> เวลาล่าสุด
        self._probes: dict[str, dict[int, list]] = {}      # "src|iface" -> {dst_port: [เวลา probe ล่าสุด, ยังไม่ตอบรับ]}
        self._last_purge: float | None = None

    def update(self, meta: dict, src_key: str, now: float) -> list[float]:
        if self._last_purge is None:
            self._last_purge = now
        if now - self._last_purge > self.purge_every:
            self._purge(now)
        proto = meta.get("proto")
        sp, dp = _num(meta.get("src_port"), None), _num(meta.get("dst_port"), None)
        if proto in ("TCP", "UDP") and sp is not None and dp is not None:
            sp, dp = int(sp), int(dp)
            a, b = meta["src_ip"], meta["dst_ip"]
            flags = int(_num(meta.get("tcp_flags"), 0))
            rev = self._flows.get((b, dp, a, sp, proto))
            if rev is not None and now - rev <= self.flow_ttl:          # เป็นการตอบกลับ flow ที่อีกฝั่งเปิด
                if proto == "UDP" or not flags & 0x04:                  # RST = ปฏิเสธ ไม่นับว่าตอบรับ
                    pend = self._probes.get(f"{b}|{meta.get('iface')}")
                    if pend is not None and sp in pend:
                        pend[sp][1] = False
            elif proto == "UDP" or (flags & 0x02 and not flags & 0x10):  # เปิดการเชื่อมต่อใหม่
                pend = self._probes.setdefault(src_key, {})
                if dp in pend:
                    pend[dp][0] = now
                else:
                    pend[dp] = [now, True]
            self._flows[(a, sp, b, dp, proto)] = now
        pend = self._probes.get(src_key)
        if not pend:
            return [0.0] * len(self.windows)
        return [float(sum(1 for t, waiting in pend.values() if waiting and now - t <= w)) for w in self.windows]

    def _purge(self, now: float) -> None:
        """ลบ flow / probe เก่าออก กัน memory โตไม่จำกัด"""
        self._flows = {k: t for k, t in self._flows.items() if now - t <= self.flow_ttl}
        for key in list(self._probes):
            kept = {p: v for p, v in self._probes[key].items() if now - v[0] <= self.keep}
            if kept:
                self._probes[key] = kept
            else:
                del self._probes[key]
        self._last_purge = now


class ConnStateTracker:
    """ติดตามสถานะ TCP connection ต่อ src -> นับ connection ที่ handshake เสร็จแล้ว (เห็น ACK)
    แต่ค้างไว้นานผิดปกติโดยไม่มี FIN/RST ใช้จับ slowloris / DoS ที่เปิด connection ค้างไว้พร้อมกันเยอะๆ (feature B)"""

    def __init__(self, min_age: float = 2.0, flow_ttl: float = 300.0, purge_every: float = 30.0):
        self.min_age = float(min_age)
        self.flow_ttl = float(flow_ttl)
        self.purge_every = float(purge_every)
        self._by_src: dict[str, dict[tuple, dict]] = {}
        self._last_purge: float | None = None

    def update(self, meta: dict, src_key: str, now: float) -> float:
        proto = meta.get("proto")
        sp, dp = _num(meta.get("src_port"), None), _num(meta.get("dst_port"), None)
        if proto == "TCP" and sp is not None and dp is not None:
            flows = self._by_src.setdefault(src_key, {})
            key = (int(sp), meta["dst_ip"], int(dp))
            flags = int(_num(meta.get("tcp_flags"), 0))
            if flags & 0x05:                       # FIN หรือ RST -> ปิด connection แล้ว
                flows.pop(key, None)
            else:
                f = flows.get(key)
                if f is None:
                    f = flows[key] = {"start": now, "open": False}
                f["last"] = now
                if flags & 0x10:                   # มี ACK = handshake เดินหน้า/เสร็จแล้ว
                    f["open"] = True
        if self._last_purge is None:
            self._last_purge = now
        if now - self._last_purge > self.purge_every:
            self._purge(now)
        flows = self._by_src.get(src_key)
        if not flows:
            return 0.0
        return float(sum(1 for f in flows.values() if f["open"] and now - f["start"] >= self.min_age))

    def _purge(self, now: float) -> None:
        for src_key in list(self._by_src):
            flows = self._by_src[src_key]
            kept = {k: f for k, f in flows.items() if now - f["last"] <= self.flow_ttl}
            if kept:
                self._by_src[src_key] = kept
            else:
                del self._by_src[src_key]
        self._last_purge = now


class BeaconTracker:
    """วัดความสม่ำเสมอของจังหวะเวลาที่ src ส่ง packet ไปยัง dst เดิม (ไม่สนใจ port) -> จับ C2 beaconing
    ที่เรียกกลับบ้านเป็นช่วงเวลาคงที่ (feature D)
    ค่า "coefficient of variation" (std/mean ของ inter-arrival time): ต่ำ = จังหวะสม่ำเสมอมาก (น่าสงสัย)
    สูง = จังหวะไม่แน่นอน (ปกติ) ข้อมูลไม่พอ (< 3 ช่วงเวลา) -> คืนค่า DEFAULT_CV (ถือว่าปกติไว้ก่อน)"""

    DEFAULT_CV = 2.0

    def __init__(self, history: int = 8, flow_ttl: float = 600.0, purge_every: float = 60.0):
        self.history = int(history)
        self.flow_ttl = float(flow_ttl)
        self.purge_every = float(purge_every)
        self._last_ts: dict[tuple, float] = {}
        self._intervals: dict[tuple, deque] = {}
        self._last_purge: float | None = None

    def update(self, src_key: str, dst_ip: str, now: float) -> float:
        key = (src_key, dst_ip)
        prev = self._last_ts.get(key)
        self._last_ts[key] = now
        if prev is not None and now > prev:
            dq = self._intervals.setdefault(key, deque(maxlen=self.history))
            dq.append(now - prev)
        if self._last_purge is None:
            self._last_purge = now
        if now - self._last_purge > self.purge_every:
            self._purge(now)
        dq = self._intervals.get(key)
        if not dq or len(dq) < 3:
            return self.DEFAULT_CV
        arr = np.asarray(dq, dtype=float)
        mean = float(arr.mean())
        if mean <= 0:
            return self.DEFAULT_CV
        return float(arr.std() / mean)

    def _purge(self, now: float) -> None:
        stale = [k for k, t in self._last_ts.items() if now - t > self.flow_ttl]
        for k in stale:
            self._last_ts.pop(k, None)
            self._intervals.pop(k, None)
        self._last_purge = now


class FeatureExtractor:
    """ตัวแปลง packet metadata (dict) -> feature vector — มี state ของ window ในตัว
    ต้องป้อน packet ตามลำดับเวลา"""

    def __init__(self, window_sec: float = 5.0, long_window_sec: float = 60.0):
        self.ctx = ContextTracker(window_sec)
        self.probes = ProbeTracker((window_sec, long_window_sec))
        self.conns = ConnStateTracker()
        self.beacon = BeaconTracker()

    def extract(self, meta: dict) -> list[float]:
        # แยก context ตาม (src IP, interface): เครื่องที่ถูกดักหลาย interface (เช่น สแกนตัวเองผ่าน loopback
        # ขณะที่ traffic ปกติวิ่งบน Wi-Fi) จะได้ไม่ปนกัน
        src_key = f"{meta['src_ip']}|{meta.get('iface')}"
        ts = float(meta["ts"])
        dst_port = None if _num(meta.get("dst_port"), None) is None else int(meta["dst_port"])
        src_port = None if _num(meta.get("src_port"), None) is None else int(meta["src_port"])
        length = float(_num(meta.get("length"), 0))
        is_dns_query = meta.get("proto") == "UDP" and dst_port == 53

        pkts, ports, ips, low, same_endpoint, bytes_sum, resp_low, dns_qrate = self.ctx.update(
            ts, src_key, meta["dst_ip"], dst_port, src_port, length, is_dns_query)
        unans = self.probes.update(meta, src_key, ts)
        half_open = self.conns.update(meta, src_key, ts)
        beacon_cv = self.beacon.update(src_key, meta["dst_ip"], ts)
        dns_qlen = float(_num(meta.get("dns_qlen"), 0))

        # ctx_ip_ratio = IP ปลายทางไม่ซ้ำ / packet: ใกล้ 1 เมื่อ src ยิง 1 packet ต่อ 1 host (ไล่สแกน host)
        return (packet_features(meta)
                + [float(pkts), float(ports), float(ips), float(low), ips / pkts]
                + unans
                + [float(same_endpoint), float(bytes_sum), float(half_open), float(beacon_cv),
                   dns_qlen, float(dns_qrate), float(resp_low)]
                + header_detail_features(meta))

    def extract_many(self, metas) -> np.ndarray:
        rows = [self.extract(m) for m in metas]
        return np.asarray(rows, dtype=float).reshape(-1, N_FEATURES)
