"""capture-service: ดัก packet ด้วย Scapy จากหลาย interface (รวม loopback) -> publish topic `packets`

ต้องรันด้วย root (Linux) หรือ Administrator (Windows, Npcap)
รันเดี่ยว:  python system/services/capture_service/main.py
"""
from __future__ import annotations

import csv
import sys
import threading
import time
from pathlib import Path

if __package__ in (None, ""):  # รันเป็นสคริปต์ตรงๆ ได้ด้วย: python services/capture_service/main.py
    sys.path.insert(0, str(Path(__file__).resolve().parents[2]))

from shared.bus import Publisher
from shared.config import bus_port, load_config, resolve_path
from shared.features import PACKET_FIELDS
from shared.schemas import TOPIC_PACKETS
from shared.utils import scapy_env, setup_logging

SERVICE = "capture"


def resolve_interfaces(names: list[str], conf, log) -> list[tuple[str, object]]:
    """แปลงชื่อใน config เป็น (ป้ายชื่อ, interface ที่ Scapy ใช้ได้)
    ข้ามตัวที่หาไม่เจอพร้อมแจ้งเตือน (ไม่ให้ทั้งระบบล้ม)"""
    result = []
    for name in names:
        key = name.strip()
        try:
            if key.lower() == "loopback":
                iface = conf.loopback_name
            elif key.lower() == "default":
                iface = conf.iface
            else:
                iface = key
            # ตรวจว่ามี interface นี้จริง (resolve_iface จะ raise ถ้าไม่เจอ)
            from scapy.interfaces import resolve_iface
            resolved = resolve_iface(iface)
            result.append((key, resolved))
            log.info("interface '%s' -> %s", key, getattr(resolved, "name", resolved))
        except Exception as e:  # noqa: BLE001
            log.error("interface '%s' not found (%s) - skipped. List valid names: python system/scripts/list_interfaces.py", key, e)
    return result


# v5 (feature I): โดเมนของผู้ให้บริการ CDN/cloud ใหญ่ที่เจอบ่อยใน traffic บ้านปกติ (ไม่ใช่รายชื่อครบถ้วน
# แค่พอให้โมเดลเห็นว่า "ปลายทางที่หนักๆ ซ้ำๆ" ส่วนใหญ่เป็นผู้ให้บริการที่รู้จัก ไม่ใช่สัญญาณ C2/exfiltration)
KNOWN_GOOD_TLS_SUFFIXES = (
    "google.com", "gstatic.com", "googleapis.com", "googleusercontent.com", "googlevideo.com", "doubleclick.net",
    "cloudflare.com", "cloudflare-dns.com", "cloudflareinsights.com",
    "akamai.net", "akamaiedge.net", "akamaitechnologies.com", "akamaihd.net",
    "amazonaws.com", "cloudfront.net", "awsstatic.com",
    "microsoft.com", "microsoftonline.com", "windows.net", "msedge.net", "live.com", "office.com", "office365.com",
    "apple.com", "icloud.com", "mzstatic.com",
    "anthropic.com", "claude.ai",
    "fastly.net", "github.com", "githubusercontent.com",
    "facebook.com", "fbcdn.net", "instagram.com", "whatsapp.net",
)


def is_known_good_domain(host: str) -> bool:
    host = host.lower().rstrip(".")
    return any(host == s or host.endswith("." + s) for s in KNOWN_GOOD_TLS_SUFFIXES)


def extract_tls_sni(data: bytes) -> str | None:
    """ดึงชื่อโดเมนจาก extension server_name ของ TLS ClientHello (RFC 8446 section 4.2.9 / RFC 6066)
    ส่วนนี้ของ TLS handshake ไม่เข้ารหัส (ตัว ClientHello เองวิ่งเป็น plaintext) ต่างจาก application data
    ที่มาทีหลัง -- เขียนแบบ parse มือ (ไม่พึ่ง scapy.layers.tls) เพราะต้องการแค่ field เดียว เร็วกว่า และกัน
    exception ทุกจุดเพราะ ClientHello อาจถูกตัดครึ่งข้าม TCP segment ได้ (ไม่ต้องสมบูรณ์ 100% แค่ best-effort)"""
    if len(data) < 9 or data[0] != 0x16 or data[5] != 0x01:   # 0x16=Handshake, 0x01=ClientHello
        return None
    pos = 9 + 2 + 32   # record header(5) + handshake header(4) + client_version(2) + random(32)
    if pos >= len(data):
        return None
    pos += 1 + data[pos]                                       # session_id
    if pos + 2 > len(data):
        return None
    pos += 2 + int.from_bytes(data[pos:pos + 2], "big")        # cipher_suites
    if pos >= len(data):
        return None
    pos += 1 + data[pos]                                       # compression_methods
    if pos + 2 > len(data):
        return None
    ext_end = pos + 2 + int.from_bytes(data[pos:pos + 2], "big")
    pos += 2
    while pos + 4 <= min(ext_end, len(data)):
        ext_type = int.from_bytes(data[pos:pos + 2], "big")
        ext_len = int.from_bytes(data[pos + 2:pos + 4], "big")
        pos += 4
        if ext_type == 0x0000:                                 # server_name
            p = pos + 2                                        # ข้าม server_name_list length
            if p + 3 > len(data):
                return None
            name_type, name_len = data[p], int.from_bytes(data[p + 1:p + 3], "big")
            p += 3
            if name_type == 0 and p + name_len <= len(data):   # 0 = host_name
                return data[p:p + name_len].decode("ascii", "replace")
            return None
        pos += ext_len
    return None


def packet_to_meta(pkt, iface_label: str) -> dict | None:
    """แปลง Scapy packet เป็น metadata dict (เฉพาะ IPv4) — ไม่เก็บ payload
    ยกเว้น: DNS query name เก็บแค่ "ความยาว" (dns_qlen, feature E) ไม่เก็บชื่อจริง เพื่อจับ DNS tunneling
            TLS ClientHello SNI เก็บแค่ "รู้จักหรือไม่" (tls_sni_known, feature I) ไม่เก็บชื่อโดเมนจริง"""
    from scapy.layers.inet import ICMP, IP, TCP, UDP

    ip = pkt.getlayer(IP)
    if ip is None:
        return None
    meta = {
        "ts": float(pkt.time), "iface": iface_label,
        "src_ip": ip.src, "dst_ip": ip.dst,
        "src_port": None, "dst_port": None,
        "proto": "OTHER",
        # ip.len อาจเป็น 0 เมื่อเปิด TSO (checksum/segmentation offload) -> ใช้ขนาด packet จริงแทน
        "length": int(ip.len) if ip.len else len(ip),
        "ttl": int(ip.ttl),
        "tcp_flags": None, "icmp_type": None, "icmp_code": None,
        "dns_qlen": None,
        "tcp_window": None, "tcp_mss": None, "tcp_wscale": None, "tcp_sack_ok": None, "tcp_ts_present": None,
        "dns_qtype": None, "dns_rcode": None,
        "tls_sni_known": None,
    }
    tcp, udp, icmp = pkt.getlayer(TCP), pkt.getlayer(UDP), pkt.getlayer(ICMP)
    if tcp is not None:
        meta.update(proto="TCP", src_port=int(tcp.sport), dst_port=int(tcp.dport), tcp_flags=int(tcp.flags),
                    tcp_window=int(tcp.window))
        # v5 (feature G): option ส่วนใหญ่มีแค่ตอน SYN/SYN-ACK -- packet อื่นเลยมักได้ None/0 เป็นปกติ
        try:
            sack_ok = ts_present = 0
            for opt in tcp.options:
                name = opt[0]
                if name == "MSS":
                    meta["tcp_mss"] = int(opt[1])
                elif name == "WScale":
                    meta["tcp_wscale"] = int(opt[1])
                elif name == "SAckOK":
                    sack_ok = 1
                elif name == "Timestamp":
                    ts_present = 1
            meta["tcp_sack_ok"] = sack_ok
            meta["tcp_ts_present"] = ts_present
        except Exception:  # noqa: BLE001  option พังไม่ควรทำให้ packet ทั้งตัวเสีย
            pass
        # v5 (feature I): เช็คเฉพาะ packet ที่ "น่าจะ" เป็น ClientHello (client -> 443, มี payload)
        if tcp.dport == 443:
            try:
                payload = bytes(tcp.payload)
                if payload:
                    sni = extract_tls_sni(payload)
                    if sni:
                        meta["tls_sni_known"] = 1 if is_known_good_domain(sni) else 0
            except Exception:  # noqa: BLE001
                pass
    elif udp is not None:
        meta.update(proto="UDP", src_port=int(udp.sport), dst_port=int(udp.dport))
        if udp.dport == 53 or udp.sport == 53:
            try:
                from scapy.layers.dns import DNS
                dns = pkt.getlayer(DNS)
                if dns is not None and dns.qdcount and dns.qd is not None:
                    qname = dns.qd.qname
                    if isinstance(qname, bytes):
                        qname = qname.decode("utf-8", "replace")
                    meta["dns_qlen"] = len(str(qname).rstrip("."))
                    meta["dns_qtype"] = int(dns.qd.qtype)      # v5 (feature H): ชนิด query (1=A, 28=AAAA, ...)
                    if int(dns.qr) == 1:                        # เป็น response -> rcode มีความหมาย (query ไม่มี)
                        meta["dns_rcode"] = int(dns.rcode)
            except Exception:  # noqa: BLE001  DNS parse พังไม่ควรทำให้ packet ทั้งตัวเสีย
                pass
    elif icmp is not None:
        meta.update(proto="ICMP", icmp_type=int(icmp.type), icmp_code=int(icmp.code))
    return meta


def main() -> None:
    log = setup_logging(SERVICE)
    cfg = load_config()
    ccfg = cfg["capture"]
    mode = ccfg.get("mode", "zmq")
    ports = cfg["bus"]["ports"]

    scapy_env()
    from scapy.all import AsyncSniffer, conf  # import ช้า จึงอยู่ใน main

    ifaces = resolve_interfaces(ccfg["interfaces"], conf, log)
    if not ifaces:
        log.error("no usable interface - fix capture.interfaces in config/config.yaml")
        sys.exit(2)

    # กรอง IPv4 และตัด port ของ ZMQ ออก ไม่งั้นจะดักข้อความของระบบเองบน loopback วนไม่รู้จบ
    zmq_ports = sorted(int(p) for p in ports.values())
    bpf = "ip and not (" + " or ".join(f"port {p}" for p in zmq_ports) + ")"
    # ZeroMQ บน Windows ใช้ TCP socket คู่ระหว่าง 127.0.0.1 กับ 127.0.0.1 เป็นช่องส่งสัญญาณภายใน (port สุ่ม)
    # ถ้าดักมาด้วยจะเกิด feedback loop ท่วมระบบ จึงข้าม TCP ที่ทั้งสองฝั่งเป็น 127.0.0.1 (ICMP/UDP ยังดักปกติ,
    # และ TCP ที่ใช้ IP จริงของเครื่องก็ยังดัก) ปิดได้ด้วย capture.ignore_loopback_tcp: false
    ignore_lo_tcp = bool(ccfg.get("ignore_loopback_tcp", True))
    if ignore_lo_tcp:
        bpf += " and not (tcp and src host 127.0.0.1 and dst host 127.0.0.1)"
    if ccfg.get("extra_bpf"):
        bpf += f" and ({ccfg['extra_bpf']})"
    log.info("BPF filter: %s", bpf)

    pub = None
    if mode in ("zmq", "both"):
        pub = Publisher(bus_port(cfg, TOPIC_PACKETS), TOPIC_PACKETS, cfg["bus"]["host"])
        log.info("publishing topic '%s' at %s", TOPIC_PACKETS, pub.endpoint)

    csv_file = csv_writer = None
    if mode in ("csv", "both"):
        path = resolve_path(ccfg["csv_path"])
        path.parent.mkdir(parents=True, exist_ok=True)
        new = not path.exists() or path.stat().st_size == 0
        csv_file = open(path, "a", newline="", encoding="utf-8")
        csv_writer = csv.DictWriter(csv_file, fieldnames=PACKET_FIELDS)
        if new:
            csv_writer.writeheader()
        log.info("writing packet metadata to CSV: %s", path)

    # บันทึก packet เต็มๆ ลง .pcap ควบคู่กันไปด้วย (เปิดดูใน Wireshark ได้ตรงๆ, ย้อนกลับมาดึง field
    # ใหม่ทีหลังได้โดยไม่ต้องดักซ้ำ) เป็นคนละเรื่องกับ CSV/mode ข้างบน -- เปิดพร้อมกันได้เสมอถ้า save_pcap: true
    pcap_writer = None
    if bool(ccfg.get("save_pcap", False)):
        from scapy.utils import PcapWriter

        pcap_path = resolve_path(ccfg.get("pcap_path", "data/captured_full.pcap"))
        pcap_path.parent.mkdir(parents=True, exist_ok=True)
        pcap_writer = PcapWriter(str(pcap_path), append=True, sync=False)
        log.info("writing full packets to pcap: %s", pcap_path)

    lock = threading.Lock()
    counters = {"captured": 0, "skipped": 0}
    zmq_port_set = set(zmq_ports)

    def make_handler(label: str):
        def handle(pkt):
            try:
                meta = packet_to_meta(pkt, label)
                if meta is None:
                    counters["skipped"] += 1
                    return
                # กันซ้ำอีกชั้น เผื่อ BPF filter ใช้ไม่ได้บางแพลตฟอร์ม
                if meta["src_port"] in zmq_port_set or meta["dst_port"] in zmq_port_set:
                    return
                if ignore_lo_tcp and meta["proto"] == "TCP" and meta["src_ip"] == meta["dst_ip"] == "127.0.0.1":
                    return
                with lock:
                    counters["captured"] += 1
                    if pub is not None:
                        pub.send(meta)
                    if csv_writer is not None:
                        csv_writer.writerow(meta)
                    if pcap_writer is not None:
                        pcap_writer.write(pkt)
            except Exception as e:  # noqa: BLE001  packet เดียวพังต้องไม่ทำให้ทั้ง service ล้ม
                log.debug("failed to parse packet: %s", e)
        return handle

    sniffers = []
    for label, iface in ifaces:
        s = AsyncSniffer(iface=iface, filter=bpf, prn=make_handler(label), store=False)
        try:
            s.start()
            sniffers.append((label, s))
            log.info("capturing on '%s'", label)
        except Exception as e:  # noqa: BLE001
            log.error("cannot open '%s': %s (run as root/Administrator and install Npcap/libpcap)", label, e)
    if not sniffers:
        log.error("no interface could be opened - exiting")
        sys.exit(2)

    try:
        interval = float(ccfg.get("stats_interval_sec", 30))
        last = 0
        while True:
            time.sleep(interval)
            n = counters["captured"]
            log.info("captured %d packets total (+%d in %.0fs)", n, n - last, interval)
            last = n
            if csv_file:
                csv_file.flush()
            if pcap_writer is not None:
                pcap_writer.flush()
            dead = [lbl for lbl, s in sniffers if s.thread is not None and not s.thread.is_alive()]
            if dead:
                log.error("sniffer stopped: %s", dead)
    except KeyboardInterrupt:
        log.info("shutting down ...")
    finally:
        for _, s in sniffers:
            try:
                if s.running:
                    s.stop()
            except Exception:  # noqa: BLE001
                pass
        if csv_file:
            csv_file.close()
        if pcap_writer is not None:
            pcap_writer.close()
        if pub:
            pub.close()
        log.info("stopped")


if __name__ == "__main__":
    main()
