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


def packet_to_meta(pkt, iface_label: str) -> dict | None:
    """แปลง Scapy packet เป็น metadata dict (เฉพาะ IPv4) — ไม่เก็บ payload"""
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
    }
    tcp, udp, icmp = pkt.getlayer(TCP), pkt.getlayer(UDP), pkt.getlayer(ICMP)
    if tcp is not None:
        meta.update(proto="TCP", src_port=int(tcp.sport), dst_port=int(tcp.dport), tcp_flags=int(tcp.flags))
    elif udp is not None:
        meta.update(proto="UDP", src_port=int(udp.sport), dst_port=int(udp.dport))
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
        if pub:
            pub.close()
        log.info("stopped")


if __name__ == "__main__":
    main()
