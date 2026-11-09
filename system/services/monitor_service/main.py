"""monitor-service: "Wireshark ฉบับ terminal" — แสดง packet ไหลเป็นบรรทัด
packet ปกติสีเทา, packet แปลกสีแดง

รันเดี่ยว:  python system/services/monitor_service/main.py
"""
from __future__ import annotations

import sys
import time
from pathlib import Path

if __package__ in (None, ""):
    sys.path.insert(0, str(Path(__file__).resolve().parents[2]))

from rich.console import Console
from rich.markup import escape

from shared.bus import Subscriber
from shared.config import bus_port, load_config
from shared.schemas import TOPIC_DETECTIONS
from shared.utils import endpoint, flags_to_str, fmt_time, setup_logging

SERVICE = "monitor"


def format_line(d: dict) -> str:
    """สร้างบรรทัดเดียวของ packet (ไม่ใส่สี)"""
    m = d["meta"]
    proto = m.get("proto", "?")
    extra = ""
    if proto == "TCP":
        extra = flags_to_str(m.get("tcp_flags"))
    elif proto == "ICMP":
        extra = f"type={m.get('icmp_type')}/{m.get('icmp_code')}"
    src = endpoint(m["src_ip"], m.get("src_port"))
    dst = endpoint(m["dst_ip"], m.get("dst_port"))
    return (f"{fmt_time(m['ts'], True)}  {src:<22} → {dst:<22} {proto:<5} {extra:<14} "
            f"len={m.get('length', 0):<5} score={d['score']:.3f}")


def main() -> None:
    log = setup_logging(SERVICE)
    cfg = load_config()
    mcfg = cfg["monitor"]
    console = Console(highlight=False)
    sub = Subscriber(bus_port(cfg, TOPIC_DETECTIONS), TOPIC_DETECTIONS, cfg["bus"]["host"])
    log.info("subscribed to '%s' at %s", TOPIC_DETECTIONS, sub.endpoint)
    console.print("[green]monitor-service ready - normal packets grey, anomalies red[/]")

    show_normal = bool(mcfg.get("show_normal", True))
    max_rate = float(mcfg.get("max_normal_lines_per_sec", 40))
    sec, shown_in_sec, hidden = int(time.time()), 0, 0
    try:
        while True:
            for d in sub.recv_many(250, 512):
                line = escape(format_line(d))
                if d.get("is_anomaly"):
                    console.print(f"[bold red]{line}  << ANOMALY[/]")
                    continue
                if not show_normal:
                    continue
                now = int(time.time())
                if now != sec:
                    if hidden:
                        console.print(f"[dim]  ... {hidden} normal packets hidden in the last second (limit {max_rate:.0f} lines/s)[/]")
                    sec, shown_in_sec, hidden = now, 0, 0
                if shown_in_sec < max_rate:
                    console.print(f"[grey50]{line}[/]")
                    shown_in_sec += 1
                else:
                    hidden += 1
    except KeyboardInterrupt:
        log.info("shutting down ...")
    finally:
        sub.close()
        log.info("stopped")


if __name__ == "__main__":
    main()
