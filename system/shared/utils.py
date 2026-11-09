"""ฟังก์ชันช่วยเล็กๆ ที่ใช้ร่วมกันหลาย service"""
from __future__ import annotations

import logging
import sys
import time

_FLAG_NAMES = (
    (0x02, "SYN"), (0x10, "ACK"), (0x08, "PSH"), (0x01, "FIN"),
    (0x04, "RST"), (0x20, "URG"), (0x40, "ECE"), (0x80, "CWR"),
)


def force_utf8() -> None:
    """ให้ stdout/stderr เป็น UTF-8 (กัน error ตอนแสดงภาษาไทยเมื่อ output ถูก pipe บน Windows)"""
    for stream in (sys.stdout, sys.stderr):
        try:
            stream.reconfigure(encoding="utf-8", errors="replace")
        except Exception:  # noqa: BLE001
            pass


def scapy_env() -> None:
    """ให้ Scapy เก็บ cache ในโปรเจกต์ (.cache/) แทน ~/.cache — กัน PermissionError
    เมื่อโฟลเดอร์ cache ของ user เคยถูกสร้างโดยสิทธิ์ Administrator
    ต้องเรียกก่อน import scapy"""
    import os
    from pathlib import Path

    cache = Path(__file__).resolve().parents[1] / ".cache"
    try:
        cache.mkdir(exist_ok=True)
        os.environ.setdefault("XDG_CACHE_HOME", str(cache))
    except OSError:
        pass


def setup_logging(service: str, level: int = logging.INFO) -> logging.Logger:
    force_utf8()
    logging.basicConfig(
        level=level,
        format="%(asctime)s [" + service + "] %(levelname)s %(message)s",
        datefmt="%H:%M:%S",
        stream=sys.stderr,
        force=True,
    )
    return logging.getLogger(service)


def flags_to_str(flags: int | None) -> str:
    """แปลง TCP flags (int) เป็นข้อความ เช่น 0x12 -> 'SYN,ACK'"""
    if not flags:
        return "-" if flags is None else "NONE"
    return ",".join(name for bit, name in _FLAG_NAMES if flags & bit)


def fmt_time(ts: float, with_ms: bool = False) -> str:
    t = time.localtime(ts)
    s = time.strftime("%H:%M:%S", t)
    if with_ms:
        s += f".{int((ts % 1) * 1000):03d}"
    return s


def endpoint(ip: str, port: int | None) -> str:
    return f"{ip}:{port}" if port is not None else ip
