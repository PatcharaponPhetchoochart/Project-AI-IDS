"""alert-service: subscribe `detections` (เฉพาะ is_anomaly) -> แสดง ALERT สีแดง + บันทึก SQLite

มี cooldown: alert ซ้ำจาก src IP เดียวกันภายใน N วินาทีจะถูกรวม (นับจำนวนครั้ง) ไม่ spam จอ
รันเดี่ยว:  python system/services/alert_service/main.py
"""
from __future__ import annotations

import sqlite3
import sys
import time
from pathlib import Path

if __package__ in (None, ""):
    sys.path.insert(0, str(Path(__file__).resolve().parents[2]))

from rich.console import Console

from shared.bus import Subscriber
from shared.config import bus_port, load_config, resolve_path
from shared.reasons import explain
from shared.schemas import TOPIC_DETECTIONS, DetectionMsg
from shared.utils import endpoint, fmt_time, setup_logging

SERVICE = "alert"

SCHEMA = """
CREATE TABLE IF NOT EXISTS alerts (
    id         INTEGER PRIMARY KEY AUTOINCREMENT,
    ts         REAL NOT NULL,      -- เวลา packet แรกของ alert นี้
    last_ts    REAL NOT NULL,      -- เวลา packet ล่าสุดที่ถูกรวมเข้ามา
    src_ip     TEXT NOT NULL,
    dst_ip     TEXT NOT NULL,
    src_port   INTEGER,
    dst_port   INTEGER,
    proto      TEXT,
    iface      TEXT,
    reason     TEXT,
    score      REAL,               -- score สูงสุดในกลุ่ม
    count      INTEGER NOT NULL DEFAULT 1
);
CREATE INDEX IF NOT EXISTS idx_alerts_ts ON alerts(ts);
CREATE INDEX IF NOT EXISTS idx_alerts_src ON alerts(src_ip);
"""


class AlertManager:
    """จัดการ cooldown ต่อ src IP + เขียน DB + แสดงผล (แยกออกมาเพื่อให้ทดสอบง่าย)"""

    def __init__(self, db_path: Path, cooldown: float, console: Console, clock=time.time, realtime: bool = False):
        db_path.parent.mkdir(parents=True, exist_ok=True)
        self.db = sqlite3.connect(db_path)
        self.db.executescript(SCHEMA)
        self.db.commit()
        self.cooldown = cooldown
        self.console = console
        self.clock = clock
        # realtime=True: แสดงทุก packet ที่แปลกทันที (บรรทัดสั้นพร้อมลำดับครั้งที่) แม้อยู่ใน cooldown
        # DB ยังรวมเป็นแถวเดียวต่อกลุ่มเหมือนเดิม
        self.realtime = realtime
        # (src_ip, dst_ip, proto) -> {start (wall clock), count, row_id, max_score, last_ts, meta}
        self.groups: dict[tuple, dict] = {}

    MAX_DST_PER_SRC = 5   # src เดียวกันแยกแสดงได้ไม่เกินกี่ปลายทางพร้อมกัน (เกินแล้วรวมเป็นกลุ่ม "*")

    def _key(self, src: str, dst: str, proto: str) -> tuple:
        """รวมซ้ำตาม src IP: ปลายทางต่างกันได้บรรทัดของตัวเอง (เช่น ping ตัวเอง vs ping ออกนอก)
        แต่จำกัดไม่เกิน MAX_DST_PER_SRC กลุ่มต่อ src เพื่อไม่ให้ scan หลาย host ทำให้จอ spam"""
        if (src, dst, proto) in self.groups:
            return (src, dst, proto)
        active = sum(1 for k in self.groups if k[0] == src and k[2] == proto and k[1] != "*")
        return (src, dst, proto) if active < self.MAX_DST_PER_SRC else (src, "*", proto)

    def handle(self, det: DetectionMsg) -> None:
        meta = det.meta
        src = meta["src_ip"]
        now = self.clock()
        key = self._key(src, meta["dst_ip"], meta.get("proto"))
        g = self.groups.get(key)
        if g is not None and now - g["start"] <= self.cooldown:
            # อยู่ใน cooldown: รวมเข้ากลุ่มเดิม ไม่พิมพ์ซ้ำ
            g["count"] += 1
            g["max_score"] = max(g["max_score"], det.score)
            g["last_ts"] = meta["ts"]
            self.db.execute("UPDATE alerts SET count=?, last_ts=?, score=? WHERE id=?",
                            (g["count"], meta["ts"], g["max_score"], g["row_id"]))
            self.db.commit()
            if self.realtime:
                self.print_repeat(meta, det.score, g["count"])
            return
        self.flush_group(key)  # กลุ่มเก่าหมดอายุแล้ว: สรุปก่อนเริ่มกลุ่มใหม่
        reason = explain(meta, det.vector)
        cur = self.db.execute(
            "INSERT INTO alerts (ts,last_ts,src_ip,dst_ip,src_port,dst_port,proto,iface,reason,score,count)"
            " VALUES (?,?,?,?,?,?,?,?,?,?,1)",
            (meta["ts"], meta["ts"], src, meta["dst_ip"], meta.get("src_port"), meta.get("dst_port"),
             meta.get("proto"), meta.get("iface"), reason, det.score))
        self.db.commit()
        self.groups[key] = {"start": now, "count": 1, "row_id": cur.lastrowid,
                            "max_score": det.score, "last_ts": meta["ts"], "meta": meta, "reason": reason}
        self.print_alert(meta, reason, det.score, det.threshold)

    def print_alert(self, meta, reason, score, threshold) -> None:
        c = self.console
        c.print(
            f"[bold white on red] ALERT [/] [red]{fmt_time(meta['ts'])}[/]  "
            f"[bold red]{endpoint(meta['src_ip'], meta.get('src_port'))} → "
            f"{endpoint(meta['dst_ip'], meta.get('dst_port'))}[/]  "
            f"[red]{meta.get('proto')}[/]  [dim red]iface={meta.get('iface')}[/]"
        )
        c.print(f"        [red]Reason:[/] {reason}   [red]score={score:.3f}[/] [dim](threshold {threshold:.3f})[/]")

    def print_repeat(self, meta, score, count) -> None:
        """โหมด realtime: packet ซ้ำในกลุ่มเดิม -> บรรทัดสั้น 1 บรรทัดต่อ packet"""
        detail = meta.get("proto")
        if detail == "ICMP":
            detail = {8: "ICMP echo request", 0: "ICMP echo reply"}.get(meta.get("icmp_type"),
                                                                        f"ICMP type {meta.get('icmp_type')}")
        self.console.print(
            f"[red] ALERT #{count:<3}[/] [red]{fmt_time(meta['ts'])}[/]  "
            f"[red]{endpoint(meta['src_ip'], meta.get('src_port'))} → {endpoint(meta['dst_ip'], meta.get('dst_port'))}[/]  "
            f"[red]{detail}[/]  [dim]score={score:.3f}[/]"
        )

    def flush_group(self, key: tuple) -> None:
        """พิมพ์สรุปของกลุ่มที่ปิดแล้ว ถ้ามี packet ซ้ำมากกว่า 1"""
        g = self.groups.pop(key, None)
        if g and g["count"] > 1:
            src, dst, proto = key
            self.console.print(
                f"[red]  └─ {proto} {src}{'' if dst == '*' else ' → ' + dst}: [bold]{g['count']}[/bold] alerts "
                f"in {max(self.clock() - g['start'], 0):.0f}s (max score {g['max_score']:.3f})[/]"
            )

    def tick(self) -> None:
        """เรียกเป็นระยะ: ปิดกลุ่มที่หมด cooldown แล้วและสรุปจำนวนครั้งที่ถูกรวม"""
        now = self.clock()
        for key in [k for k, g in self.groups.items() if now - g["start"] > self.cooldown]:
            self.flush_group(key)

    def close(self) -> None:
        for key in list(self.groups):
            self.flush_group(key)
        self.db.close()


def main() -> None:
    log = setup_logging(SERVICE)
    cfg = load_config()
    acfg = cfg["alert"]
    console = Console()

    db_path = resolve_path(acfg["db_path"])
    realtime = bool(acfg.get("realtime", True))
    mgr = AlertManager(db_path, float(acfg["cooldown_sec"]), console, realtime=realtime)
    sub = Subscriber(bus_port(cfg, TOPIC_DETECTIONS), TOPIC_DETECTIONS, cfg["bus"]["host"])
    log.info("subscribed to '%s' at %s (anomalies only)", TOPIC_DETECTIONS, sub.endpoint)
    log.info("saving alerts to SQLite: %s | cooldown %ss | realtime=%s", db_path, acfg["cooldown_sec"], realtime)
    console.print("[green]alert-service ready - waiting for alerts ...[/]")

    try:
        while True:
            for d in sub.recv_many(250, 256):
                if d.get("is_anomaly"):
                    mgr.handle(DetectionMsg.from_dict(d))
            mgr.tick()
    except KeyboardInterrupt:
        log.info("shutting down ...")
    finally:
        mgr.close()
        sub.close()
        log.info("stopped")


if __name__ == "__main__":
    main()
