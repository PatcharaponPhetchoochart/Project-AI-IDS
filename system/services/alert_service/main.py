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
from rich.live import Live
from rich.text import Text

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
        # key -> เวลาล่าสุดที่ print_repeat เขียนทับ/พิมพ์จริงให้กลุ่มนี้ (throttle เวลา กัน terminal
        # ไหลยาว/เขียนทับถี่เกินไป -- terminal นี้ถูกแชร์กับ thread อื่นที่ relay output ของ
        # capture/feature/detection พร้อมกัน (ดู run_all.py: pump()) ยิ่งเขียนทับ cursor ถี่ ยิ่งชนกับ
        # thread พวกนั้นได้ง่าย (เคยเจอข้อความปนกันเละตอนเขียนทับทุก packet) -- throttle ให้ห่างขึ้น
        # ลดโอกาสชนแต่ไม่ได้การันตี 100% เพราะเป็นคนละ process กัน ไม่มีทางล็อกกันได้จริง)
        self._last_repeat_print: dict[tuple, float] = {}
        # กลุ่มที่กำลังเขียนทับบรรทัดเดิมอยู่ตอนนี้ (print_repeat ผ่าน rich.live.Live) -- None = ไม่มีบรรทัดค้าง
        self._open_line_key: tuple | None = None
        self._live: Live | None = None

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
                self.print_repeat(meta, det.score, g["count"], key)
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

    def _close_open_line(self) -> None:
        """ปิด Live ที่ print_repeat เปิดค้างไว้ (ถ้ามี) -- บรรทัดสุดท้ายที่โชว์จะค้างอยู่ในจอตามปกติ
        (transient=False) ต้องเรียกก่อนพิมพ์อย่างอื่นทับเสมอ กัน Live คุมจอผิดบรรทัด"""
        if self._live is not None:
            self._live.stop()
            self._live = None
        self._open_line_key = None

    def print_alert(self, meta, reason, score, threshold) -> None:
        self._close_open_line()
        c = self.console
        c.print(
            f"[bold white on red] ALERT [/] [red]{fmt_time(meta['ts'])}[/]  "
            f"[bold red]{endpoint(meta['src_ip'], meta.get('src_port'))} → "
            f"{endpoint(meta['dst_ip'], meta.get('dst_port'))}[/]  "
            f"[red]{meta.get('proto')}[/]  [dim red]iface={meta.get('iface')}[/]"
        )
        c.print(f"        [red]Reason:[/] {reason}   [red]score={score:.3f}[/] [dim](threshold {threshold:.3f})[/]")

    # แดงหม่นๆ (count ยังน้อย) ไล่ไปแดงสด/จ้า (count เยอะ) -- ทำกลับทาง (ไม่ใช่อ่อนไปเข้ม) เพราะบนพื้นจอ
    # สีเข้ม/ดำ จะ "กลืนไปกับพื้นหลังจอ" (ยิ่ง stack เยอะยิ่งอันตราย แต่กลับเด่นน้อยลง ตรงข้ามกับที่ต้องการ)
    STACK_BG_LO = (90, 15, 15)    # แดงหม่น (count ยังน้อย) -- ไม่เด่นมาก
    STACK_BG_HI = (255, 20, 20)   # แดงสด/จ้า (count ชน STACK_BG_CAP) -- เด่นสุด
    STACK_BG_CAP = 50             # count ที่ถือว่า "จ้าสุดแล้ว" ไม่จ้าไปกว่านี้อีก

    def _stack_bg(self, count: int) -> str:
        """สีพื้นหลังไล่สดขึ้นเรื่อยๆ ตามจำนวน stack -- ยิ่งซ้ำถี่/นานยิ่งแดงจ้า ชนเพดานที่ STACK_BG_CAP"""
        t = min(1.0, max(0.0, (count - 2) / (self.STACK_BG_CAP - 2)))
        r, g, b = (round(lo + (hi - lo) * t) for lo, hi in zip(self.STACK_BG_LO, self.STACK_BG_HI))
        return f"#{r:02x}{g:02x}{b:02x}"

    REPEAT_PRINT_INTERVAL = 0.5   # วินาที -- เขียนทับบรรทัด repeat ของกลุ่มเดิมได้ไม่ถี่กว่านี้ (DB อัปเดต
                                   # ครบทุก packet อยู่แล้วใน handle() ไม่ว่าจะ throttle การเขียนจอหรือไม่
                                   # ยิ่งห่างยิ่งลดโอกาสชนกับ thread อื่นที่ print แทรกกลางคัน แต่ไม่ได้ล็อก
                                   # กันจริงๆ เพราะเป็นคนละ process เขียนจอเดียวกัน -- ชนได้แม้จะน้อยลงมาก)

    def print_repeat(self, meta, score, count, key: tuple) -> None:
        """โหมด realtime: packet ซ้ำในกลุ่มเดิม -- เขียนทับบรรทัดเดิมแค่อัปเดตจำนวน ผ่าน rich.live.Live
        (ไม่ขึ้นบรรทัดใหม่ทุก packet) จำกัดไม่ให้เขียนทับถี่กว่า REPEAT_PRINT_INTERVAL ลดโอกาสชนกับ thread
        อื่นที่ relay output ของ capture/feature/detection บนจอเดียวกัน (ดู run_all.py: pump()) -- ไม่โชว์
        port เพราะมันเปลี่ยนทุก connection อยู่แล้ว (ephemeral) พื้นหลังไล่สดขึ้นตาม count (ดู _stack_bg)"""
        now = self.clock()
        if count > 2 and now - self._last_repeat_print.get(key, 0.0) < self.REPEAT_PRINT_INTERVAL:
            return
        self._last_repeat_print[key] = now
        detail = meta.get("proto")
        if detail == "ICMP":
            detail = {8: "ICMP echo request", 0: "ICMP echo reply"}.get(meta.get("icmp_type"),
                                                                        f"ICMP type {meta.get('icmp_type')}")
        plain = (f" ALERT x{count:<4} {fmt_time(meta['ts'])}  "
                 f"{meta['src_ip']} ↔ {meta['dst_ip']}  {detail}  score={score:.3f} ")
        plain = plain.ljust(max(self.console.size.width, len(plain)))   # เติมเต็มบรรทัด ให้พื้นหลังเป็นแถบเต็มจอ
        text = Text(plain, style=f"bold white on {self._stack_bg(count)}")
        if self._live is not None and self._open_line_key == key:
            self._live.update(text, refresh=True)
            return
        self._close_open_line()  # กลุ่มอื่น (หรือยังไม่มี Live เปิดอยู่เลย) -- ปิดของเก่าก่อนเปิดใหม่
        self._live = Live(text, console=self.console, auto_refresh=False, transient=False)
        self._live.start(refresh=True)  # refresh=True ไม่งั้นเฟรมแรกไม่ขึ้นจนกว่าจะ .update() รอบถัดไป
        self._open_line_key = key

    def flush_group(self, key: tuple) -> None:
        """พิมพ์สรุปของกลุ่มที่ปิดแล้ว ถ้ามี packet ซ้ำมากกว่า 1"""
        g = self.groups.pop(key, None)
        self._last_repeat_print.pop(key, None)
        if g and g["count"] > 1:
            self._close_open_line()
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
        self._close_open_line()
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
