"""แปลงไฟล์ .pcap / .pcapng (เช่น dataset ที่โหลดจากออนไลน์ หรือไฟล์ที่ save จาก Wireshark)
เป็น CSV metadata รูปแบบเดียวกับที่ระบบใช้เทรน

ใช้ฟังก์ชัน packet_to_meta ตัวเดียวกับ capture-service -> ข้อมูลที่ได้ตรงกับตอนดักสดทุกประการ

รัน:
  python training/pcap_to_csv.py data/raw/Monday-WorkingHours.pcap -o data/cic_monday.csv
  python training/pcap_to_csv.py a.pcap b.pcapng -o data/mix.csv --max-packets 2000000
  python training/pcap_to_csv.py Friday-WorkingHours.pcap -o data/cic_friday_scan.csv \
      --start 2017-07-07T13:50:00-03:00 --end 2017-07-07T15:35:00-03:00   # อ่านเฉพาะช่วงเวลา
แล้วเทรน:
  python training/train.py --source data/normal_packets.csv data/cic_monday.csv
"""
from __future__ import annotations

import argparse
import csv
import json
import sys
import time
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / "system"))  # shared/, services/ อยู่ใน system/

from shared.config import resolve_path  # noqa: E402
from shared.features import PACKET_FIELDS  # noqa: E402
from shared.utils import force_utf8, scapy_env  # noqa: E402


def parse_time(v) -> float | None:
    """'' / None -> None, ตัวเลข -> epoch, ข้อความ -> ISO 8601 (ควรมี timezone เช่น -03:00)"""
    if v is None:
        return None
    if isinstance(v, (int, float)):
        return float(v)
    if isinstance(v, datetime):  # YAML อาจแปลง ISO ที่ไม่มีเครื่องหมายคำพูดเป็น datetime ให้เอง
        return v.timestamp()
    v = str(v).strip()
    if not v:
        return None
    try:
        return float(v)
    except ValueError:
        return datetime.fromisoformat(v).timestamp()


def _fmt_ts(ts: float | None) -> str:
    return "-" if ts is None else datetime.fromtimestamp(ts, timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")


def _iter_packets(path: Path, start_ts: float | None, end_ts: float | None, stats: dict):
    """ไล่ packet ในไฟล์ตามลำดับ
    - ไม่กำหนดช่วงเวลา: PcapReader ธรรมดา (แยก layer ทุก packet)
    - กำหนดช่วงเวลา + ไฟล์ .pcap: อ่านแบบ raw (ไม่แยก layer) เพื่อข้าม packet นอกช่วงได้เร็วมาก
      แยก layer เฉพาะ packet ที่อยู่ในช่วง และหยุดอ่านเมื่อเลยเวลาสิ้นสุด
    """
    from scapy.config import conf
    from scapy.utils import PcapReader, RawPcapNgReader, RawPcapReader

    windowed = start_ts is not None or end_ts is not None
    grace = 60.0  # เผื่อ packet ที่ timestamp สลับลำดับเล็กน้อย ก่อนตัดสินว่าเลยช่วงแล้ว

    def in_window(ts: float) -> str:
        if start_ts is not None and ts < start_ts:
            return "before"
        if end_ts is not None and ts > end_ts:
            return "stop" if ts > end_ts + grace else "after"
        return "in"

    if windowed:
        try:
            raw = RawPcapReader(str(path))
        except Exception:  # noqa: BLE001
            raw = None
        if isinstance(raw, RawPcapNgReader):  # pcapng เก็บเวลาอีกแบบ -> ใช้วิธีปกติ (ช้ากว่าแต่ถูกต้อง)
            raw.close()
            raw = None
        if raw is not None:
            ll_cls = conf.l2types.num2layer.get(raw.linktype, conf.raw_layer)
            div = 1e9 if getattr(raw, "nano", False) else 1e6
            with raw:
                for data, md in raw:
                    stats["read"] += 1
                    ts = md.sec + md.usec / div
                    if stats["first_ts"] is None:
                        stats["first_ts"] = ts
                    pos = in_window(ts)
                    if pos == "stop":
                        stats["stopped_early"] = True
                        return
                    if pos != "in":
                        stats["skipped_time"] += 1
                        continue
                    try:
                        pkt = ll_cls(data)
                    except Exception:  # noqa: BLE001
                        stats["errors"] += 1
                        continue
                    pkt.time = ts
                    yield pkt
            return

    with PcapReader(str(path)) as reader:
        for pkt in reader:
            stats["read"] += 1
            if windowed:
                ts = float(pkt.time)
                if stats["first_ts"] is None:
                    stats["first_ts"] = ts
                pos = in_window(ts)
                if pos == "stop":
                    stats["stopped_early"] = True
                    return
                if pos != "in":
                    stats["skipped_time"] += 1
                    continue
            yield pkt


def convert(pcaps: list[Path], out: Path, iface: str = "pcap", max_packets: int | None = None,
            progress_every: int = 100_000, start=None, end=None) -> dict:
    """อ่าน pcap ทีละ packet (stream ไม่โหลดทั้งไฟล์เข้า RAM) แล้วเขียน CSV
    start / end (epoch หรือ ISO 8601 พร้อม timezone) = เอาเฉพาะ packet ในช่วงเวลานี้ (ว่าง = ไม่จำกัด)"""
    scapy_env()
    from scapy.config import conf
    from scapy.layers.inet import ICMP, IP, TCP, UDP
    from scapy.layers.l2 import Ether

    from services.capture_service.main import packet_to_meta

    start_ts, end_ts = parse_time(start), parse_time(end)
    if start_ts is not None or end_ts is not None:
        print(f"เอาเฉพาะช่วงเวลา {_fmt_ts(start_ts)} -> {_fmt_ts(end_ts)}")

    # ให้ Scapy แยกแค่ layer ที่ใช้ -> เร็วขึ้นหลายเท่าสำหรับไฟล์ใหญ่
    conf.layers.filter([Ether, IP, TCP, UDP, ICMP])
    stats = {"read": 0, "written": 0, "skipped_non_ipv4": 0, "skipped_time": 0, "errors": 0,
             "first_ts": None, "min_written_ts": None, "max_written_ts": None, "stopped_early": False}
    out.parent.mkdir(parents=True, exist_ok=True)
    t0 = time.time()
    try:
        with open(out, "w", newline="", encoding="utf-8") as f:
            w = csv.DictWriter(f, fieldnames=PACKET_FIELDS)
            w.writeheader()
            for path in pcaps:
                print(f"อ่าน {path} ...")
                last_progress = 0
                for pkt in _iter_packets(path, start_ts, end_ts, stats):
                    if progress_every and stats["read"] - last_progress >= progress_every:
                        last_progress = stats["read"]
                        rate = stats["read"] / max(time.time() - t0, 1e-6)
                        print(f"  {stats['read']:,} packets ({rate:,.0f} packets/วินาที) | "
                              f"เขียนแล้ว {stats['written']:,}")
                    try:
                        meta = packet_to_meta(pkt, iface)
                    except Exception:  # noqa: BLE001  packet เสียบางตัวไม่ควรทำให้ทั้งไฟล์ล้ม
                        stats["errors"] += 1
                        continue
                    if meta is None:
                        stats["skipped_non_ipv4"] += 1
                        continue
                    w.writerow({k: ("" if meta[k] is None else meta[k]) for k in PACKET_FIELDS})
                    stats["written"] += 1
                    ts = meta["ts"]
                    if stats["min_written_ts"] is None or ts < stats["min_written_ts"]:
                        stats["min_written_ts"] = ts
                    if stats["max_written_ts"] is None or ts > stats["max_written_ts"]:
                        stats["max_written_ts"] = ts
                    if max_packets and stats["written"] >= max_packets:
                        print(f"ครบ --max-packets {max_packets:,} แล้ว หยุดอ่าน "
                              f"(ได้ถึงเวลา {_fmt_ts(stats['max_written_ts'])})")
                        return stats
    finally:
        conf.layers.unfilter()
        if start_ts is not None or end_ts is not None:
            print(f"  packet แรกของไฟล์: {_fmt_ts(stats['first_ts'])} | "
                  f"ช่วงที่เขียน: {_fmt_ts(stats['min_written_ts'])} -> {_fmt_ts(stats['max_written_ts'])} | "
                  f"ข้ามเพราะนอกช่วงเวลา {stats['skipped_time']:,}")
    return stats


PCAP_EXTS = (".pcap", ".pcapng", ".cap")


def list_pcaps(folder: Path) -> list[Path]:
    folder = Path(folder)
    if not folder.exists():
        return []
    return sorted(p for p in folder.iterdir() if p.suffix.lower() in PCAP_EXTS)


def _window_for(pcap: Path, windows: dict | None):
    """หาช่วงเวลาของไฟล์นี้จาก windows (key = ชื่อไฟล์ไม่มีนามสกุล หรือชื่อเต็ม) -> [start, end] หรือ None"""
    if not windows:
        return None
    w = windows.get(pcap.stem, windows.get(pcap.name))
    if not w:
        return None
    start, end = (list(w) + [None, None])[:2]
    return [parse_time(start), parse_time(end)]


def convert_folder(src_dir: Path, out_dir: Path, max_packets: int | None = None, force: bool = False,
                   iface: str = "pcap", windows: dict | None = None) -> list[Path]:
    """แปลงทุก pcap ในโฟลเดอร์ -> 1 CSV ต่อ 1 ไฟล์ ใน out_dir
    ถ้า CSV มีอยู่แล้ว ใหม่กว่า pcap และใช้ช่วงเวลาเดียวกัน จะข้าม (cache) ใส่ force=True เพื่อแปลงใหม่
    windows = {"ชื่อไฟล์": [start, end]} อ่านเฉพาะช่วงเวลา (ตั้งใน config: training.pcap_time_windows)"""
    out_dir = Path(out_dir)
    outs = []
    for pcap in list_pcaps(src_dir):
        out = out_dir / f"{Path(src_dir).name}__{pcap.stem}.csv"
        window = _window_for(pcap, windows)
        side = out.with_name(out.name + ".window.json")       # จำว่า CSV นี้แปลงด้วยช่วงเวลาไหน
        try:
            old_window = json.loads(side.read_text(encoding="utf-8")).get("window") if side.exists() else None
        except (OSError, ValueError):
            old_window = "unknown"
        if not force and out.exists() and out.stat().st_mtime >= pcap.stat().st_mtime and old_window == window:
            print(f"ใช้ CSV เดิม (แปลงไว้แล้ว): {out.name}")
        else:
            start, end = window or (None, None)
            s = convert([pcap], out, iface, max_packets, start=start, end=end)
            print(f"  -> {out.name}: เขียน {s['written']:,} packets (ข้ามที่ไม่ใช่ IPv4 {s['skipped_non_ipv4']:,})")
            if window:
                side.write_text(json.dumps({"window": window}), encoding="utf-8")
            elif side.exists():
                side.unlink()
        outs.append(out)
    return outs


def main() -> None:
    force_utf8()
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("pcaps", nargs="+", help="ไฟล์ .pcap / .pcapng (หลายไฟล์ได้ จะต่อกันตามลำดับ)")
    ap.add_argument("-o", "--out", required=True, help="ไฟล์ CSV ที่จะเขียน เช่น data/cic_monday.csv")
    ap.add_argument("--iface", default="pcap", help="ป้ายชื่อ interface ที่จะใส่ในคอลัมน์ iface (ค่าเริ่มต้น: pcap)")
    ap.add_argument("--max-packets", type=int, default=None,
                    help="หยุดเมื่อเขียนครบจำนวนนี้ (ไฟล์ dataset ใหญ่มาก แนะนำ 1-3 ล้าน)")
    ap.add_argument("--start", default=None,
                    help="เอาเฉพาะ packet ตั้งแต่เวลานี้ (ISO 8601 พร้อม timezone เช่น 2017-07-07T13:50:00-03:00 หรือ epoch)")
    ap.add_argument("--end", default=None, help="เอาเฉพาะ packet ไม่เกินเวลานี้ (รูปแบบเดียวกับ --start)")
    args = ap.parse_args()

    pcaps = [Path(p) for p in args.pcaps]
    missing = [str(p) for p in pcaps if not p.exists()]
    if missing:
        print("ERROR: ไม่พบไฟล์:", ", ".join(missing))
        sys.exit(1)
    out = resolve_path(args.out) if not Path(args.out).is_absolute() else Path(args.out)
    t0 = time.time()
    s = convert(pcaps, out, args.iface, args.max_packets, start=args.start, end=args.end)
    print(f"เสร็จใน {time.time() - t0:.1f} วินาที -> {out}")
    print(f"  อ่าน {s['read']:,} | เขียน {s['written']:,} | ข้าม (ไม่ใช่ IPv4) {s['skipped_non_ipv4']:,} | error {s['errors']:,}")
    print(f"ขั้นต่อไป: python training/train.py --source data/normal_packets.csv {args.out}")


if __name__ == "__main__":
    main()
