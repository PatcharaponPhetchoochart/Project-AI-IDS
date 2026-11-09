"""แปลงไฟล์ .pcap / .pcapng (เช่น dataset ที่โหลดจากออนไลน์ หรือไฟล์ที่ save จาก Wireshark)
เป็น CSV metadata รูปแบบเดียวกับที่ระบบใช้เทรน

ใช้ฟังก์ชัน packet_to_meta ตัวเดียวกับ capture-service -> ข้อมูลที่ได้ตรงกับตอนดักสดทุกประการ

รัน:
  python training/pcap_to_csv.py data/raw/Monday-WorkingHours.pcap -o data/cic_monday.csv
  python training/pcap_to_csv.py a.pcap b.pcapng -o data/mix.csv --max-packets 2000000
แล้วเทรน:
  python training/train.py --source data/normal_packets.csv data/cic_monday.csv
"""
from __future__ import annotations

import argparse
import csv
import sys
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / "system"))  # shared/, services/ อยู่ใน system/

from shared.config import resolve_path  # noqa: E402
from shared.features import PACKET_FIELDS  # noqa: E402
from shared.utils import force_utf8, scapy_env  # noqa: E402


def convert(pcaps: list[Path], out: Path, iface: str = "pcap", max_packets: int | None = None,
            progress_every: int = 100_000) -> dict:
    """อ่าน pcap ทีละ packet (stream ไม่โหลดทั้งไฟล์เข้า RAM) แล้วเขียน CSV"""
    scapy_env()
    from scapy.config import conf
    from scapy.layers.inet import ICMP, IP, TCP, UDP
    from scapy.layers.l2 import Ether
    from scapy.utils import PcapReader

    from services.capture_service.main import packet_to_meta

    # ให้ Scapy แยกแค่ layer ที่ใช้ -> เร็วขึ้นหลายเท่าสำหรับไฟล์ใหญ่
    conf.layers.filter([Ether, IP, TCP, UDP, ICMP])
    stats = {"read": 0, "written": 0, "skipped_non_ipv4": 0, "errors": 0}
    out.parent.mkdir(parents=True, exist_ok=True)
    t0 = time.time()
    try:
        with open(out, "w", newline="", encoding="utf-8") as f:
            w = csv.DictWriter(f, fieldnames=PACKET_FIELDS)
            w.writeheader()
            for path in pcaps:
                print(f"อ่าน {path} ...")
                with PcapReader(str(path)) as reader:
                    for pkt in reader:
                        stats["read"] += 1
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
                        if progress_every and stats["read"] % progress_every == 0:
                            rate = stats["read"] / max(time.time() - t0, 1e-6)
                            print(f"  {stats['read']:,} packets ({rate:,.0f} packets/วินาที)")
                        if max_packets and stats["written"] >= max_packets:
                            print(f"ครบ --max-packets {max_packets:,} แล้ว หยุดอ่าน")
                            return stats
    finally:
        conf.layers.unfilter()
    return stats


PCAP_EXTS = (".pcap", ".pcapng", ".cap")


def list_pcaps(folder: Path) -> list[Path]:
    folder = Path(folder)
    if not folder.exists():
        return []
    return sorted(p for p in folder.iterdir() if p.suffix.lower() in PCAP_EXTS)


def convert_folder(src_dir: Path, out_dir: Path, max_packets: int | None = None, force: bool = False,
                   iface: str = "pcap") -> list[Path]:
    """แปลงทุก pcap ในโฟลเดอร์ -> 1 CSV ต่อ 1 ไฟล์ ใน out_dir
    ถ้า CSV มีอยู่แล้วและใหม่กว่า pcap จะข้าม (cache) ใส่ force=True เพื่อแปลงใหม่"""
    out_dir = Path(out_dir)
    outs = []
    for pcap in list_pcaps(src_dir):
        out = out_dir / f"{Path(src_dir).name}__{pcap.stem}.csv"
        if not force and out.exists() and out.stat().st_mtime >= pcap.stat().st_mtime:
            print(f"ใช้ CSV เดิม (แปลงไว้แล้ว): {out.name}")
        else:
            s = convert([pcap], out, iface, max_packets)
            print(f"  -> {out.name}: เขียน {s['written']:,} packets (ข้ามที่ไม่ใช่ IPv4 {s['skipped_non_ipv4']:,})")
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
    args = ap.parse_args()

    pcaps = [Path(p) for p in args.pcaps]
    missing = [str(p) for p in pcaps if not p.exists()]
    if missing:
        print("ERROR: ไม่พบไฟล์:", ", ".join(missing))
        sys.exit(1)
    out = resolve_path(args.out) if not Path(args.out).is_absolute() else Path(args.out)
    t0 = time.time()
    s = convert(pcaps, out, args.iface, args.max_packets)
    print(f"เสร็จใน {time.time() - t0:.1f} วินาที -> {out}")
    print(f"  อ่าน {s['read']:,} | เขียน {s['written']:,} | ข้าม (ไม่ใช่ IPv4) {s['skipped_non_ipv4']:,} | error {s['errors']:,}")
    print(f"ขั้นต่อไป: python training/train.py --source data/normal_packets.csv {args.out}")


if __name__ == "__main__":
    main()
