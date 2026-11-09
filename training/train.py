"""เทรน StandardScaler + Isolation Forest จาก CSV (ทำเหมือน train.ipynb แต่รันจาก command line)

รัน:
  python training/generate_data.py          # สร้างข้อมูลปกติ (synthetic)
  python training/train.py                  # เทรน -> system/models/
  python training/train.py --source data/captured_packets.csv   # เทรนจาก traffic จริงที่ capture บันทึกไว้
  python training/train.py --source data/normal_packets.csv data/captured_packets.csv   # รวม synthetic + ของจริง
  python training/train.py --plot           # บันทึกกราฟ score ที่ data/score_plot.png
"""
from __future__ import annotations

import argparse
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / "system"))  # shared/, services/ อยู่ใน system/

from shared.config import load_config, resolve_path  # noqa: E402
from shared.utils import force_utf8  # noqa: E402
from training.common import plot_scores, print_report, run_training, save_model  # noqa: E402


def main() -> None:
    force_utf8()
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--source", nargs="+",
                    help="CSV metadata ที่จะเทรน ใส่ได้หลายไฟล์ (ค่าเริ่มต้น: training.packets_csv ใน config)")
    ap.add_argument("--keep-icmp-echo", action="store_true",
                    help="ไม่ตัด ping (ICMP echo) ออกจากข้อมูลเทรน (ค่าเริ่มต้น: ตัดออก เพื่อให้ ping ถูกมองว่าแปลก)")
    ap.add_argument("--plot", action="store_true", help="บันทึกกราฟ score เป็น data/score_plot.png")
    args = ap.parse_args()

    cfg = load_config()
    try:
        res = run_training(cfg, args.source, drop_icmp_echo=not args.keep_icmp_echo)
    except FileNotFoundError as e:
        print(f"ERROR: {e}")
        sys.exit(1)
    print_report(res)
    paths = save_model(res, cfg)
    print("บันทึกโมเดลแล้ว:")
    for p in paths.values():
        print("  ->", p)
    if args.plot:
        out = resolve_path("data/score_plot.png")
        plot_scores(res, out)
        print("  -> กราฟ:", out)


if __name__ == "__main__":
    main()
