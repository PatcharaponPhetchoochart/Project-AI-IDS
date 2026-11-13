"""แบ่งไฟล์ packet CSV เป็น 2 ส่วนตามเวลา: <ชื่อ>_train.csv (ก่อนเวลาที่กำหนด) และ <ชื่อ>_test.csv (ตั้งแต่เวลานั้น)

ใช้แยกข้อมูลที่บันทึกจาก capture (capture.mode: csv|both) เป็นชุดเทรน/ชุดทดสอบ โดยไม่ให้ช่วงเวลาซ้อนกัน

ตัวอย่าง:
  python training/split_by_time.py data/soak_active1.csv 2026-11-13T01:58:00+07:00
  python training/split_by_time.py data/soak_night1.csv  2026-11-13T05:18:00+07:00
"""
import argparse
import csv
from datetime import datetime
from pathlib import Path


def split(path: Path, split_at: str) -> tuple[int, int]:
    t_split = datetime.fromisoformat(split_at).timestamp()
    out_train = path.with_name(path.stem + "_train.csv")
    out_test = path.with_name(path.stem + "_test.csv")
    n_train = n_test = 0
    with open(path, encoding="utf-8", newline="") as f_in, \
            open(out_train, "w", encoding="utf-8", newline="") as f_tr, \
            open(out_test, "w", encoding="utf-8", newline="") as f_te:
        reader = csv.DictReader(f_in)
        w_tr = csv.DictWriter(f_tr, fieldnames=reader.fieldnames)
        w_te = csv.DictWriter(f_te, fieldnames=reader.fieldnames)
        w_tr.writeheader()
        w_te.writeheader()
        for row in reader:
            try:
                ts = float(row["ts"])
            except (TypeError, ValueError):
                continue                      # บรรทัดเสีย (เช่นตอนปิดโปรแกรมกลางคัน) ข้าม
            if ts < t_split:
                w_tr.writerow(row)
                n_train += 1
            else:
                w_te.writerow(row)
                n_test += 1
    print(f"{path.name}: train {n_train:,} -> {out_train.name} | test {n_test:,} -> {out_test.name}")
    return n_train, n_test


if __name__ == "__main__":
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("csv", type=Path, help="ไฟล์ packet CSV")
    ap.add_argument("split_at", help="เวลาที่แบ่ง ISO 8601 พร้อม timezone เช่น 2026-11-13T01:58:00+07:00")
    args = ap.parse_args()
    split(args.csv, args.split_at)
