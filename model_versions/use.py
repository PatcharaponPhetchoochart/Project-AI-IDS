"""สลับเวอร์ชัน feature + โมเดล ระหว่าง 40 feature (FEATURE_VERSION 5) กับ 36 feature (FEATURE_VERSION 6)

แต่ละเวอร์ชันเก็บไว้ครบชุดในโฟลเดอร์ของตัวเอง (features.py + โมเดลที่เทรนด้วย feature ชุดนั้น)
คำสั่ง use จะคัดลอกทั้งคู่ไปไว้ที่ที่ระบบใช้จริง (system/shared/features.py และ system/models/)
ให้ตรงกันเสมอ (detection-service ไม่ยอมโหลดโมเดลที่ feature ไม่ตรงกับ features.py)

  python model_versions/use.py 36        ใช้ 36 feature (ผ่านเกณฑ์ ping, nmap 5/6)
  python model_versions/use.py 40        ใช้ 40 feature (ping 0% - ดู results/compare_40_vs_36.md)
  python model_versions/use.py status    ดูว่าตอนนี้ระบบใช้เวอร์ชันไหน

สำหรับคนเทรน (เก็บโมเดลที่เทรนแล้วเข้าโฟลเดอร์เวอร์ชัน ก่อน commit):
  python model_versions/use.py pack 36 C:/Project_AI/models_backup_home36
  python model_versions/use.py pack 40 C:/Project_AI/models_backup_home40
  python model_versions/use.py pack        (ไม่ใส่อะไร = pack ทั้งสองจาก path ข้างบน)

หลังสลับเวอร์ชัน ถ้าจะเทรนใหม่ด้วย training/train.ipynb ได้เลย notebook ใช้ features.py ตัวที่สลับไว้
"""
from __future__ import annotations

import argparse
import gzip
import importlib.util
import json
import re
import shutil
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
ROOT = HERE.parent
LIVE_FEATURES = ROOT / "system" / "shared" / "features.py"
LIVE_MODELS = ROOT / "system" / "models"
VERSIONS = {"40": HERE / "40feat", "36": HERE / "36feat"}
DEFAULT_BACKUPS = {"40": Path(r"C:\Project_AI\models_backup_home40"),
                   "36": Path(r"C:\Project_AI\models_backup_home36")}
MODEL_GZ = "iforest.joblib.gz"
SMALL_FILES = ("scaler.joblib", "meta.json")


def load_feature_contract(path: Path) -> tuple[int, list[str]]:
    """อ่าน FEATURE_VERSION + FEATURE_NAMES จากไฟล์ features.py โดยไม่แตะ module ที่ระบบโหลดอยู่"""
    spec = importlib.util.spec_from_file_location(f"_features_{abs(hash(str(path)))}", path)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return int(mod.FEATURE_VERSION), list(mod.FEATURE_NAMES)


def check_meta(meta_path: Path, features_path: Path) -> dict:
    meta = json.loads(meta_path.read_text(encoding="utf-8"))
    fv, names = load_feature_contract(features_path)
    if meta.get("feature_version") != fv or meta.get("feature_names") != names:
        sys.exit(f"ERROR: โมเดลใน {meta_path.parent} (feature_version={meta.get('feature_version')}, "
                 f"{len(meta.get('feature_names', []))} feature) ไม่ตรงกับ {features_path} "
                 f"(feature_version={fv}, {len(names)} feature)")
    return meta


def pack(key: str, src: Path) -> None:
    dst = VERSIONS[key]
    missing = [n for n in ("iforest.joblib",) + SMALL_FILES if not (src / n).exists()]
    if missing:
        sys.exit(f"ERROR: ไม่พบ {', '.join(missing)} ใน {src}")
    meta = check_meta(src / "meta.json", dst / "features.py")
    with open(src / "iforest.joblib", "rb") as f_in, open(dst / MODEL_GZ, "wb") as raw, \
            gzip.GzipFile(filename="iforest.joblib", mode="wb", fileobj=raw, compresslevel=9, mtime=0) as f_out:
        shutil.copyfileobj(f_in, f_out, length=1 << 20)
    for n in SMALL_FILES:
        shutil.copy2(src / n, dst / n)
    size = (dst / MODEL_GZ).stat().st_size / 1e6
    print(f"pack {key}: {src} -> {dst} ({MODEL_GZ} {size:.1f} MB, trained {meta.get('trained_at')}, "
          f"threshold {meta.get('recommended_threshold')})")


def use(key: str) -> None:
    d = VERSIONS[key]
    missing = [n for n in (MODEL_GZ,) + SMALL_FILES if not (d / n).exists()]
    if missing:
        sys.exit(f"ERROR: โฟลเดอร์ {d} ยังไม่มีโมเดล ({', '.join(missing)}) -- ต้อง pack ก่อน หรือเทรนใหม่")
    meta = check_meta(d / "meta.json", d / "features.py")
    shutil.copy2(d / "features.py", LIVE_FEATURES)
    LIVE_MODELS.mkdir(parents=True, exist_ok=True)
    with gzip.open(d / MODEL_GZ, "rb") as f_in, open(LIVE_MODELS / "iforest.joblib", "wb") as f_out:
        shutil.copyfileobj(f_in, f_out, length=1 << 20)
    for n in SMALL_FILES:
        shutil.copy2(d / n, LIVE_MODELS / n)
    print(f"ใช้ {key} feature แล้ว: features.py (FEATURE_VERSION {meta['feature_version']}) + โมเดลใน system/models "
          f"(trained {meta.get('trained_at')}, threshold {meta.get('recommended_threshold')})")


def status() -> None:
    fv, names = load_feature_contract(LIVE_FEATURES)
    print(f"system/shared/features.py : FEATURE_VERSION {fv}, {len(names)} feature")
    meta_p = LIVE_MODELS / "meta.json"
    if not meta_p.exists():
        print("system/models             : ยังไม่มีโมเดล")
        return
    meta = json.loads(meta_p.read_text(encoding="utf-8"))
    ok = meta.get("feature_version") == fv and meta.get("feature_names") == names
    print(f"system/models             : feature_version {meta.get('feature_version')}, "
          f"{len(meta.get('feature_names', []))} feature, trained {meta.get('trained_at')}")
    print("ตรงกัน ใช้งานได้" if ok else "ไม่ตรงกัน! detection-service จะไม่โหลด -> รัน use.py 36 หรือ use.py 40")


def main() -> None:
    if hasattr(sys.stdout, "reconfigure"):
        sys.stdout.reconfigure(encoding="utf-8")
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("cmd", choices=["36", "40", "status", "pack"])
    ap.add_argument("version", nargs="?", choices=["36", "40"], help="(pack) เวอร์ชันที่จะเก็บ")
    ap.add_argument("src", nargs="?", type=Path, help="(pack) โฟลเดอร์โมเดลที่เทรนแล้ว")
    a = ap.parse_args()
    if a.cmd == "status":
        status()
    elif a.cmd == "pack":
        keys = [a.version] if a.version else ["40", "36"]
        for k in keys:
            pack(k, a.src if (a.src and a.version) else DEFAULT_BACKUPS[k])
    else:
        use(a.cmd)


if __name__ == "__main__":
    main()
