"""รันทุก service พร้อมกัน (แต่ละตัวเป็น process แยก) — ปิดทั้งหมดด้วย Ctrl+C

  python run_all.py                 # capture/feature/detection (log มี prefix) + alert ในหน้าต่างนี้
                                    # + monitor เปิดหน้าต่าง terminal ใหม่ (Windows)
  python run_all.py --monitor inline   # แสดง monitor ในหน้าต่างเดียวกัน (packet จะไหลท่วม alert)
  python run_all.py --monitor off      # ไม่รัน monitor

แต่ละ service ยังรันแยกเดี่ยวได้: python system/services/<ชื่อ>_service/main.py
"""
from __future__ import annotations

import argparse
import os
import subprocess
import sys
import threading
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parent
SYSTEM = ROOT / "system"          # โค้ดของระบบ (shared/, services/, models/ ...)
sys.path.insert(0, str(SYSTEM))

from shared.config import load_config, resolve_path  # noqa: E402
from shared.utils import force_utf8  # noqa: E402

WIN = sys.platform.startswith("win")
COLORS = {"capture": "36", "feature": "33", "detection": "35", "alert": "31", "monitor": "32"}


def enable_ansi_colors() -> None:
    """Windows console แบบเก่าไม่แปลรหัสสี ANSI (เห็นเป็น ←[36m) -> เปิด Virtual Terminal Processing"""
    if not WIN:
        return
    try:
        import ctypes
        k = ctypes.windll.kernel32
        for std in (-11, -12):          # STD_OUTPUT_HANDLE, STD_ERROR_HANDLE
            h = k.GetStdHandle(std)
            mode = ctypes.c_uint32()
            if k.GetConsoleMode(h, ctypes.byref(mode)):
                k.SetConsoleMode(h, mode.value | 0x0004)   # ENABLE_VIRTUAL_TERMINAL_PROCESSING
    except Exception:  # noqa: BLE001
        pass


def is_admin() -> bool:
    try:
        if WIN:
            import ctypes
            return bool(ctypes.windll.shell32.IsUserAnAdmin())
        return os.geteuid() == 0
    except Exception:  # noqa: BLE001
        return False


def pump(name: str, stream) -> None:
    """อ่าน output ของ service แล้วพิมพ์พร้อม prefix สี"""
    color = COLORS.get(name, "37")
    for line in iter(stream.readline, ""):
        line = line.rstrip()
        if line:
            print(f"\x1b[{color}m{name:<9}|\x1b[0m {line}", flush=True)


def main() -> int:
    force_utf8()
    enable_ansi_colors()
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--monitor", choices=["window", "inline", "off"], default="window" if WIN else "off",
                    help="how to run monitor-service (default: Windows=window, others=off)")
    args = ap.parse_args()

    cfg = load_config()
    dcfg = cfg["detection"]
    missing = [str(resolve_path(dcfg[k])) for k in ("model_path", "scaler_path", "meta_path") if not resolve_path(dcfg[k]).exists()]
    if missing:
        print("Model files not found:", *missing, sep="\n  ")
        print("Train the model first (one time):\n"
              "  python -m notebook training/train.ipynb   then Run All\n"
              "  (or command line: python training/train.py)")
        return 2

    if not is_admin():
        print("\x1b[33m[WARNING] not running as " + ("Administrator" if WIN else "root") +
              " - capture may fail (open the terminal with Run as administrator / use sudo)\x1b[0m")

    env = dict(os.environ, PYTHONUTF8="1", PYTHONUNBUFFERED="1",
               PYTHONPATH=os.pathsep.join([str(SYSTEM), str(ROOT)]))
    procs: dict[str, subprocess.Popen] = {}
    threads: list[threading.Thread] = []

    def start(name: str, piped: bool = True, new_window: bool = False) -> None:
        cmd = [sys.executable, "-m", f"services.{name}_service"]
        kw: dict = dict(cwd=ROOT, env=env)
        if new_window and WIN:
            kw["creationflags"] = subprocess.CREATE_NEW_CONSOLE
        elif piped:
            kw.update(stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True, encoding="utf-8", errors="replace")
        p = subprocess.Popen(cmd, **kw)
        procs[name] = p
        if piped and not new_window and p.stdout:
            t = threading.Thread(target=pump, args=(name, p.stdout), daemon=True)
            t.start()
            threads.append(t)

    # ลำดับ: ปลายทางก่อน เพื่อให้พร้อมรับก่อนที่ต้นทางจะเริ่มส่ง
    start("alert", piped=False)               # alert ใช้ terminal นี้โดยตรง (สี Rich)
    if args.monitor == "window":
        start("monitor", new_window=True)
    elif args.monitor == "inline":
        start("monitor", piped=False)
    start("detection")
    start("feature")
    start("capture")
    print(f"\x1b[1mHome NIDS started ({len(procs)} services) - press Ctrl+C to stop all\x1b[0m", flush=True)

    code = 0
    try:
        while True:
            time.sleep(0.5)
            for name, p in procs.items():
                rc = p.poll()
                if rc is not None:
                    print(f"\x1b[31m[run_all] service '{name}' exited (code {rc}) - stopping all services\x1b[0m", flush=True)
                    code = rc or 1
                    raise KeyboardInterrupt
    except KeyboardInterrupt:
        pass
    finally:
        # Ctrl+C ใน terminal เดียวกันส่งถึงลูกด้วยอยู่แล้ว: รอให้ปิดเอง แล้วค่อยบังคับปิดตัวที่ค้าง
        deadline = time.time() + 6
        for name, p in procs.items():
            if p.poll() is None and not (WIN and name == "monitor" and args.monitor == "window"):
                try:
                    p.wait(max(deadline - time.time(), 0.1))
                except subprocess.TimeoutExpired:
                    pass
        for name, p in procs.items():
            if p.poll() is None:
                p.terminate()
        for p in procs.values():
            try:
                p.wait(3)
            except subprocess.TimeoutExpired:
                p.kill()
        print("All services stopped", flush=True)
    return code


if __name__ == "__main__":
    sys.exit(main())
