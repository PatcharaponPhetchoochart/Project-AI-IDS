#!/usr/bin/env bash
# รันทุก service บน Linux (ต้อง sudo เพื่อให้ดัก packet ได้)
#   sudo ./run_all.sh                    # monitor ไม่ถูกรัน: เปิด terminal อื่นแล้วรัน python system/services/monitor_service/main.py
#   sudo ./run_all.sh --monitor inline
cd "$(dirname "$0")"
exec python3 run_all.py "$@"
