# รัน Home NIDS ใน Docker

## ⚠️ อ่านก่อน: ข้อจำกัดบน Windows (สำคัญมาก)

`capture-service` ต้องใช้ raw socket ดัก packet จาก **interface จริง** ของเครื่อง บน Linux
(`network_mode: host` + `cap_add: NET_ADMIN,NET_RAW`) มันเห็น traffic ของเครื่องจริงได้เลย

**แต่บน Windows/Mac (Docker Desktop ใช้ WSL2/Hyper-V VM เป็นฐาน):**
container ที่ `network_mode: host` จะเห็นแค่ network namespace ของ **VM ข้างใน Docker Desktop**
ไม่ใช่การ์ด Wi-Fi จริงของ Windows ดังนั้น:

| สถานการณ์ | NIDS ใน Docker เห็นไหม |
|---|---|
| ping/scan **ข้าม container → container** (คุยกันในเครื่องเดียวกัน ผ่าน docker network) | ✅ เห็น |
| traffic ภายใน container เอง (loopback) | ✅ เห็น |
| **ping/scan จากเครื่องอื่นใน LAN มาที่ Windows host IP** (เคสที่ทดสอบ Web_Test) | ❌ **ไม่เห็น** (ไม่ผ่าน WSL2 VM's network namespace ตรงๆ) |

### ทางแก้สำหรับเคส "ยิงจากเครื่องอื่นใน LAN"
ให้ **capture-service (หรือทั้งระบบ) รันแบบ native บน Windows ต่อไปเหมือนเดิม** (ตามที่เคยตั้งค่าไว้ —
`python run_all.py` แบบ Administrator, ดัก `Wi-Fi` + `loopback`) **ไม่ต้องรันผ่าน Docker สำหรับ use case นี้**
เพราะ traffic จากเครื่องอื่นที่ยิงมาที่ `WindowsHostIP:PORT` (ของ Web_Test ที่ publish port ไว้) จะวิ่งผ่าน
การ์ด Wi-Fi จริงของ Windows ก่อนที่ Docker Desktop จะ forward เข้า container เสมอ — NIDS ที่รัน native
บน Windows ดัก Wi-Fi อยู่แล้วจึงเห็น traffic นี้ได้ปกติ โดยไม่ต้อง Dockerize NIDS เลยก็ได้

**สรุป:** Docker setup ของ NIDS ในโฟลเดอร์นี้มีไว้สำหรับ
- ใช้งานจริงบน **Linux** (เซิร์ฟเวอร์ Linux ที่มี Docker) ซึ่ง `network_mode: host` ทำงานถูกต้อง 100%
- ทดสอบ pipeline ข้าม container (capture เห็น traffic ที่เกิดขึ้น "ข้างใน" Docker network) บน Windows
- **ไม่ใช่** วิธีหลักสำหรับทดสอบ "ยิงจากเครื่องอื่นใน LAN" บน Windows — ให้รัน native ตามเดิม

## วิธีรัน (Linux หรือยอมรับข้อจำกัดข้างบนแล้ว)

```bash
cd home-nids
# 1) เทรนโมเดลก่อน (บนเครื่อง host เหมือนเดิม — ยังไม่มีขั้นนี้ให้ Docker ทำ)
python -m notebook training/train.ipynb      # กด Run All แล้วจะได้ system/models/*.joblib

# 2) build + run
docker compose build
docker compose up -d
docker compose logs -f nids
```

หา interface ที่ Scapy เห็นข้างใน container (ถ้า `interfaces: ["any"]` ใน `config/config.docker.yaml` ยังไม่พอ):
```bash
docker compose exec nids python system/scripts/list_interfaces.py
```

ดู alert:
```bash
docker compose exec nids python -c "import sqlite3; [print(r) for r in sqlite3.connect('data/alerts.db').execute('select * from alerts')]"
```
(หรืออ่านจากไฟล์ `data/alerts.db` บนเครื่อง host ตรงๆ เพราะ mount volume ไว้แล้ว)

ปิด:
```bash
docker compose down
```

## ทำไมไม่ copy system/models/ เข้า image
เพราะคุณบอกว่าจะไปเทรนเองต่อ (เพิ่ม feature A-F ใหม่ ต้องเทรนโมเดลใหม่เสมอ — ดู `system/shared/features.py`
หัว docstring, `FEATURE_VERSION` ถูกบวกเป็น 4 แล้ว) โฟลเดอร์ `system/models/` เป็น **volume mount** ไม่ใช่
ส่วนหนึ่งของ image — เทรนใหม่บนเครื่อง host เมื่อไหร่ก็มีผลทันทีโดยไม่ต้อง rebuild image
