# Home NIDS — runtime image (รัน 5 service ผ่าน run_all.py)
# ไม่รวม training/ (เทรนบนเครื่อง host ด้วย Jupyter แล้ว mount system/models/ เข้ามา — ดู DOCKER.md)
FROM python:3.12-slim

# libpcap = ตัวดัก packet บน Linux (เทียบเท่า Npcap บน Windows) ที่ Scapy ต้องใช้
# iproute2 = เผื่อ debug ชื่อ interface ด้วย `ip link` ข้างใน container
RUN apt-get update && apt-get install -y --no-install-recommends \
        libpcap-dev tcpdump iproute2 \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

COPY requirements-runtime.txt .
RUN pip install --no-cache-dir -r requirements-runtime.txt

COPY config ./config
COPY system ./system
COPY run_all.py .

ENV PYTHONUNBUFFERED=1 PYTHONUTF8=1
# ค่าเริ่มต้นชี้ไปไฟล์ config สำหรับ Docker/Linux โดยเฉพาะ (interfaces: ["any"]) — override ได้ตอน docker run
ENV NIDS_CONFIG=/app/config/config.docker.yaml

# capture-service ต้องการสิทธิ์ raw socket (เทียบเท่า "รันด้วย root/Administrator" บนเครื่องจริง)
# ตั้งใน docker-compose.yml: cap_add: [NET_ADMIN, NET_RAW] + network_mode: host (ดู DOCKER.md สำหรับข้อจำกัดบน Windows)
CMD ["python", "run_all.py", "--monitor", "off"]
