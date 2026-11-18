# Dataset ที่ใช้เทรน (2026-11-17)

ใช้ชุดเดียวกันทั้งรอบ 40 feature (`results/train_20261117_191511`) และรอบ 36 feature (`results/train_20261117_210517`)
เป็นข้อมูลสาธารณะ (CIC-IDS2017) + ข้อมูลจำลอง เท่านั้น **ไม่มี traffic จากบ้านปนอยู่**

ทุกไฟล์เป็น CSV รูปแบบเดียวกับที่ capture-service v5 เขียน (มี field v5 ครบ: tcp_window ... tls_sni_known)
แปลงจาก pcap ด้วย `training/pipeline/pcap_to_csv.py` (ไม่ได้เก็บ pcap ใน git เพราะใหญ่เกินไป)
บีบด้วย gzip เพราะ GitHub รับไฟล์ไม่เกิน 100 MB ต่อไฟล์

| ไฟล์ | ใช้เป็น | แถว (packet) | ขนาดก่อนบีบ | sha256 ก่อนบีบ |
|---|---|---|---|---|
| `normal__Monday-WorkingHours.csv.gz` | traffic ปกติสำหรับเทรน (CIC Monday, 2 ล้าน packet แรก) | 2,000,000 | 182 MB | `560030a7126335f55102177cf16a2d8f86ecf7f79f70b7d7713f6827be46fed7` |
| `test__Friday-WorkingHours.csv.gz` | ชุดทดสอบ (CIC Friday 13:50–15:35 -03:00 ช่วง PortScan) | 1,624,499 | 147 MB | `f5de9a6d974f68e51debe23ada80242e07d01f6df91fefb0719f279c13dd1349` |
| `test__Friday-WorkingHours.csv.window.json` | บอกตัวแปลงว่า CSV Friday ตัดช่วงเวลาไหน (ต้องวางคู่กับ CSV) | - | - | - |
| `normal_packets.csv.gz` | traffic ปกติจำลอง (สร้างจาก `generate_data.py`, notebook สร้างใหม่ได้เอง) | 8,000 | 0.7 MB | `20da7b1000ab41ddbe1aae8432d8a424942cd1e6773eb3aedc0efb5f46a2f765` |

label ของ Friday มาจากกฎใน `training/labels.csv` (3 ข้อ) ตอนรัน notebook ไม่ได้อยู่ในไฟล์ CSV

## วิธีใช้ (เทรนซ้ำโดยไม่ต้องแปลง pcap ใหม่ ~40 นาที)

1. แตกไฟล์ `.gz` ไปไว้ที่ `data/pcap_csv_v5/` (Windows: 7-Zip หรือ `tar -xzf`, Linux/Mac: `gunzip -k`)
   แล้ววาง `test__Friday-WorkingHours.csv.window.json` ไว้ในโฟลเดอร์เดียวกัน
   `normal_packets.csv` แตกไปไว้ที่ `data/`
2. `config/config.yaml` → `training.pcap_csv_dir: "data/pcap_csv_v5"` และ `pcap_time_windows` ของ Friday ตามที่ตั้งไว้ใน commit นี้
3. รัน `training/train.ipynb` ตามปกติ — ถ้าในเครื่องมี pcap ของ CIC ใน `training/pcap/normal` และ `training/pcap/test`
   ตัวแปลงจะเห็นว่า CSV ใหม่กว่า pcap และช่วงเวลาตรงกัน แล้วใช้ CSV นี้เลย ไม่แปลงใหม่
   (ถ้าไม่มี pcap ให้ใส่ path ของ CSV ทั้งสองใน `EXTRA_NORMAL_CSVS` / `EXTRA_TEST_CSVS` ใน cell 2 แทน)
