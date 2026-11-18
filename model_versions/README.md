# เลือกเวอร์ชัน: 40 feature หรือ 36 feature

มีให้เลือก 2 เวอร์ชัน แต่ละเวอร์ชันเก็บครบชุด (features.py + โมเดลที่เทรนแล้ว) ไม่ต้องเทรนเอง

| โฟลเดอร์ | feature | FEATURE_VERSION | ผลเทรน | ผลสั้นๆ |
|---|---|---|---|---|
| `40feat/` | 40 (ของ ter-work) | 5 | `results/train_20261118_232207` (รอบ C) | ping 0%, nmap 0/6, CIC PortScan 74.7% |
| `36feat/` | 36 (ตัด tcp_mss / tcp_wscale / tcp_sack_ok / tcp_ts_present) | 6 | `results/train_20261118_234059` (รอบ D) | ping 100%, nmap 5/6, CIC PortScan 92.6% |

ทั้งสองเทรนด้วยข้อมูลชุดเดียวกัน: synthetic + CIC Monday + ข้อมูลบ้าน v5 (`data/dataset_train_20261117/`, `data/dataset_home_v5/`)
เทียบละเอียดใน `results/compare_40_vs_36.md`

## วิธีสลับ (รันจากโฟลเดอร์รากของโปรเจกต์)

```
python model_versions/use.py 36       # ใช้ 36 feature
python model_versions/use.py 40       # ใช้ 40 feature
python model_versions/use.py status   # ดูว่าตอนนี้ใช้ตัวไหน และ features.py ตรงกับโมเดลไหม
```

คำสั่ง `36` / `40` จะคัดลอก `features.py` ไปที่ `system/shared/features.py` และแตกโมเดลไปที่ `system/models/` ให้ตรงกันเสมอ
(detection-service ไม่ยอมโหลดโมเดลที่ feature ไม่ตรงกับ features.py) สลับแล้วรัน `run_all.py` ได้เลย
ถ้าจะเทรนใหม่ด้วย `training/train.ipynb` ก็จะใช้ features.py ของเวอร์ชันที่สลับไว้

โมเดลบันทึกด้วย scikit-learn ของเครื่องที่เทรน ถ้าโหลดแล้วมีคำเตือนเรื่องเวอร์ชัน sklearn ให้ติดตั้งตาม `requirements.txt`
หรือเทรนใหม่จาก dataset ที่ให้ไว้

## สำหรับคนเทรน: เก็บโมเดลใหม่เข้าโฟลเดอร์

```
python model_versions/use.py pack 36 <โฟลเดอร์โมเดล 36>
python model_versions/use.py pack 40 <โฟลเดอร์โมเดล 40>
```

ตัว pack เช็กให้ว่าโมเดลตรงกับ features.py ของเวอร์ชันนั้น แล้วบีบ `iforest.joblib` เป็น `.gz` (~26 MB, GitHub รับไม่เกิน 100 MB/ไฟล์)
