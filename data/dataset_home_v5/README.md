# Dataset ข้อมูลบ้านจริง (capture v5) ที่ใช้เทรนรอบ C และ D

ใช้คู่กับ CIC ใน `data/dataset_train_20261117/` เทรนรอบ C (40 feature) และ D (36 feature)
ดูผลใน `results/train_20261118_232207` (C), `results/train_20261118_234059` (D) และสรุปใน `results/compare_40_vs_36.md`

อัดด้วย capture-service ของ ter-work (v5, field ครบ), interface `default` (Ethernet) + `loopback`
เป็น traffic ปกติล้วน ไม่มี ping หรือ scan (ICMP มีแค่แบบ unreachable)
แบ่งตามเวลา 70/30 ด้วย `training/pipeline/split_by_time.py` เวลาไม่ซ้อนกัน

| ไฟล์ | ใช้เป็น | ช่วงเวลา (+07:00) | แถว | sha256 ก่อนบีบ |
|---|---|---|---|---|
| `captured_v5_active1_train.csv.gz` | เทรน | 17 พ.ย. 22:30–23:37 | 939,703 | `a35fe7960e9b25d9f7181e6eb805f95189aa0f99bb659bb43dfc7002967d99db` |
| `captured_v5_active1_test.csv.gz` | ทดสอบ | 17 พ.ย. 23:37–18 พ.ย. 00:06 | 251,770 | `93cf44172ea342b0e56cc4f834f578ac9475be8f88f784bfff920b1865490d0f` |
| `captured_v5_night1_train.csv.gz` | เทรน | 18 พ.ย. 05:22–17:54 | 316,278 | `aead8467911b6a7a04bbd05010f822dff6b9be78372fb3bb45b79a6b2bd547ef` |
| `captured_v5_night1_test.csv.gz` | ทดสอบ | 18 พ.ย. 17:54–23:16 | 112,952 | `538c8b747d8c2e4b1f148a234408eebe4cda6db7d4db153f301bbe7f2b1f2398` |

- active1 = ใช้คอมตามปกติ (ส่วนใหญ่เป็น UDP ของเกมออนไลน์ + Discord + เว็บ HTTPS)
- night1 = เปิดคอมทิ้งไว้ เข้า Discord ไว้เฉยๆ (traffic เบื้องหลัง: Windows, Discord, DNS, SSDP/mDNS)

## วิธีใช้
1. แตกไฟล์ทั้ง 4 ไปไว้ที่ `data/` (Windows: 7-Zip หรือ `tar -xzf`, Linux/Mac: `gunzip -k`)
   ได้ `data/captured_v5_active1_train.csv` ฯลฯ (ชื่อพวกนี้ถูก .gitignore ไว้แล้ว แตกแล้วไม่ขึ้น git ซ้ำ)
2. `training/train.ipynb` cell 2 ตั้ง `EXTRA_NORMAL_CSVS` / `EXTRA_TEST_CSVS` ชี้ไปที่ 4 ไฟล์นี้ไว้แล้ว รันได้เลย
   (ถ้าไม่ได้แตกไฟล์ notebook จะเตือนแล้วข้ามไป = ได้ผลแบบรอบ A/B)
