โฟลเดอร์เก็บไฟล์ .pcap / .pcapng สำหรับเทรนใน training/train.ipynb

normal/      traffic ปกติล้วน -> ใช้เทรนโมเดล
             เช่น CIC-IDS2017 Monday-WorkingHours.pcap, ไฟล์ที่ save จาก Wireshark ตอนใช้งานปกติ
             ห้ามมีการโจมตีปน (ไม่งั้นโมเดลจะเรียนว่าการโจมตีเป็นเรื่องปกติ)

test/        traffic ที่มีการโจมตีปน -> ใช้วัดผล (TP/FP/TN/FN, Accuracy, Precision, Recall, F1)
             เช่น CIC-IDS2017 Friday-WorkingHours.pcap (มี PortScan)
             ต้องเขียนกฎใน labels.csv ว่า packet ไหนคือการโจมตี

labels.csv   กฎติด label (IP ผู้โจมตี / เหยื่อ / ช่วงเวลา) ของไฟล์ใน test/

ไฟล์ที่แปลงเป็น CSV แล้วจะเก็บไว้ที่ data/pcap_csv/ (แปลงครั้งเดียว ครั้งถัดไปใช้ของเดิม)
path ทั้งหมดตั้งได้ใน config/config.yaml หัวข้อ training
