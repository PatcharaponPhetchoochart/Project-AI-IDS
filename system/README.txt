โฟลเดอร์นี้คือ "ตัวระบบ" — ระบบใช้เอง ไม่ต้องแก้ ถ้าไม่ได้พัฒนาโค้ดต่อ

services/   5 โปรแกรมหลัก: capture -> feature -> detection -> alert / monitor
shared/     โค้ดที่ใช้ร่วมกัน (features.py = สูตรแปลง packet เป็นตัวเลข ใช้ทั้งเทรนและรันจริง)
models/     โมเดลที่เทรนแล้ว (train.ipynb บันทึกให้อัตโนมัติ) ห้ามลบ ไม่งั้นระบบไม่ทำงาน
tests/      ชุดทดสอบ: รัน python -m pytest จากโฟลเดอร์หลัก
scripts/    list_interfaces.py ดูชื่อ network interface: python system/scripts/list_interfaces.py
docs/       ต้นฉบับ HTML ของ README.pdf

ของที่ต้องใช้อยู่ข้างนอก: config/ (ตั้งค่า), training/ (เทรน), data/ (ข้อมูล + alerts.db), run_all.py (รันระบบ)
