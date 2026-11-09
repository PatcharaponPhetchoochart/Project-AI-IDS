"""ตัวช่วยสร้าง ZeroMQ publisher / subscriber (PUB/SUB, ส่ง JSON เป็น multipart [topic, payload])"""
from __future__ import annotations

import json
import threading

import zmq


class Publisher:
    """Publisher: bind ที่ port ของ topic ตัวเอง (socket ของ zmq ไม่ thread-safe จึงมี lock)"""

    def __init__(self, port: int, topic: str, host: str = "127.0.0.1", hwm: int = 20000):
        self.topic = topic
        self.endpoint = f"tcp://{host}:{port}"
        self._ctx = zmq.Context()
        self._sock = self._ctx.socket(zmq.PUB)
        self._sock.setsockopt(zmq.LINGER, 0)
        self._sock.setsockopt(zmq.SNDHWM, hwm)
        self._sock.bind(self.endpoint)
        self._lock = threading.Lock()
        self._topic_b = topic.encode()

    def send(self, payload: dict) -> None:
        data = json.dumps(payload, separators=(",", ":")).encode()
        with self._lock:
            self._sock.send_multipart([self._topic_b, data])

    def close(self) -> None:
        self._sock.close(0)
        self._ctx.term()


class Subscriber:
    """Subscriber: connect ไปหา publisher (เริ่มก่อน/หลังกันได้ ZMQ จะ reconnect ให้เอง)"""

    def __init__(self, port: int, topic: str, host: str = "127.0.0.1", hwm: int = 20000):
        self.topic = topic
        self.endpoint = f"tcp://{host}:{port}"
        self._ctx = zmq.Context()
        self._sock = self._ctx.socket(zmq.SUB)
        self._sock.setsockopt(zmq.LINGER, 0)
        self._sock.setsockopt(zmq.RCVHWM, hwm)
        self._sock.connect(self.endpoint)
        self._sock.setsockopt(zmq.SUBSCRIBE, topic.encode())
        self._poller = zmq.Poller()
        self._poller.register(self._sock, zmq.POLLIN)

    def recv_many(self, timeout_ms: int = 200, max_items: int = 256) -> list[dict]:
        """รอ message สูงสุด timeout_ms แล้วดึงที่ค้างอยู่ทั้งหมด (ไม่เกิน max_items)
        ใช้ poll แบบมี timeout เพื่อให้ Ctrl+C ทำงานได้ทันบน Windows"""
        out: list[dict] = []
        if not self._poller.poll(timeout_ms):
            return out
        while len(out) < max_items:
            try:
                _topic, data = self._sock.recv_multipart(flags=zmq.NOBLOCK)
            except zmq.Again:
                break
            try:
                out.append(json.loads(data))
            except json.JSONDecodeError:
                continue
        return out

    def close(self) -> None:
        self._sock.close(0)
        self._ctx.term()
