"""
Packet capture using PyDivert (Windows native driver).
No Wireshark or TShark needed.
"""
from pydivert import WinDivert
import threading
import socket


class LiveCaptureManager:
    def __init__(self, interface, display_filter, pkt_handler):
        # interface is ignored (WinDivert captures all)
        self.filter = display_filter or "true"
        self.pkt_handler = pkt_handler
        self._running = False
        self._thread = None
        self._w = None

    def _run(self):
        try:
            self._w = WinDivert(self.filter)
            self._w.open()
            self._running = True
            print(f"✅ Capturing packets (filter={self.filter}) ...")
            for packet in self._w:
                if not self._running:
                    break

                # Attach pseudo-fields for compatibility with flow.py
                try:
                    proto = "tcp" if packet.tcp else "udp" if packet.udp else "ip"
                    pkt_obj = type("Pkt", (), {})()
                    pkt_obj.ip = type("IP", (), {})()
                    pkt_obj.ip.src = packet.src_addr
                    pkt_obj.ip.dst = packet.dst_addr
                    if proto == "tcp":
                        pkt_obj.tcp = type("TCP", (), {})()
                        pkt_obj.tcp.srcport = packet.src_port
                        pkt_obj.tcp.dstport = packet.dst_port
                    elif proto == "udp":
                        pkt_obj.udp = type("UDP", (), {})()
                        pkt_obj.udp.srcport = packet.src_port
                        pkt_obj.udp.dstport = packet.dst_port
                    pkt_obj.length = len(packet.raw)
                    self.pkt_handler(pkt_obj)
                except Exception as e:
                    print("Packet parsing error:", e)
                    continue

        except Exception as e:
            print("❌ PyDivert capture error:", e)
        finally:
            if self._w:
                try:
                    self._w.close()
                except Exception:
                    pass
            self._running = False

    def start(self):
        if self._thread and self._thread.is_alive():
            return
        self._thread = threading.Thread(target=self._run, daemon=True)
        self._thread.start()

        try:
            while self._thread.is_alive():
                self._thread.join(timeout=0.5)
        except KeyboardInterrupt:
            self.stop()

    def stop(self):
        self._running = False
        if self._w:
            try:
                self._w.close()
            except Exception:
                pass
