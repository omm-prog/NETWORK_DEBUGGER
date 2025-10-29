"""
Simple console-based UI.
"""
import threading
import time


class ConsoleUI:
    def __init__(self, flow_table, mapper, interval=5):
        self.flow_table = flow_table
        self.mapper = mapper
        self.interval = interval
        self._running = False
        self._thread = None

    def _render_loop(self):
        self.mapper.start()
        while self._running:
            print("\n--- Active flows ---")
            print(self.flow_table.snapshot())

            expired = self.flow_table.flush_expired()
            for k, v in expired:
                src, sport, dst, dport, proto = k
                pid = self.mapper.lookup(src, sport, dst, dport, proto)
                print(f"[EXPIRED] {proto} {src}:{sport} -> {dst}:{dport} pkts={v['pkts']} bytes={v['bytes']} pid={pid}")
            time.sleep(self.interval)

        self.mapper.stop()

    def start(self):
        if self._thread and self._thread.is_alive():
            return
        self._running = True
        self._thread = threading.Thread(target=self._render_loop, daemon=True)
        self._thread.start()

    def stop(self):
        self._running = False
        if self._thread:
            self._thread.join(timeout=1)
