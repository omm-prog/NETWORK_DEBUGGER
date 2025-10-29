"""
Maps sockets to owning PIDs using psutil.
"""
import psutil
import threading
import time


class SocketMapper:
    def __init__(self, refresh_interval=3):
        self._map = {}
        self._interval = refresh_interval
        self._lock = threading.Lock()
        self._running = False
        self._thread = None

    def _build_map(self):
        newmap = {}
        for c in psutil.net_connections(kind="inet"):
            try:
                laddr = (c.laddr.ip, c.laddr.port) if c.laddr else (None, None)
                raddr = (c.raddr.ip, c.raddr.port) if c.raddr else (None, None)
                proto = "tcp" if c.type == psutil.SOCK_STREAM else "udp"
                key = (laddr[0], laddr[1], raddr[0], raddr[1], proto)
                newmap[key] = c.pid
            except Exception:
                continue
        with self._lock:
            self._map = newmap

    def start(self):
        if self._thread and self._thread.is_alive():
            return
        self._running = True
        self._thread = threading.Thread(target=self._loop, daemon=True)
        self._thread.start()

    def _loop(self):
        while self._running:
            self._build_map()
            time.sleep(self._interval)

    def stop(self):
        self._running = False
        if self._thread:
            self._thread.join(timeout=1)

    def lookup(self, src, sport, dst, dport, proto):
        with self._lock:
            k1 = (src, sport, dst, dport, proto)
            k2 = (dst, dport, src, sport, proto)
            return self._map.get(k1) or self._map.get(k2)
