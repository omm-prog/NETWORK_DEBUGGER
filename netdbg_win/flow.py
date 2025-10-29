"""
Flow aggregation logic.
"""
from datetime import datetime, timedelta
from threading import Lock
from tabulate import tabulate


class FlowTable:
    def __init__(self, timeout_sec=60):
        self.timeout = timedelta(seconds=timeout_sec)
        self._flows = {}
        self._lock = Lock()

    def _make_key(self, pkt):
        try:
            src = pkt.ip.src
            dst = pkt.ip.dst
        except AttributeError:
            return None

        proto = "?"
        sport = 0
        dport = 0
        if hasattr(pkt, "tcp"):
            proto = "tcp"
            sport = int(pkt.tcp.srcport)
            dport = int(pkt.tcp.dstport)
        elif hasattr(pkt, "udp"):
            proto = "udp"
            sport = int(pkt.udp.srcport)
            dport = int(pkt.udp.dstport)

        return (src, sport, dst, dport, proto)

    def handle_packet(self, pkt):
        k = self._make_key(pkt)
        if not k:
            return

        now = datetime.now()
        size = int(getattr(pkt, "length", 0) or 0)
        with self._lock:
            e = self._flows.get(k)
            if not e:
                self._flows[k] = {"first": now, "last": now, "pkts": 1, "bytes": size}
            else:
                e["last"] = now
                e["pkts"] += 1
                e["bytes"] += size

    def flush_expired(self):
        now = datetime.now()
        expired = []
        with self._lock:
            for k, v in list(self._flows.items()):
                if now - v["last"] > self.timeout:
                    expired.append((k, v))
                    del self._flows[k]
        return expired

    def flush_all(self):
        with self._lock:
            items = list(self._flows.items())
            self._flows.clear()
        return items

    def snapshot(self):
        rows = []
        with self._lock:
            for k, v in self._flows.items():
                src, sport, dst, dport, proto = k
                dur = (v["last"] - v["first"]).total_seconds()
                rows.append([proto, f"{src}:{sport}", f"{dst}:{dport}", v["pkts"], v["bytes"], f"{dur:.2f}s"])
        return tabulate(rows, headers=["Proto", "Src", "Dst", "Pkts", "Bytes", "Duration"]) if rows else "(no active flows)"
