"""
Entry point for the Windows Network Debugger.
"""

import argparse
from netdbg_win.capture import LiveCaptureManager
from netdbg_win.flow import FlowTable
from netdbg_win.mapper import SocketMapper
from netdbg_win.ui import ConsoleUI


def main():
    parser = argparse.ArgumentParser(description="Windows Network Debugger (Prototype)")
    parser.add_argument("--iface", required=True, help="Interface name (as seen by Wireshark)")
    parser.add_argument("--filter", default="", help="Wireshark/TShark display filter")
    parser.add_argument("--timeout", type=int, default=60, help="Flow idle timeout in seconds")
    args = parser.parse_args()

    flow_table = FlowTable(timeout_sec=args.timeout)
    mapper = SocketMapper()
    ui = ConsoleUI(flow_table, mapper)

    cap = LiveCaptureManager(interface=args.iface, display_filter=args.filter, pkt_handler=flow_table.handle_packet)

    try:
        ui.start()
        cap.start()
    except KeyboardInterrupt:
        print("\nStopping capture...")
    finally:
        cap.stop()
        ui.stop()
        for k, v in flow_table.flush_all():
            src, sport, dst, dport, proto = k
            pid = mapper.lookup(src, sport, dst, dport, proto)
            print(f"[FINAL] {proto} {src}:{sport} -> {dst}:{dport} pkts={v['pkts']} bytes={v['bytes']} pid={pid}")


if __name__ == "__main__":
    main()
