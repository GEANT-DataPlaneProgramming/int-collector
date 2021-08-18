from __future__ import print_function
import argparse
from PTCollector import PTCollector
from prometheus_client import start_http_server
if __name__ == "__main__":

    parser = argparse.ArgumentParser(description='Prometheus client.')
    parser.add_argument("ifaces", nargs='+',
        help="List of ifaces to receive INT reports")
    parser.add_argument("-m", "--max_int_hop", default=6, type=int,
        help="MAX INT HOP")
    parser.add_argument("-i", "--int_port", default=54321, type=int,
        help="Destination port of INT Telemetry reports")
    parser.add_argument("-d", "--debug_mode", default=0, type=int,
        help="set to 1 to print event")
    args = parser.parse_args()

    collector = PTCollector(max_int_hop=args.max_int_hop,
                            int_dst_port=args.int_port,
                            debug_mode=args.debug_mode)
    for iface in args.ifaces:
        collector.attach_iface(iface)

    collector.open_events()

    start_http_server(8000)

    try:
        print("eBPF progs Loaded")
        while 1:
            collector.poll_events()

    except KeyboardInterrupt:
        pass

    finally:
        collector.detach_all_iface()
        print("Done")

