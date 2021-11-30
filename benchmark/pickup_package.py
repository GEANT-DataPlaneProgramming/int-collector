from scapy.sendrecv import sniff
import time
import argparse
from datetime import datetime

if __name__ == "__main__":

    parser = argparse.ArgumentParser(description="Sniffing packages. ")

    parser.add_argument(
        "-n",
        "--number",
        default=1000,
        type=int,
        help="Measurement of the time in which a given number of packets was received",
    )
    parser.add_argument(
        "-i", "--interface", type=str, required=True, help="Listening network interface"
    )
    args = parser.parse_args()
    iface = args.interface

    print("Start sniffing your packages")
    pak = sniff(iface=iface, count=args.number)
    while 1:
        start = datetime.now()
        pak = sniff(iface=iface, count=args.number)
        print("Time:", datetime.now() - start, "Number of packages:", len(pak))
        time.sleep(1)
