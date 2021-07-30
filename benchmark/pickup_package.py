from __future__ import print_function
from scapy import data
from scapy.all import *
import time
import argparse
from datetime import date, datetime

if __name__ == "__main__":

    parser = argparse.ArgumentParser(description='Sniffing packages. ')

    parser.add_argument("-n", "--number", default=1000, type=int, 
            help="Measurement of the time in which a given number of packets was received")
    parser.add_argument("-i", "--interface", type=str, required=True,
            help="Listening network interface")
    args = parser.parse_args()
    iface = args.interface


    print("Start sniffing your packages")

    while 1:
        start = datetime.now()
        pak = sniff(iface = iface,count=100)
        print("Time:", datetime.now()-start,"Number of packages:", len(pak))
        time.sleep(1)
