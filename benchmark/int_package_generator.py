from __future__ import print_function
import argparse
import logging
from datetime import datetime
from modules.generators import LinearGenerator, ConstantGenerator


logging.basicConfig(level = logging.INFO)
logger = logging.getLogger(__name__)


if __name__ == "__main__":
    
    parser = argparse.ArgumentParser(description='INT Telemetry Report pkt gen.')
    parser.add_argument("-c", "--constant", action='store_true',
        help="Generating two packets with constant values. One per second.")
    parser.add_argument("-l", "--linear", action = 'store_true',
        help="Generates packets with linearly growing values")
    parser.add_argument("-hop", "--hops", default=3, type=int, choices=range(1,7),
        help="Number of hops in packet. Max - 6. Default: 3")
    parser.add_argument("-i","--interface", type=str, default='veth_1',
        help="Interface through which packets will be sent, Default: veth_1")
    parser.add_argument("-n", "--number", default=1000, type=int,
        help="Number of sending packets per second. Only works with `l' option. Default: 1000;")
    parser.add_argument("-g", "--gen", default=1000, type = int,
        help='')
    parser.add_argument("-v", "--verbose", default = 0, type=int, choices=range(0,2),
        help='Scapy verbose, 0 - disable, 1 - enable. Default: 0')
    parser.add_argument("-log", "--log_level", default= 20, type=int,
        help="CRITICAL = 50\
            ERROR = 40;\
            WARNING = 30;\
            INFO = 20;\
            DEBUG = 10;\
            NOTSET = 0;\
            Default: 20")
            
    args = parser.parse_args()

    logger.setLevel(args.log_level)

    if args.linear:
        logger.info(f'Start of generating of packages')
        generator = LinearGenerator(hops = args.hops, log_level = args.log_level, packets_gen = args.gen ,packets_sent= args.number)
        mode = int(input("Do you want to use senp or senpfast (1-sendp, 2-sendpfast)?\nMODE: "))
        generator.send_packets(mode, args.interface, args.verbose)
    

    if args.constant:        
       logger.info(f'Start of generating of packages')
       generator = ConstantGenerator(args.hops, args.log_level)
       generator.send_two_packets()