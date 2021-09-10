from __future__ import print_function
from random import choices
from scapy import data
from scapy.all import *
from scapy.utils import PcapReader
import time
import argparse
import logging
from datetime import datetime

logging.basicConfig(level = logging.INFO)
logger = logging.getLogger(__name__)

'''
header int_report_fixed_header_t {
    bit<4> ver;
    bit<4> len;
    bit<3> nprot;
    bit<6> rep_md_bits;
    bit<6> reserved;
    bit<1> d;
    bit<1> q;
    bit<1> f;
    bit<6> hw_id;
    bit<32> switch_id;
    bit<32> seq_num;
    bit<32> ingress_tstamp;
}
const bit<8> REPORT_FIXED_HEADER_LEN = 16;
'''

class TelemetryReport_v10(Packet):

    name = "INT telemetry report v1.0"

    # default value a for telemetry report with INT
    fields_desc = [
        BitField("ver" , 1 , 4),
        BitField("len" , 1 , 4),
        BitField("nProto", 0, 3),
        BitField("repMdBits", 0, 6),
        BitField("reserved", None, 6),
        BitField("d", 0, 1),
        BitField("q", 0, 1),
        BitField("f", 1, 1),
        BitField("hw_id", None, 6),

        IntField("swid", None),
        IntField("seqNumber", None),
        IntField("ingressTimestamp", None) ]

''' 
INT header version 1.0
    header int_header_t {
        bit<4>  ver;
        bit<2>  rep;
        bit<1>  c;
        bit<1>  e;
        bit<1>  m;
        bit<7>  rsvd1;
        bit<3>  rsvd2;
        bit<5>  hop_metadata_len;   // the length of the metadata added by a single INT node (4-byte words)
        bit<8>  remaining_hop_cnt;  // how many switches can still add INT metadata
        bit<16>  instruction_mask;   
        bit<16> rsvd3;
    }
'''

class INT_v10(Packet):

    name = "INT v1.0"

    fields_desc = [
        XByteField("type", 1),
        XByteField("shimRsvd1", None),
        XByteField("length", None),
        BitField("dscp", None, 6),
        BitField("shimRsvd2", None, 2),

        BitField("ver", 0, 4),
        BitField("rep", 0, 2),
        BitField("c", 0, 1),
        BitField("e", 0, 1),
        BitField("m", 0, 1),
        BitField("rsvd1", 0, 7),
        BitField("rsvd2", 0, 3),
        BitField("hopMLen", None, 5),
        XByteField("remainHopCnt", None),

        XShortField("ins", None),
        XShortField("rsvd3", 0),

        FieldListField("INTMetadata", [], XIntField("", None), count_from=lambda p:p.length - 2)
        ]    

class INTMetadata():
    def __init__(self, hops, switch_id = 1, ingress_port = 2, egress_port = 3, hop_latency = 20, queue_id = 5, 
                queue_occups = 600, ingress_timestamp = 700, egress_timestamp = 15242, lv2_in_e_port = 5 << 15 | 1000,
                tx_utilizes = 1):

        self.__hops = hops
        self.switch_id = switch_id
        self.ingress_port = ingress_port
        self.egress_port = egress_port
        self.hop_latency = hop_latency
        self.queue_id = queue_id
        self.queue_occups = queue_occups
        self.ingress_timestamp = ingress_timestamp
        self.egress_timestamp = egress_timestamp
        self.lv2_in_e_port = lv2_in_e_port
        self.tx_utilizes = tx_utilizes

        self.__queue_id_occups: int = 0
        self.__ing_egr_port_id: int = 0

        self.int_metadata = []
    
    def create_metadata(self):

        """
        INTMetadata = [switch_id, ingress_port_id, egress_port_id, hop_latency, queue_id, queue_occups,
                        ingress_timestamp, egress_timestamp, lv2_in_e_port, tx_utilizes ]
        """
        self.__queue_id_occups = self.queue_id <<16 | self.queue_occups #queue_id << 16 | queue_occups
        self.__ing_egr_port_id = self.ingress_port << 16 | self.egress_port  #ingress_port << 16 | egr_port

        self.int_metadata = [self.switch_id, self.__ing_egr_port_id, self.hop_latency, self.__queue_id_occups,
                        self.ingress_timestamp, self.egress_timestamp, self.lv2_in_e_port, self.tx_utilizes] * self.__hops
        
        for hop in range(self.__hops):
            self.int_metadata[0+hop*8] += hop

    def edit_hop_latency(self, new_hop_latency = 60):

        for hop in range(1,self.__hops):
            self.int_metadata[2+hop*8] += new_hop_latency * (hop+1)
 
    def edit_queue_occups(self, new_queue_occups = 6):

        for hop in range(self.__hops):
            queue_id_occups = self.queue_id <<16 | new_queue_occups #queue_id << 16 | queue_occups
            self.int_metadata[3+hop*8] = queue_id_occups

    def edit_timestamps(self, new_ing_time = 60, new_egr_time = 60):
        
        for hop in range(self.__hops):
            self.int_metadata[4+hop*8] += new_ing_time * hop
            self.int_metadata[5+hop*8] += new_egr_time * hop

    def edit_tx_utilizes(self, hop = 0, new_tx = 0):
        try:
            self.int_metadata[7+hop*8] = new_tx
        except:
            pass

    def print_metadata(self, name):
        print(f'\n{"*"*15}{name} INT METADATA{"*"*15}')
        for hop in range(self.__hops):
            shift = hop*8+8
            print((f'HOP {hop}: {self.int_metadata[hop*8:shift]}'))

    def print_metadata_build(self):

        print(f'\n{"*"*15}METADATA BUILD:{"*"*15}\n'
            f"[0.switch_id, \n1.ingress_port_id, \n2.egress_port_id,\n"
            f"3.hop_latency, \n4.queue_id, \n5.queue_occups, \n6.ingress_timestamp,\n"
            f"7.egress_timestamp, \n8.lv2_in_e_port, \n9.tx_utilizes]")

        

def gen_packets():

    list_switch_id = [1,2,3,4,5,6]
    int_length = args.hops * 8 + 3
    packets = []
    int_metadata = INTMetadata(args.hops)
    int_metadata.create_metadata()


    if args.log_level == 10: 
        int_metadata.print_metadata_build()
        int_metadata.print_metadata("FIRST")

    if args.linear:
        if args.number > 1000:
            for counter in range(0,1000):
                p = Ether()/ \
                    IP(tos=0x17<<2)/ \
                    UDP(sport=5000, dport=8086)/ \
                    TelemetryReport_v10(ingressTimestamp= 1524138290)/ \
                    Ether()/ \
                    IP(src="10.0.0.1", dst="10.0.0.2")/ \
                    UDP(sport=5000, dport=5000)/ \
                    INT_v10(length=int_length, hopMLen=8, remainHopCnt=3, ins=(1<<7|1<<6|1<<5|1<<4|1<<3|1<<2|1<<1|1)<<8,
                        INTMetadata = int_metadata.int_metadata)

                # p = Ether()/ \
                #     IP(src="10.0.0.1", dst="10.0.0.2")/ \
                #     UDP(sport=5000, dport=5000)/ \
                #     TelemetryReport_v10(ingressTimestamp= 1524138290)/ \
                #     INT_v10(length=int_length, hopMLen=8, remainHopCnt=3, ins=(1<<7|1<<6|1<<5|1<<4|1<<3|1<<2|1<<1|1)<<8,
                #         INTMetadata = int_metadata)
                
                packets.append(bytes(p))
                int_metadata.edit_hop_latency()
                int_metadata.edit_queue_occups()
                int_metadata.edit_timestamps()
                int_metadata.edit_tx_utilizes()

            if args.log_level == 10: int_metadata.print_metadata("LAST")

            
            while 1:
                for i in range(len(packets)):
                    if len(packets) < args.number:
                        packets.append(packets[i])
                    else:
                        logger.info(f'{len(packets)} packages were generated.\n')
                        return packets

        else:
            for counter in range(0,args.number):
                p = Ether()/ \
                    IP(tos=0x17<<2)/ \
                    UDP(sport=5000, dport=8086)/ \
                    TelemetryReport_v10(ingressTimestamp= 1524138290)/ \
                    Ether()/ \
                    IP(src="10.0.0.1", dst="10.0.0.2")/ \
                    UDP(sport=5000, dport=5000)/ \
                    INT_v10(length=int_length, hopMLen=8, remainHopCnt=3, ins=(1<<7|1<<6|1<<5|1<<4|1<<3|1<<2|1<<1|1)<<8,
                        INTMetadata = int_metadata.int_metadata)

                # p = Ether()/ \
                #     IP(src="10.0.0.1", dst="10.0.0.2")/ \
                #     UDP(sport=5000, dport=5000)/ \
                #     TelemetryReport_v10(ingressTimestamp= 1524138290)/ \
                #     INT_v10(length=int_length, hopMLen=8, remainHopCnt=3, ins=(1<<7|1<<6|1<<5|1<<4|1<<3|1<<2|1<<1|1)<<8,
                #         INTMetadata = int_metadata)
                
                packets.append(bytes(p))
                int_metadata.edit_hop_latency()
                int_metadata.edit_queue_occups()
                int_metadata.edit_timestamps()
                int_metadata.edit_tx_utilizes()

            if args.log_level == 10: int_metadata.print_metadata("LAST")   
            logger.info(f'{len(packets)} packages were generated.\n')
            return packets 

    else:
        p0 = Ether()/ \
            IP(tos=0x17<<2)/ \
            UDP(sport=5000, dport=8086)/ \
            TelemetryReport_v10(swid = 1, seqNumber = 5, ingressTimestamp= 1524138290)/ \
            Ether()/ \
            IP(src="10.0.0.1", dst="10.0.0.2")/ \
            UDP(sport=5000, dport=5000)/ \
            INT_v10(length=int_length,hopMLen=8, remainHopCnt=3, ins=(1<<7|1<<6|1<<5|1<<4|1<<3|1<<2|1<<1|1)<<8,
                INTMetadata= int_metadata.int_metadata)

        # p0 = Ether()/ \
        #     IP(src="10.0.0.1", dst="10.0.0.2")/ \
        #     UDP(sport=5000, dport=5000)/ \
        #     TelemetryReport_v10(swid = 1, seqNumber = 5, ingressTimestamp= 1524138290)/ \
        #     INT_v10(length=27,hopMLen=8, remainHopCnt=3, ins=(1<<7|1<<6|1<<5|1<<4|1<<3|1<<2|1<<1|1)<<8,
        #         INTMetadata= int_metadata.int_metadata)

        int_metadata.edit_hop_latency(70)
        int_metadata.edit_queue_occups()
        int_metadata.edit_timestamps()
        int_metadata.edit_tx_utilizes(3)

        p1 = Ether()/ \
            IP(tos=0x17<<2)/ \
            UDP(sport=5000, dport=8086)/ \
            TelemetryReport_v10(swid = 1,seqNumber = 200,ingressTimestamp= 1524138290)/ \
            Ether()/ \
            IP(src="10.0.0.1", dst="10.0.0.2")/ \
            UDP(sport=5000, dport=5000)/ \
            INT_v10(length=int_length,hopMLen=8, remainHopCnt=3, ins=(1<<7|1<<6|1<<5|1<<4|1<<3|1<<2|1<<1|1)<<8,
                INTMetadata= int_metadata.int_metadata)

        # p1 = Ether()/ \
        #     IP(src="10.0.0.1", dst="10.0.0.2")/ \
        #     UDP(sport=5000, dport=5000)/ \
        #     TelemetryReport_v10(swid = 1,seqNumber = 200,ingressTimestamp= 1524138290)/ \
        #     INT_v10(length=27,hopMLen=8, remainHopCnt=3, ins=(1<<7|1<<6|1<<5|1<<4|1<<3|1<<2|1<<1|1)<<8,
        #         INTMetadata= int_metadata.int_metadata)

        packets.append(bytes(p0))
        packets.append(bytes(p1))
        if args.log_level == 10: int_metadata.print_metadata("LAST")

    logger.info(f'{len(packets)} packages were generated.\n')
    return packets
        
    

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
        help="Number of generating packets per one second. Default: 1000")
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
    iface = args.interface

    if args.constant:        
        logger.info(f'Start of generating of packages')
        packets = gen_packets()
        logger.info(f'Start of sending packages through the {iface} interface')
        spackets: int = 0

        try:
            start_time = datetime.now()
            while 1:
                sendp(packets[0], iface=iface, verbose = args.verbose)
                time.sleep(1)
                sendp(packets[1], iface=iface, verbose = args.verbose)
                time.sleep(1)
                
                spackets += 2
                if spackets == args.number:
                    end_time = datetime.now()
                    logger.info(f'{spackets} packets were sent within {end_time-start_time}s.')
                    start_time = end_time
                    spackets = 0

        except KeyboardInterrupt:
            pass

    if args.linear:
        
        counter = 0
        logger.info(f'Start of generating of packages')
        packets = gen_packets()
        logger.info(f'Start of sending packages through the {iface} interface')
        try:
            mode = int(input("Do you want to use senp or senpfast (1-sendp, 2-sendpfast)?\nMODE: "))
            if mode == 1:
                while 1:
                    start = datetime.now()
                    sendp(packets, iface=iface, verbose = args.verbose, inter = 1/args.number)
                    logger.info(f'{len(packets)} packets were sent within {datetime.now()-start}s')
                    counter += len(packets)
                    logger.info(f'{counter} packets were sent.\n')
            elif mode == 2:
                 while 1:
                    start = datetime.now()
                    sendpfast(packets, iface=iface, pps=args.number)
                    logger.info(f'{len(packets)} packets were sent within {datetime.now()-start}s')
                    counter += len(packets)
                    logger.info(f'{counter} packets were sent.\n')

                    

        except KeyboardInterrupt:
            pass