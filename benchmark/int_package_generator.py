from __future__ import print_function
from random import choices
from scapy import data
from scapy.all import *
import time
import argparse
import logging
from datetime import datetime
from dataclasses import dataclass

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

@dataclass 
class INTMetadata():
    def __init__(self, hops):
        self.switch_id = 1
        self.ing_egr_port_id = 2 << 16 | 3  #ingress_port << 16 | egr_port
        self.hop_latency = 20
        self.queue_id_occups = 5 <<16 | 600 #queue_id << 16 | queue_occups
        self.ingress_timestamp = 700
        self.egress_timestamp = 15242
        self.lv2_in_e_port = 5<<15|1000
        self.tx_utilizes = 1

        """
        INTMetadata = [switch_id, ingress_port_id, egress_port_id, hop_latency, queue_id, queue_occups,
                        ingress_timestamp, egress_timestamp, lv2_in_e_port, tx_utilizes ]
        """
        self.int_metadata = [self.switch_id, self.ing_egr_port_id, self.hop_latency, self.queue_id_occups,
                        self.ingress_timestamp, self.egress_timestamp, self.lv2_in_e_port, self.tx_utilizes]
        self.int_metadata = self.int_metadata * hops

def gen_packets():

    list_switch_id = [1,2,3,4,5,6]
    int_length = args.hops * 8 + 3
    packets = []
    int_metadata = INTMetadata(args.hops)

    logger.debug(f'First INTMetada:\n {int_metadata.int_metadata}')

    if args.linear:
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
            for x in range(1,args.hops):
                int_metadata.int_metadata[2+x*8] = int_metadata.hop_latency + counter*100 + x*100
                int_metadata.int_metadata[4+x*8] = int_metadata.ingress_timestamp + counter * 100 + x * 100
                int_metadata.int_metadata[5+x*8] = int_metadata.egress_timestamp + counter * 100 + x *100
                int_metadata.int_metadata[0+x*8] = list_switch_id[x]

        else:
            p0 = Ether()/ \
                IP(tos=0x17<<2)/ \
                UDP(sport=5000, dport=8086)/ \
                TelemetryReport_v10(swid = 1, seqNumber = 5, ingressTimestamp= 1524138290)/ \
                Ether()/ \
                IP(src="10.0.0.1", dst="10.0.0.2")/ \
                UDP(sport=5000, dport=5000)/ \
                INT_v10(length=27,hopMLen=8, remainHopCnt=3, ins=(1<<7|1<<6|1<<5|1<<4|1<<3|1<<2|1<<1|1)<<8,
                    INTMetadata= [4, 2<<16| 3, 400, 5<<16| 600, 700, 1524234560, 5<<16| 1000, 1,
                    5, 2<<16| 3, 4, 5<<16| 6, 7, 1524234560, 5<<16| 10, 1,
                    6, 2<<16| 3, 4, 5<<16| 6, 7, 1524234560, 5<<16| 10, 1]
                )
            p1 = Ether()/ \
            IP(tos=0x17<<2)/ \
            UDP(sport=5000, dport=8086)/ \
            TelemetryReport_v10(swid = 1,seqNumber = 200,ingressTimestamp= 1524138290)/ \
            Ether()/ \
            IP(src="10.0.0.1", dst="10.0.0.2")/ \
            UDP(sport=5000, dport=5000)/ \
            INT_v10(length=27,hopMLen=8, remainHopCnt=3, ins=(1<<7|1<<6|1<<5|1<<4|1<<3|1<<2|1<<1|1)<<8,
                INTMetadata= [4, 2<<16| 3, 4, 5<<16| 6, 7, 1524234560, 5<<16| 10, 1000,
                5, 2<<16| 3, 4, 5<<16| 6, 7, 1524234560, 5<<16| 10, 1,
                6, 2<<16| 3, 4, 5<<16| 6, 7, 1524234560, 5<<16| 10, 1]
            )

        # p0 = Ether()/ \
        #     IP(src="10.0.0.1", dst="10.0.0.2")/ \
        #     UDP(sport=5000, dport=5000)/ \
        #     TelemetryReport_v10(swid = 1, seqNumber = 5, ingressTimestamp= 1524138290)/ \
        #     INT_v10(length=27,hopMLen=8, remainHopCnt=3, ins=(1<<7|1<<6|1<<5|1<<4|1<<3|1<<2|1<<1|1)<<8,
        #         INTMetadata= [4, 2<<16| 3, 400, 5<<16| 600, 700, 1524234560, 5<<16| 1000, 1,
        #         5, 2<<16| 3, 4, 5<<16| 6, 7, 1524234560, 5<<16| 10, 1,
        #         6, 2<<16| 3, 4, 5<<16| 6, 7, 1524234560, 5<<16| 10, 1]
        #     )

        # p1 = Ether()/ \
        #     IP(src="10.0.0.1", dst="10.0.0.2")/ \
        #     UDP(sport=5000, dport=5000)/ \
        #     TelemetryReport_v10(swid = 1,seqNumber = 200,ingressTimestamp= 1524138290)/ \
        #     INT_v10(length=27,hopMLen=8, remainHopCnt=3, ins=(1<<7|1<<6|1<<5|1<<4|1<<3|1<<2|1<<1|1)<<8,
        #         INTMetadata= [4, 2<<16| 3, 4, 5<<16| 6, 7, 1524234560, 5<<16| 10, 1000,
        #         5, 2<<16| 3, 4, 5<<16| 6, 7, 1524234560, 5<<16| 10, 1,
        #         6, 2<<16| 3, 4, 5<<16| 6, 7, 1524234560, 5<<16| 10, 1]
        #     )
            packets = [p0,p1]
        
        logger.debug(f'Last INTMetadata:\n{int_metadata.int_metadata}')
        logger.info(f'Generated {len(packets)} packages.')
        return packets
        
    

if __name__ == "__main__":
    
    parser = argparse.ArgumentParser(description='INT Telemetry Report pkt gen.')
    parser.add_argument("-c", "--constant", action='store_true',
        help="Generating two packets with constant values. One per second.")
    parser.add_argument("-l", "--linear", action = 'store_true',
        help="Generates packets with linearly growing values")
    parser.add_argument("-hop", "--hops", default=3, type=int, choices=range(1,7),
        help="Number of hops in packet. Max - 6.")
    parser.add_argument("-i","--interface", type=str, default='veth_1',
        help="Interface through which packets will be sent")
    parser.add_argument("-n", "--number", default=1000, type=int,
        help="Number of generating packets per one second")
    parser.add_argument("-v", "--verbose", default = 0, type=int, choices=range(0,2),
        help='Scapy verbose, 0 - disable, 1 - enable')
    parser.add_argument("-log", "--log_level", default= 20, type=int,
        help="CRITICAL = 50\
            ERROR = 40;\
            WARNING = 30;\
            INFO = 20;\
            DEBUG = 10;\
            NOTSET = 0;")
            
    args = parser.parse_args()

    logger.setLevel(args.log_level)
    iface = args.interface

    if args.constant:        

        try:
            while 1:
                sendp(p0, iface=iface)
                time.sleep(1)
                sendp(p1, iface=iface)
                time.sleep(1)

        except KeyboardInterrupt:
            pass

    if args.linear:
        
        counter = 0
        logger.info(f'Start generating packages')
        packets = gen_packets()
        logger.info(f'Start sending packages')
        try:
                while 1:
                    start = datetime.now()
                    # for x in range(args.number):
                    sendp(packets, iface=iface, verbose = args.verbose)#, inter = 1/args.number)
                    # sendpfast(packets, iface=iface, pps=args.number)
                    logger.debug(f'Sent {len(packets)} packages in: {datetime.now()-start}s')
                    

        except KeyboardInterrupt:
            pass