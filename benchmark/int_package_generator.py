from __future__ import print_function
from scapy.all import *
import time
import argparse

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

if __name__ == "__main__":

    iface = "veth_0"

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

    iface = "veth_0"

    try:
        while 1:
            sendp(p0, iface=iface)
            time.sleep(2)
            sendp(p1, iface=iface)
            time.sleep(2)

    except KeyboardInterrupt:
        pass