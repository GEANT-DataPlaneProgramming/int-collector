from __future__ import print_function
from scapy.all import *
import time
import argparse

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

class TelemetryReport(Packet):

    name = "INT telemetry report v0.5"

    # default value a for telemetry report with INT
    fields_desc = [ BitField("ver" , 1 , 4),
        BitField("nProto", 0, 4),
        BitField("d", 0, 1),
        BitField("q", 0, 1),
        BitField("f", 1, 1),
        BitField("reserved", None, 15),
        BitField("hw_id", None, 6),

        IntField("seqNumber", None),
        IntField("ingressTimestamp", None) ]



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
        XShortField("res", 0),

        FieldListField("INTMetadata", [], XIntField("", None), count_from=lambda p:p.length - 2)
        ]

class INT(Packet):

    name = "INT v0.5"

    fields_desc = [ XByteField("type", 1),
        XByteField("shimRsvd1", None),
        XByteField("length", None),
        XByteField("shimRsvd2", None),

        BitField("ver", 0, 4),
        BitField("rep", 0, 2),
        BitField("c", 0, 1),
        BitField("e", 0, 1),
        BitField("r", 0, 3),
        BitField("insCnt", None, 5),

        XByteField("maxHopCnt", 8),
        XByteField("totalHopCnt", 0),
        XShortField("ins", None),
        XShortField("res", 0),

        FieldListField("INTMetadata", [], XIntField("", None), count_from=lambda p:p.totalHopCnt*p.insCnt),

        XByteField("proto", None),
        XShortField("port", None),
        XByteField("originDSCP", 0)]

if __name__ == "__main__":

    parser = argparse.ArgumentParser(description='INT Telemetry Report pkt gen.')
    parser.add_argument("-t1", "--test1", action='store_true',
        help="Gen pcaps for Test 1")
    parser.add_argument("-t2", "--test2", action='store_true',
        help="Gen pcaps for Test 2")
    parser.add_argument("-t3", "--test3", action='store_true',
        help="Gen pcaps for Test 3")
    parser.add_argument("-t4", "--test4", action='store_true',
        help="Gen pcaps for Test 4")
    parser.add_argument("-t5", "--test_event_detection", action='store_true',
        help="Test out of interval")
    parser.add_argument("-t6", "--test_onos_collector", action='store_true',
        help="Test collector from ONOS P4 group")
    parser.add_argument("-t7", "--test_event_correctness", action='store_true',
        help="Test the correctness of event detection")
    parser.add_argument("-t8", "--test_v10_spec", action='store_true',
        help="Test v1.0 spec implementation")
    args = parser.parse_args()

    # p_3sw_8d = []
    # p_6sw_8d = []
    # p_6sw_f_id = []
    # tcp_p_3sw_8d = []

    # TEST 1: How does number of flow affect CPU usage?
    # -- 6sw, flow_path only
    # -- num flow: 10, 100, 500, 1000, 2000, 5000
    if args.test1:
        n_sw = 6
        n_flows = [10, 100, 500, 1000, 2000, 5000]
        for n_fl in n_flows:
            p=[]
            for i in range(0, n_fl):
                p.append(Ether()/ \
                    IP(tos=0x17<<2)/ \
                    UDP(sport=5000, dport=8086)/ \
                    TelemetryReport(ingressTimestamp= 1524138290)/ \
                    Ether()/ \
                    IP(src="10.0.0.1", dst="10.0.{0}.{1}".format(i/256, i%256))/ \
                    UDP(sport=5000, dport=5000)/ \
                    INT(insCnt=1, totalHopCnt=n_sw, ins=(1<<7)<<8, \
                        INTMetadata=[j for j in range(0,6)], \
                        originDSCP=14))
            wrpcap("pcaps/t1_{0}sw_{1}fl_swid.pcap".format(n_sw, n_fl), p)
            print("Done: t1_{0}sw_{1}fl_swid.pcap".format(n_sw, n_fl))



    # TEST2: How does the number of sw affect CPU usage?
    # -- flow_path only, num flow = 100
    # -- all fields, num flow = 100
    # -- 1, 2, 3, 4, 5, 6 sws
    if args.test2:
        n_sws = [1, 2, 3, 4, 5, 6]
        n_fl = 100
        for n_sw in n_sws:
            # flow path only
            p=[]
            for i in range(0, n_fl):
                p.append(Ether()/ \
                    IP(tos=0x17<<2)/ \
                    UDP(sport=5000, dport=8086)/ \
                    TelemetryReport(ingressTimestamp= 1524138290)/ \
                    Ether()/ \
                    IP(src="10.0.0.1", dst="10.0.{0}.{1}".format(i/256, i%256))/ \
                    UDP(sport=5000, dport=5000)/ \
                    INT(insCnt=1, totalHopCnt=n_sw, ins=(1<<7)<<8, \
                        INTMetadata=[j for j in range(0,n_sw)], \
                        originDSCP=14))
            wrpcap("pcaps/t2_{0}sw_{1}fl_swid.pcap".format(n_sw, n_fl), p)
            print("Done: t2_{0}sw_{1}fl_swid.pcap".format(n_sw, n_fl))

            # all fields
            p=[]
            for i in range(0, n_fl):
                INTdata = []
                for j in range(0,n_sw):
                    INTdata += [j, 2<<16| 3, 4+j, 5<<16| 6, 7+j, 1524234560, 5<<16| 10+j, 11+j]
                p.append(Ether()/ \
                    IP(tos=0x17<<2)/ \
                    UDP(sport=5000, dport=8086)/ \
                    TelemetryReport(ingressTimestamp= 1524138290)/ \
                    Ether()/ \
                    IP(src="10.0.0.1", dst="10.0.{0}.{1}".format(i/256, i%256))/ \
                    UDP(sport=5000, dport=5000)/ \
                    INT(insCnt=8, totalHopCnt=n_sw, ins=(1<<7|1<<6|1<<5|1<<4|1<<3|1<<2|1<<1|1)<<8,
                        INTMetadata= INTdata,
                        originDSCP=14))
            wrpcap("pcaps/t2_{0}sw_{1}fl_all.pcap".format(n_sw, n_fl), p)
            print("Done: t2_{0}sw_{1}fl_all.pcap".format(n_sw, n_fl))



    # TEST3: How does number of INT metadata affect CPU usage?
    # -- 3 sw, 100 flow
    # -- 6 sw, 100 flow
    # -- sw_id; sw_id + hop latency; sw_id + tx_utilize; sw_id + q occ + q congest; all fields
    if args.test3:
        n_sws = [3, 6]
        n_fl = 100
        for n_sw in n_sws:
            # flow path only
            p=[]
            for i in range(0, n_fl):
                p.append(Ether()/ \
                    IP(tos=0x17<<2)/ \
                    UDP(sport=5000, dport=8086)/ \
                    TelemetryReport(ingressTimestamp= 1524138290)/ \
                    Ether()/ \
                    IP(src="10.0.0.1", dst="10.0.{0}.{1}".format(i/256, i%256))/ \
                    UDP(sport=5000, dport=5000)/ \
                    INT(insCnt=1, totalHopCnt=n_sw, ins=(1<<7)<<8, \
                        INTMetadata=[j for j in range(0,n_sw)], \
                        originDSCP=14))
            wrpcap("pcaps/t3_{0}sw_{1}fl_swid.pcap".format(n_sw, n_fl), p)
            print("Done: t3_{0}sw_{1}fl_swid.pcap".format(n_sw, n_fl))

            # sw_id + hop latency
            p=[]
            for i in range(0, n_fl):
                INTdata = []
                for j in range(0,n_sw):
                    INTdata += [j, 4+j, 1524234560]
                p.append(Ether()/ \
                    IP(tos=0x17<<2)/ \
                    UDP(sport=5000, dport=8086)/ \
                    TelemetryReport(ingressTimestamp= 1524138290)/ \
                    Ether()/ \
                    IP(src="10.0.0.1", dst="10.0.{0}.{1}".format(i/256, i%256))/ \
                    UDP(sport=5000, dport=5000)/ \
                    INT(insCnt=3, totalHopCnt=n_sw, ins=(1<<7|1<<5|1<<2)<<8,
                        INTMetadata= INTdata,
                        originDSCP=14))
            wrpcap("pcaps/t3_{0}sw_{1}fl_swid_hoplatency.pcap".format(n_sw, n_fl), p)
            print("Done: t3_{0}sw_{1}fl_swid_hoplatency.pcap".format(n_sw, n_fl))

            # sw_id + txutilize
            p=[]
            for i in range(0, n_fl):
                INTdata = []
                for j in range(0,n_sw):
                    INTdata += [j,2<<16|3, 1524234560, 4+j]
                p.append(Ether()/ \
                    IP(tos=0x17<<2)/ \
                    UDP(sport=5000, dport=8086)/ \
                    TelemetryReport(ingressTimestamp= 1524138290)/ \
                    Ether()/ \
                    IP(src="10.0.0.1", dst="10.0.{0}.{1}".format(i/256, i%256))/ \
                    UDP(sport=5000, dport=5000)/ \
                    INT(insCnt=4, totalHopCnt=n_sw, ins=(1<<7|1<<6|1<<2|1)<<8,
                        INTMetadata= INTdata,
                        originDSCP=14))
            wrpcap("pcaps/t3_{0}sw_{1}fl_swid_txutilize.pcap".format(n_sw, n_fl), p)
            print("Done: t3_{0}sw_{1}fl_swid_txutilize.pcap".format(n_sw, n_fl))

            # sw_id + qoccup + qcongest
            p=[]
            for i in range(0, n_fl):
                INTdata = []
                for j in range(0,n_sw):
                    INTdata += [j, (5+j)<<16| 6, 1524234560, (5+j)<<16| 10+j]
                p.append(Ether()/ \
                    IP(tos=0x17<<2)/ \
                    UDP(sport=5000, dport=8086)/ \
                    TelemetryReport(ingressTimestamp= 1524138290)/ \
                    Ether()/ \
                    IP(src="10.0.0.1", dst="10.0.{0}.{1}".format(i/256, i%256))/ \
                    UDP(sport=5000, dport=5000)/ \
                    INT(insCnt=4, totalHopCnt=n_sw, ins=(1<<7|1<<4|1<<2|1<<1)<<8,
                        INTMetadata= INTdata,
                        originDSCP=14))
            wrpcap("pcaps/t3_{0}sw_{1}fl_swid_qoccup_qcongest.pcap".format(n_sw, n_fl), p)
            print("Done: t3_{0}sw_{1}fl_swid_qoccup_qcongest.pcap".format(n_sw, n_fl))

            # all fields
            p=[]
            for i in range(0, n_fl):
                INTdata = []
                for j in range(0,n_sw):
                    INTdata += [j, 2<<16| 3, 4+j, (5+j)<<16| 6, 7+j, 1524234560, (5+j)<<16| 10+j, 11+j]
                p.append(Ether()/ \
                    IP(tos=0x17<<2)/ \
                    UDP(sport=5000, dport=8086)/ \
                    TelemetryReport(ingressTimestamp= 1524138290)/ \
                    Ether()/ \
                    IP(src="10.0.0.1", dst="10.0.{0}.{1}".format(i/256, i%256))/ \
                    UDP(sport=5000, dport=5000)/ \
                    INT(insCnt=8, totalHopCnt=n_sw, ins=(1<<7|1<<6|1<<5|1<<4|1<<3|1<<2|1<<1|1)<<8,
                        INTMetadata= INTdata,
                        originDSCP=14))
            wrpcap("pcaps/t3_{0}sw_{1}fl_all.pcap".format(n_sw, n_fl), p)
            print("Done: t3_{0}sw_{1}fl_all.pcap".format(n_sw, n_fl))



    # TEST4: How does number of event affect CPU usage?
    # -- 3sw, all fields, 5000 flow
    # -- num of event per seconds:
    if args.test4:
        n_sw = 3
        n_fl = 100
        n_events = [20, 50, 100, 200, 500, 1000]
        TMP = 1000000*2/100
        for n_event in n_events:
            # all fields
            p=[]
            for i in range(0, n_fl):
                print("flow: ", i)
                # 1000000 pps; 1 abnormal packet is 2 events (11+j -> 1000, and 1000 -> 11+j)
                for l in range(0, TMP/n_event):
                    INTdata = []
                    for j in range(0,n_sw):
                        addedINT = [j, 2<<16| 3, 4+j, 5<<16| 6, 7+j, 1524234560, 5<<16| 10+j, 11+j]
                        if (l < TMP/(n_event*2) and i==0 and j==0):
                            # use j as sw_id to ensure diff switches so that the number of event is correct
                            addedINT = [j, 2<<16| 3, 4+j, 5<<16| 6, 7+j, 1524234560, 5<<16| 10+j, 5000]
                        INTdata += addedINT
                    p.append(Ether()/ \
                        IP(tos=0x17<<2)/ \
                        UDP(sport=5000, dport=8086)/ \
                        TelemetryReport(ingressTimestamp= 1524138290)/ \
                        Ether()/ \
                        IP(src="10.0.0.1", dst="10.0.{0}.{1}".format(i/256, i%256))/ \
                        UDP(sport=5000, dport=5000)/ \
                        INT(insCnt=8, totalHopCnt=n_sw, ins=(1<<7|1<<6|1<<5|1<<4|1<<3|1<<2|1<<1|1)<<8,
                            INTMetadata= INTdata,
                            originDSCP=14))
            wrpcap("pcaps/t4_{0}sw_{1}fl_{2}event_all.pcap".format(n_sw, n_fl, n_event), p)
            print("Done: t4_{0}sw_{1}fl_{2}event_all.pcap".format(n_sw, n_fl, n_event))


    # test event_detection
    if args.test_event_detection:
        p0 = Ether()/ \
            IP(tos=0x17<<2)/ \
            UDP(sport=5000, dport=8086)/ \
            TelemetryReport(ingressTimestamp= 1524138290)/ \
            Ether()/ \
            IP(src="10.0.0.1", dst="10.0.0.2")/ \
            UDP(sport=5000, dport=5000)/ \
            INT(insCnt=8, totalHopCnt=3, ins=(1<<7|1<<6|1<<5|1<<4|1<<3|1<<2|1<<1|1)<<8,
                INTMetadata= [4, 5<<16| 3, 400, 5<<16| 600, 700, 1524234560, 5<<16| 1000, 1,
                5, 2<<16| 3, 4, 5<<16| 6, 7, 1524234560, 5<<16| 10, 1,
                6, 2<<16| 3, 4, 5<<16| 6, 7, 1524234560, 5<<16| 10, 1],
                originDSCP=14)

        p1 = Ether()/ \
            IP(tos=0x17<<2)/ \
            UDP(sport=5000, dport=8086)/ \
            TelemetryReport(ingressTimestamp= 1524138290)/ \
            Ether()/ \
            IP(src="10.0.0.1", dst="10.0.0.2")/ \
            UDP(sport=5000, dport=5000)/ \
            INT(insCnt=8, totalHopCnt=3, ins=(1<<7|1<<6|1<<5|1<<4|1<<3|1<<2|1<<1|1)<<8,
                INTMetadata= [4, 5<<16| 3, 4, 5<<16| 6, 7, 1524234560, 5<<16| 10, 1000,
                5, 2<<16| 3, 4, 5<<16| 6, 7, 1524234560, 5<<16| 10, 1,
                6, 2<<16| 3, 4, 5<<16| 6, 7, 1524234560, 5<<16| 10, 1],
                originDSCP=14)

        iface = "veth_0"

        try:
            while 1:
                sendp(p0, iface=iface)
                time.sleep(5)
                sendp(p1, iface=iface)
                time.sleep(5)

        except KeyboardInterrupt:
            pass

    # test onos collector
    if args.test_onos_collector:
        p0 = Ether(dst="52:54:00:d5:81:bb")/ \
            IP(tos=0x17<<2, dst="192.168.122.191")/ \
            UDP(sport=5000, dport=1234)/ \
            TelemetryReport(ingressTimestamp= 1524138290)/ \
            Ether()/ \
            IP(src="10.0.0.1", dst="10.0.0.2", tos=0x1<<2)/ \
            UDP(sport=5000, dport=5000)/ \
            INT(insCnt=8, totalHopCnt=3, ins=(1<<7|1<<6|1<<5|1<<4|1<<3|1<<2|1<<1|1)<<8,
                INTMetadata= [4, 2<<16| 3, 4, 5<<16| 6, 7, 1524234560, 5<<16| 10, 1,
                5, 2<<16| 3, 4, 5<<16| 6, 7, 1524234560, 5<<16| 10, 1,
                6, 2<<16| 3, 4, 5<<16| 6, 7, 1524234560, 5<<16| 10, 1],
                originDSCP=14)


        # wrpcap("pcaps/test_onos_collector.pcap", p0*10)

        # iface = "vnet0"
        # try:
        #     while 1:
        #         sendp(p0, iface=iface)
        #         time.sleep(1)

        # except KeyboardInterrupt:
        #     pass

        n_sws = [5]
        n_fl = 10
        for n_sw in n_sws:
            # all fields
            p=[]
            for i in range(0, n_fl):
                INTdata = []
                for j in range(0,n_sw):
                    INTdata += [j, 2<<16| 3, 4+j, 5<<16| 6, 7+j, 1524234560, 5<<16| 10+j, 11+j]
                p.append(Ether(dst="52:54:00:d5:81:bb")/ \
                    IP(tos=0x17<<2, dst="192.168.122.191")/ \
                    UDP(sport=5000, dport=1234)/ \
                    TelemetryReport(ingressTimestamp= 1524138290)/ \
                    Ether()/ \
                    IP(src="10.0.0.1", dst="10.0.{0}.{1}".format(i/256, i%256), tos=0x1<<2)/ \
                    UDP(sport=5000, dport=5000)/ \
                    INT(insCnt=8, totalHopCnt=n_sw, ins=(1<<7|1<<6|1<<5|1<<4|1<<3|1<<2|1<<1|1)<<8,
                        INTMetadata= INTdata,
                        originDSCP=14))
            wrpcap("pcaps/t6_{0}sw_{1}fl_all.pcap".format(n_sw, n_fl), p)
            print("Done: t6_{0}sw_{1}fl_all.pcap".format(n_sw, n_fl))


    # test event_detection
    if args.test_event_correctness:
        p = []
        n_sw = 3
        lats = [200, 202, 196, 223, 212, 215, 198, 218, 186, 186, 202, 186, 202, 221, 185, 225, 186, 269, 211, 196, 252, 239, 193, 209, 235, 192, 756, 465, 488, 484, 490, 452, 438, 483, 448, 439, 439, 465, 458, 351, 249, 213, 249, 213, 186, 187, 199, 245, 206, 199, 225, 398, 233, 300, 241, 205, 199, 248, 215, 234, 226, 239, 193, 193, 185, 203, 186, 190, 185, 184, 246, 218, 182, 234, 229, 249, 209, 247, 250, 195, 201, 239, 222, 234, 272, 247, 213, 171, 182, 239, 174, 832, 224, 234, 238, 230, 238, 192, 222, 232]

        for i, lat in enumerate(lats):
            INTdata = [4, 40, (i+1)*1e6, 5, 41, (i+1)*1e6, 6, lat, (i+1)*1e6]
            p.append(Ether()/ \
                        IP(tos=0x17<<2)/ \
                        UDP(sport=5000, dport=8086)/ \
                        TelemetryReport(ingressTimestamp= 1524138290)/ \
                        Ether()/ \
                        IP(src="10.0.0.1", dst="10.0.0.2")/ \
                        UDP(sport=5000, dport=5000)/ \
                        INT(insCnt=3, totalHopCnt=n_sw, ins=(1<<7|1<<5|1<<2)<<8,
                            INTMetadata= INTdata,
                            originDSCP=14))


        iface = "vtap0"

        for p0 in p:
            sendp(p0, iface=iface)
            time.sleep(1)


        # wrpcap("pcaps/t7.pcap", p)
        # print("Done: t7.pcap")


    # test v1.0 spec impelementation
    if args.test_v10_spec:
        p0 = Ether()/ \
            IP(tos=0x17<<2)/ \
            UDP(sport=5000, dport=8086)/ \
            TelemetryReport_v10(ingressTimestamp= 1524138290)/ \
            Ether()/ \
            IP(src="10.0.0.1", dst="10.0.0.2")/ \
            UDP(sport=5000, dport=5000)/ \
            INT_v10(length=27, hopMLen=8, remainHopCnt=3, ins=(1<<7|1<<6|1<<5|1<<4|1<<3|1<<2|1<<1|1)<<8,
                INTMetadata= [4, 2<<16| 3, 400, 5<<16| 600, 700, 1524234560, 5<<16| 1000, 1,
                5, 2<<16| 3, 4, 5<<16| 6, 7, 1524234560, 5<<16| 10, 1,
                6, 2<<16| 3, 4, 5<<16| 6, 7, 1524234560, 5<<16| 10, 1]
            )

        p1 = Ether()/ \
            IP(tos=0x17<<2)/ \
            UDP(sport=5000, dport=8086)/ \
            TelemetryReport_v10(ingressTimestamp= 1524138290)/ \
            Ether()/ \
            IP(src="10.0.0.1", dst="10.0.0.2")/ \
            UDP(sport=5000, dport=5000)/ \
            INT_v10(length=27, hopMLen=8, remainHopCnt=3, ins=(1<<7|1<<6|1<<5|1<<4|1<<3|1<<2|1<<1|1)<<8,
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
