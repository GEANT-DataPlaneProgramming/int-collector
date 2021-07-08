from __future__ import print_function
from bcc import BPF
from prometheus_client import Gauge
import ctypes as ct

class PTCollector(object):
    """docstring for PTCollector"""

    def __init__(self, max_int_hop=6, int_dst_port=54321, debug_mode=0):
        super(PTCollector, self).__init__()

        self.MAX_INT_HOP = max_int_hop
        self.SERVER_MODE = "PROMETHEUS"
        self.INT_DST_PORT = int_dst_port

        self.ifaces = set()

        #load eBPF program
        self.bpf_collector = BPF(src_file="BPFCollector.c", debug=0,
            cflags=["-w",
                    "-D_MAX_INT_HOP=%s" % self.MAX_INT_HOP,
                    "-D_INT_DST_PORT=%s" % self.INT_DST_PORT,
                    "-D_SERVER_MODE=%s" % self.SERVER_MODE,])
        self.fn_collector = self.bpf_collector.load_func("collector", BPF.XDP)

        # get all the info table
        self.tb_flow  = self.bpf_collector.get_table("tb_flow")
        self.tb_egr   = self.bpf_collector.get_table("tb_egr")
        self.tb_queue = self.bpf_collector.get_table("tb_queue")

        self.flow_paths = {}

        self.debug_mode = debug_mode

        # gauge
        # self.g_flow_pkt_cnt = Gauge('flow_pkt_cnt', 'flow packet count',
        #     ['src_ip', 'src_port', 'dst_ip', 'dst_port', 'ip_proto'])
        # self.g_flow_byte_cnt = Gauge('flow_byte_cnt', 'flow byte count',
        #     ['src_ip', 'src_port', 'dst_ip', 'dst_port', 'ip_proto'])
        self.g_flow_latency = Gauge('flow_latency', 'total flow latency',
            ['src_ip', 'src_port', 'dst_ip', 'dst_port', 'ip_proto'])
        self.g_flow_hop_latency = Gauge('flow_hop_latency', 'per-hop latency of flow',
            ['src_ip', 'src_port', 'dst_ip', 'dst_port', 'ip_proto', 'sw_id'])
        self.g_tx_utilize = Gauge('tx_utilize', 'tx link utilization',
            ['sw_id', 'p_id'])
        self.g_queue_occup = Gauge('queue_occup', 'queue occupancy',
            ['sw_id', 'q_id'])
        # self.g_queue_congest = Gauge('queue_congest', 'queue congestion',
        #     ['sw_id', 'q_id'])

    def attach_iface(self, iface):
        if iface in self.ifaces:
            print("already attached to ", iface)
            return
        self.bpf_collector.attach_xdp(iface, self.fn_collector, 0)
        self.ifaces.add(iface)

    def detach_iface(self, iface):
        if iface not in self.ifaces:
            print("no program attached to ", iface)
            return
        self.bpf_collector.remove_xdp(iface, 0)
        self.ifaces.remove(iface)

    def detach_all_iface(self):
        for iface in self.ifaces:
            self.bpf_collector.remove_xdp(iface, 0)
        self.ifaces = set()


    # invalid key raises error. However, invalid key is prevented by prometheus

    def get_flow_pkt_cnt(self, src_ip, dst_ip, src_port, dst_port, ip_proto):
        def _get_flow_pkt_cnt():
            key = self.tb_flow.Key(src_ip, dst_ip, src_port, dst_port, ip_proto)
            val = self.tb_flow[key]
            return val.pkt_cnt
        return _get_flow_pkt_cnt

    def get_flow_byte_cnt(self, src_ip, dst_ip, src_port, dst_port, ip_proto):
        def _get_flow_byte_cnt():
            key = self.tb_flow.Key(src_ip, dst_ip, src_port, dst_port, ip_proto)
            val = self.tb_flow[key]
            return val.byte_cnt
        return _get_flow_byte_cnt

    def get_flow_latency(self, src_ip, dst_ip, src_port, dst_port, ip_proto):
        def _get_flow_latency():
            key = self.tb_flow.Key(src_ip, dst_ip, src_port, dst_port, ip_proto)
            val = self.tb_flow[key]
            return val.flow_latency
        return _get_flow_latency

    def get_flow_hop_latency(self, src_ip, dst_ip, src_port, dst_port, ip_proto, sw_id):
        def _get_flow_hop_latency():
            key = self.tb_flow.Key(src_ip, dst_ip, src_port, dst_port, ip_proto)
            val = self.tb_flow[key]
            for i in range(0, self.MAX_INT_HOP):
                if sw_id == val.sw_ids[i]:
                    return val.hop_latencies[i]
            return 0
        return _get_flow_hop_latency

    def get_tx_utilize(self, sw_id, p_id):
        def _get_tx_utilize():
            key = self.tb_egr.Key(sw_id, p_id)
            val = self.tb_egr[key]
            return val.tx_utilize
        return _get_tx_utilize

    def get_queue_occup(self, sw_id, q_id):
        def _get_queue_occup():
            key = self.tb_queue.Key(sw_id, q_id)
            val = self.tb_queue[key]
            return val.occup
        return _get_queue_occup

    # def get_queue_congest(self, sw_id, q_id):
    #     def _get_queue_congest():
    #         key = self.tb_queue.Key(sw_id, q_id)
    #         val = self.tb_queue[key]
    #         return val.congest
    #     return _get_queue_congest


    def open_events(self):
        def _process_event(ctx, data, size):
            class Event(ct.Structure):
                _fields_ =  [("src_ip", ct.c_uint32),
                             ("dst_ip", ct.c_uint32),
                             ("src_port", ct.c_ushort),
                             ("dst_port", ct.c_ushort),
                             ("ip_proto", ct.c_ushort),

                             # ("pkt_cnt", ct.c_uint64),
                             # ("byte_cnt", ct.c_uint64),

                             ("num_INT_hop", ct.c_ubyte),

                             ("sw_ids", ct.c_uint32 * self.MAX_INT_HOP),
                             ("in_port_ids", ct.c_uint16 * self.MAX_INT_HOP),
                             ("e_port_ids", ct.c_uint16 * self.MAX_INT_HOP),
                             ("hop_latencies", ct.c_uint32 * self.MAX_INT_HOP),
                             ("queue_ids", ct.c_uint16 * self.MAX_INT_HOP),
                             ("queue_occups", ct.c_uint16 * self.MAX_INT_HOP),
                             ("ingr_times", ct.c_uint32 * self.MAX_INT_HOP),
                             ("egr_times", ct.c_uint32 * self.MAX_INT_HOP),
                             ("lv2_in_e_port_ids", ct.c_uint32 * self.MAX_INT_HOP),
                             ("tx_utilizes", ct.c_uint32 * self.MAX_INT_HOP),

                             ("flow_latency", ct.c_uint32),
                             ("flow_sink_time", ct.c_uint32),

                             ("is_n_flow", ct.c_ubyte),
                             ("is_hop_latency", ct.c_ubyte),
                             ("is_queue_occup", ct.c_ubyte),
                             # ("is_queue_congest", ct.c_ubyte),
                             ("is_tx_utilize", ct.c_ubyte)

                             # ("is_path", ct.c_ubyte),
                             # ("is_hop_latency", ct.c_ubyte),
                             # ("is_queue_occup", ct.c_ubyte),
                             # ("is_queue_congest", ct.c_ubyte),
                             # ("is_tx_utilize", ct.c_ubyte)
                             ]

            event = ct.cast(data, ct.POINTER(Event)).contents

            #add new gauges
            if event.is_n_flow:
                # self.g_flow_pkt_cnt.labels(event.src_ip, event.dst_ip, \
                #                            event.src_port, event.dst_port, \
                #                            event.ip_proto) \
                #                    .set_function(self.get_flow_pkt_cnt(event.src_ip, \
                #                            event.dst_ip, event.src_port, \
                #                            event.dst_port, event.ip_proto))

                # self.g_flow_byte_cnt.labels(event.src_ip, event.dst_ip, \
                #                            event.src_port, event.dst_port, \
                #                            event.ip_proto) \
                #                    .set_function(self.get_flow_byte_cnt(event.src_ip, \
                #                            event.dst_ip, event.src_port, \
                #                            event.dst_port, event.ip_proto))

                self.g_flow_latency.labels(event.src_ip, event.dst_ip, \
                                           event.src_port, event.dst_port, \
                                           event.ip_proto) \
                                   .set_function(self.get_flow_latency(event.src_ip, \
                                           event.dst_ip, event.src_port, \
                                           event.dst_port, event.ip_proto))

            if event.is_hop_latency:
                flow_id = (event.src_ip, event.dst_ip, event.src_port, \
                            event.dst_port, event.ip_proto)

                # delete all old one
                if self.flow_paths.has_key(flow_id):
                    for sw_id in self.flow_paths[flow_id]:
                        self.g_flow_hop_latency.remove(event.src_ip, event.dst_ip, \
                                                      event.src_port, event.dst_port,\
                                                      event.ip_proto, sw_id)

                self.flow_paths[flow_id] = [event.sw_ids[i]for i in range(0, event.num_INT_hop)]

                # add all because old one is deleted
                for i in range(0, event.num_INT_hop):
                    self.g_flow_hop_latency.labels(event.src_ip, event.dst_ip, \
                                               event.src_port, event.dst_port, \
                                               event.ip_proto, event.sw_ids[i]) \
                                    .set_function(self.get_flow_hop_latency( \
                                               event.src_ip, event.dst_ip, \
                                               event.src_port, event.dst_port, \
                                               event.ip_proto, event.sw_ids[i]))


            if event.is_tx_utilize:
                for i in range(0, event.num_INT_hop):
                    if ((event.is_tx_utilize >> i) & 0x01):
                        self.g_tx_utilize.labels(event.sw_ids[i],\
                                                  event.e_port_ids[i]) \
                                        .set_function(self.get_tx_utilize( \
                                                  event.sw_ids[i], \
                                                  event.e_port_ids[i]))

            if event.is_queue_occup:
                for i in range(0, event.num_INT_hop):
                    if ((event.is_queue_occup >> i) & 0x01):
                        self.g_queue_occup.labels(event.sw_ids[i],\
                                                  event.queue_ids[i]) \
                                        .set_function(self.get_queue_occup( \
                                                  event.sw_ids[i], \
                                                  event.queue_ids[i]))

            # if event.is_queue_congest:
            #     for i in range(0, event.num_INT_hop):
            #         if ((event.is_queue_congest >> i) & 0x01):
            #             self.g_queue_congest.labels(event.sw_ids[i],\
            #                                       event.queue_ids[i]) \
            #                             .set_function(self.get_queue_congest( \
            #                                       event.sw_ids[i], \
            #                                       event.queue_ids[i]))


            # Print event data for debug
            if self.debug_mode==1:
                print("*" * 20)
                for field_name, field_type in event._fields_:
                    field_arr = getattr(event, field_name)
                    if field_name in ["sw_ids","in_port_ids","e_port_ids","hop_latencies",
                                      "queue_occups", "queue_ids","egr_times",
                                      "queue_congests","tx_utilizes"]:
                        _len = len(field_arr)
                        s = ""
                        for e in field_arr:
                            s = s+str(e)+", "
                        print(field_name+": ", s)
                    else:
                        print(field_name+": ", field_arr)

        self.bpf_collector["events"].open_perf_buffer(_process_event, page_cnt=512)

    def poll_events(self):
        self.bpf_collector.kprobe_poll()

#---------------------------------------------------------------------------
# if __name__ == "__main__":
