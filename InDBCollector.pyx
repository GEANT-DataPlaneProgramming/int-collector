from __future__ import print_function
import threading
from bcc import BPF
from influxdb import InfluxDBClient
from ipaddress import IPv4Address
from libc.stdint cimport uintptr_t
import argparse
import time
import socket
import struct
import binascii
import pprint
import logging
from copy import copy
import io
import json
from datetime import datetime

# change array len of sw_ids.. to .. tx_utilizes to match with max_int_hop in the collector
cdef enum: __MAX_INT_HOP = 6
_MAX_INT_HOP = __MAX_INT_HOP
cdef struct Event:
    unsigned int   src_ip
    unsigned int   dst_ip
    unsigned short src_port
    unsigned short dst_port
    unsigned short ip_proto
    unsigned char  num_INT_hop
    unsigned int   sw_ids[__MAX_INT_HOP]
    unsigned short in_port_ids[__MAX_INT_HOP]
    unsigned short e_port_ids[__MAX_INT_HOP]
    unsigned int   hop_latencies[__MAX_INT_HOP]
    unsigned short queue_ids[__MAX_INT_HOP]
    unsigned short queue_occups[__MAX_INT_HOP]
    unsigned int   ingr_times[__MAX_INT_HOP]
    unsigned int   egr_times[__MAX_INT_HOP]
    unsigned int   lv2_in_e_port_ids[__MAX_INT_HOP]
    unsigned int   tx_utilizes[__MAX_INT_HOP]
    unsigned int   flow_latency
    unsigned int   flow_sink_time
    unsigned char  is_n_flow
    unsigned char  is_flow
    unsigned char  is_hop_latency
    unsigned char  is_queue_occup
    unsigned char  is_queue_congest
    unsigned char  is_tx_utilize
    unsigned int   seq_num
    unsigned int   sw_id

logging.basicConfig(level = logging.INFO)
logger = logging.getLogger(__name__)
logger_raports = logging.getLogger('LogRaport')

class InDBCollector(object):
    """docstring for InDBCollector"""

    def __init__(self, max_int_hop=6, int_dst_port=54321, int_time=False,
                    host="localhost", database="int_telemetry_db",event_mode="THRESHOLD", 
                    log_level=20, log_raports_lvl = 20):
        super(InDBCollector, self).__init__()

        self.MAX_INT_HOP = _MAX_INT_HOP
        self.SERVER_MODE = "INFLUXDB"
        self.INT_DST_PORT = int_dst_port
        self.EVENT_MODE = event_mode
        self.int_time = int_time

        self.reports = []
        self.last_dstts = {} # save last `dstts` per each monitored flow
        self.last_reordering = {}  # save last `reordering` per each monitored flow
        self.last_hop_ingress_timestamp = {} #save last ingress timestamp per each hop in each monitored flow
        self.last_send = time.time() # last time when reports were send to influx

        self.start = datetime.now()
        self.ifaces = set()

        #load eBPF program
        self.bpf_collector = BPF(src_file="BPFCollector.c", debug=0,
            cflags=["-w",
                    "-D_MAX_INT_HOP=%s" % self.MAX_INT_HOP,
                    "-D_INT_DST_PORT=%s" % self.INT_DST_PORT,
                    "-D_EVENT_MODE=%s" % self.EVENT_MODE,
                    "-D_SERVER_MODE=%s" % self.SERVER_MODE])
        self.fn_collector = self.bpf_collector.load_func("collector", BPF.XDP)

        # get all the info table
        self.tb_flow  = self.bpf_collector.get_table("tb_flow")
        self.tb_egr   = self.bpf_collector.get_table("tb_egr")
        self.tb_queue = self.bpf_collector.get_table("tb_queue")

        self.flow_paths = {}

        self.lock = threading.Lock()
        self.event_data = []

        self.client = InfluxDBClient(host=host, database=database)
        self.log_level = log_level
        self.log_raports_lvl = log_raports_lvl
        self.number_of_event = 0 

        logger.setLevel(self.log_level)
        logger_raports.setLevel(self.log_raports_lvl)

    def prepare_e2e_report(self, flow_id, ingr_times, seq_num, flow_key, last_hop_index):        
        
        try:
            origin_timestamp = ingr_times[0]
            destination_timestamp = ingr_times[last_hop_index]
        except Exception as e:
            origin_timestamp, destination_timestamp = 0, 0
        
        json_report = {
            "measurement": "int_telemetry_new_collector",
            "tags": flow_id,
            'time': int(time.time()*1e9), # use local time because bmv2 clock is a little slower making time drift 
            "fields": {
                "origts": 1.0*origin_timestamp,
                "dstts": 1.0*destination_timestamp,
                "seq": 1.0*seq_num,
                "delay": 1.0*(destination_timestamp-origin_timestamp),
                }
        }
        
        # add sink_jitter only if can be calculated (not first packet in the flow)  
        if flow_key in self.last_dstts:
            json_report["fields"]["sink_jitter"] = 1.0*destination_timestamp - self.last_dstts[flow_key]
        
        # # add reordering only if can be calculated (not first packet in the flow)  
        if flow_key in self.last_reordering:
            json_report["fields"]["reordering"] = 1.0*seq_num - self.last_reordering[flow_key] - 1
                        
        # # save dstts for purpose of sink_jitter calculation
        self.last_dstts[flow_key] = destination_timestamp
        
        # # save dstts for purpose of sink_jitter calculation
        self.last_reordering[flow_key] = seq_num

        logger_raports.debug(f"E2E report\n {json.dumps(json_report, indent = 4)}") 
        return json_report

    def prepare_hop_report(self, flow_id, index, flow_key, hop_latencies, ingr_times):
        # each INT hop metadata are sent as independed json message to Influx
        tags = copy(flow_id)
        tags['hop_index'] = index
        json_report = {
            "measurement": "int_telemetry_new_collector",
            "tags": tags,
            'time': int(time.time()*1e9), # use local time because bmv2 clock is a little slower making time drift 
            "fields": {}
        }
        
        # combine flow id with hop index 
        flow_hop_key = (*flow_key, index)
        
        # # add sink_jitter only if can be calculated (not first packet in the flow)  
        if flow_hop_key in self.last_hop_ingress_timestamp:
            json_report["fields"]["hop_jitter"] =  ingr_times[index] - self.last_hop_ingress_timestamp[flow_hop_key]
            
        if hop_latencies[index]:
            json_report["fields"]["hop_delay"] = hop_latencies[index]
            
        if ingr_times[index] and index > 0:
            json_report["fields"]["link_delay"] = ingr_times[index] - self.last_hop_delay
            self.last_hop_delay = ingr_times[index]
            
        if ingr_times[index]:
            self.last_hop_ingress_timestamp[flow_hop_key] = ingr_times[index]
        
        logger_raports.debug(f"HOP - report {index}\n {json.dumps(json_report, indent = 4)}") 
        return json_report

    def prepare_reports(self, flow_id, hop_latencies, seq_num, ingr_times, egr_times):
        flow_key = "%(srcip)s, %(dstip)s, %(srcp)s, %(dstp)s, %(protocol)s" % flow_id 
        reports = []

        for index in range(_MAX_INT_HOP):
            if ingr_times[index] == 0:
                last_hop_index = index - 1
                last_ingr_time = ingr_times[last_hop_index]
                break
        else:
            last_hop_index = 5
            last_ingr_time = ingr_times[last_hop_index]

        reports.append(self.prepare_e2e_report(flow_id, ingr_times, seq_num, flow_key, last_hop_index))

        self.last_hop_delay = last_ingr_time
        for index in range(last_hop_index+1):
            reports.append(self.prepare_hop_report(flow_id, index, flow_key, hop_latencies, ingr_times))
        
        logger_raports.debug(f'\n{"*"*50}')

        json_body = []
        return reports

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

    def int_2_ip4_str(self, ipint):
        cdef unsigned char i
        return '.'.join([str(ipint >> (i << 3) & 0xFF) for i in [3, 2, 1, 0]])

    def poll_events(self):
        self.bpf_collector.kprobe_poll()

    def open_events(self):
        def _process_event(ctx, data, size):

            cdef uintptr_t _event =  <uintptr_t> data
            cdef Event *event = <Event*> _event
            # push data

            event_flag: bool = False
            event_data = []
            
            flow_id = {
                'srcip': str(IPv4Address(event.src_ip)),
                'dstip': str(IPv4Address(event.dst_ip)), 
                'srcp': event.src_port,
                'dstp': event.dst_port,
                'protocol': event.ip_proto,       
            }

            if event.is_n_flow or event.is_flow:
                path_str = ":".join(str(event.sw_ids[i]) for i in reversed(range(0, event.num_INT_hop)))
                event_data.append(self.prepare_reports(flow_id, event.hop_latencies, event.seq_num, event.ingr_times, event.egr_times))
                event_flag = True

            if event.is_hop_latency:
                for i in range(0, event.num_INT_hop):
                    if ((event.is_hop_latency >> i) & 0x01):
                        event_data.append(self.prepare_reports(flow_id, event.hop_latencies, event.seq_num, event.ingr_times, event.egr_times))
                        event_flag = True

            if event.is_tx_utilize:
                for i in range(0, event.num_INT_hop):
                    if ((event.is_tx_utilize >> i) & 0x01):
                        event_data.append(self.prepare_reports(flow_id, event.hop_latencies, event.seq_num, event.ingr_times, event.egr_times))
                        event_flag = True

            if event.is_queue_occup:
                for i in range(0, event.num_INT_hop):
                    if ((event.is_queue_occup >> i) & 0x01):
                        event_data.append(self.prepare_reports(flow_id, event.hop_latencies, event.seq_num, event.ingr_times, event.egr_times))
                        event_flag = True

            self.lock.acquire()
            self.event_data.extend(event_data)
            self.lock.release()

            # Print event data for debug
            self.number_of_event += 1
            logger.debug((f"\n{'*'*15}{self.number_of_event} Event {'*'*15}\n"
                f"src_ip: {str(IPv4Address(event.src_ip))}\n"
                f"dst_ip: {str(IPv4Address(event.dst_ip))}\n"
                f"src_port: {event.src_port}\n"
                f"dst_port: {event.dst_port}\n"
                f"ip_proto: {event.ip_proto}\n"
                f"num_INT_hop: {event.num_INT_hop}\n"
                f"sw_ids: {event.sw_ids}\n"
                f"in_port_ids: {event.in_port_ids}\n"
                f"e_port_ids: {event.e_port_ids}\n"
                f"hop_latencies: {event.hop_latencies}\n"
                f"queue_ids: {event.queue_ids}\n"
                f"queue_occups: {event.queue_occups}\n"
                f"ingr_times: {event.ingr_times}\n"
                f"egr_times: {event.egr_times}\n"
                f"lv2_in_e_port_ids: {event.lv2_in_e_port_ids}\n"
                f"tx_utilizes: {event.tx_utilizes}\n"
                f"flow_latency: {event.flow_latency}\n"
                f"flow_sink_time: {event.flow_sink_time}\n"
                f"is_n_flow: {event.is_n_flow}\n"
                f"is_flow: {event.is_flow}\n"
                f"is_hop_latency: {event.is_hop_latency}\n"
                f"is_queue_occup: {event.is_queue_occup}\n"
                f"is_queue_congest: {event.is_queue_congest}\n"
                f"is_tx_utilize: {event.is_tx_utilize}\n"
                f"seq_num: {event.seq_num}\n"
                f"sw_id: {event.sw_id}\n"))

        self.bpf_collector["events"].open_perf_buffer(_process_event, page_cnt=512)


    def collect_data(self):

        data = []

        for (flow_id, flow_info) in self.tb_flow.iteritems():
            path_str = ":".join(str(flow_info.sw_ids[i]) for i in reversed(range(0, flow_info.num_INT_hop)))

            flow_id_str = "%s:%d->%s:%d\\,proto\\=%d" % (self.int_2_ip4_str(flow_id.src_ip), \
                                                    flow_id.src_port, \
                                                    self.int_2_ip4_str(flow_id.dst_ip), \
                                                    flow_id.dst_port, \
                                                    flow_id.ip_proto)

            data.append("flow_stat\\,%s flow_latency=%d,path=\"%s\"%s" % (
                    flow_id_str, flow_info.flow_latency, path_str,
                    ' %d' % flow_info.flow_sink_time if self.int_time else ''))

            if flow_info.is_hop_latency:
                for i in range(0, flow_info.num_INT_hop):
                    data.append("flow_hop_latency\\,%s\\,sw_id\\=%d value=%d%s" % (
                            flow_id_str, flow_info.sw_ids[i], flow_info.hop_latencies[i],
                            ' %d' % flow_info.egr_times[i] if self.int_time else ''))

        for (egr_id, egr_info) in self.tb_egr.items():
            data.append("port_tx_utilize\\,sw_id\\=%d\\,port_id\\=%d value=%d%s" % (
                    egr_id.sw_id, egr_id.p_id, egr_info.tx_utilize,
                    ' %d' % egr_info.egr_time if self.int_time else ''))

        for (queue_id, queue_info) in self.tb_queue.items():
            data.append("queue_occupancy\\,sw_id\\=%d\\,queue_id\\=%d value=%d%s" % (
                    queue_id.sw_id, queue_id.q_id, queue_info.occup,
                    ' %d' % queue_info.q_time if self.int_time else ''))

            # data.append("queue_congestion\\,sw_id\\=%d\\,queue_id\\=%d value=%d%s" % (
            #         queue_id.sw_id, queue_id.q_id, queue_info.congest,
            #         ' %d' % queue_info.q_time if self.int_time else ''))

        return data
