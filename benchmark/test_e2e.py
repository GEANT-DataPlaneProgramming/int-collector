from __future__ import print_function
import pytest
import subprocess
import time
import os
import signal
import sys
from scapy.all import *
from influxdb import InfluxDBClient
from int_package_generator import *

sys.path.insert(0, './benchmark')
from INTReport import TelemetryReport_v10, INT_v10

inif = "int_veth_0"
outif = "int_veth_1"
subp = None
test_db = "int_test_database"
idbclient = InfluxDBClient(host="localhost", database=test_db)
python_ver = "python3"

def start_collector(cmd):
    global subp
    try:
        subp = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
            universal_newlines=True)
    except Exception as e:
        print(e)
        return None

    # p = subp.stdout.readline()
    assert (subp.poll() == None), "Error loading XDP program"

    time.sleep(3)

@pytest.fixture
def setup_veth():
    os.system("ip link add %s type veth peer name %s" % (inif, outif))
    os.system("ip link set dev %s up" % inif)
    os.system("ip link set dev %s up" % outif)
    os.system("systemctl restart influxdb")
    time.sleep(0.5)
    yield

    if (subp != None):
        subp.send_signal(signal.SIGINT)
        time.sleep(0.5)
    idbclient.drop_database(test_db)
    os.system("ip link del %s" % inif)

def end_to_end_influxdb_v10(cmd):
    start_collector(cmd)
    assert (subp != None), "Fail subprocess to load XDP program"

    int_length = 3 * 8 + 3
    packets = []
    int_metadata = INTMetadata(3)
    int_metadata.create_metadata()

    p0 = Ether()/ \
            IP(tos=0x17<<2)/ \
            UDP(sport=5000, dport=8090)/ \
            TelemetryReport_v10(swid = 1, seqNumber = 5, ingressTimestamp= 1524138290)/ \
            Ether()/ \
            IP(src="10.0.0.1", dst="10.0.0.2")/ \
            UDP(sport=5000, dport=5000)/ \
            INT_v10(length=int_length,hopMLen=8, remainHopCnt=3, ins=(1<<7|1<<6|1<<5|1<<4|1<<3|1<<2|1<<1|1)<<8,
                INTMetadata= int_metadata.int_metadata)

    int_metadata.edit_hop_latency(70)
    int_metadata.edit_queue_occups()
    int_metadata.edit_timestamps()
    int_metadata.edit_tx_utilizes(3)

    p1 = Ether()/ \
        IP(tos=0x17<<2)/ \
        UDP(sport=5000, dport=8090)/ \
        TelemetryReport_v10(swid = 1,seqNumber = 200,ingressTimestamp= 1524138290)/ \
        Ether()/ \
        IP(src="10.0.0.1", dst="10.0.0.2")/ \
        UDP(sport=5000, dport=5000)/ \
        INT_v10(length=int_length,hopMLen=8, remainHopCnt=3, ins=(1<<7|1<<6|1<<5|1<<4|1<<3|1<<2|1<<1|1)<<8,
            INTMetadata= int_metadata.int_metadata)

    for p in [p0, p1]:
        
        sendp(p0, iface=inif)
        time.sleep(1)
        
        db_flag = False
        for db in idbclient.get_list_database():
            if test_db == db['name']:
                db_flag = True   
        assert db_flag == True
        time.sleep(1)

        measurements_flag = False
        for measurement in idbclient.get_list_measurements():
            if measurement['name'] == 'int_telemetry':
                measurements_flag = True
        assert measurements_flag == True

        r = idbclient.query('select * from int_telemetry', epoch='ns')
        e2e_report = list(r.get_points(measurement = 'int_telemetry', 
                                     tags={"seq": 5}))[0]
        assert (e2e_report['origts']==700 and e2e_report['dstts']==700)

        hop_index_0 = list(r.get_points(measurement = 'int_telemetry',
                                        tags = {'hop_index': '0'}))[0]
        assert hop_index_0['hop_delay']==20

        hop_index_1 = list(r.get_points(measurement = 'int_telemetry',
                                        tags = {'hop_index': '1'}))[0]
        assert hop_index_1['hop_delay']==20

        hop_index_2 = list(r.get_points(measurement = 'int_telemetry',
                                        tags = {'hop_index': '2'}))[0]
        assert hop_index_2['hop_delay']==20

        sendp(p1, iface=inif)
        time.sleep(1)
        r = idbclient.query('select * from int_telemetry', epoch='ns')
        e2e_report = list(r.get_points(measurement = 'int_telemetry', 
                                       tags = {'seq': 200}))[0]
        assert (e2e_report['origts']==700 and e2e_report['dstts']==820)

        hop_index_0 = list(r.get_points(measurement = 'int_telemetry',
                                        tags = {'hop_index': '0'}))[0]
        assert hop_index_0['hop_delay']==20

        hop_index_1 = list(r.get_points(measurement = 'int_telemetry',
                                        tags = {'hop_index': '1'}))[0]
        assert hop_index_1['hop_delay']==20

        hop_index_2 = list(r.get_points(measurement = 'int_telemetry',
                                        tags = {'hop_index': '2'}))[0]
        assert hop_index_2['hop_delay']==20


        # print(e2e_report,'\n')
        # print(hop_index_0,'\n')
        # print(hop_index_1,'\n')
        # print(hop_index_2,'\n')
        # assert False

def test_e2e_indb_threshold_v10(setup_veth):
    cmd = ['python3', "collector/InDBClient.py", outif, '-D', test_db]
    end_to_end_influxdb_v10(cmd)
