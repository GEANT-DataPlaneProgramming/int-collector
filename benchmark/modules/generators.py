import logging
from scapy.base_classes import Gen
from scapy.layers.l2 import Ether
from scapy.layers.inet import IP, UDP
from scapy.sendrecv import sendp, sendpfast
from datetime import datetime
from time import sleep

from modules.headers import TelemetryReport_v10, INT_v10
from modules.int_metadata import INTMetadata

class Generator():

    list_switch_id = [1,2,3,4,5,6]

    def __init__(self, hops, log_level = 20):
        self.hops = hops
        self.int_header_size = hops * 8 + 3
        self.packets = []

        self.generator_logger = logging.getLogger("Generator")
        self.generator_logger.setLevel(log_level)

class LinearGenerator(Generator):

    def __init__(self, hops, log_level = 20, packets_gen = 1000, packets_sent = 20000):
        super().__init__(hops, log_level)
        self.number_of_packets_gen = packets_gen
        self.number_of_packets_sent = packets_sent

        self.generator_logger.info(f"This generator will generate {self.number_of_packets_gen} packets and it will send {self.number_of_packets_sent} packets.")
        self.create_packets()


    def create_packets(self):

        start_time = datetime.now()
        int_metadata = INTMetadata(self.hops)
        int_metadata.create_metadata()

        for counter in range(self.number_of_packets_gen):

            p = Ether()/ \
                IP(tos=0x17<<2)/ \
                UDP(sport=5000, dport=8090)/ \
                TelemetryReport_v10(ingressTimestamp= 1524138290)/ \
                Ether()/ \
                IP(src="10.0.0.1", dst="10.0.0.2")/ \
                UDP(sport=5000, dport=5000)/ \
                INT_v10(length=self.int_header_size, hopMLen=8, remainHopCnt=3, ins=(1<<7|1<<6|1<<5|1<<4|1<<3|1<<2|1<<1|1)<<8,
                    INTMetadata = int_metadata.all_int_metadata)
            
            if counter in [0,self.number_of_packets_gen-1]:
                self.generator_logger.info(f'{counter}. {int_metadata}')
            else: 
                self.generator_logger.debug(f'{counter}. {int_metadata}')

            self.packets.append(bytes(p))
            int_metadata.edit_hop_latency(5)
        
        end_time = datetime.now() - start_time
        self.generator_logger.info(f'{len(self.packets)} packages were generated in {end_time}.')
        
        while 1:
            for i in range(len(self.packets)):
                if len(self.packets) < self.number_of_packets_sent:
                    self.packets.append(self.packets[i])
                else:
                    self.generator_logger.info(f'The rest of the packages were duplicated.')
                    self.generator_logger.info(f'Totalnumber of packages ready for transsmision is {len(self.packets)}\n')
                    return self.packets
    
    def send_packets(self, mode, iface, verbose):
        self.generator_logger.info(f'Start of sending packages through the {iface} interface')
        counter = 0
        repetitions = 0
        try:
            if mode == 1:
                while repetitions < 1:
                    start = datetime.now()
                    sendp(self.packets, iface=iface, verbose = verbose)#, inter = 1/args.number)
                    self.generator_logger.info(f'{len(self.packets)} packets were sent within {datetime.now()-start}s')
                    counter += len(self.packets)
                    repetitions += 1
                    self.generator_logger.info(f'{counter} packets were sent.\n')
            elif mode == 2:
                 while repetitions < 1:
                    start = datetime.now()
                    sendpfast(self.packets, iface=iface, pps=self.number_of_packets_sent)
                    self.generator_logger.info(f'{len(self.packets)} packets were sent within {datetime.now()-start}s')
                    counter += len(self.packets)
                    repetitions += 1
                    self.generator_logger.info(f'{counter} packets were sent.\n')

        except KeyboardInterrupt:
            pass

    
class ConstantGenerator(Generator):

    def send_two_packets(self, iface, verbose):

        self.generator_logger.info('Start of sending two packets.')

        int_metadata = INTMetadata(self.hops)
        int_metadata.create_metadata()

        for counter in range(2):

            p = Ether()/ \
                IP(tos=0x17<<2)/ \
                UDP(sport=5000, dport=8090)/ \
                TelemetryReport_v10(ingressTimestamp= 1524138290)/ \
                Ether()/ \
                IP(src="10.0.0.1", dst="10.0.0.2")/ \
                UDP(sport=5000, dport=5000)/ \
                INT_v10(length=self.int_header_size, hopMLen=8, remainHopCnt=3, ins=(1<<7|1<<6|1<<5|1<<4|1<<3|1<<2|1<<1|1)<<8,
                    INTMetadata = int_metadata.all_int_metadata)

            self.generator_logger.info(f'{counter}. {int_metadata}')

            self.packets.append(bytes(p))
            int_metadata.edit_hop_latency(60)
        
        repetitions = 0

        while repetitions < 20:
            sendp(self.packets[0], iface=iface, verbose = verbose)
            sleep(1)
            sendp(self.packets[1], iface=iface, verbose = verbose)
            sleep(1)