from curses import meta
import logging
from struct import pack
import numpy
import sys

from importlib_metadata import metadata

logging.basicConfig(level=logging.DEBUG)
logger = logging.getLogger(__name__)

class INTMetadata():
    """
    Representes intmetadata
    INTMetadata = [switch_id (32bits), ingress_port_id (16), egress_port_id(16), hop_latency(32), queue_id(8), queue_occups(24),
                ingress_timestamp(64), egress_timestamp(64), lv2_in_e_port(32), tx_utilizes(32) ]
    """
    def __init__(self, ins_mask, hops: int, *switch_id) -> None:
        """Initilizes metadata according to the provided instruction mask and hops"""
        # print(hops)
        # print(len(switch_id))
        if hops != len(switch_id):
            logger.error("Number of switch id must be the same as the hops!")
            sys.exit()

        self.__hops = hops
        self.switch_ids = switch_id
        self.metadata_fields = {15:['switch_id',32], 14:['ing_egr_port_l1',32], 
                                13:['hop_latency',32], 12:['queue_id_occup',32],
                                11:['ing_timestamp',64],10:['egr_timestamp',64],
                                9:['ing_egr_port_l2',32], 8:['tx_utilization',32]}
        self.mask = self.check_mask(ins_mask)
        self.metadata = []
        self.initialize_metadata(ins_mask)
        print(self.metadata)

    def __str__(self) -> str:
        """Beuty str of metadata"""
        metadata = f"{'*'*15} INT METADATA {'*'*15} \n"

        for hop in range(self.__hops):
            shift = hop * 8 + 8 
            metadata += f"\t\tHOP {hop}: {self.metadata[hop*8:shift]}"
        
        return metadata

    def initialize_metadata(self, ins_mask):
        
        for hop in range(0, self.__hops):
            for field_name in self.mask.keys():
                if field_name == 'switch_id':
                    self.metadata.append(self.set_switch_id(hop))
                elif field_name == 'ing_egr_port_l1':
                    self.metadata.append(self.set_4_bytes(128))
                elif field_name == 'ing_timestamp':
                    self.metadata.append(self.set_8_bytes(20))
                elif field_name == 'egr_timestamp':
                    self.metadata.append(self.set_8_bytes(40))

    def set_switch_id(self, hop_number):
        return self.set_4_bytes(self.switch_ids[hop_number])

    @staticmethod
    def set_4_bytes(value):
        return numpy.int32(value)
        # return pack('!i', value)
    
    @staticmethod
    def set_8_bytes(value):
        return numpy.int64(value)


    def check_mask(self,ins_mask):
        """
        Checking instruction bitmask. 
        Return dictionary: key=shift in bits: value=[field name, size of field in bits]
        """
        mask_bits = {}
        # print("Maska:",bin(ins_mask))
        for shift in self.metadata_fields.keys():
            # print("PRzesuniecie",shift)
            # print("Maska po przesunieciu:",bin(ins_mask>>shift & 0b1))
            if (ins_mask >> shift) & 0b1 == 1:
                # print(ins_mask)
                # print(metadata_fields[shift])
                mask_bits[self.metadata_fields[shift][0]] = 1

        return mask_bits
    
