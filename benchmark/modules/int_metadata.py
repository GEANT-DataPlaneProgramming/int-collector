from curses import meta
import logging
from sre_parse import HEXDIGITS
from struct import pack

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
        self.__hops = hops
        self.switch_id = self.set_4_bytes(switch_id)
        self.mask = self.check_mask(ins_mask)
        self.metadata = []

    def __str__(self) -> str:
        """Beuty str of metadata"""
        metadata = f"{'*'*15} INT METADATA {'*'*15} \n"

        for hop in range(self.__hops):
            shift = hop * 8 + 8 
            metadata += f"\t\tHOP {hop}: {self.metadata[hop*8:shift]}"
        
        return metadata

    def initialize_metadata(self, ins_mask):
    
        for hop in range(0, self.__hops):
            pass

    @staticmethod
    def set_4_bytes(value):
        return pack('!i', value)
    
    @staticmethod
    def set_8_bytes(value):
        return pack('!l', value)


    def check_mask(self,ins_mask):
        """
        Checking instruction bitmask. 
        Return dictionary: key=name of field: value=[mask bit, size of field in bits]
        """
        metadata_fields = {15:['switch_id',32], 14:['ing_egr_port_l1',32], 13:['hop_latency',32], 12:['queue_id_occup',32],
        11:['ing_timestamp',64],10:['egr_timestamp',64],11:['ing_egr_port_l2',32], 10:['tx_utilization',32]}
        mask_bits = {}

        for shift in metadata_fields.keys():
            if ins_mask >> shift & 0b1 == 1:
                mask_bits[metadata_fields[shift]] = 1

        return mask_bits