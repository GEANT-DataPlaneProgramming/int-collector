"""
    INTMetadata = [switch_id, ingress_port_id, egress_port_id, hop_latency, queue_id, queue_occups,
                ingress_timestamp, egress_timestamp, lv2_in_e_port, tx_utilizes ]
"""


class INTMetadata():

    def __init__(self, 
                hops, 
                switch_id = 1, 
                ingress_port = 0, 
                egress_port = 1, 
                hop_latency = 20, 
                queue_id = 5, 
                queue_occups = 600, 
                ingress_timestamp = 700, 
                egress_timestamp = 15242, 
                lv2_in_e_port = 5 << 15 | 1000,
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

        self.all_int_metadata = []

    def __str__(self) -> str:
        metadata = f"{'*'*15} INT METADATA {'*'*15} \n"

        for hop in range(self.__hops):
            shift = hop*8+8
            metadata += f"\t\tHOP {hop}: {self.all_int_metadata[hop*8:shift]}\n"            

        return metadata

    def create_metadata(self):

        self.__queue_id_occups = self.queue_id <<16 | self.queue_occups #queue_id << 16 | queue_occups
        self.__ing_egr_port_id = self.ingress_port << 16 | self.egress_port  #ingress_port << 16 | egr_port

        self.all_int_metadata = [self.switch_id, self.__ing_egr_port_id, self.hop_latency, self.__queue_id_occups,
                        self.ingress_timestamp, self.egress_timestamp, self.lv2_in_e_port, self.tx_utilizes] * self.__hops
    
    def edit_hop_latency(self, value = 60):

        for hop in range(0,self.__hops):
            self.all_int_metadata[2+hop*8] += value * (hop+1)

    