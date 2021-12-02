import logging

logging.basicConfig(level=logging.DEBUG)
logger = logging.getLogger(__name__)

"""
    INTMetadata = [switch_id, ingress_port_id, egress_port_id, hop_latency, queue_id, queue_occups,
                ingress_timestamp, egress_timestamp, lv2_in_e_port, tx_utilizes ]
"""


class INTMetadata:
    def __init__(
        self,
        hops,
        switch_id=1,
        ingress_port=1,
        egress_port=2,
        hop_latency=10,
        queue_id=5,
        queue_occups=600,
        ingress_timestamp=700,
        egress_timestamp=15242,
        lv2_in_e_port=5 << 15 | 1000,
        tx_utilizes=1,
    ):

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
            shift = hop * 8 + 8
            metadata += f"\t\tHOP {hop}: {self.all_int_metadata[hop*8:shift]}\n"

        return metadata

    @staticmethod
    def make_one_filed(field1, field2):
        return field1 << 16 | field2

    def create_metadata(self):

        self.__queue_id_occups = self.make_one_filed(self.queue_id, self.queue_occups)
        self.__ing_egr_port_id = self.make_one_filed(
            self.ingress_port, self.egress_port
        )

        self.all_int_metadata = [
            self.switch_id,
            self.__ing_egr_port_id,
            self.hop_latency,
            self.__queue_id_occups,
            self.ingress_timestamp,
            self.egress_timestamp,
            self.lv2_in_e_port,
            self.tx_utilizes,
        ] * self.__hops
        self.add_value_to_field_per_hop(5, 0)
        self.add_value_to_field_per_hop(5, 2)
        # self.add_value_to_field_per_hop(10, )
        self.add_value_to_field_per_hop(7, 5)
        return self.all_int_metadata

    def edit_hop_latency(self, value=60):

        for hop in range(0, self.__hops):
            self.all_int_metadata[2 + hop * 8] += value * (hop + 1)

    def check_field(self, field_name):
        if hasattr(self, field_name):
            logger.debug(f'Field {field_name} exist.')
        else:
            logger.exception(f"'{field_name}' field does not exist.")

    def add_value_to_field_per_hop(self, value, position):
        for hop in range(0, self.__hops):
            self.all_int_metadata[position + hop * 8] += (value * (hop + 1))


    @staticmethod
    def get_position_of_field(field_name):
        fields_positions = {
            "switch_id": 0,
            "ingress_port": 1,
            "egress_port": 1,
            "hop_latency": 2,
            "queue_id": 3,
            "queue_occups": 3,
            "ingress_timestamp": 4,
            "egress_timestamp": 5,
            "lv2_in_e_port": 6,
            "tx_utilizes": 7,
        }
        return fields_positions[field_name]

    def edit_ports_id(self, ing_port=None, egr_port=None):

        if ing_port is None:
            ing_port = self.ingress_port

        if egr_port is None:
            egr_port = self.egress_port

        return self.make_one_filed(ing_port, egr_port)

    def edit_queue(self, queue_occups=None, queue_id=None):

        if queue_occups is None:
            queue_occups = self.queue_occups

        if queue_id is None:
            queue_id = self.queue_id

        return self.make_one_filed(queue_id, queue_occups)
    

    def increment_per_hop(self, field_name, value):

        self.check_field(field_name)
        position_of_field = self.get_position_of_field(field_name)

        if position_of_field is not (1, 3):
            for hop in range(0, self.__hops):
                self.all_int_metadata[position_of_field + hop*8] += value
        elif field_name == "ingress_port":
            for hop in range(0, self.__hops):
                self.all_int_metadata[
                    position_of_field + hop * 8
                ] += self.make_one_filed(field1= value)
        elif field_name == "egress_port":
            for hop in range(0, self.__hops):
                self.all_int_metadata[
                    position_of_field + hop * 8
                ] += self.make_one_filed(field2= value)
        elif field_name == "queue_id":
            for hop in range(0, self.__hops):
                self.all_int_metadata[
                    position_of_field + hop * 8
                ] += self.make_one_filed(field1=value)
        else:
            for hop in range(0, self.__hops):
                self.all_int_metadata[
                    position_of_field + hop * 8
                ] += self.make_one_filed(field1=value)

    def increment_per_packet(self, field_name, value):

        self.check_field(field_name)

    def increment_per_hop_and_packet(self, field_name, hop_value, packet_value):

        self.check_field(field_name)
