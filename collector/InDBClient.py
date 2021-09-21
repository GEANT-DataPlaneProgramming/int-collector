from __future__ import print_function

import argparse
import threading
import time
import sys
import logging

from argparse import RawTextHelpFormatter
import pyximport
from scapy.plist import QueryAnswer; pyximport.install()
import InDBCollector

logging.basicConfig(level = logging.INFO)
logger = logging.getLogger(__name__)

def parse_params():
    parser = argparse.ArgumentParser(description='InfluxBD INTCollector client.')#, formatter_class=RawTextHelpFormatter)
    
    parser.add_argument("ifaces", nargs="+",
        help="List of ifaces to receive INT reports.")

    parser.add_argument("-i", "--int_port", default=8090, type=int,
        help="Destination port of INT Telemetry reports. Default: 8090")

    parser.add_argument("-H", "--host", default="localhost",
        help="InfluxDB server address. Default: localhost")
    
    parser.add_argument("-P", "--port", default=8086,
     help="InfluxDB server port. Default: 8086")

    parser.add_argument("-D", "--database", default="int_telemetry_db",
        help="Database name. Default: int_telemetry_db")

    parser.add_argument("-p", "--period", default=1, type=int,
        help="Time period to push data in normal condition. Default: 1")

    parser.add_argument("-P", "--event_period", default=0, type=float,
        help="Time period to push event data. Default: 0")

    parser.add_argument("-t", "--int_time", action='store_true',
        help="Use INT timestamp instead of local time")

    parser.add_argument("-e", "--event_mode", default="THRESHOLD",
        help="Event detection mode: INTERVAL or THRESHOLD. \
            Option -p is disabled for THRESHOLD and is hard-coded instead")

    parser.add_argument("-l", "--log_level", default=20, type=int,
        help="CRITICAL = 50\
            ERROR = 40;\
            WARNING = 30;\
            INFO = 20;\
            DEBUG = 10;\
            NOTSET = 0;\
            Default: 20")
    
    parser.add_argument("-l_rap", "--log_raports_lvl", default=20, type=int,
        help='DEBUG = 10 - enables logging of raports. Default: 20')

    parser.add_argument('--clear', default='n', help = ' [yes,y,YES,Y] - clear database')

    return parser.parse_args()


if __name__ == "__main__":

    args = parse_params()

    logger.setLevel(args.log_level)

    logger.debug(f"\n\tInterface: {args.ifaces}\n"
                f"\tInflux address: {args.host}\n"
                f"\tInflux port: {args.influx_port}")


    collector = InDBCollector.InDBCollector(int_dst_port=args.int_port, 
        host=args.host, database=args.database, 
        int_time=args.int_time, event_mode=args.event_mode, 
        log_level=args.log_level, log_raports_lvl = args.log_raports_lvl,
        influx_port = args.influx_port
        )

    for iface in args.ifaces:
        collector.attach_iface(iface)

    # clear all old dbs. For easy testing
    clear_db: str = 'n'
    # clear_db = input(f'Database name: {args.database}.\nShould the database be cleared? [y/n]: ')
    if args.clear in ['yes', 'y', 'Y', 'YES']:
        for db in collector.client.get_list_database():
            collector.client.drop_database(db["name"])
        collector.client.create_database(args.database)
        logger.info(f'Database has been cleared.')

    databases_list = [x['name'] for x in collector.client.get_list_database()]
    if not(args.database in databases_list):
        collector.client.create_database(args.database)
        logger.info(f'Database has been created.')

    push_stop_flag = threading.Event()

    # # A separated thread to push event data
    def _event_push():

        while not push_stop_flag.is_set():

            time.sleep(args.event_period)
 
            collector.lock.acquire()
            data = collector.event_data
            collector.event_data = []
            collector.lock.release()

            if data:
                collector.client.write_points(points=data[0])
                logger.debug(f'Len of data: {len(data)}')


    # A separated thread to push data
    if args.event_mode == "INTERVAL":
        def _periodically_push():
            cnt = 0
            while not push_stop_flag.is_set():
                # use cnt to partition sleep time,
                # so Ctrl-C could terminate the program earlier
                time.sleep(1)
                cnt += 1
                if cnt < args.period:
                    continue
                cnt = 0

                data = collector.collect_data()
                if data:
                    collector.client.write_points(points=data, protocol=protocol)
                    logger.debug(f'Periodically push: {len(data[0])}')

        periodically_push = threading.Thread(target=_periodically_push)
        periodically_push.start()

    event_push = threading.Thread(target=_event_push)
    event_push.start()


    # Start polling events
    collector.open_events()

    logger.info("eBPF progs Loaded")
    sys.stdout.flush()

    try:
        while 1:
            collector.poll_events()

    except KeyboardInterrupt:
        pass

    finally:
        push_stop_flag.set()
        if args.event_mode == "INTERVAL":
            periodically_push.join()
        event_push.join()

        collector.detach_all_iface()
        print("Done")
