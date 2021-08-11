from __future__ import print_function

import argparse
import threading
import time
import sys

import pyximport; pyximport.install()
import InDBCollector

def parse_params():
    parser = argparse.ArgumentParser(description='InfluxBD INTCollector client.')

    parser.add_argument("ifaces", nargs='+',
    help="List of ifaces to receive INT reports")

    parser.add_argument("-i", "--int_port", default=8086, type=int,
        help="Destination port of INT Telemetry reports")

    parser.add_argument("-H", "--host", default="localhost",
        help="InfluxDB server address")

    parser.add_argument("-D", "--database", default="INTdatabase",
        help="Database name")

    parser.add_argument("-p", "--period", default=10, type=int,
        help="Time period to push data in normal condition")

    parser.add_argument("-P", "--event_period", default=1, type=float,
        help="Time period to push event data")

    parser.add_argument("-t", "--int_time", action='store_true',
        help="Use INT timestamp instead of local time")

    parser.add_argument("-e", "--event_mode", default="THRESHOLD",
        help="Event detection mode: INTERVAL or THRESHOLD. \
        Option -p is disabled for THRESHOLD and is hard-coded instead")

    parser.add_argument("-d", "--debug_mode", default=0, type=int,
        help="Set to 1 to print event")

    return parser.parse_args()


if __name__ == "__main__":

    args = parse_params()

    # number_of_events = 0

    collector = InDBCollector.InDBCollector(int_dst_port=args.int_port,
        debug_mode=args.debug_mode, host=args.host,
        database=args.database, int_time=args.int_time,
        event_mode=args.event_mode)


    for iface in args.ifaces:
        collector.attach_iface(iface)

    # clear all old dbs. For easy testing
    for db in collector.client.get_list_database():
        collector.client.drop_database(db["name"])
    collector.client.create_database(args.database)


    push_stop_flag = threading.Event()

    # A separated thread to push event data
    def _event_push():

        while not push_stop_flag.is_set():

            # time.sleep(args.event_period)

            collector.lock.acquire()
            data = collector.event_data
            collector.event_data = []
            collector.lock.release()

            if args.debug_mode==2:
                print("Len of events: ", len(data))
                # number_of_events = number_of_events+ 1
                # print(f'{number_of_events}')                

            if data:
                collector.client.write_points(points=data[0])
                # print(type(data))
                # print(data)
                # for x in range(len(data[0])):
                    # collector.client.write_points(points=data[0][x])
                    # points=data[0][x]
                    # print(type(points))


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
                    if args.debug_mode==2:
                        print("Periodically push: ", len(data))


        periodically_push = threading.Thread(target=_periodically_push)
        periodically_push.start()

    event_push = threading.Thread(target=_event_push)
    event_push.start()


    # Start polling events
    collector.open_events()

    print("eBPF progs Loaded")
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
