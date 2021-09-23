# Table of contents
- [Table of contents](#table-of-contents)
- [__INT-collector__](#int-collector)
- [__Installation__](#installation)
  - [Collector setup](#collector-setup)
  - [Server setup](#server-setup)
- [__Usage__](#usage)
  - [Notes](#notes)
  - [Test](#test)
  - [All starting arguments](#all-starting-arguments)
  - [Fragment of code resposible for filtering the packages](#fragment-of-code-resposible-for-filtering-the-packages)
- [__Start in Docker container__](#start-in-docker-container)
- [__INT packages generator__](#int-packages-generator)
- [__Publication__](#publication)

# __INT-collector__
A high-performance collector to process INT Telemetry reports, and send data to database server InfluxDB.
Currently, int-collector supports [Telemetry report v1.0](https://github.com/p4lang/p4-applications/tree/master/docs), and [INT spec v1.0](https://github.com/p4lang/p4-applications/tree/master/docs) with TCP/UDP encapsulation.
`Int-collector` uses [eBPF](https://www.iovisor.org/technology/ebpf) and [XDP](https://www.iovisor.org/technology/xdp), which requires linux kernel in v4.15.

This int-collector is a modified version of the following project: [BPFCollector](https://gitlab.com/tunv_ebpf/BPFCollector/tree/master).

The INT collector implementation changes and testing was done within the GEANT Data Plane Programmibilty activity:
* https://wiki.geant.org/display/NETDEV/INT


# __Installation__
## Collector setup

* Install Ubuntu VM. We have only tested int-collector with Ubuntu 18.04 64 bit with kernel v4.15 and python3.
* Install `bcc` package from https://github.com/iovisor/bcc.
* Clone this repo
   ``` shell
      git clone https://github.com/GEANT-DataPlaneProgramming/int-collector.git
   ```
* Install requirements
   ``` shell
      sudo pip3 install -r requirements.txt
   ```
* [Optional] Enable `JIT` for eBPF, which makes code run faster (recommended):
   ``` shell
      sudo sysctl net/core/bpf_jit_enable=1
   ```

## Server setup

* InfluxDB python client requires InfluxDB sever v1.2.4:
   ``` shell
      wget https://dl.influxdata.com/influxdb/releases/influxdb_1.2.4_amd64.deb
      sudo dpkg -i influxdb_1.2.4_amd64.deb
      sudo systemctl start influxdb
   ```
   Package of InfluxDB is available in folder: `additional_packages/influxdb_1.2.4_amd64.deb`.

# __Usage__

* Collector captures UDP packages with port 8090. If you want to change a port you must run a collector with a specific argument:

   ```shell
   sudo python3 InDBClient.py {interface_name} -i {new_port}
   ```

* [Optional] Create `veth` pair for testing. We can send INT Telemetry reports to one endpoint, and let INTCollector listen to the reports at the other endpoint.
  ``` shell
    sudo ip link add veth_0 type veth peer name veth_1
    sudo ip link set dev veth_0 up
    sudo ip link set dev veth_1 up
  ```
  A script which creates interfaces is available in folder `int-collector/scripts/`:
  ```
  cd int-collector
  sudo sh scipts/create_vinterfaces.sh
  ```
* Run int-collector at the network interface that can listen to INT Telemetry reports. If you create `veth` pair (from the point above), you can send reports to `veth_0` and listen to reports at `veth_1`:
   ``` shell
      sudo python3 InDBClient.py veth_1
   ```



## Notes

* If InfluxDB server does not run in the same machine as the collector, we need to specify the server address with `-H` option when running `InDBClient.py`.
* Run the collector with `-h` option for more help. If there are any missing libraries, install them using `pip`.
* INT Telemetry reports in pcap file can be created using `benchmark/INTReport.py` or `benchmark/int_package_generator.py`.
* If there are errors (such as _cannot allocate memory_), eBPF program cannot load. In that case, please ensure that the network interfaces, on which INTCollector works, has XDP support by current kernel. Check [here](https://github.com/iovisor/bcc/blob/master/docs/kernel-versions.md#xdp).

## Test
End to end tests for InfluxDB only. InfluxDB needs to run in localhost.
``` shell
   sudo pip3 install pytest
   sudo python3 -m pytest -v
```

## All starting arguments

 ```shell
   -h, --help              show this help message and exit
   -i INT_PORT, --int_port INT_PORT
                           Destination port of INT Telemetry reports. Default:
                           8090
   -H HOST, --host HOST    InfluxDB server address. Default: localhost
   -INFP INFLUX_PORT, --influx_port INFLUX_PORT
                           InfluxDB server port. Default: 8086
   -D DATABASE, --database DATABASE
                           Database name. Default: int_telemetry_db
   -p PERIOD, --period PERIOD
                           Time period to push data in normal condition. Default:
                           1
   -P EVENT_PERIOD, --event_period EVENT_PERIOD
                           Time period to push event data. Default: 0
   -t, --int_time          Use INT timestamp instead of local time
   -e EVENT_MODE, --event_mode EVENT_MODE
                           Event detection mode: INTERVAL or THRESHOLD. Option -p
                           is disabled for THRESHOLD and is hard-coded instead
   -l LOG_LEVEL, --log_level LOG_LEVEL
                           CRITICAL = 50 ERROR = 40; WARNING = 30; INFO = 20;
                           DEBUG = 10; NOTSET = 0; Default: 20
   -l_rap LOG_RAPORTS_LVL, --log_raports_lvl LOG_RAPORTS_LVL
                           DEBUG = 10 - enables logging of raports. Default: 20
   --clear CLEAR           [yes,y,YES,Y] - clear database
   ```

## Fragment of code resposible for filtering the packages

   The fragment of code mentioned below is resposible for passing packages, which meet the conditions, to the collector. The packages which don't meet the conditions are transmitted to the normal path of transmission. 

   Firstly, the Ethernet header's presence is checked. If it is present, the type of protocol is checked in IP header. If the protocol type is UDP, the destination port is checked. Destination port must be the same as the port indicated while running the INTCollector (argument `-i`, default: 8090).

   If you want to change the filtering of packages, you must change this [fragment of code](https://github.com/GEANT-DataPlaneProgramming/int-collector/blob/2f5f07adeb46499890363f327bcefec992654f80/collector/BPFCollector.c#L376). 

   ```c
   struct eth_tp *eth;
      CURSOR_ADVANCE(eth, cursor, sizeof(*eth), data_end);

      if (unlikely(ntohs(eth->type) != ETHTYPE_IP))
         return XDP_PASS;
      struct iphdr *ip;
      CURSOR_ADVANCE(ip, cursor, sizeof(*ip), data_end);

      if (unlikely(ip->protocol != IPPROTO_UDP))
         return XDP_PASS;
      struct udphdr *udp;
      CURSOR_ADVANCE(udp, cursor, sizeof(*udp), data_end);

      if (unlikely(ntohs(udp->dest) != INT_DST_PORT))
         return XDP_PASS;
   ```


# __Start in Docker container__
Container available on DockerHub works only on host with kernel 4.15.0-154-generic.

Image: https://hub.docker.com/repository/docker/jaxa/int_collector

Instructions for the owner of kernel 4.15.0-154-generic:
- docker pull jaxa/int_collector
- docker run --name int-collector --privileged --network host -e IFACE=enp0s3 -e INFLUX_ADDRESS=localhost -e INFLUX_PORT=8086 -d jaxa/int_collector

Available environment variables:

<div align=center>

|        ENV        |                                                                                    Description                                                                                     |  Default value   |
| :---------------: | :--------------------------------------------------------------------------------------------------------------------------------------------------------------------------------: | :--------------: |
|       IFACE       |                                                                          Interface to receive INT reports                                                                          |       eth0       |
|  INFLUX_ADDRESS   |                                                                              InfluxDB server address                                                                               |    127.0.0.1    |
|    INFLUX_PORT       |                InfluxDB port                                                                      |       8086       |
| INT_PORT       |                                 Destination port of INT Telemetry raports | 8090 |
|   DATABASE_NAME   |                                                                                   Database name                                                                                    | int_telemetry_db |
|      PERIOD       |                                                                    Time period to push data in normal condition                                                                    |        1         |
|   EVENT_PERIOD    |                                                                           Time period to push event data                                                                           |        0         |
|    EVENT_MODE     |                                  Event detection mode: INTERVAL or THRESHOLD.</br> Option -p is disabled for THRESHOLD and is hard-coded instead                                   |    THRESHOLD     |
|     LOG_LEVEL     | Displaying logs in terminal. This option makes sense when the container is launched in an interactive mode.</br> Available options: > 20 - no log </br> 20 - info </br> 10 - debug |        30        |
| LOG_RAPORTS_LEVEL |    Displaying raports in terminal. This option makes sense when the container is launched in an interactive mode.</br> Available options: > 10 - no raports log</br> 10 - debug    |        20        |
|       CLEAR       |                                                                          yes,y,YES,Y - clean the database                                                                          |        n         |
</div>

If kernel is in an older version, you can update it:
- sudo apt-get update
- sudo apt-get upgrade
- sudo apt-get install linux-image-4.15.0-154-generic linux-headers-4.15.0-154-generic 
- reboot

If you don't want to update kernel or it's in a newer version, you have to build a new docker image from the source:
- git clone https://github.com/GEANT-DataPlaneProgramming/INT-collector
- cd INT-collector
- docker build -t int-collector .

# __INT packages generator__

[`Int_package_generator.py`](https://github.com/GEANT-DataPlaneProgramming/int-collector/blob/master/benchmark/int_package_generator.py) can generate INT packets and send them to a specified interface. 

Optional arguments:
 
      -h - shows help message;

      -c - generating only two packets with constant values. One per second;

      -l - generates 1k packets with linearly growing values;

      -hop NUMBER - Number of hops in a packet. Min - 1,  Max - 6. Default: 3;

      -i INTERFACE - Interface through which packets will be sent, Default: veth_1;

      -n NUMBER - Number of sending packets per second. Works only with `-l' option. 1000 generated packets from the '-l' option are duplicated up to the indicated number. Default: 1000;

      -v {0,1} - Scapy verbose, 0 - disable, 1 - enable. Default: 0;

      -log LOG_LEVEL - log level - CRITICAL = 50 ERROR = 40; WARNING = 30; INFO = 20; DEBUG = 10; NOTSET = 0; Default: 20.
# __Publication__
- N. V. Tu, J. Hyun, G. Y. Kim, J. Yoo and J. W. Hong, "INTCollector: A High-performance Collector for In-band Network Telemetry," *2018 14th International Conference on Network and Service Management (CNSM)*, Rome, 2018, pp. 10-18.




