# INTCollector
A high-performance collector to process INT Telemetry reports, and send data to database servers such as Prometheus and InfluxDB.
Currently, INTCollector supports [Telemetry report v1.0](https://github.com/p4lang/p4-applications/tree/master/docs), and [INT spec v1.0](https://github.com/p4lang/p4-applications/tree/master/docs) with TCP/UDP encapsulation.
`INTCollector` use [eBPF](https://www.iovisor.org/technology/ebpf) and [XDP](https://www.iovisor.org/technology/xdp), which require recent linux kernel. For best practice, kernel version >= v4.14 should be used.
# Installation
## Collector setup

* Install Ubuntu VM. We only tested INTCollector with Ubuntu 18.04 64 bit with kernel v4.15. Both python2 and python3 should work.
* Install `bcc` package from https://github.com/iovisor/bcc.
* Clone this repo
   ``` shell
      git clone https://gitlab.com/tunv_ebpf/BPFCollector.git
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

* For Prometheus: Install and run Prometheus server from https://prometheus.io . Config the `.yml` file to scrape the INTCollector client. Address should be `localhost` if Prometheus server and INTCollector run on the same machine.
* For InfluxDB: InfluxDB python client requires InfluxDB sever v1.2.4:
   ``` shell
      wget https://dl.influxdata.com/influxdb/releases/influxdb_1.2.4_amd64.deb
      sudo dpkg -i influxdb_1.2.4_amd64.deb
      sudo systemctl start influxdb
   ```

# Usage

* [Optional] create `veth` pair for testing. We can send INT Telemetry reports to one endpoint, and let INTCollector listens to the reports at the other endpoint.
  ``` shell
    sudo ip link add veth_0 type veth peer name veth_1
    sudo ip link set dev veth_0 up
    sudo ip link set dev veth_1 up
  ```
* Run INTCollector at the network interface that can listen to INT Telemetry reports. If you create `veth` pair above, you can send reports to `veth_0` and listen to reports at `veth_1`:
   ``` shell
      sudo python3 PTClient.py veth_1 # For Prometheus
      sudo python3 InDBClient.py veth_1 # For InfluxDB
   ```

## Notes

* If InfluxDB server does not run in the same machine as the collector, we need to specify the server address with `-H` option when running `InDBClient.py`.
* Run the collector with `-h` option for more help. If there are any missing libraries, install them using `pip`.
* INT Telemetry reports in pcap file can be created using `benchmark/INTReport.py`.
* If there are errors that eBPF program cannot load (such as _cannot allocate memory_), please ensure that the network interfaces the INTCollector listens to has XDP support by current kernel. Check [here](https://github.com/iovisor/bcc/blob/master/docs/kernel-versions.md#xdp).

## Test
End to end tests for InfluxDB only. InfluxDB needs to run in localhost.
``` shell
   sudo pip3 install pytest
   sudo python3 -m pytest -v
```

# Pulication
- N. V. Tu, J. Hyun, G. Y. Kim, J. Yoo and J. W. Hong, "INTCollector: A High-performance Collector for In-band Network Telemetry," *2018 14th International Conference on Network and Service Management (CNSM)*, Rome, 2018, pp. 10-18.


# Start in Docker container
- docker run --name INTcollector --privileged -d test_collector
