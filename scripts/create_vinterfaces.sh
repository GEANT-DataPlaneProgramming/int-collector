ip link add veth_0 type veth peer name veth_1
ip link set dev veth_0 up
ip link set dev veth_1 up