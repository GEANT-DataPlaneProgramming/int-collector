#!/bin/bash

# xdotool key ctrl+112 # prev tab
# xdotool key ctrl+117 # next tab

# LX terminal
# We need 3 tabs: 1: for run script - 2: for tcpreplay - 
# 3: for ssh to run BPF collector - 4: for ssh mpstat - 5: VM2 for influxDB and Prometheus
TCPREPLAY=2
BPF=3
MPSTAT=4
VM2=5
PGW=6

CPU_EVAL_TIME=180

# xdotool key alt+$MPSTAT
# xdotool type "echo --------INT ONOS Collector--------- >> result.txt"
# xdotool key Return
# sleep 2

# # start test
# for RATE in 60000 90000 120000 150000 180000 210000; do
# 	# start prometheus
# 	xdotool key alt+$VM2
# 	xdotool type "./prometheus --config.file=prometheus.yml"
# 	xdotool key Return
# 	sleep 5

# 	# start push gw
# 	xdotool key alt+$PGW
# 	xdotool type "./pushgateway"
# 	xdotool key Return
# 	sleep 5

# 	# start Collector
# 	xdotool key alt+$BPF
# 	xdotool type "java -jar int_col_push_remote.jar"
# 	xdotool key Return
# 	sleep 10

# 	# start tcpreplay
# 	xdotool key alt+$TCPREPLAY
# 	xdotool type "tcpreplay -i vnet0  -K --loop 50000000 -p $RATE pcaps/t6_5sw_100fl_all.pcap"
# 	# xdotool type "./pkt-gen -i vtap0 -f tx -P pcaps/t3_6sw_100fl_all.pcap -R $RATE -b 128"
# 	xdotool key Return
# 	sleep 12

# 	# start mpstart
# 	xdotool key alt+$MPSTAT
# 	xdotool type "echo rate: $RATE >> result.txt"
# 	xdotool key Return
# 	sleep 2
# 	xdotool type "mpstat $CPU_EVAL_TIME 1 | grep -E \"idle|Average\" >> result.txt"
# 	xdotool key Return
# 	sleep $CPU_EVAL_TIME
# 	sleep 2
# 	xdotool type "echo >> result.txt"
# 	xdotool key Return
# 	sleep 2

# 	#cancel tcpreplay
# 	xdotool key alt+$TCPREPLAY
# 	xdotool key ctrl+c
# 	sleep 2

# 	# cancel Collector
# 	xdotool key alt+$BPF
# 	xdotool key ctrl+c
# 	sleep 2

# 	# cancel push gw
# 	xdotool key alt+$PGW
# 	xdotool key ctrl+c
# 	sleep 2

# 	# delete prometheus data
# 	xdotool key alt+$VM2
# 	xdotool key ctrl+c
# 	sleep 2
# 	xdotool type "rm  -rf data/wal"
# 	xdotool key Return
# 	sleep 2
# done


# TEST 0: how does the packet report rate affect CPU usage?
# -- tcpreplay (Mpps): 0.4, 0.6, 0.8, 1.0, 1.2, 1.4
# -- 6sw, flow path on hop latency

xdotool key alt+$MPSTAT
xdotool type "echo --------TEST 0--------- >> result.txt"
xdotool key Return
sleep 2

# start test
for COLLECTOR in "InDBClient.py -H 192.168.122.106" "PTClient.py"; do
	for RATE in 200000 400000 600000 800000 1000000 1200000 1400000; do
		if [ $COLLECTOR == "PTClient.py" ]
		then
			# start prometheus
			xdotool key alt+$VM2
			xdotool type "./prometheus --config.file=prometheus.yml"
			xdotool key Return
			sleep 5
		fi

		# start Collector
		xdotool key alt+$BPF
		xdotool type "python $COLLECTOR ens4"
		xdotool key Return
		sleep 10

		# start tcpreplay
		xdotool key alt+$TCPREPLAY
		# xdotool type "tcpreplay -i vtap0  -K --loop 50000000 --unique-ip -p $RATE pcaps/t3_6sw_100fl_swid_hoplatency.pcap"
		xdotool type "./pkt-gen -i vtap0 -f tx -P pcaps/t3_6sw_100fl_all.pcap -R $RATE"
		xdotool key Return

		sleep 12

		# start mpstart
		xdotool key alt+$MPSTAT
		xdotool type "echo $COLLECTOR, rate: $RATE >> result.txt"
		xdotool key Return
		sleep 2
		xdotool type "mpstat $CPU_EVAL_TIME 1 | grep -E \"idle|Average\" >> result.txt"
		xdotool key Return
		sleep $CPU_EVAL_TIME
		sleep 2
		xdotool type "echo >> result.txt"
		xdotool key Return
		sleep 2

		#cancel tcpreplay
		xdotool key alt+$TCPREPLAY
		xdotool key ctrl+c
		sleep 2

		# cancel Collector
		xdotool key alt+$BPF
		xdotool key ctrl+c
		sleep 2

		if [ $COLLECTOR == "PTClient.py" ]
		then
			# delete prometheus data
			xdotool key alt+$VM2
			xdotool key ctrl+c
			sleep 2
			xdotool type "rm  -rf data/wal"
			xdotool key Return
			sleep 2
		fi
	done
done



# TEST 1, 2, 3, 4

xdotool key alt+$MPSTAT
xdotool type "echo --------TEST 1, 2, 3, 4--------- >> result.txt"
xdotool key Return
sleep 2


# start test
for COLLECTOR in "PTClient.py" "InDBClient.py -H 192.168.122.106"; do
	for REPORT in 	"t1_6sw_10fl_swid.pcap" \
					"t1_6sw_100fl_swid.pcap" \
					"t1_6sw_500fl_swid.pcap" \
					"t1_6sw_1000fl_swid.pcap" \
					"t1_6sw_2000fl_swid.pcap" \
					"t1_6sw_5000fl_swid.pcap" \
					"t2_1sw_100fl_swid.pcap" \
					"t2_2sw_100fl_swid.pcap" \
					"t2_3sw_100fl_swid.pcap" \
					"t2_4sw_100fl_swid.pcap" \
					"t2_5sw_100fl_swid.pcap" \
					"t2_6sw_100fl_swid.pcap" \
					"t2_1sw_100fl_all.pcap" \
					"t2_2sw_100fl_all.pcap" \
					"t2_3sw_100fl_all.pcap" \
					"t2_4sw_100fl_all.pcap" \
					"t2_5sw_100fl_all.pcap" \
					"t2_6sw_100fl_all.pcap" \
					"t3_3sw_100fl_swid.pcap" \
					"t3_3sw_100fl_swid_hoplatency.pcap" \
					"t3_3sw_100fl_swid_qoccup_qcongest.pcap" \
					"t3_3sw_100fl_swid_txutilize.pcap" \
					"t3_3sw_100fl_all.pcap" \
					"t3_6sw_100fl_swid.pcap" \
					"t3_6sw_100fl_swid_hoplatency.pcap" \
					"t3_6sw_100fl_swid_qoccup_qcongest.pcap" \
					"t3_6sw_100fl_swid_txutilize.pcap" \
					"t3_6sw_100fl_all.pcap" \
					"t4_3sw_100fl_20event_all.pcap" \
					"t4_3sw_100fl_50event_all.pcap" \
					"t4_3sw_100fl_100event_all.pcap" \
					"t4_3sw_100fl_200event_all.pcap" \
					"t4_3sw_100fl_500event_all.pcap"; do


		if [ $COLLECTOR == "PTClient.py" ]
		then
			# start prometheus
			xdotool key alt+$VM2
			xdotool type "./prometheus --config.file=prometheus.yml"
			xdotool key Return
			sleep 5
		fi

		# start Collector
		xdotool key alt+$BPF
		xdotool type "python $COLLECTOR ens4"
		xdotool key Return
		sleep 10

		# start tcpreplay
		xdotool key alt+$TCPREPLAY
		xdotool type "tcpreplay -i vtap0  -K --loop 50000000 --unique-ip -p 1000000 pcaps/$REPORT"
		xdotool key Return

		sleep 12

		# start mpstart
		xdotool key alt+$MPSTAT
		xdotool type "echo $COLLECTOR, test file: $REPORT >> result.txt"
		xdotool key Return
		sleep 2
		xdotool type "mpstat $CPU_EVAL_TIME 1 | grep -E \"idle|Average\" >> result.txt"
		xdotool key Return
		sleep $CPU_EVAL_TIME
		sleep 2
		xdotool type "echo >> result.txt"
		xdotool key Return
		sleep 2

		#cancel tcpreplay
		xdotool key alt+$TCPREPLAY
		xdotool key ctrl+c
		sleep 2

		# cancel Collector
		xdotool key alt+$BPF
		xdotool key ctrl+c
		sleep 2

		if [ $COLLECTOR == "PTClient.py" ]
		then
			# delete prometheus data
			xdotool key alt+$VM2
			xdotool key ctrl+c
			sleep 2
			xdotool type "rm  -rf data/wal"
			xdotool key Return
			sleep 2
		fi
	done
done

xdotool key Return
