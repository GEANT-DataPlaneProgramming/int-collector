FROM ubuntu:18.04

RUN apt-get update
RUN apt-get -y install python3 python3-distutils python3-pip
RUN apt-get -y install sudo linux-headers-$(uname -r) bison build-essential cmake flex git libedit-dev \
  libllvm6.0 llvm-6.0-dev libclang-6.0-dev python zlib1g-dev libelf-dev libfl-dev

# Install BCC
RUN git clone https://github.com/iovisor/bcc.git
RUN mkdir bcc/build

WORKDIR bcc/build
RUN cmake ..
RUN make && make install

RUN cmake -DPYTHON_CMD=python3 ..
WORKDIR src/python
RUN make && make install
#Install network tools
RUN apt-get -y install net-tools tcpdump

#Install requirements
WORKDIR /
COPY ./requirements.txt /
RUN pip3 install -r requirements.txt

COPY ./collector /INTcollector
WORKDIR /INTcollector

ENV IFACE eth0
ENV INFLUX_ADDRESS 127.0.0.1
ENV INFLUX_PORT 8086
ENV INT_PORT 8090
ENV DATABASE_NAME int_telemetry_db
ENV PERIOD 1
ENV EVENT_PERIOD 1
ENV EVENT_MODE THRESHOLD
ENV LOG_LEVEL 30
ENV LOG_RAPORTS_LEVEL 20
ENV CLEAR n

ENTRYPOINT python3 InDBClient.py $IFACE -H $INFLUX_ADDRESS -INFP $INFLUX_PORT -i $INT_PORT -D $DATABASE_NAME -p $PERIOD -P $EVENT_PERIOD -e $EVENT_MODE \
-l $LOG_LEVEL -l_rap $LOG_RAPORTS_LEVEL --clear $CLEAR




