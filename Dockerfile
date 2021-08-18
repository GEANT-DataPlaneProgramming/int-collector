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

#Install requirements
COPY ./collector /INTcollector
WORKDIR /INTcollector
RUN pip3 install -r requirements.txt

ENV INFLUX_ADDRESS 172.17.0.2
ENV INFLUX_PORT 8086

ENTRYPOINT python3 InDBClient.py eth0 -H $INFLUX_ADDRESS -i $INFLUX_PORT




