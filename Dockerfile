FROM ubuntu:18.04

# Install BCC
RUN apt-get update
RUN apt-get -y install python3 python3-distutils python3-pip
RUN apt-get -y install bison build-essential cmake flex git libedit-dev \
  libllvm6.0 llvm-6.0-dev libclang-6.0-dev python zlib1g-dev libelf-dev libfl-dev

RUN git clone https://github.com/iovisor/bcc.git
RUN mkdir bcc/build

WORKDIR /bcc/build
RUN cmake ..
RUN make && make install

RUN cmake -DPYTHON_CMD=python3 ..
WORKDIR /src/python
RUN make && make install


#Install requirements and local influxdb
COPY . /INT-collector
WORKDIR /INT-collector
RUN pip3 install -r requirements.txt

RUN dpkg -i ./additional_packages/influxdb_1.2.4_amd64.deb
RUN service influxdb start





