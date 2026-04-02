FROM ubuntu:20.04

RUN chmod 777 /tmp

# Install common dependencies
ENV DEBIAN_FRONTEND=noninteractive

RUN apt-get -y update && \
    apt-get -y install sudo apt-utils build-essential git autoconf python3-pip net-tools vim wget logrotate libsnappy-dev systemctl libgpm2 libncurses5 libsctp1 libtinfo5 cmake unzip default-jdk


# USER ubuntu
ENV WORKDIR=/root/

RUN cd $WORKDIR && wget https://binaries2.erlang-solutions.com/ubuntu/pool/contrib/e/esl-erlang/esl-erlang_25.0-1~ubuntu~focal_amd64.deb && \
    dpkg -i esl-erlang_25.0-1~ubuntu~focal_amd64.deb 

RUN pip3 install gcovr==4.2 psutil colorama psutil

# # Add a new user ubuntu, pass: ubuntu
# RUN groupadd ubuntu && \
#     useradd -rm -d $WORKDIR -s /bin/bash -g ubuntu -G sudo -u 1000 ubuntu -p "$(openssl passwd -1 ubuntu)"

# Move config file
COPY conf/ ${WORKDIR}/conf

# Download mosquitto
RUN cd $WORKDIR/ && wget https://github.com/eclipse/mosquitto/archive/refs/tags/v2.0.18.tar.gz  && \
    tar -zxf v2.0.18.tar.gz && \
    cd mosquitto-2.0.18/src && \
    make WITH_TLS=no 

# Download nanomq
RUN cd ${WORKDIR}/ && git clone https://github.com/nanomq/nanomq.git nanomq && \
    cd nanomq && git checkout 236c9c5 && git submodule update --init --recursive && \    
    mkdir build && cd build && cmake .. -DDEBUG=ON -DNNG_ENABLE_SQLITE=ON && make

# Download FlashMQ
RUN apt install -y libssl-dev
RUN cd ${WORKDIR}/ && git clone https://github.com/halfgaar/FlashMQ.git flashmq && cd flashmq && \
    git checkout d82cba5 && \
    ./build.sh 

# Download Vernemq  
COPY vernemq.tar.gz $WORKDIR/
RUN cd $WORKDIR/ && tar -zxf vernemq.tar.gz && \
    cp $WORKDIR/conf/vernemq.conf $WORKDIR/vernemq/_build/default/rel/vernemq/etc/vernemq.conf

# Download emqx   
RUN cd $WORKDIR/ && wget https://www.emqx.com/en/downloads/broker/v5.6.0/emqx-5.6.0-ubuntu20.04-amd64.tar.gz && \
    mkdir -p emqx && tar -zxvf emqx-5.6.0-ubuntu20.04-amd64.tar.gz -C emqx

RUN cp $WORKDIR/conf/emqx.conf $WORKDIR/emqx/data
    
# Download hivemq
COPY hivemq-4.24.0.zip ${WORKDIR}/
RUN cd ${WORKDIR}/ && \
    unzip hivemq-4.24.0.zip && \
    cp $WORKDIR/conf/hivemq_config.xml $WORKDIR/hivemq-4.24.0/extensions/hivemq-bridge-extension/conf/config.xml

COPY run_broker.py ${WORKDIR}/run_broker.py
COPY run_broker_hivemq.py ${WORKDIR}/run_broker_hivemq.py
COPY run.sh ${WORKDIR}/run.sh

RUN apt-get clean && \
    rm -rf /var/lib/apt/lists/* /tmp/* /var/tmp/*