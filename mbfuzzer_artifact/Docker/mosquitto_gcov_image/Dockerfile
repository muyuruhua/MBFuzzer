FROM ubuntu:20.04

ENV DEBIAN_FRONTEND=noninteractive
ENV WORKDIR=/opt
ENV MOSQUITTO_SRC=/opt/mosquitto-gcov

RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential \
    ca-certificates \
    curl \
    gcovr \
    libwebsockets-dev \
    libc-ares-dev \
    libssl-dev \
    python3 \
    python3-pip \
    wget \
 && rm -rf /var/lib/apt/lists/*

RUN mkdir -p "$WORKDIR" && \
    cd "$WORKDIR" && \
    wget -O mosquitto-2.0.18.tar.gz https://github.com/eclipse/mosquitto/archive/refs/tags/v2.0.18.tar.gz && \
    tar -xzf mosquitto-2.0.18.tar.gz && \
    mv mosquitto-2.0.18 "$MOSQUITTO_SRC"

RUN cd "$MOSQUITTO_SRC" && \
    make clean || true && \
    make \
      WITH_TLS=no \
      WITH_STATIC_LIBRARIES=no \
      WITH_STRIP=no \
      CFLAGS='-O0 -g --coverage -fprofile-arcs -ftest-coverage' \
      LDFLAGS='--coverage -fprofile-arcs -ftest-coverage'

COPY conf/mosquitto.conf /opt/mosquitto.conf
COPY mosquitto_gcov_collect.sh /usr/local/bin/mosquitto_gcov_collect.sh
RUN chmod +x /usr/local/bin/mosquitto_gcov_collect.sh

EXPOSE 1883
WORKDIR /opt
CMD ["/opt/mosquitto-gcov/src/mosquitto", "-c", "/opt/mosquitto.conf"]
