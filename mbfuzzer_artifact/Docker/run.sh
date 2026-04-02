#!/bin/bash

if [ $# -ne 1 ]; then
    echo "Usage: $0 {vernemq|nanomq|flashmq|mosquitto|hivemq|emqx}"
    exit 1
fi

PARAM=$1

case "$PARAM" in
    vernemq)
        echo "Starting vernemq..."
        ${WORKDIR}/vernemq/_build/default/rel/vernemq/bin/vernemq start
        ;;
    nanomq)
        echo "Starting nanomq..."
        python3 ${WORKDIR}/run_broker.py  --command "${WORKDIR}/nanomq/build/nanomq/nanomq start --conf ${WORKDIR}/conf/nanomq.conf" --host "127.0.0.1" --port 1883
        ;;
    flashmq)
        mkdir /tmp/flashmq
        python3 ${WORKDIR}/run_broker.py  --command "${WORKDIR}/flashmq/FlashMQBuildRelease/flashmq -c ${WORKDIR}/conf/flashmq.conf" --host "127.0.0.1" --port 1883
        ;;
    mosquitto)
        echo "Starting mosquitto..."
        python3 ${WORKDIR}/run_broker.py  --command "${WORKDIR}/mosquitto-2.0.18/src/mosquitto -c ${WORKDIR}/conf/mosquitto.conf" --host "127.0.0.1" --port 1883
        ;;
    hivemq)
        echo "Starting hivemq..."
        python3 ${WORKDIR}/run_broker_hivemq.py --command "${WORKDIR}/hivemq-4.24.0/bin/run.sh" --host 127.0.0.1 --port 1883 --path1 ${WORKDIR}/hivemq-4.24.0/extensions/hivemq-bridge-extension/DISABLED --path2 ${WORKDIR}/hivemq-4.24.0/extensions/hivemq-mysql-extension/DISABLED
        ;;
    emqx)
        echo "Starting emqx..."
        ${WORKDIR}/emqx/bin/emqx start
        ;;
    *)
        echo "Invalid parameter: $PARAM"
        echo "Allowed parameters: vernemq, nanomq, flashmq, mosquitto, hivemq, emqx"
        exit 1
        ;;
esac