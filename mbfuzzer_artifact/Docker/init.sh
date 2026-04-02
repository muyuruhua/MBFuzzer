# FlashMQ
mkdir /tmp/flashmq
/root/flashmq/FlashMQBuildRelease/flashmq -c /root/conf/flashmq.conf 

# Mosquitto
./mosquitto -c /home/ubuntu/conf/mosquitto.conf  -v

# NanoMQ
/root/nanomq/build/nanomq

./nanomq start --conf /root/conf/nanomq.conf

# Vernemq
/root/vernemq/_build/default/rel/vernemq/bin
./vernemq start

# HiveMQ
service mysql start

cp /root/conf/hivemq_config.xml /root/hivemq-4.24.0/extensions/hivemq-bridge-extension/conf/config.xml 