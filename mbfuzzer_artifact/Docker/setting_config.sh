#!/bin/bash

if [ -z "$1" ]; then
  echo "Usage: $0 <IP_ADDRESS>"
  exit 1
fi

NEW_IP=$1

sed -i -E "s/(bridge\.mqtt\.aws\.address\s*=\s*)[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+:[0-9]+/\1$NEW_IP:1884/g" ./conf/*

sed -i -E "s/\<address\>\s+[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+/address $NEW_IP/g" ./conf/*

sed -i -E "s/\<address\>\s+[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+:1884/address $NEW_IP:1884/g" ./conf/*

sed -i -E "s/<host>[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+<\/host>/<host>$NEW_IP<\/host>/g" ./conf/*

sed -i -E 's|server\s*=\s*"mqtt-tcp://[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+:1884"|server = "mqtt-tcp://'$NEW_IP':1884"|g' ./conf/*

sed -i -E "s/(vmq_bridge\.tcp\.br0\s*=\s*)[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+:1884/\1$NEW_IP:1884/g" ./conf/*

echo "IP addresses have been updated to $NEW_IP in all files."