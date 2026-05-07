#!/bin/bash

TARGET_IP=$1
COUNT=$2

if [ -z "$TARGET_IP" ] || [ -z "$COUNT" ]; then
    echo "Usage: ./attack_hping3.sh <target_ip> <count>"
    echo "Example: ./attack_hping3.sh 10.0.0.2 50"
    exit 1
fi

echo "Starting hping3 ICMP flood to $TARGET_IP with count $COUNT"
sudo hping3 --icmp -c "$COUNT" "$TARGET_IP"
