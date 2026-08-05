# Enhancing SDN Network Security Using Game Theory


# Enhancing SDN Network Security Using Game Theory

## Overview

This project presents an intelligent Software Defined Networking (SDN) security framework that combines:

- Ryu SDN Controller
- OpenFlow 1.3
- Snort IDS
- Machine Learning Detection
- Multi-Stage Attack Pattern Segmentation
- Dynamic Game Theory Engine

The system detects and mitigates ICMP Flooding and IP Spoofing attacks while adapting its defense strategy according to the observed attack stage.

---

# System Architecture

Network Traffic
→ Dataset Processing
→ Feature Extraction
→ Attack Pattern Segmentation
→ Machine Learning Detection
→ Dynamic Game Theory Engine
→ Defense Decision
→ OpenFlow Mitigation

---

# Main Components

## Controller

- Ryu Controller (OpenFlow 1.3)
- Traffic Monitoring
- Flow Statistics Collection
- Multi-Stage Attack Detection
- Dynamic Defense Deployment

## Intrusion Detection

- Snort IDS
- Real-time ICMP Detection
- Alert Forwarding

## Machine Learning

- Attack Classification
- Multi-stage Detection
- Confidence Evaluation

## Game Theory Engine

- Utility Function
- Expected Utility
- Belief Update
- Reputation Score
- Adaptive Defense Strategy

---

# Defense Actions

| Strategy | Description |
|----------|-------------|
| ALLOW | Normal Traffic |
| RL_1 | Rate Limit 4000 kbps |
| RL_2 | Rate Limit 1024 kbps |
| RL_3 | Rate Limit 512 kbps |
| BLOCK | Block Attack Traffic |

---

# Supported Attack Stages

- NORMAL
- PROBE
- FLOOD_LOW
- FLOOD_HIGH
- IP_SPOOFING
- SPOOFED_FLOOD

---

# Technologies

- Python
- Ryu SDN Framework
- OpenFlow 1.3
- Mininet
- Open vSwitch
- Snort IDS
- Machine Learning
- Markov-Based Stage Transition
- Dynamic Game Theory

---

# Repository Structure
controllers/
    ryu_ddos_controller_multistage.py
    game_engine_multistage.py

topology/
    topology.py

snort/
    snort.conf

scripts/

attacks/
attack_hping3.sh
attack_scapy.py
run_ddos_attack.sh
run_multistage_attack.sh

docs/


---

# Features

- Multi-stage attack detection
- Dynamic game-theoretic defense
- Machine learning integration
- Snort IDS integration
- ICMP Flood detection
- IP Spoofing detection
- Adaptive rate limiting
- Automatic traffic blocking
- Real-time logging

---

Enhancing SDN Network Security Using Game Theory
