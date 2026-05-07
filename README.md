# Enhancing SDN Network Security Using Game Theory

This project implements a game-theoretic defense mechanism for Software-Defined Networking (SDN) environments. The system integrates Mininet, Open vSwitch, Ryu Controller, and Snort IDS to detect and mitigate ICMP Flooding and IP Spoofing attacks.

## Main Components

- Mininet topology with two OpenFlow switches and six hosts
- Ryu SDN controller using OpenFlow 1.3
- Dynamic game-theoretic decision engine
- Snort IDS for mirrored traffic inspection
- Alert forwarding agent from Snort VM to the controller VM
- Mitigation actions: ALLOW, RL_1, RL_2, RL_3, and BLOCK

## Defense Strategies

| Strategy | Action |
|---|---|
| ALLOW | Allow normal traffic |
| RL_1 | Rate limit to 4000 kbps |
| RL_2 | Rate limit to 1024 kbps |
| RL_3 | Rate limit to 512 kbps |
| BLOCK | Install OpenFlow drop rule |

## Tested Attacks

1. ICMP Flood Attack
2. IP Spoofing Attack
3. Spoofed ICMP Flood Attack

## Project Workflow

1. Build the SDN topology using Mininet.
2. Mirror traffic from OpenFlow switches to the Snort VM.
3. Detect suspicious traffic using Snort IDS.
4. Forward Snort alerts to the Ryu controller.
5. Evaluate the flow using the game-theoretic decision engine.
6. Apply mitigation using OpenFlow rules.

## Running the Controller

```bash
ryu-manager controllers/ryu_ddos_controller.py
