import os
import re
import time
import shlex
import subprocess
from pathlib import Path
from datetime import datetime

MININET_USER = "mininet"
MININET_HOST = "192.168.57.130"

REMOTE_ALERT_LOG = "~/SDN-GameTheory-Security/logs/snort_alerts.log"

LOCAL_LOGS = [
    Path.home() / "snort_real/logs/snort_s1.log",
    Path.home() / "snort_real/logs/snort_s2.log",
]

FLOW_RE = re.compile(r"\b(10\.0\.0\.\d+)\s*->\s*(10\.0\.0\.\d+)\b")


last_sent = {}
COOLDOWN_SECONDS = 2


def send_alert(src, dst, source_log):
    now = time.time()
    key = (src, dst, source_log)

    if key in last_sent and now - last_sent[key] < COOLDOWN_SECONDS:
        return

    last_sent[key] = now

    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    alert_line = f"{timestamp} PROJECT_ICMP_ATTACK src={src} dst={dst} source_log={source_log}"

    remote_cmd = (
        "mkdir -p ~/SDN-GameTheory-Security/logs && "
        f"printf '%s\n' {shlex.quote(alert_line)} >> {REMOTE_ALERT_LOG}"
    )

    try:
        result = subprocess.run(
            ["ssh", f"{MININET_USER}@{MININET_HOST}", remote_cmd],
            timeout=15,
            capture_output=True,
            text=True
        )

        if result.returncode == 0:
            print(f"[SENT] {alert_line}", flush=True)
        else:
            print(f"[ERROR] SSH failed: {result.stderr}", flush=True)

    except Exception as e:
        print(f"[ERROR] Could not send alert: {e}", flush=True)


def init_positions():
    positions = {}

    for log_path in LOCAL_LOGS:
        log_path.parent.mkdir(parents=True, exist_ok=True)
        log_path.touch(exist_ok=True)
        positions[log_path] = log_path.stat().st_size

    return positions


def read_new_lines(log_path, positions):
    try:
        current_size = log_path.stat().st_size

        # إذا الملف انعمل له truncate بسبب tee بدون -a
        if current_size < positions[log_path]:
            positions[log_path] = 0

        with open(log_path, "r", errors="ignore") as f:
            f.seek(positions[log_path])
            lines = f.readlines()
            positions[log_path] = f.tell()

        return lines

    except Exception as e:
        print(f"[ERROR] Reading {log_path}: {e}", flush=True)
        return []


def main():
    print("[START] Snort real alert forwarder", flush=True)
    print(f"[INFO] Forwarding to {MININET_USER}@{MININET_HOST}:{REMOTE_ALERT_LOG}", flush=True)

    for log_path in LOCAL_LOGS:
        print(f"[INFO] Watching {log_path}", flush=True)

    positions = init_positions()

    while True:
        for log_path in LOCAL_LOGS:
            lines = read_new_lines(log_path, positions)

            for line in lines:
                upper = line.upper()

                # نركز فقط على ICMP لأن هجومنا الأساسي ICMP Flood / Spoofed ICMP
                if "ICMP" not in upper:
                    continue

                match = FLOW_RE.search(line)

                if not match:
                    continue

                src = match.group(1)
                dst = match.group(2)

                send_alert(src, dst, log_path.name)

        time.sleep(0.2)


if __name__ == "__main__":
    main()
