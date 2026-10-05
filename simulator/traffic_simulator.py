"""
Network Traffic Simulator
Continuously simulates real-time network flow metadata stream without sending
any raw packets over physical networks.

Supports:
- Modes: normal, mixed
- Speeds: slow, fast
- Direct dispatch to IDS REST API or standalone console output
"""

import argparse
import json
import os
import random
import sys
import time
from datetime import datetime
import requests

# Add project root to sys.path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))
from simulator.generate_dataset import generate_single_record, NORMAL_SCENARIOS, SUSPICIOUS_SCENARIOS


def stream_flows(mode: str = "mixed", speed: str = "fast", target_url: str = None, max_events: int = None):
    """
    Stream synthetic flow events.
    :param mode: 'normal' (only benign traffic) or 'mixed' (75% normal, 25% suspicious)
    :param speed: 'slow' (1.5-3.0s delay) or 'fast' (0.2-0.5s delay)
    :param target_url: REST API endpoint to POST flow event to (e.g., http://127.0.0.1:5000/api/flows)
    :param max_events: Optional maximum number of events to generate (useful for testing)
    """
    print("=" * 65)
    print(" [*] DEFENSIVE NETWORK IDS TRAFFIC SIMULATOR ACTIVE")
    print(f" [*] Mode   : {mode.upper()}")
    print(f" [*] Speed  : {speed.upper()}")
    print(f" [*] Target : {target_url or 'Console Output (Dry-run)'}")
    print(" [*] Press Ctrl+C to terminate simulation gracefully")
    print("=" * 65)

    delay_range = (1.5, 3.0) if speed == "slow" else (0.2, 0.6)
    event_counter = 0

    try:
        while True:
            if max_events and event_counter >= max_events:
                print(f"[+] Reached max events limit: {max_events}. Terminating simulation.")
                break

            now = datetime.now()
            if mode == "normal":
                scenario = random.choice(NORMAL_SCENARIOS)
            else:
                # 75% normal, 25% suspicious
                if random.random() < 0.75:
                    scenario = random.choice(NORMAL_SCENARIOS)
                else:
                    scenario = random.choice(SUSPICIOUS_SCENARIOS)

            flow_record = generate_single_record(scenario, now)
            event_counter += 1

            # Dispatch flow
            if target_url:
                try:
                    resp = requests.post(target_url, json=flow_record, timeout=3)
                    status_code = resp.status_code
                    resp_data = resp.json() if resp.status_code in [200, 201] else {}
                    alert_info = resp_data.get("alert")
                    risk_score = resp_data.get("risk_score", "N/A")

                    alert_flag = f"[ALERT: {alert_info['severity']}]" if alert_info else "[CLEAN]"
                    print(
                        f"[{event_counter:04d}] {now.strftime('%H:%M:%S')} | "
                        f"{flow_record['source_ip']}:{flow_record['source_port']} -> "
                        f"{flow_record['destination_ip']}:{flow_record['destination_port']} "
                        f"({flow_record['protocol']}) | Risk: {risk_score} | {alert_flag} "
                        f"Scenario: {flow_record['scenario_type']}"
                    )
                except requests.exceptions.RequestException as e:
                    print(f"[{event_counter:04d}] Failed to send to {target_url}: {e}")
            else:
                print(
                    f"[{event_counter:04d}] [DRY-RUN] {now.strftime('%H:%M:%S')} | "
                    f"{flow_record['source_ip']}:{flow_record['source_port']} -> "
                    f"{flow_record['destination_ip']}:{flow_record['destination_port']} "
                    f"({flow_record['protocol']}) | {flow_record['scenario_type']} | "
                    f"Packets: {flow_record['packet_count']}, Bytes: {flow_record['byte_count']}"
                )

            sleep_time = random.uniform(*delay_range)
            time.sleep(sleep_time)

    except KeyboardInterrupt:
        print(f"\n[!] Traffic simulation stopped by user. Total events generated: {event_counter}")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Synthetic Network IDS Traffic Simulator")
    parser.add_argument("--mode", choices=["normal", "mixed"], default="mixed", help="Traffic simulation mode")
    parser.add_argument("--speed", choices=["slow", "fast"], default="fast", help="Simulation streaming speed")
    parser.add_argument("--target-url", type=str, default=None, help="Backend API endpoint URL (e.g. http://127.0.0.1:5000/api/flows)")
    parser.add_argument("--count", type=int, default=None, help="Number of flow events to generate before exiting")

    args = parser.parse_args()
    stream_flows(mode=args.mode, speed=args.speed, target_url=args.target_url, max_events=args.count)
