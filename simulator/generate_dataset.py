"""
Synthetic Network Traffic Dataset Generator
Generates realistic, defensive network flow records for testing and ML training.
Strictly adheres to RFC 5737 reserved documentation IP ranges:
- 192.0.2.0/24 (TEST-NET-1)
- 198.51.100.0/24 (TEST-NET-2)
- 203.0.113.0/24 (TEST-NET-3)
"""

import os
import random
import uuid
from datetime import datetime, timedelta
import pandas as pd


# RFC 5737 Safe IP pools
SRC_IPS_POOL = [f"192.0.2.{i}" for i in range(10, 80)]
DST_IPS_POOL = [f"198.51.100.{i}" for i in range(10, 50)] + [f"203.0.113.{i}" for i in range(10, 50)]

# Scenario definitions with generator parameters
NORMAL_SCENARIOS = ["NORMAL_WEB", "NORMAL_DNS", "NORMAL_SSH", "NORMAL_EMAIL", "NORMAL_DATABASE"]
SUSPICIOUS_SCENARIOS = [
    "HIGH_CONNECTION_RATE",
    "REPEATED_FAILED_CONNECTIONS",
    "MULTI_PORT_PROBING_PATTERN",
    "SYN_HEAVY_PATTERN",
    "UNUSUAL_PORT_ACTIVITY",
    "HIGH_TRAFFIC_VOLUME",
]


def generate_single_record(scenario_type: str, current_time: datetime) -> dict:
    """Generate a single realistic network flow record based on scenario."""
    flow_id = f"flow-{uuid.uuid4().hex[:10]}"
    src_ip = random.choice(SRC_IPS_POOL)
    dst_ip = random.choice(DST_IPS_POOL)
    src_port = random.randint(49152, 65535)

    if scenario_type == "NORMAL_WEB":
        dst_port = random.choice([80, 443, 8080, 8443])
        protocol = "TCP"
        packet_count = random.randint(10, 60)
        avg_pkt_size = random.uniform(400, 1100)
        byte_count = int(packet_count * avg_pkt_size)
        duration = round(random.uniform(0.5, 6.0), 3)
        conn_count = random.randint(1, 5)
        failed_conn = 0
        syn_count = random.randint(1, 3)
        rst_count = random.choice([0, 0, 0, 1])
        label = "NORMAL"

    elif scenario_type == "NORMAL_DNS":
        dst_port = 53
        protocol = "UDP"
        packet_count = random.randint(2, 6)
        avg_pkt_size = random.uniform(60, 250)
        byte_count = int(packet_count * avg_pkt_size)
        duration = round(random.uniform(0.02, 0.4), 3)
        conn_count = 1
        failed_conn = 0
        syn_count = 0
        rst_count = 0
        label = "NORMAL"

    elif scenario_type == "NORMAL_SSH":
        dst_port = 22
        protocol = "TCP"
        packet_count = random.randint(30, 200)
        avg_pkt_size = random.uniform(80, 400)
        byte_count = int(packet_count * avg_pkt_size)
        duration = round(random.uniform(10.0, 180.0), 3)
        conn_count = 1
        failed_conn = 0
        syn_count = 1
        rst_count = 0
        label = "NORMAL"

    elif scenario_type == "NORMAL_EMAIL":
        dst_port = random.choice([25, 465, 587, 993])
        protocol = "TCP"
        packet_count = random.randint(15, 80)
        avg_pkt_size = random.uniform(250, 750)
        byte_count = int(packet_count * avg_pkt_size)
        duration = round(random.uniform(1.0, 12.0), 3)
        conn_count = random.randint(1, 3)
        failed_conn = 0
        syn_count = 1
        rst_count = 0
        label = "NORMAL"

    elif scenario_type == "NORMAL_DATABASE":
        dst_port = random.choice([3306, 5432, 1433, 27017])
        protocol = "TCP"
        packet_count = random.randint(20, 120)
        avg_pkt_size = random.uniform(300, 950)
        byte_count = int(packet_count * avg_pkt_size)
        duration = round(random.uniform(0.8, 15.0), 3)
        conn_count = random.randint(1, 4)
        failed_conn = 0
        syn_count = 1
        rst_count = 0
        label = "NORMAL"

    elif scenario_type == "HIGH_CONNECTION_RATE":
        # Rapid connection attempts in short duration
        dst_port = random.choice([80, 443, 8080])
        protocol = "TCP"
        packet_count = random.randint(200, 1500)
        avg_pkt_size = random.uniform(80, 300)
        byte_count = int(packet_count * avg_pkt_size)
        duration = round(random.uniform(0.2, 2.0), 3)
        conn_count = random.randint(80, 400)
        failed_conn = random.randint(10, 50)
        syn_count = random.randint(80, 350)
        rst_count = random.randint(5, 40)
        label = "SUSPICIOUS"

    elif scenario_type == "REPEATED_FAILED_CONNECTIONS":
        # Repeated authentication/connection failures (e.g. brute force pattern)
        dst_port = random.choice([22, 3389, 445, 21])
        protocol = "TCP"
        packet_count = random.randint(40, 300)
        avg_pkt_size = random.uniform(60, 180)
        byte_count = int(packet_count * avg_pkt_size)
        duration = round(random.uniform(2.0, 10.0), 3)
        conn_count = random.randint(25, 120)
        failed_conn = random.randint(20, 110)
        syn_count = random.randint(25, 120)
        rst_count = random.randint(15, 80)
        label = "SUSPICIOUS"

    elif scenario_type == "MULTI_PORT_PROBING_PATTERN":
        # Source probing multiple ports on destination (port sweep pattern)
        dst_port = random.randint(1, 65535)
        protocol = "TCP"
        packet_count = random.randint(10, 50)
        avg_pkt_size = random.uniform(40, 70)
        byte_count = int(packet_count * avg_pkt_size)
        duration = round(random.uniform(0.1, 1.5), 3)
        conn_count = random.randint(30, 150)
        failed_conn = random.randint(25, 140)
        syn_count = random.randint(30, 145)
        rst_count = random.randint(20, 130)
        label = "SUSPICIOUS"

    elif scenario_type == "SYN_HEAVY_PATTERN":
        # Abnormally high ratio of SYN packets with minimal data transfer (SYN flood pattern)
        dst_port = random.choice([80, 443, 8080])
        protocol = "TCP"
        packet_count = random.randint(500, 3000)
        avg_pkt_size = random.uniform(40, 64)
        byte_count = int(packet_count * avg_pkt_size)
        duration = round(random.uniform(0.5, 3.0), 3)
        conn_count = random.randint(100, 500)
        failed_conn = random.randint(80, 450)
        syn_count = int(packet_count * random.uniform(0.85, 0.99))
        rst_count = random.randint(10, 80)
        label = "SUSPICIOUS"

    elif scenario_type == "UNUSUAL_PORT_ACTIVITY":
        # Activity on high/suspicious unassigned ports (e.g. backdoors / IRC / trojan ports)
        dst_port = random.choice([4444, 5555, 6667, 31337, 1337, 8888, 9999])
        protocol = random.choice(["TCP", "UDP"])
        packet_count = random.randint(30, 180)
        avg_pkt_size = random.uniform(150, 600)
        byte_count = int(packet_count * avg_pkt_size)
        duration = round(random.uniform(1.0, 8.0), 3)
        conn_count = random.randint(5, 25)
        failed_conn = random.randint(1, 10)
        syn_count = random.randint(4, 20) if protocol == "TCP" else 0
        rst_count = random.randint(0, 5)
        label = "SUSPICIOUS"

    elif scenario_type == "HIGH_TRAFFIC_VOLUME":
        # Abnormally large byte volume / bandwidth consumption (exfiltration or volumetric pattern)
        dst_port = random.choice([80, 443, 8443])
        protocol = "TCP"
        packet_count = random.randint(2000, 12000)
        avg_pkt_size = random.uniform(1200, 1460)
        byte_count = int(packet_count * avg_pkt_size)
        duration = round(random.uniform(5.0, 30.0), 3)
        conn_count = random.randint(10, 60)
        failed_conn = random.randint(0, 5)
        syn_count = random.randint(10, 50)
        rst_count = random.randint(0, 5)
        label = "SUSPICIOUS"

    else:
        dst_port = 80
        protocol = "TCP"
        packet_count = 20
        avg_pkt_size = 500.0
        byte_count = 10000
        duration = 1.0
        conn_count = 1
        failed_conn = 0
        syn_count = 1
        rst_count = 0
        label = "NORMAL"

    return {
        "flow_id": flow_id,
        "timestamp": current_time.strftime("%Y-%m-%d %H:%M:%S"),
        "source_ip": src_ip,
        "destination_ip": dst_ip,
        "source_port": src_port,
        "destination_port": dst_port,
        "protocol": protocol,
        "packet_count": packet_count,
        "byte_count": byte_count,
        "duration_seconds": duration,
        "connection_count": conn_count,
        "failed_connection_count": failed_conn,
        "syn_count": syn_count,
        "rst_count": rst_count,
        "average_packet_size": round(avg_pkt_size, 2),
        "label": label,
        "scenario_type": scenario_type,
    }


def generate_dataset(total_records: int = 6000, output_path: str = "data/network_traffic.csv") -> pd.DataFrame:
    """
    Generate synthetic network traffic records (balanced: ~70% normal, ~30% suspicious)
    and save to CSV file.
    """
    random.seed(42)
    os.makedirs(os.path.dirname(output_path), exist_ok=True)

    records = []
    base_time = datetime.now() - timedelta(days=2)

    normal_count = int(total_records * 0.70)
    suspicious_count = total_records - normal_count

    print(f"[*] Generating {total_records} synthetic flow records...")
    print(f"    - Normal flows: {normal_count}")
    print(f"    - Suspicious flows: {suspicious_count}")

    # Generate Normal records
    for i in range(normal_count):
        curr_time = base_time + timedelta(seconds=i * random.uniform(10, 40))
        scen = random.choice(NORMAL_SCENARIOS)
        records.append(generate_single_record(scen, curr_time))

    # Generate Suspicious records
    for j in range(suspicious_count):
        curr_time = base_time + timedelta(seconds=j * random.uniform(30, 90))
        scen = random.choice(SUSPICIOUS_SCENARIOS)
        records.append(generate_single_record(scen, curr_time))

    # Shuffle to simulate mixed real-world traffic timeline
    random.shuffle(records)
    df = pd.DataFrame(records)
    # Sort chronologically
    df["timestamp"] = pd.to_datetime(df["timestamp"])
    df = df.sort_values(by="timestamp").reset_index(drop=True)
    df["timestamp"] = df["timestamp"].dt.strftime("%Y-%m-%d %H:%M:%S")

    df.to_csv(output_path, index=False)
    print(f"[+] Successfully saved dataset to {output_path}")
    print(f"    Shape: {df.shape}")
    print(f"    Class distribution:\n{df['label'].value_counts()}")
    return df


if __name__ == "__main__":
    current_dir = os.path.dirname(os.path.abspath(__file__))
    project_root = os.path.abspath(os.path.join(current_dir, ".."))
    out_file = os.path.join(project_root, "data", "network_traffic.csv")
    generate_dataset(total_records=6000, output_path=out_file)
