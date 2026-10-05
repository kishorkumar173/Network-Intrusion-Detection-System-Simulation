"""
Network Feature Engineering Engine
Extracts statistical and domain-specific features from raw flow dictionaries.
Performs defensive data cleaning, handling division by zero, missing keys,
and IP/port validation.
"""

import ipaddress
from typing import Dict, Any, Tuple


VALID_PROTOCOLS = {"TCP", "UDP", "ICMP"}


def validate_ip_address(ip_str: str) -> bool:
    """Validate if the string is a valid IPv4 address."""
    if not ip_str or not isinstance(ip_str, str):
        return False
    try:
        ipaddress.IPv4Address(ip_str.strip())
        return True
    except (ipaddress.AddressValueError, ValueError):
        return False


def validate_port(port: Any) -> bool:
    """Validate port number in valid range [1, 65535]."""
    try:
        p = int(port)
        return 1 <= p <= 65535
    except (ValueError, TypeError):
        return False


def extract_network_features(flow_record: Dict[str, Any]) -> Tuple[Dict[str, Any], bool, str]:
    """
    Extracts engineered features from a single raw flow record.

    :param flow_record: Dictionary containing flow attributes
    :return: (features_dict, is_valid, error_message)
    """
    if not isinstance(flow_record, dict):
        return {}, False, "Input flow record must be a dictionary"

    # 1. Defensive validation of mandatory identity fields
    src_ip = flow_record.get("source_ip", "")
    dst_ip = flow_record.get("destination_ip", "")
    src_port = flow_record.get("source_port")
    dst_port = flow_record.get("destination_port")
    protocol = str(flow_record.get("protocol", "")).upper()

    if not validate_ip_address(src_ip):
        return {}, False, f"Invalid source IP address: {src_ip}"
    if not validate_ip_address(dst_ip):
        return {}, False, f"Invalid destination IP address: {dst_ip}"
    if not validate_port(src_port):
        return {}, False, f"Invalid source port: {src_port}"
    if not validate_port(dst_port):
        return {}, False, f"Invalid destination port: {dst_port}"
    if protocol not in VALID_PROTOCOLS:
        return {}, False, f"Unsupported protocol '{protocol}'. Must be TCP, UDP, or ICMP"

    # 2. Defensive extraction of numerical fields with type safety
    try:
        packet_count = max(0, int(flow_record.get("packet_count", 0)))
        byte_count = max(0, int(flow_record.get("byte_count", 0)))
        duration = max(0.001, float(flow_record.get("duration_seconds", flow_record.get("duration", 0.001))))
        connection_count = max(1, int(flow_record.get("connection_count", 1)))
        failed_conn_count = max(0, int(flow_record.get("failed_connection_count", 0)))
        syn_count = max(0, int(flow_record.get("syn_count", 0)))
        rst_count = max(0, int(flow_record.get("rst_count", 0)))
    except (ValueError, TypeError) as e:
        return {}, False, f"Numerical field parsing error: {str(e)}"

    # 3. Calculate derived metrics with division-by-zero protection
    bytes_per_second = round(byte_count / duration, 2)
    packets_per_second = round(packet_count / duration, 2)
    
    # Average packet size: byte_count / packet_count
    average_packet_size = round(byte_count / packet_count, 2) if packet_count > 0 else 0.0

    # Failure ratio: failed_connections / total_connections
    failure_ratio = round(min(1.0, failed_conn_count / connection_count), 4) if connection_count > 0 else 0.0

    # SYN ratio: syn_count / packet_count
    syn_ratio = round(min(1.0, syn_count / packet_count), 4) if packet_count > 0 else 0.0

    # Connection rate: connection_count / duration
    connection_rate = round(connection_count / duration, 2)

    # Multi-target cardinality (default to 1 for atomic flow, or passed from tracking window)
    unique_destination_ports = int(flow_record.get("unique_destination_ports", 1))
    unique_destination_ips = int(flow_record.get("unique_destination_ips", 1))

    features = {
        "source_ip": src_ip,
        "destination_ip": dst_ip,
        "source_port": int(src_port),
        "destination_port": int(dst_port),
        "protocol": protocol,
        "packet_count": packet_count,
        "byte_count": byte_count,
        "duration": duration,
        "bytes_per_second": bytes_per_second,
        "packets_per_second": packets_per_second,
        "average_packet_size": average_packet_size,
        "connection_count": connection_count,
        "failed_connection_count": failed_conn_count,
        "failure_ratio": failure_ratio,
        "syn_count": syn_count,
        "rst_count": rst_count,
        "syn_ratio": syn_ratio,
        "unique_destination_ports": unique_destination_ports,
        "unique_destination_ips": unique_destination_ips,
        "connection_rate": connection_rate,
    }

    return features, True, ""
