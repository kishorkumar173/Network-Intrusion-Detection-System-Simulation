"""
Input Validation Utilities
Provides sanitization and defensive checks for API request payloads.
"""

from typing import Dict, Any, Tuple
from ids.feature_extractor import validate_ip_address, validate_port, VALID_PROTOCOLS


def validate_flow_payload(payload: Dict[str, Any]) -> Tuple[bool, str]:
    """Validate mandatory structure of incoming flow JSON."""
    if not isinstance(payload, dict):
        return False, "Request payload must be a JSON object"

    required_fields = ["source_ip", "destination_ip", "source_port", "destination_port", "protocol"]
    for field in required_fields:
        if field not in payload:
            return False, f"Missing required field: '{field}'"

    if not validate_ip_address(payload["source_ip"]):
        return False, f"Invalid IPv4 format for source_ip: {payload['source_ip']}"

    if not validate_ip_address(payload["destination_ip"]):
        return False, f"Invalid IPv4 format for destination_ip: {payload['destination_ip']}"

    if not validate_port(payload["source_port"]):
        return False, f"source_port must be an integer between 1 and 65535: {payload['source_port']}"

    if not validate_port(payload["destination_port"]):
        return False, f"destination_port must be an integer between 1 and 65535: {payload['destination_port']}"

    protocol = str(payload.get("protocol", "")).upper()
    if protocol not in VALID_PROTOCOLS:
        return False, f"Unsupported protocol '{protocol}'. Allowed: {', '.join(VALID_PROTOCOLS)}"

    return True, ""
