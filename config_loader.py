"""
Configuration Loader Module

Safely loads, validates, and manages organizational security baselines and thresholds
from external JSON configuration files.
"""

from dataclasses import dataclass, field
import ipaddress
import json
from pathlib import Path
from typing import Any, Collection, Dict, List, Optional, Set, Union


class ConfigError(Exception):
    """Base exception for configuration-related errors."""
    pass


class ConfigNotFoundError(ConfigError):
    """Raised when the specified configuration file is not found."""
    pass


class ConfigValidationError(ConfigError):
    """Raised when configuration content fails structural or semantic validation."""
    pass


@dataclass
class SecurityConfig:
    """
    Structured representation of validated security baselines and operating parameters.
    """
    known_internal_ips: Set[str] = field(default_factory=lambda: {
        "10.0.1.45",
        "10.0.2.80",
        "10.0.0.0/16",
        "192.168.1.0/24",
        "127.0.0.1",
    })
    known_hosts: Set[str] = field(default_factory=lambda: {
        "DC-PROD-01",
        "WKSTN-FIN-12",
        "JUMPBOX-01",
        "SRV-APP-01",
        "SRV-DB-02",
        "SRV-BACKUP-03",
    })
    normal_login_start_hour: int = 8
    normal_login_end_hour: int = 18
    raw_data: Dict[str, Any] = field(default_factory=dict)


def get_default_config() -> SecurityConfig:
    """
    Returns the standard fallback baseline security configuration.
    """
    return SecurityConfig()


def validate_and_parse_config(data: Any) -> SecurityConfig:
    """
    Validates the structure, types, and values of a raw configuration dictionary.

    Validation Rules:
      1. Root must be a dictionary.
      2. 'known_internal_ips' is required and must be a list/set of valid IP strings or CIDR notations.
      3. 'known_hosts' is required and must be a list/set of non-empty host strings.
      4. 'normal_login_hours' is required with 'start' and 'end' integers satisfying 0 <= start < end <= 24.

    Raises:
        ConfigValidationError: If any validation rule fails.
    """
    if not isinstance(data, dict):
        raise ConfigValidationError(f"Configuration root must be a JSON object, got {type(data).__name__}")

    # 1. Validate required fields presence
    required_keys = ["known_internal_ips", "known_hosts", "normal_login_hours"]
    for key in required_keys:
        if key not in data:
            raise ConfigValidationError(f"Missing required configuration field: '{key}'")

    # 2. Validate known_internal_ips
    raw_ips = data.get("known_internal_ips")
    if not isinstance(raw_ips, (list, set, tuple)):
        raise ConfigValidationError(
            f"'known_internal_ips' must be a list of IP/CIDR strings, got {type(raw_ips).__name__}"
        )

    validated_ips: Set[str] = set()
    for item in raw_ips:
        if not isinstance(item, str) or not item.strip():
            raise ConfigValidationError(f"IP address entry must be a non-empty string, got: {repr(item)}")
        ip_entry = item.strip()
        # Verify it is a valid IP or CIDR network
        try:
            if "/" in ip_entry:
                ipaddress.ip_network(ip_entry, strict=False)
            else:
                ipaddress.ip_address(ip_entry)
        except ValueError as exc:
            raise ConfigValidationError(
                f"Invalid IP address or CIDR notation '{ip_entry}' in known_internal_ips: {exc}"
            ) from exc
        validated_ips.add(ip_entry)

    # 3. Validate known_hosts
    raw_hosts = data.get("known_hosts")
    if not isinstance(raw_hosts, (list, set, tuple)):
        raise ConfigValidationError(
            f"'known_hosts' must be a list of host strings, got {type(raw_hosts).__name__}"
        )

    validated_hosts: Set[str] = set()
    for item in raw_hosts:
        if not isinstance(item, str) or not item.strip():
            raise ConfigValidationError(f"Host entry must be a non-empty string, got: {repr(item)}")
        validated_hosts.add(item.strip())

    # 4. Validate normal_login_hours
    raw_hours = data.get("normal_login_hours")
    if not isinstance(raw_hours, dict):
        raise ConfigValidationError(
            f"'normal_login_hours' must be a dictionary with 'start' and 'end', got {type(raw_hours).__name__}"
        )

    if "start" not in raw_hours or "end" not in raw_hours:
        raise ConfigValidationError("'normal_login_hours' must contain both 'start' and 'end' integer fields")

    start_hour = raw_hours.get("start")
    end_hour = raw_hours.get("end")

    if not isinstance(start_hour, int) or isinstance(start_hour, bool):
        raise ConfigValidationError(f"'normal_login_hours.start' must be an integer, got {repr(start_hour)}")

    if not isinstance(end_hour, int) or isinstance(end_hour, bool):
        raise ConfigValidationError(f"'normal_login_hours.end' must be an integer, got {repr(end_hour)}")

    if not (0 <= start_hour <= 24):
        raise ConfigValidationError(
            f"'normal_login_hours.start' must be between 0 and 24, got {start_hour}"
        )

    if not (0 <= end_hour <= 24):
        raise ConfigValidationError(
            f"'normal_login_hours.end' must be between 0 and 24, got {end_hour}"
        )

    if start_hour >= end_hour:
        raise ConfigValidationError(
            f"'normal_login_hours.start' ({start_hour}) must be strictly less than 'end' ({end_hour})"
        )

    return SecurityConfig(
        known_internal_ips=validated_ips,
        known_hosts=validated_hosts,
        normal_login_start_hour=start_hour,
        normal_login_end_hour=end_hour,
        raw_data=dict(data),
    )


def load_config(config_path: Optional[Union[Path, str]] = None) -> SecurityConfig:
    """
    Loads and validates the external security configuration file from the filesystem.

    Args:
        config_path: Path to the JSON configuration file. If omitted, defaults to
                     'config/security_config.json' relative to project root.

    Returns:
        SecurityConfig instance populated with validated baselines.

    Raises:
        ConfigNotFoundError: If the configuration file cannot be found.
        ConfigValidationError: If the configuration syntax or schema is invalid.
    """
    if config_path is None:
        base_dir = Path(__file__).parent.resolve()
        target_path = base_dir / "config" / "security_config.json"
    else:
        target_path = Path(config_path).resolve()

    if not target_path.exists():
        raise ConfigNotFoundError(f"Configuration file not found at: {target_path}")

    try:
        with open(target_path, "r", encoding="utf-8") as f:
            data = json.load(f)
    except json.JSONDecodeError as exc:
        raise ConfigValidationError(
            f"Invalid JSON syntax in configuration file {target_path}: {exc}"
        ) from exc
    except OSError as exc:
        raise ConfigError(f"Failed to read configuration file {target_path}: {exc}") from exc

    return validate_and_parse_config(data)
