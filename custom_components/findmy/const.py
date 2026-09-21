"""Integration constants."""

DOMAIN = "findmy"

CONFIG_FLOW_VERSION_MAJOR = 2
CONFIG_FLOW_VERSION_MINOR = 0

CONF_AWAY_TIMEOUT = "away_timeout"
DEFAULT_AWAY_TIMEOUT_MINUTES = 10


def signal_local_observation(unique_id: str) -> str:
    """Dispatcher signal fired when a rolling accessory is matched locally."""
    return f"{DOMAIN}_local_observation_{unique_id}"
