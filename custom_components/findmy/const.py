"""Integration constants."""

DOMAIN = "findmy"

CONFIG_FLOW_VERSION_MAJOR = 2
CONFIG_FLOW_VERSION_MINOR = 0

CONF_AWAY_TIMEOUT = "away_timeout"
DEFAULT_AWAY_TIMEOUT_MINUTES = 10

# Option of a rolling-key accessory: how many days of key indices are searched for it when its
# alignment is older than that (see key_cache.py). The search cost grows linearly with the
# window: an accessory that was not located for years is only searched within this many days
# below the newest possible index. An accessory that rolled over slower than every 15 minutes
# (powered off, flat battery) for more than this many days is no longer recognised until it is
# located again.
CONF_KEY_SEARCH_WINDOW_DAYS = "key_search_window_days"
DEFAULT_KEY_SEARCH_WINDOW_DAYS = 30
MIN_KEY_SEARCH_WINDOW_DAYS = 1
MAX_KEY_SEARCH_WINDOW_DAYS = 365


def signal_local_observation(unique_id: str) -> str:
    """Dispatcher signal fired when a rolling accessory is matched locally."""
    return f"{DOMAIN}_local_observation_{unique_id}"


def signal_local_rssi(unique_id: str) -> str:
    """Dispatcher signal fired when the signal strength of a local accessory changes."""
    return f"{DOMAIN}_local_rssi_{unique_id}"


def signal_account_fetch(account_name: str) -> str:
    """Dispatcher signal fired when an Apple account fetch starts or ends."""
    return f"{DOMAIN}_account_fetch_{account_name}"
