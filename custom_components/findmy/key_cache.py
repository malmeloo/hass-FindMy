"""Rolling-key accessory that keeps its derived key pairs between uses.

FindMy.py derives a new :class:`KeyPair` (one elliptic-curve operation) for every key index on
every call, and hashing a key pair derives its public key again. Location fetches walk up to a
week of indices for every accessory on the event loop, and the local Bluetooth matching rebuilds
a two-day window every 15 minutes, so the same keys were derived over and over again.

The accessory below derives every key once, hands out key pairs whose public key and hash are
stored, and can be warmed up from a worker thread so the event loop only reads finished keys.
"""

from __future__ import annotations

import hashlib
import logging
import threading
from datetime import UTC, datetime
from typing import TYPE_CHECKING, final, override

from findmy import FindMyAccessory, KeyPair

if TYPE_CHECKING:
    from findmy import KeyPairType

_LOGGER = logging.getLogger(__name__)

# Number of key indices kept per accessory (15 minutes each, so about 85 days). An accessory
# that was not located for longer than this has a larger search window; the indices beyond the
# limit are derived on demand.
MAX_CACHED_INDICES = 8192

# Number of newest key indices that are searched for an accessory. FindMy.py searches every
# index since the last alignment, which never ends for an accessory that is not located any more
# (empty battery, lost): after years that is ~100,000 indices, i.e. hundreds of requests to
# Apple per fetch and more than a minute of key derivation per local refresh. Such an accessory
# is only searched within this many indices (about 83 days) below the highest possible index;
# the margin to MAX_CACHED_INDICES keeps the whole searched range in the cache.
MAX_SEARCH_INDICES = MAX_CACHED_INDICES - 192

# Deriving keys is CPU-bound Python and OpenSSL work that holds the GIL. Only one thread derives
# at a time, so a restart with many accessories cannot starve the event loop from several
# worker threads at once. The lock is held for a single index only.
_DERIVE_LOCK = threading.Lock()


@final
class CachedKeyPair(KeyPair):
    """A key pair that remembers its public key and hash instead of deriving them per access."""

    def __init__(
        self,
        private_key: bytes,
        key_type: KeyPairType,
        name: str | None = None,
    ) -> None:
        super().__init__(private_key, key_type, name)

        self._adv_key_bytes: bytes = super().adv_key_bytes
        self._hashed_adv_key_bytes: bytes = hashlib.sha256(self._adv_key_bytes).digest()
        # Same value as HasHashedPublicKey.__hash__, so plain and cached key pairs stay equal.
        self._hash: int = int.from_bytes(self._hashed_adv_key_bytes, "big")

    @classmethod
    def from_keypair(cls, key: KeyPair) -> CachedKeyPair:
        """Create a cached copy of a key pair."""
        return cls(key.private_key_bytes, key.key_type, key.name)

    @property
    @override
    def adv_key_bytes(self) -> bytes:
        return self._adv_key_bytes

    @property
    @override
    def hashed_adv_key_bytes(self) -> bytes:
        return self._hashed_adv_key_bytes

    @override
    def __hash__(self) -> int:
        return self._hash

    @override
    def __eq__(self, other: object) -> bool:
        if isinstance(other, CachedKeyPair):
            return self._hashed_adv_key_bytes == other._hashed_adv_key_bytes
        return super().__eq__(other)


@final
class CachedFindMyAccessory(FindMyAccessory):
    """A :class:`FindMyAccessory` whose keys are derived once per index.

    :meth:`keys_at` may be called from the event loop and from worker threads.
    """

    def __init__(self, **kwargs) -> None:
        super().__init__(**kwargs)

        # Key pairs per key index. Only indices in [_cache_floor, _cache_top] are kept.
        self._key_cache: dict[int, tuple[KeyPair, ...]] = {}
        self._cache_top: int = -1
        self._cache_floor: int = 0
        # Secondary keys are valid for many indices; share one object between them.
        self._interned: dict[bytes, CachedKeyPair] = {}

    @override
    def get_min_index(self, dt: datetime) -> int:
        newest = self.get_max_index(datetime.now(tz=UTC))
        return max(super().get_min_index(dt), newest - MAX_SEARCH_INDICES + 1)

    @override
    def keys_at(self, ind: int) -> set[KeyPair]:
        if ind < 0:
            return set()

        keys = self._key_cache.get(ind)
        if keys is None:
            with _DERIVE_LOCK:
                keys = self._key_cache.get(ind)
                if keys is None:
                    keys = tuple(self._intern(key) for key in super().keys_at(ind))
                    self._store(ind, keys)
        return set(keys)

    def warm_keys(self, start: datetime, end: datetime) -> int:
        """Derive the keys possibly in use between two moments; returns the derived index count.

        Meant to be run in a worker thread before the same range is read on the event loop.
        """
        max_index = self.get_max_index(end)
        min_index = max(self.get_min_index(start), max_index - MAX_CACHED_INDICES + 1, 0)

        derived = 0
        # Newest first: this is the order in which a location fetch asks for the keys.
        for ind in range(max_index, min_index - 1, -1):
            if ind not in self._key_cache:
                _ = self.keys_at(ind)
                derived += 1

        if derived:
            _LOGGER.debug(
                "Derived keys for %i indices of %s (%i indices cached)",
                derived,
                self.name,
                len(self._key_cache),
            )
        return derived

    def _intern(self, key: KeyPair) -> CachedKeyPair:
        private_key = key.private_key_bytes
        cached = self._interned.get(private_key)
        if cached is None:
            cached = CachedKeyPair.from_keypair(key)
            self._interned[private_key] = cached
        return cached

    def _store(self, ind: int, keys: tuple[KeyPair, ...]) -> None:
        """Remember the keys of an index and drop indices that fell out of the kept range."""
        if ind > self._cache_top:
            new_floor = max(ind - MAX_CACHED_INDICES + 1, 0)
            for old in [i for i in self._key_cache if i < new_floor]:
                self._evict(old, new_floor)
            self._cache_top = ind
            self._cache_floor = new_floor

        if ind >= self._cache_floor:
            self._key_cache[ind] = keys
        else:
            # Not kept: forget the key objects again unless a kept index shares them.
            self._release(keys, self._key_cache.get(self._cache_floor, ()))

    def _evict(self, ind: int, new_floor: int) -> None:
        keys = self._key_cache.pop(ind)
        self._release(keys, self._key_cache.get(new_floor, ()))

    def _release(self, keys: tuple[KeyPair, ...], still_used: tuple[KeyPair, ...]) -> None:
        for key in keys:
            if key not in still_used:
                _ = self._interned.pop(key.private_key_bytes, None)
