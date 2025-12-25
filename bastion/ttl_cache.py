"""
Bastion Firewall - TTL Cache Implementation

Provides time-to-live caching for firewall decisions to prevent
stale cache entries from being reused inappropriately.
"""

import time
import threading
from typing import Optional, Any, Dict
from collections import OrderedDict


class TTLCache:
    """Thread-safe cache with TTL and LRU eviction.
    
    Prevents stale entries from accumulating over time, mitigating risks like
    port reuse or dynamic IP rotation in long-running processes.
    """
    
    def __init__(self, max_size: int = 10000, default_ttl: int = 300):
        """Initialize TTL cache.
        
        Args:
            max_size: Maximum number of entries (LRU eviction)
            default_ttl: Default time-to-live in seconds
        """
        self.max_size = max_size
        self.default_ttl = default_ttl
        self._cache: OrderedDict[str, tuple[Any, float]] = OrderedDict()
        self._lock = threading.RLock()
    
    def get(self, key: str) -> Optional[Any]:
        """Get value from cache if not expired.
        
        Args:
            key: Cache key
            
        Returns:
            Cached value or None if expired/not found
        """
        with self._lock:
            if key not in self._cache:
                return None
            
            value, expiry = self._cache[key]
            
            # Check if expired
            if time.time() > expiry:
                del self._cache[key]
                return None
            
            # Move to end (LRU)
            self._cache.move_to_end(key)
            return value
    
    def set(self, key: str, value: Any, ttl: Optional[int] = None) -> None:
        """Set value in cache with TTL.
        
        Args:
            key: Cache key
            value: Value to cache
            ttl: Time-to-live in seconds (None = use default)
        """
        with self._lock:
            if ttl is None:
                ttl = self.default_ttl
            
            expiry = time.time() + ttl
            
            # Remove if exists (to update position)
            if key in self._cache:
                del self._cache[key]
            
            # Add new entry
            self._cache[key] = (value, expiry)
            
            # Enforce max size (LRU eviction)
            while len(self._cache) > self.max_size:
                # Remove oldest (first) item
                self._cache.popitem(last=False)
    
    def delete(self, key: str) -> bool:
        """Delete entry from cache.
        
        Args:
            key: Cache key
            
        Returns:
            True if deleted, False if not found
        """
        with self._lock:
            if key in self._cache:
                del self._cache[key]
                return True
            return False
    
    def clear(self) -> None:
        """Clear all cache entries."""
        with self._lock:
            self._cache.clear()
    
    def cleanup_expired(self) -> int:
        """Remove all expired entries.
        
        Returns:
            Number of entries removed
        """
        with self._lock:
            now = time.time()
            expired = [k for k, (_, expiry) in self._cache.items() if now > expiry]
            
            for key in expired:
                del self._cache[key]
            
            return len(expired)
    
    def size(self) -> int:
        """Get current cache size."""
        with self._lock:
            return len(self._cache)
    
    def stats(self) -> Dict[str, Any]:
        """Get cache statistics.
        
        Returns:
            Dictionary with size, max_size, default_ttl
        """
        with self._lock:
            return {
                'size': len(self._cache),
                'max_size': self.max_size,
                'default_ttl': self.default_ttl
            }
