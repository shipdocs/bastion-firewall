
import pytest
from unittest.mock import patch
from bastion.ttl_cache import TTLCache

class TestTTLCache:
    
    @pytest.fixture
    def cache(self):
        """Standard cache fixture (size=3, ttl=100)"""
        return TTLCache(max_size=3, default_ttl=100)

    def test_basic_set_get(self, cache):
        cache.set("key1", "val1")
        assert cache.get("key1") == "val1"
        assert cache.size() == 1

    @patch('time.time')
    def test_ttl_expiry(self, mock_time, cache):
        """Smart test: Simulate time passing without sleep"""
        # Start at t=1000
        mock_time.return_value = 1000.0
        cache.set("key", "value", ttl=10) # Expires at 1010
        
        # Check immediately (t=1000) -> Should exist
        assert cache.get("key") == "value"
        
        # Fast forward time to t=1011 (expired)
        mock_time.return_value = 1011.0
        assert cache.get("key") is None
        assert cache.size() == 0 # Should be auto-removed on access

    def test_lru_eviction_strategy(self):
        """Verify oldest items are evicted when full"""
        cache = TTLCache(max_size=3) # Small size for testing
        
        # Fill cache
        cache.set("A", 1)
        cache.set("B", 2)
        cache.set("C", 3)
        assert cache.size() == 3
        
        # Add 4th item -> "A" (oldest) should be evicted
        cache.set("D", 4)
        
        assert cache.get("A") is None
        assert cache.get("B") == 2
        assert cache.get("C") == 3
        assert cache.get("D") == 4
        assert cache.size() == 3

    def test_lru_update_on_access(self):
        """Accessing an item should make it 'new' again for LRU"""
        cache = TTLCache(max_size=3)
        
        cache.set("A", 1)
        cache.set("B", 2)
        cache.set("C", 3)
        
        # Access "A" (making it most recent)
        val = cache.get("A")
        assert val == 1
        
        # Add "D" -> "B" should be evicted now ("A" was saved)
        cache.set("D", 4)
        
        assert cache.get("B") is None # Evicted
        assert cache.get("A") == 1    # Saved
        assert cache.get("D") == 4

    @patch('time.time')
    def test_cleanup_expired_batch(self, mock_time, cache):
        """Test bulk cleanup of expired items"""
        mock_time.return_value = 1000.0
        
        cache.set("fresh", "val", ttl=100)  # Exp 1100
        cache.set("stale1", "val", ttl=10)  # Exp 1010
        cache.set("stale2", "val", ttl=10)  # Exp 1010
        
        # Fast forward to 1050
        mock_time.return_value = 1050.0
        
        removed = cache.cleanup_expired()
        
        assert removed == 2
        assert cache.get("fresh") == "val"
        assert cache.get("stale1") is None

    @pytest.mark.parametrize("operation, input_key, check_val", [
        ("delete", "key1", None),
        ("overwrite", "key1", "new_value"),
    ])
    def test_operations_parametrized(self, operation, input_key, check_val, cache):
        """Parametrized structural test"""
        cache.set("key1", "initial")
        
        if operation == "delete":
            assert cache.delete(input_key) is True
            assert cache.get(input_key) is None
            assert cache.delete("non-existent") is False
            
        elif operation == "overwrite":
            # Overwriting updates value
            cache.set(input_key, "new_value")
            assert cache.get(input_key) == "new_value"

    def test_clear_and_stats(self, cache):
        cache.set("k", "v")
        stats = cache.stats()
        
        assert stats['size'] == 1
        assert stats['max_size'] == 3
        
        cache.clear()
        assert cache.size() == 0
        assert cache.stats()['size'] == 0
