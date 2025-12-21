
import json
import logging
from pathlib import Path
from typing import Dict, Any

logger = logging.getLogger(__name__)

class ConfigManager:
    """Manages application configuration"""
    
    DEFAULT_CONFIG = {
        'mode': 'learning',
        'cache_decisions': True,
        'default_action': 'deny',
        'timeout_seconds': 30,
        'allow_localhost': True,
        'allow_lan': False,
        'log_decisions': True
    }
    
    CONFIG_PATH = Path('/etc/bastion/config.json')
    
    @classmethod
    def load_config(cls) -> Dict[str, Any]:
        """Load configuration from file or return defaults"""
        if cls.CONFIG_PATH.exists():
            try:
                with open(cls.CONFIG_PATH) as f:
                    config = json.load(f)
                    # Merge with defaults to ensure all keys exist
                    return {**cls.DEFAULT_CONFIG, **config}
            except Exception as e:
                logger.error(f"Error loading config: {e}")
        
        return cls.DEFAULT_CONFIG.copy()
