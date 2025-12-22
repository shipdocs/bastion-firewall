
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
    def validate_config(cls, config: Dict[str, Any]) -> Dict[str, Any]:
        """
        Validate configuration values to prevent security issues.
        
        SECURITY: Prevents:
        - Path traversal via malicious log paths
        - Integer overflow via extreme timeout values
        - Unexpected behavior via invalid mode values
        
        Args:
            config: Raw configuration dictionary
            
        Returns:
            Validated and sanitized configuration
            
        Raises:
            ValueError: If configuration contains invalid values
        """
        validated = {}
        
        # Validate mode
        mode = config.get('mode', cls.DEFAULT_CONFIG['mode'])
        if mode not in ['learning', 'enforcement']:
            logger.warning(f"Invalid mode '{mode}', defaulting to 'learning'")
            mode = 'learning'
        validated['mode'] = mode
        
        # Validate timeout_seconds (must be positive integer, reasonable range)
        timeout = config.get('timeout_seconds', cls.DEFAULT_CONFIG['timeout_seconds'])
        try:
            timeout = int(timeout)
            if timeout < 5:
                logger.warning(f"Timeout too low ({timeout}s), using minimum 5s")
                timeout = 5
            elif timeout > 300:
                logger.warning(f"Timeout too high ({timeout}s), using maximum 300s")
                timeout = 300
        except (TypeError, ValueError):
            logger.warning(f"Invalid timeout value, using default 30s")
            timeout = 30
        validated['timeout_seconds'] = timeout
        
        # Validate boolean flags
        for key in ['cache_decisions', 'allow_localhost', 'allow_lan', 'log_decisions']:
            value = config.get(key, cls.DEFAULT_CONFIG.get(key, False))
            validated[key] = bool(value)
        
        # Validate default_action
        default_action = config.get('default_action', cls.DEFAULT_CONFIG['default_action'])
        if default_action not in ['allow', 'deny', 'prompt']:
            logger.warning(f"Invalid default_action '{default_action}', using 'deny'")
            default_action = 'deny'
        validated['default_action'] = default_action
        
        # Validate log_file path if present
        if 'log_file' in config:
            log_file = Path(config['log_file'])
            # SECURITY: Prevent path traversal - must be absolute and in safe locations
            safe_log_dirs = ['/var/log', '/tmp', '/home']
            try:
                log_file = log_file.resolve()  # Resolve symlinks
                is_safe = any(str(log_file).startswith(safe_dir) for safe_dir in safe_log_dirs)
                if not is_safe:
                    logger.warning(f"Log file path {log_file} not in safe directory, ignoring")
                else:
                    validated['log_file'] = str(log_file)
            except Exception as e:
                logger.warning(f"Invalid log_file path: {e}")
        
        return validated
    
    @classmethod
    def load_config(cls) -> Dict[str, Any]:
        """Load configuration from file or return defaults"""
        if cls.CONFIG_PATH.exists():
            try:
                # SECURITY: Check if config path is a symlink to prevent symlink attacks
                if cls.CONFIG_PATH.is_symlink():
                    logger.error(f"Config path {cls.CONFIG_PATH} is a symlink, refusing to load")
                    return cls.DEFAULT_CONFIG.copy()
                
                with open(cls.CONFIG_PATH) as f:
                    raw_config = json.load(f)
                    
                # SECURITY: Validate all configuration values
                validated = cls.validate_config(raw_config)
                
                # Merge with defaults to ensure all keys exist
                return {**cls.DEFAULT_CONFIG, **validated}
            except json.JSONDecodeError as e:
                logger.error(f"Invalid JSON in config file: {e}")
            except Exception as e:
                logger.error(f"Error loading config: {e}")
        
        return cls.DEFAULT_CONFIG.copy()
