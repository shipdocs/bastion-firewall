
import json
import logging
import time
import os
from pathlib import Path
from typing import Dict, Optional, Tuple
import threading

logger = logging.getLogger(__name__)

class RuleManager:
    """Manages firewall rules and decision caching"""
    
    RULES_PATH = Path('/etc/bastion/rules.json')
    
    def __init__(self):
        self._rules: Dict[str, bool] = {}
        self._lock = threading.RLock()
        self.load_rules()
        
    def load_rules(self) -> None:
        """Load rules from disk, rejecting symlinks."""
        with self._lock:
            if not self.RULES_PATH.exists():
                self._rules = {}
                return
            if self.RULES_PATH.is_symlink():
                logger.error("Rules file is a symlink, refusing to load")
                self._rules = {}
                return
            try:
                with open(self.RULES_PATH) as f:
                    self._rules = json.load(f)
                    logger.info(f"Loaded {len(self._rules)} rules")
            except (json.JSONDecodeError, OSError) as e:
                logger.error(f"Error loading rules: {e}")
                self._rules = {}

    def save_rules(self) -> None:
        """Save rules atomically, rejecting symlinks."""
        with self._lock:
            try:
                if self.RULES_PATH.exists() and self.RULES_PATH.is_symlink():
                    logger.error(f"Rules file is a symlink, refusing to save")
                    return

                self.RULES_PATH.parent.mkdir(parents=True, exist_ok=True)
                temp_path = self.RULES_PATH.with_suffix('.tmp')

                if temp_path.exists():
                    temp_path.unlink()

                fd = os.open(
                    temp_path,
                    os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW,
                    0o600
                )

                with os.fdopen(fd, 'w') as f:
                    json.dump(self._rules, f, indent=2)

                # Atomic rename (replaces existing file)
                # On POSIX systems, this is atomic even if target exists
                temp_path.rename(self.RULES_PATH)

                # Make rules file readable by all users (GUI needs to read it)
                # Keep write access restricted to root only
                os.chmod(self.RULES_PATH, 0o644)
                
                logger.info(f"Saved {len(self._rules)} rules to {self.RULES_PATH}")
            except FileExistsError:
                logger.error(f"Temporary rules file {temp_path} already exists")
            except Exception as e:
                logger.error(f"Error saving rules: {e}")
                
    def reload_rules(self) -> None:
        """Reload rules from disk"""
        logger.info("Reloading rules...")
        self.load_rules()

    def get_decision(self, app_path: str, dest_port: int) -> Optional[bool]:
        """Get cached decision for application and port"""
        key = f"{app_path}:{dest_port}"
        with self._lock:
            return self._rules.get(key)
            
    def add_rule(self, app_path: str, dest_port: int, allow: bool) -> None:
        """Add a permanent rule"""
        key = f"{app_path}:{dest_port}"
        with self._lock:
            self._rules[key] = allow
            self.save_rules()
            
    def get_all_rules(self) -> Dict[str, bool]:
        """Get copy of all rules"""
        with self._lock:
            return self._rules.copy()
            
