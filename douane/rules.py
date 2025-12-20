
import json
import logging
import time
from pathlib import Path
from typing import Dict, Optional, Tuple
import threading

logger = logging.getLogger(__name__)

class RuleManager:
    """Manages firewall rules and decision caching"""
    
    RULES_PATH = Path('/etc/douane/rules.json')
    
    def __init__(self):
        self._rules: Dict[str, bool] = {}
        self._lock = threading.RLock()
        self.load_rules()
        
    def load_rules(self) -> None:
        """Load rules from disk"""
        with self._lock:
            if self.RULES_PATH.exists():
                try:
                    with open(self.RULES_PATH) as f:
                        self._rules = json.load(f)
                        logger.info(f"Loaded {len(self._rules)} saved rules")
                except Exception as e:
                    logger.error(f"Error loading rules: {e}")
                    self._rules = {}
            else:
                self._rules = {}

    def save_rules(self) -> None:
        """Save rules to disk"""
        with self._lock:
            try:
                self.RULES_PATH.parent.mkdir(parents=True, exist_ok=True)
                with open(self.RULES_PATH, 'w') as f:
                    json.dump(self._rules, f, indent=2)
                logger.info(f"Saved {len(self._rules)} rules to {self.RULES_PATH}")
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
            
