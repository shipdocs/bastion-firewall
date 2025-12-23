
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
        """Load rules from disk"""
        with self._lock:
            if self.RULES_PATH.exists():
                try:
                    # SECURITY: Check if rules file is a symlink to prevent symlink attacks
                    if self.RULES_PATH.is_symlink():
                        logger.error(f"Rules file {self.RULES_PATH} is a symlink, refusing to load")
                        logger.error("This could be a symlink attack. Using empty ruleset.")
                        self._rules = {}
                        return
                        
                    with open(self.RULES_PATH) as f:
                        self._rules = json.load(f)
                        logger.info(f"Loaded {len(self._rules)} saved rules")
                except json.JSONDecodeError as e:
                    logger.error(f"Invalid JSON in rules file: {e}")
                    self._rules = {}
                except Exception as e:
                    logger.error(f"Error loading rules: {e}")
                    self._rules = {}
            else:
                self._rules = {}

    def save_rules(self) -> None:
        """
        Save rules to disk with security checks.
        
        SECURITY: Prevents symlink attacks by:
        1. Creating temporary file with O_EXCL flag
        2. Checking for existing symlinks
        3. Using atomic rename operation
        """
        with self._lock:
            try:
                # SECURITY: Check if target is a symlink before writing
                if self.RULES_PATH.exists() and self.RULES_PATH.is_symlink():
                    logger.error(f"Rules file {self.RULES_PATH} is a symlink, refusing to save")
                    logger.error("This could be a symlink attack. Rules NOT saved.")
                    return
                
                # Create parent directory if needed
                self.RULES_PATH.parent.mkdir(parents=True, exist_ok=True)
                
                # SECURITY: Write to temporary file first, then atomic rename
                # This prevents partial writes and symlink TOCTOU attacks
                temp_path = self.RULES_PATH.with_suffix('.tmp')
                
                # Remove temp file if it exists
                if temp_path.exists():
                    temp_path.unlink()
                
                # SECURITY: Use O_EXCL to prevent race conditions
                # O_NOFOLLOW prevents following symlinks during creation
                # Use 0o600 (root-only) even for temp file to prevent information disclosure
                fd = os.open(
                    temp_path,
                    os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW,
                    0o600  # SECURITY FIX: root-only permissions for temp file
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
            
