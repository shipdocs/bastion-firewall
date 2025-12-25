
import pytest
import tempfile
import json
import shutil
from pathlib import Path
from bastion.config import ConfigManager

class TestConfigManager:
    @pytest.fixture(autouse=True)
    def setup_config(self):
        """Fixture to handle temp directory setup/teardown automatically"""
        self.test_dir = tempfile.mkdtemp()
        self.config_file = Path(self.test_dir) / 'config.json'
        
        # Save original path
        self.original_path = ConfigManager.CONFIG_PATH
        ConfigManager.CONFIG_PATH = self.config_file
        
        yield
        
        # Cleanup
        ConfigManager.CONFIG_PATH = self.original_path
        shutil.rmtree(self.test_dir)

    def test_default_config_loading(self):
        """Test that missing file results in default secure config"""
        if self.config_file.exists():
            self.config_file.unlink()
            
        config = ConfigManager.load_config()
        
        # Verify critical defaults
        assert config['mode'] == 'learning'
        assert config['default_action'] == 'deny'
        assert config['timeout_seconds'] == 30
        assert config['allow_localhost'] is True

    @pytest.mark.parametrize("input_json, expected_checks, description", [
        # --- HAPPY PATHS ---
        (
            {'mode': 'enforcement', 'timeout_seconds': 60}, 
            {'mode': 'enforcement', 'timeout_seconds': 60}, 
            "Valid enforcement config"
        ),
        (
            {'allow_localhost': False, 'default_action': 'allow'}, 
            {'allow_localhost': False, 'default_action': 'allow'}, 
            "Valid boolean flags"
        ),

        # --- INVALID ENUMS (Should Fallback) ---
        (
            {'mode': 'ultra-secure', 'default_action': 'destroy'}, 
            {'mode': 'learning', 'default_action': 'deny'}, 
            "Invalid enum values fallback to safe defaults"
        ),

        # --- BOUNDARY VALUES (Timeouts) ---
        (
            {'timeout_seconds': 1}, 
            {'timeout_seconds': 5}, 
            "Timeout too low (clamps to 5s)"
        ),
        (
            {'timeout_seconds': 9999}, 
            {'timeout_seconds': 300}, 
            "Timeout too high (clamps to 300s)"
        ),
        (
            {'timeout_seconds': "invalid"}, 
            {'timeout_seconds': 30}, 
            "Non-numeric timeout (defaults to 30s)"
        ),

        # --- TYPE SAFETY ---
        (
            {'cache_decisions': "true"}, 
            {'cache_decisions': True}, 
            "String 'true' converts to boolean True"
        ),
        (
            {'cache_decisions': "false"}, 
            {'cache_decisions': True}, 
            "String 'false' - wait, bool('false') is True in Python!" 
            # Note: This checks specific python behavior bool("string") is True.
            # Ideally config loader might want stricter parsing, but this confirms CURRENT behavior.
        ),
        (
            {'cache_decisions': 0}, 
            {'cache_decisions': False}, 
            "Integer 0 converts to boolean False"
        ),

        # --- SECURITY: PATHS ---
        (
            {'log_file': '/var/log/bastion.log'}, 
            {'log_file': '/var/log/bastion.log'}, 
            "Valid absolute log path"
        ),
        (
            {'log_file': '../../etc/passwd'}, 
            # Should NOT key 'log_file' in result implies it was stripped/ignored
            lambda c: 'log_file' not in c, 
            "Path traversal attempt (should be ignored)"
        ),
        (
            {'log_file': '/home/user/my.log'}, 
            lambda c: 'log_file' not in c, 
            "Unsafe directory (not /var/log) should be ignored"
        ),
    ])
    def test_config_validation_scenarios(self, input_json, expected_checks, description):
        """Smart parametrized test for config validation logic"""
        
        # Write input to file
        with open(self.config_file, 'w') as f:
            json.dump(input_json, f)
            
        # PRO TIP: We exercise the loading logic which calls validate_config internally
        loaded_config = ConfigManager.load_config()
        
        # Verify expectations
        if callable(expected_checks):
            # Advanced: Allow passing a lambda for complex checks
            assert expected_checks(loaded_config), f"Complex check failed: {description}"
        else:
            # Simple dict subset check
            for key, val in expected_checks.items():
                assert loaded_config.get(key) == val, \
                    f"Scenario '{description}' failed for key '{key}'. Expected {val}, got {loaded_config.get(key)}"

