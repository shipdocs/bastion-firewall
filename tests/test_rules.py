
import pytest
import os
import json
import tempfile
import shutil
import threading
from pathlib import Path
from bastion.rules import RuleManager

class TestRuleManagerSmart:
    
    @pytest.fixture(autouse=True)
    def setup_rules(self):
        """Fixture to setup temp rules environment"""
        self.test_dir = tempfile.mkdtemp()
        self.rules_file = Path(self.test_dir) / 'rules.json'
        
        # Patch the class constant properly
        # Note: In a real scenario, dependency injection would be cleaner,
        # but patching works for this codebase structure.
        self.original_path = RuleManager.RULES_PATH
        RuleManager.RULES_PATH = self.rules_file
        
        yield
        
        # Cleanup
        RuleManager.RULES_PATH = self.original_path
        shutil.rmtree(self.test_dir)

    def test_basic_crud_operations(self):
        """Verify Create, Read operations"""
        manager = RuleManager()
        
        # 1. Start empty
        assert manager.get_all_rules() == {}
        
        # 2. Add Rule (Allow)
        manager.add_rule("/usr/bin/python", 443, True)
        assert manager.get_decision("/usr/bin/python", 443) is True
        
        # 3. Add Rule (Block)
        manager.add_rule("/usr/bin/curl", 80, False)
        assert manager.get_decision("/usr/bin/curl", 80) is False
        
        # 4. Unknown rule
        assert manager.get_decision("/usr/bin/unknown", 123) is None

    def test_persistence_logic(self):
        """Verify rules are actually saved to disk and reloadable"""
        manager = RuleManager()
        manager.add_rule("/bin/test", 8080, True)
        
        # Verify file exists
        assert self.rules_file.exists()
        
        # Create NEW manager instance to simulate restart
        new_manager = RuleManager()
        assert new_manager.get_decision("/bin/test", 8080) is True

    def test_corrupt_json_handling(self):
        """Manager should handle corrupt files gracefully (empty rules)"""
        # Write garbage to file
        with open(self.rules_file, 'w') as f:
            f.write("{ invalid json ...")
            
        manager = RuleManager()
        # Should start empty, logging error but not crashing
        assert manager.get_all_rules() == {}

    def test_security_symlink_attack_prevention(self):
        """Ensure manager refuses to load or save if file is a symlink"""
        # Create a dummy target
        target = Path(self.test_dir) / 'target.json'
        target.touch()
        
        # Create symlink: rules.json -> target.json
        # NOTE: Config file usually shouldn't be a symlink for security
        os.symlink(target, self.rules_file)
        
        # 1. Test Load Prevention
        manager = RuleManager()
        assert manager.get_all_rules() == {} # Should refuse to load
        
        # 2. Test Save Prevention
        # If it wrote through symlink, 'target.json' would change
        manager.add_rule("/bin/attack", 666, True)
        
        # Verify target is EMPTY (save aborted)
        assert target.stat().st_size == 0
        
        # Verify memory might have it, but persistence failed
        # Actually persistence implementation logs error and continues?
        # Let's check logic: returning early prevents save.
        
        # Verify reload clears it (since save failed)
        manager.reload_rules()
        assert manager.get_decision("/bin/attack", 666) is None

    @pytest.mark.parametrize("app, port, allow", [
        ("/usr/bin/ssh", 22, True),
        ("/usr/bin/game", 5000, False),
        ("strange path with spaces", 80, True),
    ])
    def test_rule_combinations(self, app, port, allow):
        """Parametrized test for various rule inputs"""
        manager = RuleManager()
        manager.add_rule(app, port, allow)
        
        # Verify correct decision stored
        assert manager.get_decision(app, port) == allow
        
        # Verify key format in file
        with open(self.rules_file) as f:
            data = json.load(f)
            expected_key = f"{app}:{port}"
            assert expected_key in data
            assert data[expected_key] == allow

    def test_atomic_save_permissions(self):
        """Verify saved files have correct permissions (644)"""
        manager = RuleManager()
        manager.add_rule("/bin/ls", 80, True)
        
        mode = self.rules_file.stat().st_mode
        # Check explicit octal matching (roughly validation)
        # 0o644 -> rw-r--r--
        assert mode & 0o777 == 0o644

