
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


class TestWildcardRules:
    """Tests for wildcard port rules (issue #13)

    Wildcard rules allow a single rule to apply to ALL ports for an application.
    Format: "app_path:*" in JSON, stored and matched with special handling.
    """

    @pytest.fixture(autouse=True)
    def setup_rules(self):
        """Fixture to setup temp rules environment"""
        self.test_dir = tempfile.mkdtemp()
        self.rules_file = Path(self.test_dir) / 'rules.json'
        self.original_path = RuleManager.RULES_PATH
        RuleManager.RULES_PATH = self.rules_file
        yield
        RuleManager.RULES_PATH = self.original_path
        shutil.rmtree(self.test_dir)

    # --- Core Wildcard Matching ---

    def test_wildcard_matches_any_port(self):
        """Wildcard rule should match ANY destination port"""
        manager = RuleManager()
        manager.add_rule("/usr/bin/zoom", 8801, True, all_ports=True)

        # Should match various ports
        assert manager.get_decision("/usr/bin/zoom", 80) is True
        assert manager.get_decision("/usr/bin/zoom", 443) is True
        assert manager.get_decision("/usr/bin/zoom", 8801) is True
        assert manager.get_decision("/usr/bin/zoom", 12345) is True
        assert manager.get_decision("/usr/bin/zoom", 1) is True
        assert manager.get_decision("/usr/bin/zoom", 65535) is True

    def test_wildcard_deny_blocks_all_ports(self):
        """Wildcard DENY rule should block all ports"""
        manager = RuleManager()
        manager.add_rule("/usr/bin/malware", 443, False, all_ports=True)

        assert manager.get_decision("/usr/bin/malware", 80) is False
        assert manager.get_decision("/usr/bin/malware", 443) is False
        assert manager.get_decision("/usr/bin/malware", 8080) is False

    def test_wildcard_does_not_affect_other_apps(self):
        """Wildcard for one app should NOT match other apps"""
        manager = RuleManager()
        manager.add_rule("/usr/bin/zoom", 8801, True, all_ports=True)

        # Different app should return None
        assert manager.get_decision("/usr/bin/firefox", 443) is None
        assert manager.get_decision("/usr/bin/curl", 80) is None

    # --- Precedence Tests (Critical for Security!) ---

    def test_specific_rule_overrides_wildcard_allow(self):
        """Specific DENY should override wildcard ALLOW (security critical)"""
        manager = RuleManager()

        # Allow all ports for zoom
        manager.add_rule("/usr/bin/zoom", 8801, True, all_ports=True)
        # But specifically block port 22 (SSH tunneling prevention)
        manager.add_rule("/usr/bin/zoom", 22, False, all_ports=False)

        # Wildcard should work for most ports
        assert manager.get_decision("/usr/bin/zoom", 443) is True
        assert manager.get_decision("/usr/bin/zoom", 8801) is True

        # But specific rule should block port 22
        assert manager.get_decision("/usr/bin/zoom", 22) is False

    def test_specific_rule_overrides_wildcard_deny(self):
        """Specific ALLOW should override wildcard DENY"""
        manager = RuleManager()

        # Block all ports by default
        manager.add_rule("/usr/bin/app", 80, False, all_ports=True)
        # But allow specific trusted port
        manager.add_rule("/usr/bin/app", 443, True, all_ports=False)

        # Wildcard blocks most
        assert manager.get_decision("/usr/bin/app", 80) is False
        assert manager.get_decision("/usr/bin/app", 8080) is False

        # But specific allows 443
        assert manager.get_decision("/usr/bin/app", 443) is True

    # --- JSON Serialization ---

    def test_wildcard_serialized_as_asterisk(self):
        """Wildcard rules should be stored as 'app:*' in JSON"""
        manager = RuleManager()
        manager.add_rule("/usr/bin/zoom", 8801, True, all_ports=True)

        with open(self.rules_file) as f:
            data = json.load(f)

        # Should have app:* key, NOT app:0 or app:8801
        assert "/usr/bin/zoom:*" in data
        assert "/usr/bin/zoom:0" not in data
        assert "/usr/bin/zoom:8801" not in data
        assert data["/usr/bin/zoom:*"] is True

    def test_wildcard_loaded_from_json(self):
        """Rules with '*' port should be loaded and work correctly"""
        # Pre-create rules file with wildcard
        rules = {
            "/usr/bin/slack:*": True,
            "/usr/bin/teams:443": False
        }
        with open(self.rules_file, 'w') as f:
            json.dump(rules, f)

        manager = RuleManager()

        # Wildcard should match any port
        assert manager.get_decision("/usr/bin/slack", 80) is True
        assert manager.get_decision("/usr/bin/slack", 9999) is True

        # Specific rule only matches that port
        assert manager.get_decision("/usr/bin/teams", 443) is False
        assert manager.get_decision("/usr/bin/teams", 80) is None

    # --- Edge Cases ---

    def test_wildcard_with_name_based_rule(self):
        """Wildcard should work with @name: prefix rules"""
        manager = RuleManager()
        manager.add_rule("@name:electron", 443, True, all_ports=True)

        assert manager.get_decision("@name:electron", 80) is True
        assert manager.get_decision("@name:electron", 443) is True

    def test_mixed_specific_and_wildcard_rules(self):
        """Complex scenario with multiple apps and rule types"""
        manager = RuleManager()

        # App 1: Wildcard allow
        manager.add_rule("/usr/bin/zoom", 8801, True, all_ports=True)

        # App 2: Specific allow only
        manager.add_rule("/usr/bin/curl", 443, True, all_ports=False)

        # App 3: Wildcard deny with specific exception
        manager.add_rule("/usr/bin/game", 80, False, all_ports=True)
        manager.add_rule("/usr/bin/game", 443, True, all_ports=False)

        # Verify App 1 (wildcard allow)
        assert manager.get_decision("/usr/bin/zoom", 12345) is True

        # Verify App 2 (specific only)
        assert manager.get_decision("/usr/bin/curl", 443) is True
        assert manager.get_decision("/usr/bin/curl", 80) is None

        # Verify App 3 (wildcard with exception)
        assert manager.get_decision("/usr/bin/game", 80) is False
        assert manager.get_decision("/usr/bin/game", 443) is True
        assert manager.get_decision("/usr/bin/game", 8080) is False

    def test_persistence_of_wildcard_rules(self):
        """Wildcard rules should persist across manager restarts"""
        manager = RuleManager()
        manager.add_rule("/usr/bin/zoom", 8801, True, all_ports=True)
        manager.add_rule("/usr/bin/zoom", 22, False, all_ports=False)

        # Simulate restart
        new_manager = RuleManager()

        # Verify both rules loaded correctly
        assert new_manager.get_decision("/usr/bin/zoom", 443) is True  # wildcard
        assert new_manager.get_decision("/usr/bin/zoom", 22) is False  # specific

