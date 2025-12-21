
import unittest
import json
import tempfile
import shutil
from pathlib import Path
from bastion.rules import RuleManager

class TestRuleManager(unittest.TestCase):
    def setUp(self):
        self.test_dir = tempfile.mkdtemp()
        self.rules_file = Path(self.test_dir) / 'rules.json'
        # Patch the constant
        RuleManager.RULES_PATH = self.rules_file
        
    def tearDown(self):
        shutil.rmtree(self.test_dir)
        
    def test_load_empty_rules(self):
        manager = RuleManager()
        self.assertEqual(manager.get_all_rules(), {})
        
    def test_add_and_get_rule(self):
        manager = RuleManager()
        manager.add_rule("/usr/bin/test", 80, True)
        
        # Verify in memory
        self.assertTrue(manager.get_decision("/usr/bin/test", 80))
        
        # Verify persistence
        with open(self.rules_file) as f:
            data = json.load(f)
            self.assertTrue(data["/usr/bin/test:80"])
            
    def test_reload_rules(self):
        manager = RuleManager()
        manager.add_rule("/usr/bin/test", 80, True)
        
        # Modify file externally
        with open(self.rules_file, 'w') as f:
            json.dump({"/usr/bin/test:80": False}, f)
            
        manager.reload_rules()
        self.assertFalse(manager.get_decision("/usr/bin/test", 80))

if __name__ == '__main__':
    unittest.main()
