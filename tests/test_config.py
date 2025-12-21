
import unittest
import tempfile
import json
import shutil
from pathlib import Path
from bastion.config import ConfigManager

class TestConfigManager(unittest.TestCase):
    def setUp(self):
        self.test_dir = tempfile.mkdtemp()
        self.config_file = Path(self.test_dir) / 'config.json'
        # Patch constant
        ConfigManager.CONFIG_PATH = self.config_file
        
    def tearDown(self):
        shutil.rmtree(self.test_dir)
        
    def test_default_config(self):
        # Ensure file doesn't exist
        if self.config_file.exists():
            self.config_file.unlink()
            
        config = ConfigManager.load_config()
        self.assertEqual(config['mode'], 'learning')
        self.assertTrue(config['cache_decisions'])
        
    def test_load_custom_config(self):
        # Write custom config
        with open(self.config_file, 'w') as f:
            json.dump({'mode': 'enforcement', 'timeout_seconds': 10}, f)
            
        config = ConfigManager.load_config()
        self.assertEqual(config['mode'], 'enforcement')
        self.assertEqual(config['timeout_seconds'], 10)
        # Check defaults are preserved for missing keys
        self.assertTrue(config['allow_localhost'])

if __name__ == '__main__':
    unittest.main()
