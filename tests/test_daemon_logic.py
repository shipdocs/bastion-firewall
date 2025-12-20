
import unittest
from unittest.mock import MagicMock, patch
from douane.daemon import DouaneDaemon, PacketInfo
from douane.rules import RuleManager

class TestDaemonIntegration(unittest.TestCase):
    """
    Integration-style tests for the Daemon logic.
    We mock the external inputs (NetfilterQueue, Socket) but test the internal decision logic flows.
    """
    
    def setUp(self):
        # Prevent actually loading config/rules from disk during test init
        with patch('douane.config.ConfigManager.load_config', return_value={'mode': 'enforcement'}):
            self.daemon = DouaneDaemon()
            # Reset rules for test
            self.daemon.rule_manager._rules = {}
            self.daemon.pending_requests = {}
        
    @patch('douane.daemon.should_auto_allow')
    def test_packet_blocking_logic(self, mock_auto_allow):
        """
        Critical Test: Ensure unknown packets are actually BLOCKED (return False) 
        if the GUI (simulated) says Deny.
        """
        # Setup: Auto-allow is False (not a whitelist app)
        mock_auto_allow.return_value = (False, "")
        
        # Setup: Mock GUI socket to return "Deny"
        mock_socket = MagicMock()
        # Side effect: receive returns JSON for "deny"
        # Protocol: Daemon sends json\n, waits for json response
        import json
        mock_socket.recv.return_value = json.dumps({'allow': False, 'permanent': False}).encode()
        self.daemon.gui_socket = mock_socket
        
        # Packet Info
        pkt = PacketInfo("192.168.1.5", 12345, "8.8.8.8", 53, "tcp")
        pkt.app_name = "malware.exe"
        pkt.app_path = "/tmp/malware.exe"
        
        # EXECUTE
        # In enforcement mode, with no rule, and GUI saying Deny...
        # It should return False.
        decision = self.daemon._handle_packet(pkt)
        
        # VERIFY
        self.assertFalse(decision, "Daemon SHOULD return False (Deny) when GUI says deny in enforcement mode")
        
        # Verify it actually asked the GUI
        mock_socket.sendall.assert_called()

    @patch('douane.daemon.should_auto_allow')
    def test_packet_allow_logic(self, mock_auto_allow):
        """Test allowing a packet"""
        mock_auto_allow.return_value = (False, "")
        mock_socket = MagicMock()
        import json
        mock_socket.recv.return_value = json.dumps({'allow': True, 'permanent': False}).encode()
        self.daemon.gui_socket = mock_socket
        
        pkt = PacketInfo("192.168.1.5", 12345, "8.8.8.8", 443, "tcp")
        pkt.app_name = "browser"
        pkt.app_path = "/usr/bin/browser"
        
        decision = self.daemon._handle_packet(pkt)
        
        self.assertTrue(decision, "Daemon SHOULD return True (Allow) when GUI says allow")

    def test_learning_mode_default_allow(self):
        """Test logic in learning mode"""
        self.daemon.config['mode'] = 'learning'
        # No GUI socket needed for learning mode (it just sends and returns True)
        # But we mock it to avoid errors log
        self.daemon.gui_socket = MagicMock()
        
        pkt = PacketInfo("1.2.3.4", 123, "5.6.7.8", 80, "tcp")
        pkt.app_name = "test"
        pkt.app_path = "/bin/test"
        
        decision = self.daemon._handle_packet(pkt)
        self.assertTrue(decision, "Learning mode should ALWAYS allow")

if __name__ == '__main__':
    unittest.main()
