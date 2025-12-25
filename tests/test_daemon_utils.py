
import unittest
from unittest.mock import patch, MagicMock
from bastion.daemon import RateLimiter, SystemdNotifier
import time

class TestRateLimiter(unittest.TestCase):
    def test_rate_limiting(self):
        limiter = RateLimiter(max_requests_per_second=5, window_seconds=1)
        # First 5 should succeed
        for _ in range(5):
            self.assertTrue(limiter.allow_request())
        
        # 6th should fail
        self.assertFalse(limiter.allow_request())
        
    def test_rate_recovery(self):
        limiter = RateLimiter(max_requests_per_second=1, window_seconds=0.1)
        self.assertTrue(limiter.allow_request())
        self.assertFalse(limiter.allow_request())
        time.sleep(0.2)
        self.assertTrue(limiter.allow_request())

class TestSystemdNotifier(unittest.TestCase):
    @patch.dict('os.environ', {'NOTIFY_SOCKET': '/run/systemd/notify'})
    @patch('socket.socket')
    def test_notify_ready(self, mock_socket_cls):
        mock_sock = MagicMock()
        mock_socket_cls.return_value = mock_sock
        
        notifier = SystemdNotifier()
        notifier.ready()
        
        mock_sock.sendto.assert_called_with(b'READY=1', b'/run/systemd/notify')

    @patch.dict('os.environ', {}, clear=True)
    def test_notify_no_socket(self):
        notifier = SystemdNotifier()
        self.assertFalse(notifier.notify("READY=1"))

if __name__ == '__main__':
    unittest.main()
