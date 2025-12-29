"""
Inbound firewall detection and integration.
Currently a stub implementation for GUI compatibility.
"""


class InboundFirewallDetector:
    """
    Detects and manages inbound firewall (UFW) integration.
    Stub implementation - full integration planned for future release.
    """

    @staticmethod
    def detect_firewall():
        """
        Detect which inbound firewall is active (UFW, firewalld, iptables, etc.)

        Returns:
            dict: Firewall status information
        """
        # Stub: Return minimal status
        return {
            'active': False,
            'type': 'none',
            'status': 'Not configured',
            'message': 'Inbound firewall integration coming soon'
        }

    @staticmethod
    def setup_inbound_protection():
        """
        Configure inbound firewall for integration with Bastion.

        Returns:
            tuple: (success: bool, message: str)
        """
        # Stub: Return not implemented message
        return (False, "Inbound firewall integration not yet implemented.\n"
                      "Use UFW or firewalld directly for inbound protection.")
