"""
Chharcop VPN integration module.

Provides WireGuard and Tor proxy support for anonymous scanning.
Use :class:`~chharcop.vpn.manager.VpnManager` to select and manage the
active VPN mode for an investigation.
"""

from chharcop.vpn.manager import VpnManager, VpnMode, VpnStatus
from chharcop.vpn.tor_integration import TorProxy
from chharcop.vpn.wireguard import WireGuardClient

__all__ = ["VpnManager", "VpnMode", "VpnStatus", "WireGuardClient", "TorProxy"]
