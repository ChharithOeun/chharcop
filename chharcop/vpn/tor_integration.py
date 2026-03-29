"""
Tor SOCKS proxy integration for Chharcop.

Provides anonymous scanning by routing HTTP requests through the Tor network
via a local SOCKS5 proxy.  Supports:
- Detecting an existing Tor daemon
- Launching Tor via the ``stem`` Python library (optional)
- Requesting a new Tor circuit (new identity) between scans
- Providing an httpx-compatible proxy URL for collectors

Requires:
- Tor installed and running  (or the ``stem`` package for in-process control)
"""

from __future__ import annotations

import asyncio
import platform
import shutil
import socket
from dataclasses import dataclass
from typing import Optional

import httpx
from loguru import logger


# ---------------------------------------------------------------------------
# Data classes
# ---------------------------------------------------------------------------


@dataclass
class TorStatus:
    """Current Tor connectivity state."""

    installed: bool = False
    running: bool = False
    socks_host: str = "127.0.0.1"
    socks_port: int = 9050
    control_port: int = 9051
    public_ip: Optional[str] = None
    circuit_id: Optional[str] = None
    error: Optional[str] = None

    @property
    def proxy_url(self) -> str:
        return f"socks5://{self.socks_host}:{self.socks_port}"


# ---------------------------------------------------------------------------
# TorProxy
# ---------------------------------------------------------------------------


class TorProxy:
    """
    Tor SOCKS proxy client for anonymous HTTP requests.

    Usage::

        tor = TorProxy()
        status = await tor.connect()
        if status.running:
            # Use proxy in httpx:
            async with httpx.AsyncClient(proxies=status.proxy_url) as client:
                resp = await client.get("https://check.torproject.org/api/ip")

            await tor.new_identity()   # rotate circuit
            await tor.disconnect()
    """

    DEFAULT_SOCKS_PORT: int = 9050
    DEFAULT_CONTROL_PORT: int = 9051
    CHECK_URL: str = "https://check.torproject.org/api/ip"

    def __init__(
        self,
        socks_host: str = "127.0.0.1",
        socks_port: int = DEFAULT_SOCKS_PORT,
        control_port: int = DEFAULT_CONTROL_PORT,
        control_password: str = "",
    ) -> None:
        self.socks_host = socks_host
        self.socks_port = socks_port
        self.control_port = control_port
        self.control_password = control_password
        self._stem_controller = None  # type: ignore[assignment]

    # ------------------------------------------------------------------
    # Installation check
    # ------------------------------------------------------------------

    def is_installed(self) -> bool:
        """Return True if the ``tor`` binary is available in PATH."""
        return shutil.which("tor") is not None

    def install_instructions(self) -> str:
        """Return platform-appropriate Tor installation instructions."""
        system = platform.system()
        if system == "Windows":
            return (
                "Tor not found.\n"
                "Install Tor Browser Bundle (includes Tor daemon):\n"
                "  https://www.torproject.org/download/\n"
                "\nOr install Expert Bundle for CLI use:\n"
                "  https://www.torproject.org/download/tor/"
            )
        elif system == "Darwin":
            return "Tor not found.\nInstall: brew install tor\nStart:   brew services start tor"
        else:
            return (
                "Tor not found.\n"
                "Install:\n"
                "  Ubuntu/Debian: sudo apt install tor\n"
                "  Fedora/RHEL:   sudo dnf install tor\n"
                "  Arch:          sudo pacman -S tor\n"
                "Start:   sudo systemctl start tor"
            )

    # ------------------------------------------------------------------
    # Connection lifecycle
    # ------------------------------------------------------------------

    async def connect(self) -> TorStatus:
        """
        Verify Tor is reachable and return its status.

        Does NOT start the Tor daemon; call ``start_daemon()`` first if needed.
        """
        status = TorStatus(
            installed=self.is_installed(),
            socks_host=self.socks_host,
            socks_port=self.socks_port,
            control_port=self.control_port,
        )

        if not self._port_open(self.socks_host, self.socks_port):
            status.running = False
            status.error = (
                f"Tor SOCKS proxy not reachable at "
                f"{self.socks_host}:{self.socks_port}. "
                "Is Tor running?"
            )
            logger.warning(status.error)
            return status

        status.running = True
        status.public_ip = await self._get_tor_ip()
        logger.info("Tor proxy active at {}:{}", self.socks_host, self.socks_port)
        return status

    async def disconnect(self) -> None:
        """Release the stem controller if held."""
        if self._stem_controller is not None:
            try:
                self._stem_controller.close()
            except Exception:
                pass
            self._stem_controller = None
        logger.debug("Tor proxy disconnected")

    async def new_identity(self) -> bool:
        """
        Request a new Tor circuit (NEWNYM signal).

        This rotates the exit node so successive scans appear to come from
        different IP addresses.  Requires the Tor control port to be reachable
        and the ``stem`` library to be installed.

        Returns True on success, False otherwise.
        """
        try:
            controller = await self._get_controller()
            if controller is None:
                logger.warning("stem not available — cannot request new identity")
                return False
            controller.signal("NEWNYM")
            logger.info("Tor new identity requested")
            await asyncio.sleep(1)  # give Tor time to build new circuit
            return True
        except Exception as exc:
            logger.warning("NEWNYM failed: {}", exc)
            return False

    async def start_daemon(self) -> bool:
        """
        Launch the Tor daemon in the background (if not already running).

        Returns True if Tor started successfully, False otherwise.
        """
        if self._port_open(self.socks_host, self.socks_port):
            logger.info("Tor already running on port {}", self.socks_port)
            return True

        if not self.is_installed():
            logger.error("Tor not installed. {}", self.install_instructions())
            return False

        try:
            proc = await asyncio.create_subprocess_exec(
                "tor",
                "--SocksPort", str(self.socks_port),
                "--ControlPort", str(self.control_port),
                stdout=asyncio.subprocess.DEVNULL,
                stderr=asyncio.subprocess.DEVNULL,
            )
            # Wait up to 15 seconds for Tor to bootstrap
            for _ in range(15):
                await asyncio.sleep(1)
                if self._port_open(self.socks_host, self.socks_port):
                    logger.info("Tor daemon started (pid {})", proc.pid)
                    return True
            logger.error("Tor daemon did not start within 15 seconds")
            proc.terminate()
            return False
        except Exception as exc:
            logger.error("Failed to start Tor: {}", exc)
            return False

    # ------------------------------------------------------------------
    # HTTP helper
    # ------------------------------------------------------------------

    def get_http_client(self, timeout: float = 30.0) -> httpx.AsyncClient:
        """
        Return an httpx AsyncClient pre-configured to use the Tor SOCKS proxy.

        Usage::

            async with tor.get_http_client() as client:
                resp = await client.get("https://example.com")
        """
        proxy_url = f"socks5://{self.socks_host}:{self.socks_port}"
        return httpx.AsyncClient(
            proxies={"all://": proxy_url},
            timeout=timeout,
            follow_redirects=True,
        )

    async def current_status(self) -> TorStatus:
        """Return the current Tor proxy status."""
        return await self.connect()

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------

    @staticmethod
    def _port_open(host: str, port: int, timeout: float = 2.0) -> bool:
        """Check if a TCP port is open."""
        try:
            with socket.create_connection((host, port), timeout=timeout):
                return True
        except OSError:
            return False

    async def _get_tor_ip(self) -> Optional[str]:
        """Fetch the public IP seen through Tor."""
        try:
            async with self.get_http_client(timeout=15) as client:
                resp = await client.get(self.CHECK_URL)
                data = resp.json()
                return data.get("IP")
        except Exception as exc:
            logger.debug("Could not fetch Tor IP: {}", exc)
            return None

    async def _get_controller(self):  # type: ignore[return]
        """Return a stem controller, creating one if needed."""
        if self._stem_controller is not None:
            return self._stem_controller
        try:
            from stem import Signal
            from stem.control import Controller

            controller = Controller.from_port(
                address=self.socks_host, port=self.control_port
            )
            controller.authenticate(password=self.control_password)
            self._stem_controller = controller
            return controller
        except ImportError:
            logger.warning(
                "stem library not installed. Install: pip install stem"
            )
            return None
        except Exception as exc:
            logger.warning("Could not connect to Tor control port: {}", exc)
            return None
