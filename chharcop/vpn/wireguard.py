"""
WireGuard client integration for Chharcop.

Manages WireGuard tunnel configuration, connection lifecycle, and status
checking.  WireGuard is the preferred VPN mode: it is lightweight, fast,
and leaves a minimal footprint on the host system.

Requires:
- WireGuard installed on the host (``wg`` and ``wg-quick`` in PATH)
- A valid WireGuard config file (auto-generated or user-supplied)

This module does NOT generate cryptographic keys on behalf of the user;
private key generation is a security-sensitive operation that must be
performed by the user or their key-management system.
"""

from __future__ import annotations

import asyncio
import ipaddress
import platform
import re
import shutil
import subprocess
import tempfile
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional

from loguru import logger


# ---------------------------------------------------------------------------
# Data classes
# ---------------------------------------------------------------------------


@dataclass
class WireGuardConfig:
    """Parsed WireGuard interface configuration."""

    private_key: str
    address: str
    dns: str = "1.1.1.1"
    listen_port: Optional[int] = None

    # Peer section
    peer_public_key: str = ""
    peer_endpoint: str = ""
    peer_allowed_ips: str = "0.0.0.0/0, ::/0"
    peer_persistent_keepalive: int = 25

    def to_wg_conf(self) -> str:
        """Render as a WireGuard config file string."""
        lines = [
            "[Interface]",
            f"PrivateKey = {self.private_key}",
            f"Address = {self.address}",
            f"DNS = {self.dns}",
        ]
        if self.listen_port:
            lines.append(f"ListenPort = {self.listen_port}")
        lines += [
            "",
            "[Peer]",
            f"PublicKey = {self.peer_public_key}",
            f"Endpoint = {self.peer_endpoint}",
            f"AllowedIPs = {self.peer_allowed_ips}",
            f"PersistentKeepalive = {self.peer_persistent_keepalive}",
        ]
        return "\n".join(lines) + "\n"

    @classmethod
    def from_file(cls, path: Path) -> "WireGuardConfig":
        """Parse a WireGuard config file into a :class:`WireGuardConfig`."""
        text = path.read_text(encoding="utf-8")
        return cls._parse(text)

    @classmethod
    def from_string(cls, config_text: str) -> "WireGuardConfig":
        """Parse a WireGuard config string."""
        return cls._parse(config_text)

    @classmethod
    def _parse(cls, text: str) -> "WireGuardConfig":
        def _get(pattern: str, default: str = "") -> str:
            m = re.search(pattern, text, re.IGNORECASE | re.MULTILINE)
            return m.group(1).strip() if m else default

        return cls(
            private_key=_get(r"PrivateKey\s*=\s*(.+)"),
            address=_get(r"Address\s*=\s*(.+)"),
            dns=_get(r"DNS\s*=\s*(.+)", "1.1.1.1"),
            listen_port=int(_get(r"ListenPort\s*=\s*(\d+)", "0")) or None,
            peer_public_key=_get(r"PublicKey\s*=\s*(.+)"),
            peer_endpoint=_get(r"Endpoint\s*=\s*(.+)"),
            peer_allowed_ips=_get(r"AllowedIPs\s*=\s*(.+)", "0.0.0.0/0, ::/0"),
            peer_persistent_keepalive=int(_get(r"PersistentKeepalive\s*=\s*(\d+)", "25")),
        )


@dataclass
class WireGuardStatus:
    """Current WireGuard tunnel state."""

    installed: bool = False
    connected: bool = False
    interface: str = ""
    public_ip: Optional[str] = None
    error: Optional[str] = None


# ---------------------------------------------------------------------------
# WireGuardClient
# ---------------------------------------------------------------------------


class WireGuardClient:
    """
    Manages a WireGuard tunnel for Chharcop scans.

    Usage::

        client = WireGuardClient()
        if not client.is_installed():
            print(client.install_instructions())
        else:
            await client.connect(config=WireGuardConfig.from_file(Path("wg0.conf")))
            # ... run scans ...
            await client.disconnect()
    """

    # Temporary interface name used when managing a config in-process
    INTERFACE_NAME: str = "chharcop0"

    def __init__(self, config_dir: Path | None = None) -> None:
        self.config_dir = config_dir or Path.home() / ".config" / "chharcop" / "wireguard"
        self.config_dir.mkdir(parents=True, exist_ok=True)
        self._active_interface: Optional[str] = None

    # ------------------------------------------------------------------
    # Installation check
    # ------------------------------------------------------------------

    def is_installed(self) -> bool:
        """Return True if both ``wg`` and ``wg-quick`` are available in PATH."""
        return shutil.which("wg") is not None and shutil.which("wg-quick") is not None

    def install_instructions(self) -> str:
        """Return platform-appropriate WireGuard installation instructions."""
        system = platform.system()
        if system == "Windows":
            return (
                "WireGuard not found.\n"
                "Install from: https://www.wireguard.com/install/\n"
                "  1. Download the Windows installer\n"
                "  2. Run the installer — WireGuard will be added to PATH\n"
                "  3. Restart your terminal and re-run Chharcop"
            )
        elif system == "Darwin":
            return (
                "WireGuard not found.\n"
                "Install via Homebrew: brew install wireguard-tools\n"
                "Or via App Store: WireGuard (official)"
            )
        else:  # Linux
            return (
                "WireGuard not found.\n"
                "Install via package manager:\n"
                "  Ubuntu/Debian: sudo apt install wireguard\n"
                "  Fedora/RHEL:   sudo dnf install wireguard-tools\n"
                "  Arch:          sudo pacman -S wireguard-tools"
            )

    # ------------------------------------------------------------------
    # Config management
    # ------------------------------------------------------------------

    def save_config(self, config: WireGuardConfig, name: str = INTERFACE_NAME) -> Path:
        """Write a WireGuard config to disk and return the path."""
        path = self.config_dir / f"{name}.conf"
        path.write_text(config.to_wg_conf(), encoding="utf-8")
        path.chmod(0o600)  # WireGuard requires strict permissions
        logger.debug("Saved WireGuard config to {}", path)
        return path

    def load_config(self, name: str = INTERFACE_NAME) -> WireGuardConfig:
        """Load a previously saved config by interface name."""
        path = self.config_dir / f"{name}.conf"
        if not path.exists():
            raise FileNotFoundError(f"No WireGuard config for interface '{name}'")
        return WireGuardConfig.from_file(path)

    # ------------------------------------------------------------------
    # Connection lifecycle
    # ------------------------------------------------------------------

    async def connect(
        self,
        config: WireGuardConfig | None = None,
        interface: str = INTERFACE_NAME,
    ) -> WireGuardStatus:
        """
        Bring up a WireGuard tunnel.

        Args:
            config: Config to use.  If ``None``, loads the stored config for
                *interface*.
            interface: Interface name (default: ``chharcop0``).

        Returns:
            :class:`WireGuardStatus` reflecting the new state.
        """
        if not self.is_installed():
            return WireGuardStatus(
                installed=False,
                error="WireGuard not installed. " + self.install_instructions(),
            )

        if config is not None:
            conf_path = self.save_config(config, interface)
        else:
            conf_path = self.config_dir / f"{interface}.conf"
            if not conf_path.exists():
                return WireGuardStatus(
                    installed=True,
                    error=f"No config found for interface '{interface}'",
                )

        logger.info("Connecting WireGuard interface {}", interface)
        try:
            await self._run(["wg-quick", "up", str(conf_path)])
            self._active_interface = interface
        except subprocess.CalledProcessError as exc:
            stderr = exc.stderr or ""
            return WireGuardStatus(
                installed=True,
                connected=False,
                error=f"wg-quick up failed: {stderr}",
            )

        status = await self.status()
        logger.info("WireGuard connected: {}", status)
        return status

    async def disconnect(self, interface: str | None = None) -> bool:
        """
        Bring down the WireGuard tunnel.

        Returns True on success, False if not connected or WireGuard not found.
        """
        iface = interface or self._active_interface or self.INTERFACE_NAME
        conf_path = self.config_dir / f"{iface}.conf"
        if not conf_path.exists():
            logger.warning("No config to disconnect for interface {}", iface)
            return False

        try:
            await self._run(["wg-quick", "down", str(conf_path)])
            self._active_interface = None
            logger.info("WireGuard disconnected")
            return True
        except subprocess.CalledProcessError as exc:
            logger.error("wg-quick down failed: {}", exc.stderr)
            return False

    async def status(self) -> WireGuardStatus:
        """Query the current WireGuard tunnel state."""
        if not self.is_installed():
            return WireGuardStatus(installed=False)

        try:
            result = await self._run(["wg", "show"], capture=True)
            connected = bool(result.strip())
            interface = self._active_interface or ""
            public_ip = await self._get_public_ip() if connected else None
            return WireGuardStatus(
                installed=True,
                connected=connected,
                interface=interface,
                public_ip=public_ip,
            )
        except Exception as exc:
            return WireGuardStatus(installed=True, error=str(exc))

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------

    async def _get_public_ip(self) -> Optional[str]:
        """Fetch the public IP address via ipify."""
        try:
            import httpx

            async with httpx.AsyncClient(timeout=5) as client:
                resp = await client.get("https://api.ipify.org?format=json")
                return resp.json().get("ip")
        except Exception:
            return None

    @staticmethod
    async def _run(
        cmd: list[str], capture: bool = False
    ) -> str:
        """Run a subprocess command asynchronously."""
        proc = await asyncio.create_subprocess_exec(
            *cmd,
            stdout=asyncio.subprocess.PIPE if capture else None,
            stderr=asyncio.subprocess.PIPE,
        )
        stdout, stderr = await proc.communicate()
        if proc.returncode != 0:
            err = subprocess.CalledProcessError(proc.returncode, cmd)
            err.stderr = stderr.decode(errors="replace") if stderr else ""
            raise err
        return stdout.decode(errors="replace") if stdout else ""
