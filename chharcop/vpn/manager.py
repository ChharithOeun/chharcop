"""
VPN mode manager for Chharcop.

Provides a unified interface for selecting between no VPN, WireGuard, and Tor.
Tracks connection state and exposes speed-test comparison utilities.
"""

from __future__ import annotations

import asyncio
import time
from enum import Enum
from typing import Any, Optional

import httpx
from loguru import logger
from pydantic import BaseModel, Field

from chharcop.vpn.tor_integration import TorProxy, TorStatus
from chharcop.vpn.wireguard import WireGuardClient, WireGuardConfig, WireGuardStatus


# ---------------------------------------------------------------------------
# Enums / models
# ---------------------------------------------------------------------------


class VpnMode(str, Enum):
    """Available VPN modes."""

    NONE = "none"
    WIREGUARD = "wireguard"
    TOR = "tor"


class SpeedResult(BaseModel):
    """Result of a single latency/speed test."""

    mode: VpnMode
    latency_ms: Optional[float] = None
    success: bool = False
    error: Optional[str] = None


class VpnStatus(BaseModel):
    """Current VPN manager state."""

    mode: VpnMode = VpnMode.NONE
    connected: bool = False
    public_ip: Optional[str] = None
    speed_ms: Optional[float] = None
    error: Optional[str] = None

    def to_dict(self) -> dict[str, Any]:
        return {
            "mode": self.mode.value,
            "connected": self.connected,
            "ip": self.public_ip,
            "speed": self.speed_ms,
        }


# ---------------------------------------------------------------------------
# VpnManager
# ---------------------------------------------------------------------------


class VpnManager:
    """
    Unified VPN lifecycle manager.

    Usage::

        manager = VpnManager()

        # Connect with WireGuard
        status = await manager.connect(VpnMode.WIREGUARD, wg_config=my_config)

        # Run your scans here …

        # Disconnect
        await manager.disconnect()

        # Speed comparison
        results = await manager.speed_test_all()
        for r in results:
            print(f"{r.mode}: {r.latency_ms:.0f} ms")
    """

    # URL used for latency probing
    PROBE_URL: str = "https://www.example.com"

    def __init__(
        self,
        wg_config_dir=None,  # type: ignore[assignment]
        tor_socks_port: int = 9050,
        tor_control_port: int = 9051,
    ) -> None:
        self._mode: VpnMode = VpnMode.NONE
        self._connected: bool = False
        self._public_ip: Optional[str] = None

        self._wg = WireGuardClient(config_dir=wg_config_dir)
        self._tor = TorProxy(socks_port=tor_socks_port, control_port=tor_control_port)

    # ------------------------------------------------------------------
    # Connection lifecycle
    # ------------------------------------------------------------------

    async def connect(
        self,
        mode: VpnMode,
        wg_config: WireGuardConfig | None = None,
    ) -> VpnStatus:
        """
        Connect using the specified VPN mode.

        Args:
            mode: :class:`VpnMode` to activate.
            wg_config: WireGuard config (required when mode is WIREGUARD).

        Returns:
            :class:`VpnStatus` reflecting the new state.
        """
        if mode == VpnMode.NONE:
            self._mode = VpnMode.NONE
            self._connected = True
            self._public_ip = await self._get_direct_ip()
            return VpnStatus(
                mode=VpnMode.NONE,
                connected=True,
                public_ip=self._public_ip,
            )

        if mode == VpnMode.WIREGUARD:
            wg_status = await self._wg.connect(config=wg_config)
            self._mode = VpnMode.WIREGUARD
            self._connected = wg_status.connected
            self._public_ip = wg_status.public_ip
            return VpnStatus(
                mode=VpnMode.WIREGUARD,
                connected=wg_status.connected,
                public_ip=wg_status.public_ip,
                error=wg_status.error,
            )

        if mode == VpnMode.TOR:
            tor_status = await self._tor.connect()
            self._mode = VpnMode.TOR
            self._connected = tor_status.running
            self._public_ip = tor_status.public_ip
            return VpnStatus(
                mode=VpnMode.TOR,
                connected=tor_status.running,
                public_ip=tor_status.public_ip,
                error=tor_status.error,
            )

        raise ValueError(f"Unknown VPN mode: {mode}")

    async def disconnect(self) -> None:
        """Disconnect the active VPN tunnel."""
        if self._mode == VpnMode.WIREGUARD:
            await self._wg.disconnect()
        elif self._mode == VpnMode.TOR:
            await self._tor.disconnect()
        self._mode = VpnMode.NONE
        self._connected = False
        self._public_ip = None
        logger.info("VPN disconnected")

    async def rotate(self) -> bool:
        """
        Rotate the active connection for anonymity.

        - For Tor: request a new identity.
        - For WireGuard: not applicable (returns True).
        - For NONE: no-op (returns True).
        """
        if self._mode == VpnMode.TOR:
            return await self._tor.new_identity()
        return True

    # ------------------------------------------------------------------
    # Status
    # ------------------------------------------------------------------

    async def current_status(self) -> VpnStatus:
        """Return the current VPN manager status."""
        if not self._connected:
            return VpnStatus(mode=self._mode, connected=False)

        if self._mode == VpnMode.WIREGUARD:
            wg = await self._wg.status()
            return VpnStatus(
                mode=VpnMode.WIREGUARD,
                connected=wg.connected,
                public_ip=wg.public_ip,
                error=wg.error,
            )

        if self._mode == VpnMode.TOR:
            tor = await self._tor.connect()
            return VpnStatus(
                mode=VpnMode.TOR,
                connected=tor.running,
                public_ip=tor.public_ip,
                error=tor.error,
            )

        return VpnStatus(mode=VpnMode.NONE, connected=True, public_ip=self._public_ip)

    def get_httpx_proxies(self) -> dict[str, str] | None:
        """
        Return an httpx-compatible proxy dict for the active mode, or None.

        Pass the result directly as the ``proxies`` kwarg to
        ``httpx.AsyncClient``.
        """
        if self._mode == VpnMode.TOR and self._connected:
            return {"all://": self._tor.get_http_client().base_url.__str__()}
        return None

    # ------------------------------------------------------------------
    # Speed test
    # ------------------------------------------------------------------

    async def speed_test_all(self) -> list[SpeedResult]:
        """
        Measure latency for each VPN mode.

        The test probes PROBE_URL and records the round-trip time.
        WireGuard and Tor are tested using their respective proxy settings.

        Returns a list of :class:`SpeedResult` objects.
        """
        results: list[SpeedResult] = []

        # Direct
        results.append(await self._probe(VpnMode.NONE, proxies=None))

        # WireGuard — requires an active tunnel; skip if not connected
        if self._mode == VpnMode.WIREGUARD and self._connected:
            results.append(await self._probe(VpnMode.WIREGUARD, proxies=None))
        else:
            results.append(
                SpeedResult(
                    mode=VpnMode.WIREGUARD,
                    success=False,
                    error="Not connected",
                )
            )

        # Tor
        if self._tor._port_open(self._tor.socks_host, self._tor.socks_port):
            tor_proxy = f"socks5://{self._tor.socks_host}:{self._tor.socks_port}"
            results.append(
                await self._probe(VpnMode.TOR, proxies={"all://": tor_proxy})
            )
        else:
            results.append(
                SpeedResult(
                    mode=VpnMode.TOR,
                    success=False,
                    error="Tor not running",
                )
            )

        return results

    async def _probe(
        self,
        mode: VpnMode,
        proxies: dict[str, str] | None,
    ) -> SpeedResult:
        """Probe PROBE_URL and measure latency."""
        try:
            kwargs: dict[str, Any] = {"timeout": 10.0, "follow_redirects": True}
            if proxies:
                kwargs["proxies"] = proxies  # type: ignore[assignment]
            async with httpx.AsyncClient(**kwargs) as client:
                t0 = time.perf_counter()
                await client.get(self.PROBE_URL)
                latency_ms = (time.perf_counter() - t0) * 1000
            return SpeedResult(mode=mode, latency_ms=round(latency_ms, 1), success=True)
        except Exception as exc:
            return SpeedResult(mode=mode, success=False, error=str(exc))

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------

    @staticmethod
    async def _get_direct_ip() -> Optional[str]:
        try:
            async with httpx.AsyncClient(timeout=5) as client:
                resp = await client.get("https://api.ipify.org?format=json")
                return resp.json().get("ip")
        except Exception:
            return None
