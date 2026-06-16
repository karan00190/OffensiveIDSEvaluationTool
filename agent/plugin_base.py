#!/usr/bin/env python3
# agent/plugin_base.py
# =============================================================================
#  MIAT — Plugin Contract
#  Every plugin MUST subclass MIATPlugin and implement:
#    • name (str property)
#    • version (str property)
#    • description (str property)
#    • execute(args: dict) (async coroutine)
#  The ABC metaclass raises TypeError at import time if the contract is broken.
# =============================================================================

import asyncio
import logging
import threading
from abc       import ABC, abstractmethod
from dataclasses import dataclass, field
from enum      import Enum
from typing    import Any, Optional

logger = logging.getLogger('MIAT.PluginBase')


# =============================================================================
# PLUGIN STATUS
# =============================================================================

class PluginStatus(str, Enum):
    IDLE      = 'idle'
    RUNNING   = 'running'
    COMPLETE  = 'complete'
    FAILED    = 'failed'
    STOPPED   = 'stopped'


# =============================================================================
# PLUGIN RESULT — placed on the telemetry queue
# =============================================================================

@dataclass
class PluginResult:
    plugin_name: str
    success:     bool
    data:        dict        = field(default_factory=dict)
    endpoint:    str         = '/api/agent/results/'
    live_output: str         = ''


# =============================================================================
# ABSTRACT BASE CLASS
# =============================================================================

class MIATPlugin(ABC):
    """
    Contract that every MIAT attack-simulation plugin must satisfy.

    The orchestrator calls:
        plugin._stop_event.clear()
        plugin.status     = PluginStatus.RUNNING
        plugin.config     = args
        plugin._transport = self.transport   # for pull-model plugins
        await plugin.execute(args)

    Subclasses call:
        await self._emit(data, endpoint)     → queues a PluginResult
        await self._emit_live(text)          → sends live output over WS
        self._stop_event.is_set()            → check for cancellation
        self.stop()                          → signal self to stop
    """

    def __init__(self, telemetry_queue: asyncio.Queue) -> None:
        self._queue      : asyncio.Queue = telemetry_queue
        self._stop_event : threading.Event = threading.Event()
        self.status      : PluginStatus = PluginStatus.IDLE
        self.config      : dict         = {}
        self._transport  = None    # injected by orchestrator for pull-model
        self._ws_thread  = None    # injected by orchestrator for live output

    # ── Abstract contract ─────────────────────────────────────────────────────

    @property
    @abstractmethod
    def name(self) -> str:
        """Short identifier used for routing: 'dga', 'exfil', 'nmap'."""

    @property
    @abstractmethod
    def version(self) -> str:
        """Semantic version string, e.g. '1.0.0'."""

    @property
    @abstractmethod
    def description(self) -> str:
        """One-line human-readable description."""

    @abstractmethod
    async def execute(self, args: dict) -> None:
        """
        Main plugin logic.  Must honour self._stop_event.is_set().
        Must call await self._emit(...) when results are ready.
        Must NEVER block the event loop with synchronous I/O.
        """

    # ── Helpers available to all subclasses ───────────────────────────────────

    async def _emit(
        self,
        data:     dict,
        endpoint: str  = '/api/agent/results/',
        success:  bool = True,
    ) -> None:
        """
        Place a PluginResult on the telemetry queue.
        TelemetryEngine drains the queue and POSTs to the C2 server.
        """
        result = PluginResult(
            plugin_name = self.name,
            success     = success,
            data        = data,
            endpoint    = endpoint,
        )
        await self._queue.put(result)

    async def _emit_live(self, text: str) -> None:
        """
        Send a live output line to every connected browser dashboard via WS.
        Falls back silently if the WS thread is not connected.
        """
        if self._ws_thread and getattr(self._ws_thread, 'connected', False):
            try:
                self._ws_thread.send({
                    'type':   'module_output',
                    'module': self.name,
                    'output': text,
                })
            except Exception as exc:
                logger.debug(f'_emit_live WS send failed: {exc}')

    def stop(self) -> None:
        """Signal the plugin to stop at its next _stop_event check."""
        self._stop_event.set()
        self.status = PluginStatus.STOPPED

    # ── Capability metadata ───────────────────────────────────────────────────

    def info(self) -> dict:
        """Serialisable capability record registered with the C2 on connect."""
        return {
            'name':        self.name,
            'version':     self.version,
            'description': self.description,
            'status':      self.status.value,
        }

    def __repr__(self) -> str:
        return (
            f"<{self.__class__.__name__} "
            f"name={self.name!r} "
            f"v{self.version} "
            f"status={self.status.value}>"
        )