#!/usr/bin/env python3
# agent/plugin_base.py
# =============================================================================
#  MIAT — Plugin Base Contract
#
#  Every plugin MUST inherit from MIATPlugin and implement all abstract
#  methods. The orchestrator only knows about this interface — it never
#  imports plugin code directly. This is what makes the system truly
#  modular: you can add a new attack module by dropping one file into
#  plugins/ with no changes to orchestrator.py.
#
#  Plugin lifecycle:
#    1. plugin_loader.py discovers the file and calls Plugin()
#    2. Orchestrator calls plugin.get_info() to register capabilities
#    3. Server sends command → orchestrator calls plugin.execute(args)
#    4. Plugin pushes results to telemetry queue (never posts directly)
#    5. Orchestrator drains queue and posts to server
#    6. Orchestrator calls plugin.stop() on shutdown
# =============================================================================

import asyncio
import logging
from abc  import ABC, abstractmethod
from enum import Enum
from typing import Any


class PluginStatus(Enum):
    IDLE     = 'idle'
    RUNNING  = 'running'
    COMPLETE = 'complete'
    FAILED   = 'failed'
    STOPPED  = 'stopped'


class PluginResult:
    """
    Standardised result object every plugin pushes to the telemetry queue.
    The orchestrator reads these and decides how to post to the server.
    Using a structured result — not raw dicts — means the telemetry engine
    can retry, prioritise, and batch without knowing plugin internals.
    """

    def __init__(
        self,
        plugin_name : str,
        success     : bool,
        data        : dict,
        endpoint    : str,           # server API path to post to
        live_output : str = '',      # single line streamed to dashboard NOW
        retryable   : bool = True,   # retry this POST if server unreachable?
    ):
        self.plugin_name = plugin_name
        self.success     = success
        self.data        = data
        self.endpoint    = endpoint
        self.live_output = live_output
        self.retryable   = retryable

    def to_dict(self) -> dict:
        return {
            'plugin':   self.plugin_name,
            'success':  self.success,
            'endpoint': self.endpoint,
            'data':     self.data,
        }


class MIATPlugin(ABC):
    """
    Abstract base class for all MIAT attack plugins.

    Every plugin gets:
      self.telemetry  — asyncio.Queue to push PluginResult objects into
      self.logger     — pre-configured logger named after the plugin
      self.config     — the args dict passed from the server command
      self._stop_event — set this to abort a long-running operation cleanly

    What a plugin must NOT do:
      ✗ Import or call orchestrator internals
      ✗ Call self.http.post() directly (use telemetry queue)
      ✗ Spawn unmanaged threads (use asyncio tasks or pass executor)
      ✗ Catch all exceptions silently (let them propagate to orchestrator)
    """

    def __init__(self, telemetry_queue: asyncio.Queue):
        self.telemetry   = telemetry_queue
        self.logger      = logging.getLogger(f'MIAT.Plugin.{self.name}')
        self._stop_event = asyncio.Event()
        self.status      = PluginStatus.IDLE
        self.config      : dict = {}

    # ── Abstract interface ────────────────────────────────────────────────────
    # Every plugin MUST implement these four methods.

    @property
    @abstractmethod
    def name(self) -> str:
        """
        Unique plugin identifier.
        Must match the command name the server sends.
        e.g. 'nmap' → server sends {"command": "nmap", "args": {...}}
        """

    @property
    @abstractmethod
    def version(self) -> str:
        """Semantic version string e.g. '1.0.0'"""

    @property
    @abstractmethod
    def description(self) -> str:
        """One-line description shown in agent status."""

    @abstractmethod
    async def execute(self, args: dict) -> None:
        """
        Main plugin logic. Called by the orchestrator in an asyncio task.

        Rules:
          - Check self._stop_event.is_set() regularly in long loops
          - Push progress via: await self._emit(live_output='...')
          - Push final result via: await self._emit(data={...})
          - Raise exceptions freely — orchestrator handles them
          - Never block the event loop with long synchronous calls;
            use: await asyncio.get_event_loop().run_in_executor(None, sync_fn)

        Args:
            args: dict from the server command's 'args' field
        """

    # ── Concrete helpers — available to all plugins ───────────────────────────

    async def _emit(
        self,
        data        : dict  = None,
        live_output : str   = '',
        success     : bool  = True,
        endpoint    : str   = None,
        retryable   : bool  = True,
    ) -> None:
        """
        Push a result into the telemetry queue.
        The orchestrator drains this queue and posts to the server.

        Call with live_output only for streaming progress:
            await self._emit(live_output="Scanning port 22...")

        Call with data for final/summary results:
            await self._emit(data={"total": 50, "nxdomain": 48}, endpoint='/api/...')
        """
        result = PluginResult(
            plugin_name = self.name,
            success     = success,
            data        = data or {},
            endpoint    = endpoint or f'/api/agent/{self.name}/results/',
            live_output = live_output,
            retryable   = retryable,
        )
        await self.telemetry.put(result)

    async def _emit_live(self, line: str) -> None:
        """Shortcut: push a single live output line to dashboard."""
        await self._emit(live_output=line)

    def stop(self) -> None:
        """
        Signal the plugin to stop gracefully.
        Called by orchestrator on shutdown or 'stop' command.
        Plugin must check self._stop_event.is_set() in its main loop.
        """
        self._stop_event.set()
        self.status = PluginStatus.STOPPED
        self.logger.info(f"Plugin {self.name} stop requested")

    def get_info(self) -> dict:
        """
        Returns plugin capabilities to the orchestrator.
        The orchestrator registers this with the server on startup
        so the server knows what commands this agent can handle.
        """
        return {
            'name':        self.name,
            'version':     self.version,
            'description': self.description,
            'status':      self.status.value,
        }