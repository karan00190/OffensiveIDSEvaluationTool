#!/usr/bin/env python3
# agent/telemetry.py
# =============================================================================
#  MIAT — Telemetry Engine
#
#  The shared async queue that sits between plugins and the server.
#
#  WHY THIS EXISTS:
#    Before: every plugin called self.agent_ref.http.post() directly.
#    Problem: if the server is down, results are lost. If 3 plugins run
#    simultaneously they all hammer the server with concurrent POSTs.
#
#  NOW:
#    Plugins push PluginResult objects into an asyncio.Queue.
#    TelemetryEngine runs as a background async task, draining the queue
#    one item at a time, posting to the server with retry logic.
#    Plugins never touch the network — only TelemetryEngine does.
#
#  BENEFITS:
#    - Results survive temporary server downtime (buffered in queue)
#    - Controlled concurrency (one POST at a time)
#    - Live output streamed via WebSocket separately from summary data
#    - Retry logic in one place — not duplicated across every plugin
# =============================================================================

import asyncio
import logging
import time
from typing import Optional

from plugin_base import PluginResult

logger = logging.getLogger('MIAT.Telemetry')

MAX_QUEUE_SIZE  = 500     # drop oldest if queue fills past this
MAX_RETRIES     = 3       # retry failed POSTs this many times
RETRY_DELAY_SEC = 5.0     # wait between retries


class TelemetryEngine:
    """
    Background async task that drains the telemetry queue.

    Lifecycle:
      engine = TelemetryEngine(transport, ws_thread)
      asyncio.create_task(engine.run())   # started by orchestrator
      engine.stop()                       # called on shutdown
    """

    def __init__(self, transport, ws_thread=None):
        """
        Args:
            transport:  SecureTransport instance (for HTTP POSTs)
            ws_thread:  WebSocketThread instance (for live output streaming)
        """
        self.transport = transport
        self.ws_thread = ws_thread
        self.queue     = asyncio.Queue(maxsize=MAX_QUEUE_SIZE)
        self._running  = False
        self._stats    = {
            'posted':  0,
            'failed':  0,
            'retried': 0,
            'streamed': 0,
        }

    async def run(self) -> None:
        """
        Main drain loop. Runs forever until stop() is called.
        Started as an asyncio task by the orchestrator.
        """
        self._running = True
        logger.info("TelemetryEngine started — draining queue")

        while self._running:
            try:
                # Wait up to 1s for a result — then loop to check _running
                result: PluginResult = await asyncio.wait_for(
                    self.queue.get(), timeout=1.0
                )
                await self._process(result)
                self.queue.task_done()

            except asyncio.TimeoutError:
                continue   # no item in queue — check _running and loop
            except Exception as exc:
                logger.error(f"TelemetryEngine error: {exc}")

        logger.info(
            f"TelemetryEngine stopped — stats: "
            f"posted={self._stats['posted']}, "
            f"failed={self._stats['failed']}, "
            f"retried={self._stats['retried']}, "
            f"streamed={self._stats['streamed']}"
        )

    def stop(self) -> None:
        self._running = False

    async def _process(self, result: PluginResult) -> None:
        """
        Handle one PluginResult:
          1. If it has live_output → stream via WebSocket immediately
          2. If it has data → POST to server API with retry
        """

        # ── Stream live output via WebSocket ──────────────────────────────────
        if result.live_output and self.ws_thread:
            try:
                self.ws_thread.send_module_output(
                    result.plugin_name,
                    result.live_output,
                )
                self._stats['streamed'] += 1
            except Exception as exc:
                logger.debug(f"WebSocket stream failed: {exc}")

        # ── POST summary data to server ───────────────────────────────────────
        if result.data and result.endpoint:
            await self._post_with_retry(result)

    async def _post_with_retry(self, result: PluginResult) -> None:
        """POST result.data to result.endpoint with retry on failure."""
        loop     = asyncio.get_event_loop()
        attempts = 0

        while attempts <= MAX_RETRIES:
            try:
                # transport.post() is synchronous — run in executor
                await loop.run_in_executor(
                    None,
                    lambda: self.transport.post(result.endpoint, result.data)
                )
                self._stats['posted'] += 1
                logger.debug(
                    f"Posted [{result.plugin_name}] → {result.endpoint}"
                )
                return

            except Exception as exc:
                attempts += 1
                if attempts > MAX_RETRIES:
                    self._stats['failed'] += 1
                    logger.error(
                        f"Failed to post [{result.plugin_name}] result "
                        f"after {MAX_RETRIES} retries: {exc}"
                    )
                    if not result.retryable:
                        return
                else:
                    self._stats['retried'] += 1
                    logger.warning(
                        f"POST failed (attempt {attempts}/{MAX_RETRIES}), "
                        f"retrying in {RETRY_DELAY_SEC}s: {exc}"
                    )
                    await asyncio.sleep(RETRY_DELAY_SEC)

    @property
    def queue_size(self) -> int:
        return self.queue.qsize()