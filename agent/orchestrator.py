#!/usr/bin/env python3
# agent/orchestrator.py
# =============================================================================
#  MIAT — Async Orchestrator
#
#  Change from original:
#    _run_plugin() now sends a 'task_started' WebSocket message to the server
#    immediately before calling plugin.execute(). The server's AgentConsumer
#    handles this message and transitions the matching ModuleTask from
#    DISPATCHED → RUNNING, so the browser status panel updates in real time.
# =============================================================================

import asyncio
import json
import logging
import signal
import sys
import argparse
from pathlib import Path

from config        import AgentConfig
from transport     import SecureTransport, WebSocketThread, build_ssl_context
from plugin_loader import PluginLoader
from telemetry     import TelemetryEngine

logging.basicConfig(
    level   = logging.INFO,
    format  = '%(asctime)s [%(levelname)s] %(name)s: %(message)s',
    datefmt = '%H:%M:%S',
)
logger = logging.getLogger('MIAT.Orchestrator')

HEARTBEAT_INTERVAL = 30


class Orchestrator:
    """
    Async orchestrator — routes WebSocket commands to plugins.
    Knows about transport and plugins; nothing else.
    """

    def __init__(self, config: AgentConfig):
        self.config   = config
        self._running = False

        self.ssl_ctx = build_ssl_context(
            config.ca_cert, config.agent_cert, config.agent_key,
        )

        self.transport = SecureTransport(
            server_url = config.server_url,
            config     = config.as_dict(),
            ssl_ctx    = self.ssl_ctx,
        )

        self.telemetry = TelemetryEngine(
            transport = self.transport,
            ws_thread = None,
        )

        self.plugins = PluginLoader(telemetry_queue=self.telemetry.queue)
        self.ws_thread: WebSocketThread | None = None
        self._active_tasks: dict[str, asyncio.Task] = {}

    # =========================================================================
    # STARTUP
    # =========================================================================

    # =========================================================================
    # STARTUP
    # =========================================================================

    async def start(self) -> None:
        self._running = True
        
        # ─── ADD THIS LINE HERE ──────────────────────────────────────────────
        self.loop = asyncio.get_running_loop()
        # ─────────────────────────────────────────────────────────────────────

        logger.info("=" * 56)
        logger.info("  MIAT Orchestrator starting")
        logger.info(f"  Agent ID : {self.config.agent_id}")
        logger.info(f"  Server   : {self.config.server_url}")
        logger.info(f"  Security : mTLS + JWT + HMAC")
        logger.info("=" * 56)

        # Update this line to use self.loop instead of loop
        await self.loop.run_in_executor(None, self.transport.authenticate)

        count = self.plugins.load_all()
        if count == 0:
            logger.warning("No plugins loaded — agent will accept no commands")

        self.ws_thread = WebSocketThread(
            server_url = self.config.server_url,
            agent_id   = self.config.agent_id,
            auth_token = self.config.auth_token,
            ssl_ctx    = self.ssl_ctx,
            on_command = self._on_ws_command,
        )
        self.telemetry.ws_thread = self.ws_thread
        self.ws_thread.start()

        asyncio.create_task(self.telemetry.run(), name='telemetry')

        await self._register_capabilities()

        logger.info("Orchestrator running. Ctrl+C to stop.")
        await self._heartbeat_loop()

    # =========================================================================
    # HEARTBEAT
    # =========================================================================

    async def _heartbeat_loop(self) -> None:
        while self._running:
            if self.ws_thread and self.ws_thread.connected:
                self.ws_thread.send_heartbeat(self.plugins.all_names())
            await asyncio.sleep(HEARTBEAT_INTERVAL)

    # =========================================================================
    # CAPABILITY REGISTRATION
    # =========================================================================

    async def _register_capabilities(self) -> None:
        capabilities = self.plugins.get_all_info()
        try:
            # Replaced local loop lookup with self.loop
            await self.loop.run_in_executor(
                None,
                lambda: self.transport.post('/api/agent/capabilities/', {
                    'agent_id':     self.config.agent_id,
                    'capabilities': capabilities,
                }),
            )
            logger.info(
                f"Capabilities registered: "
                f"{[c['name'] for c in capabilities]}"
            )
        except Exception as exc:
            logger.warning(f"Could not register capabilities: {exc}")

    # =========================================================================
    # COMMAND DISPATCH
    # =========================================================================

    # =========================================================================
    # COMMAND DISPATCH
    # =========================================================================

    def _on_ws_command(self, data: dict) -> None:
        """Bridge from WS thread (sync) into the asyncio event loop."""
        # Check if our main loop is alive, then pass the work to it safely
        if hasattr(self, 'loop') and self.loop.is_running():
            asyncio.run_coroutine_threadsafe(
                self.dispatch_command(data), self.loop
            )
        else:
            logger.error("Main event loop is not running. Cannot process WS command.")

    async def dispatch_command(self, data: dict) -> None:
        """Route an incoming server command to the correct plugin."""
        command = data.get('command', '').strip()
        args    = data.get('args', {})

        logger.info(f"Command received: '{command}' args={list(args.keys())}")

        if command == 'stop':
            target = args.get('plugin', None)
            if target:
                await self._stop_plugin(target)
            else:
                await self._stop_all_plugins()
            return

        if command == 'status':
            await self._send_status()
            return

        plugin = self.plugins.get(command)
        if plugin is None:
            logger.warning(
                f"Unknown command '{command}'. "
                f"Loaded: {self.plugins.all_names()}"
            )
            if self.ws_thread and self.ws_thread.connected:
                self.ws_thread.send({
                    'type':    'error',
                    'message': (
                        f"Unknown command '{command}'. "
                        f"Available: {self.plugins.all_names()}"
                    ),
                })
            return

        # Cancel any existing task for this plugin before launching a new one
        if command in self._active_tasks:
            existing = self._active_tasks[command]
            if not existing.done():
                logger.info(f"Cancelling existing '{command}' task")
                existing.cancel()

        task = asyncio.create_task(
            self._run_plugin(plugin, args),
            name=f'plugin-{command}',
        )
        self._active_tasks[command] = task

    # =========================================================================
    # PLUGIN RUNNER
    # =========================================================================

    async def _run_plugin(self, plugin, args: dict) -> None:
        """
        Execute one plugin inside an asyncio task.
        Catches all exceptions so a bad plugin never crashes the orchestrator.

        KEY CHANGE:
          Sends a 'task_started' WebSocket message to the server immediately
          before calling plugin.execute(). This lets AgentConsumer transition
          the matching ModuleTask from DISPATCHED → RUNNING, giving the browser
          a real-time status update without waiting for the plugin to finish.

          The task_id travels like this:
            dispatch_dga_task()          injects task_id into config_json
            channel_layer.group_send()   forwards it in the args dict
            AgentConsumer.agent_command() passes args unchanged to orchestrator
            dispatch_command()           passes args unchanged to _run_plugin
            _run_plugin()               reads task_id here and sends task_started
            plugin.execute(args)        reads task_id and includes it in summary
            api_dga_results()           reads task_id and calls mark_complete()
        """
        from plugin_base import PluginStatus

        plugin._stop_event.clear()
        plugin.status = PluginStatus.RUNNING
        plugin.config = args

        logger.info(f"Plugin [{plugin.name}] starting")

        # ── Send task_started acknowledgement ─────────────────────────────────
        # Do this BEFORE execute() so the server can mark the task RUNNING
        # even if the plugin takes a long time to produce its first output.
        task_id = str(args.get('task_id', ''))
        if task_id and self.ws_thread and self.ws_thread.connected:
            self.ws_thread.send({
                'type':    'task_started',
                'task_id': task_id,
                'command': plugin.name,
            })
            logger.info(
                f"task_started sent — "
                f"task_id={task_id[:8].upper()} plugin={plugin.name}"
            )

        try:
            await plugin.execute(args)
            plugin.status = PluginStatus.COMPLETE
            logger.info(f"Plugin [{plugin.name}] completed successfully")

        except asyncio.CancelledError:
            plugin.status = PluginStatus.STOPPED
            logger.info(f"Plugin [{plugin.name}] was cancelled")

        except Exception as exc:
            plugin.status = PluginStatus.FAILED
            logger.error(
                f"Plugin [{plugin.name}] raised exception: {exc}",
                exc_info=True,
            )
            # Emit failure so the server can mark the ModuleTask as failed.
            # Include task_id so _close_moduletask_loop() can be called.
            await plugin._emit(
                data    = {
                    'error':   str(exc),
                    'plugin':  plugin.name,
                    'task_id': task_id,
                },
                success  = False,
                endpoint = f'/api/agent/{plugin.name}/results/',
            )

    # =========================================================================
    # BUILT-IN COMMAND HANDLERS
    # =========================================================================

    async def _stop_plugin(self, name: str) -> None:
        plugin = self.plugins.get(name)
        if plugin:
            plugin.stop()
            task = self._active_tasks.get(name)
            if task and not task.done():
                task.cancel()
            logger.info(f"Plugin [{name}] stopped")
        else:
            logger.warning(f"Cannot stop unknown plugin: {name}")

    async def _stop_all_plugins(self) -> None:
        self.plugins.stop_all()
        for name, task in self._active_tasks.items():
            if not task.done():
                task.cancel()
        logger.info("All plugins stopped")

    async def _send_status(self) -> None:
        from plugin_base import PluginResult
        status_data = {
            'agent_id':     self.config.agent_id,
            'plugins':      self.plugins.get_all_info(),
            'queue_size':   self.telemetry.queue_size,
            'ws_connected': self.ws_thread.connected if self.ws_thread else False,
        }
        result = PluginResult(
            plugin_name = 'orchestrator',
            success     = True,
            data        = status_data,
            endpoint    = '/api/agent/status/report/',
            live_output = (
                f"Status: {len(self.plugins.all_names())} plugins, "
                f"queue={self.telemetry.queue_size}"
            ),
        )
        await self.telemetry.queue.put(result)

    # =========================================================================
    # SHUTDOWN
    # =========================================================================

    async def stop(self) -> None:
        logger.info("Orchestrator shutting down...")
        self._running = False
        await self._stop_all_plugins()
        self.telemetry.stop()
        if self.ws_thread:
            self.ws_thread.stop()
        logger.info("Orchestrator stopped cleanly.")


# =============================================================================
# REGISTRATION HELPER
# =============================================================================

def register_agent(server_url: str, agent_id: str,
                   name: str, reg_key: str) -> None:
    import urllib.request
    import urllib.error

    cert_dir   = Path(__file__).parent / 'certs'
    ssl_ctx    = build_ssl_context(
        cert_dir / 'ca.crt',
        cert_dir / 'agent.crt',
        cert_dir / 'agent.key',
    )
    body = json.dumps({
        'agent_id':         agent_id,
        'name':             name or agent_id,
        'registration_key': reg_key,
    }).encode('utf-8')

    req = urllib.request.Request(
        f"{server_url.rstrip('/')}/api/agent/register/",
        data=body, headers={'Content-Type': 'application/json'}, method='POST',
    )

    logger.info(f"Registering agent '{agent_id}' with server...")
    try:
        with urllib.request.urlopen(req, context=ssl_ctx, timeout=10) as r:
            data = json.loads(r.read())
    except urllib.error.HTTPError as exc:
        logger.error(f"Registration failed: {exc.code} {exc.read().decode()}")
        sys.exit(1)
    except urllib.error.URLError as exc:
        logger.error(f"Cannot reach server: {exc.reason}")
        sys.exit(1)

    config_obj = AgentConfig.__new__(AgentConfig)
    config_obj._path = Path(__file__).parent / 'agent_config.json'
    config_obj.save({
        'server_url':       server_url,
        'agent_id':         data['agent_id'],
        'auth_token':       data['auth_token'],
        'secret_key':       data['secret_key'],
        'registration_key': reg_key,
    })

    logger.info(f"Registration complete!")
    logger.info(f"  Agent ID  : {data['agent_id']}")
    logger.info(f"  Auth Token: {data['auth_token'][:16]}...")
    logger.info(f"  Config    : agent_config.json")
    logger.info("  Next: python orchestrator.py --run")


# =============================================================================
# CLI
# =============================================================================

def main() -> None:
    parser = argparse.ArgumentParser(
        description='MIAT Agent Orchestrator — mTLS + JWT + HMAC + Plugins',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Commands:
  Register (run once):
    python orchestrator.py --register --agent-id barc-lab-01 --reg-key KEY

  Start persistent agent:
    python orchestrator.py --run

  Against a specific server:
    python orchestrator.py --run --server https://10.0.0.1:8443
        """,
    )
    parser.add_argument('--register',   action='store_true')
    parser.add_argument('--run',        action='store_true')
    parser.add_argument('--agent-id',   help='Agent ID for registration')
    parser.add_argument('--agent-name', help='Display name')
    parser.add_argument('--reg-key',    help='Registration key from settings.py')
    parser.add_argument('--server',     default='https://127.0.0.1:8443')

    args = parser.parse_args()

    if args.register:
        if not args.agent_id or not args.reg_key:
            parser.error('--register requires --agent-id and --reg-key')
        register_agent(
            server_url = args.server,
            agent_id   = args.agent_id,
            name       = args.agent_name or args.agent_id,
            reg_key    = args.reg_key,
        )
        return

    if args.run:
        config = AgentConfig()
        if args.server:
            config._data['server_url'] = args.server

        orchestrator = Orchestrator(config)
        loop         = asyncio.get_event_loop()

        def _shutdown():
            logger.info("Shutdown signal received")
            loop.create_task(orchestrator.stop())

        for sig in (signal.SIGINT, signal.SIGTERM):
            try:
                loop.add_signal_handler(sig, _shutdown)
            except NotImplementedError:
                pass  # Windows

        try:
            loop.run_until_complete(orchestrator.start())
        except KeyboardInterrupt:
            loop.run_until_complete(orchestrator.stop())
        finally:
            loop.close()
        return

    parser.print_help()


if __name__ == '__main__':
    main()