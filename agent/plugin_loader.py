#!/usr/bin/env python3
# agent/plugin_loader.py
import asyncio, importlib, importlib.util, inspect, logging, sys
from pathlib import Path
from plugin_base import MIATPlugin

logger = logging.getLogger('MIAT.PluginLoader')

PLUGINS_DIR = Path(__file__).parent / 'plugins'


class PluginLoader:
    def __init__(self, telemetry_queue: asyncio.Queue) -> None:
        self._queue    = telemetry_queue
        self._plugins: dict[str, MIATPlugin] = {}

    # ── Public API ────────────────────────────────────────────────────────────

    def load_all(self) -> int:
        """
        Scan PLUGINS_DIR for .py files, import each, find MIATPlugin subclasses,
        instantiate them, and register by name.  Returns the count loaded.
        """
        if not PLUGINS_DIR.exists():
            logger.warning(f'Plugin directory not found: {PLUGINS_DIR}')
            return 0

        loaded = 0
        for path in sorted(PLUGINS_DIR.glob('*.py')):
            if path.stem.startswith('_'):
                continue
            try:
                mod = self._import_module(path)
                for _, cls in inspect.getmembers(mod, inspect.isclass):
                    if (issubclass(cls, MIATPlugin)
                            and cls is not MIATPlugin
                            and not inspect.isabstract(cls)):
                        instance = cls(telemetry_queue=self._queue)
                        self._plugins[instance.name] = instance
                        logger.info(
                            f'Plugin loaded: {instance.name} '
                            f'v{instance.version} ({path.name})'
                        )
                        loaded += 1
            except Exception as exc:
                logger.error(f'Failed to load plugin {path.name}: {exc}')

        logger.info(f'PluginLoader: {loaded} plugin(s) registered')
        return loaded

    def get(self, name: str) -> MIATPlugin | None:
        return self._plugins.get(name)

    def all_names(self) -> list[str]:
        return list(self._plugins.keys())

    def get_all_info(self) -> list[dict]:
        return [p.info() for p in self._plugins.values()]

    def stop_all(self) -> None:
        for p in self._plugins.values():
            p.stop()

    def set_ws_thread(self, ws_thread) -> None:
        """Inject WS thread into every plugin so _emit_live() can push live output."""
        for p in self._plugins.values():
            p._ws_thread = ws_thread

    # ── Private ───────────────────────────────────────────────────────────────

    @staticmethod
    def _import_module(path: Path):
        spec   = importlib.util.spec_from_file_location(path.stem, path)
        module = importlib.util.module_from_spec(spec)
        sys.modules[path.stem] = module
        spec.loader.exec_module(module)
        return module