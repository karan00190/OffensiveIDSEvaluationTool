#!/usr/bin/env python3
# agent/plugin_loader.py
# =============================================================================
#  MIAT — Dynamic Plugin Loader
#
#  Scans the plugins/ directory at startup, imports every .py file,
#  finds classes that inherit from MIATPlugin, and registers them.
#
#  Why dynamic loading?
#    You can add a new attack module by dropping a .py file into plugins/.
#    No changes to orchestrator.py, no import statements to add, no
#    restarts required if hot-reload is implemented later.
#
#  How it works:
#    1. Scan plugins/*.py
#    2. Import each module with importlib
#    3. Inspect each class in the module
#    4. If it's a subclass of MIATPlugin (but not MIATPlugin itself) → register
#    5. Instantiate it with the shared telemetry queue
#    6. Store in self._registry dict keyed by plugin.name
# =============================================================================

import asyncio
import importlib.util
import inspect
import logging
import sys
from pathlib import Path
from typing  import Dict, Optional

from plugin_base import MIATPlugin

logger = logging.getLogger('MIAT.PluginLoader')

PLUGINS_DIR = Path(__file__).parent / 'plugins'


class PluginLoader:
    """
    Discovers, loads, and manages all MIAT plugins.
    The orchestrator holds one instance of this class.
    """

    def __init__(self, telemetry_queue: asyncio.Queue):
        self.telemetry  = telemetry_queue
        self._registry  : Dict[str, MIATPlugin] = {}

    # ── Loading ───────────────────────────────────────────────────────────────

    def load_all(self) -> int:
        """
        Discover and load all plugins from the plugins/ directory.
        Returns the number of plugins successfully loaded.
        """
        if not PLUGINS_DIR.exists():
            logger.warning(f"Plugins directory not found: {PLUGINS_DIR}")
            return 0

        loaded = 0
        for plugin_file in sorted(PLUGINS_DIR.glob('*.py')):
            if plugin_file.name.startswith('_'):
                continue   # skip __init__.py etc.
            if self._load_file(plugin_file):
                loaded += 1

        logger.info(
            f"Plugin loader: {loaded} plugin(s) loaded — "
            f"registered: {list(self._registry.keys())}"
        )
        return loaded

    def _load_file(self, path: Path) -> bool:
        """
        Import one plugin file and register any MIATPlugin subclasses found.
        Returns True if at least one plugin was registered from this file.
        """
        module_name = f"miat_plugin_{path.stem}"
        try:
            spec   = importlib.util.spec_from_file_location(module_name, path)
            module = importlib.util.module_from_spec(spec)
            sys.modules[module_name] = module
            spec.loader.exec_module(module)
        except Exception as exc:
            logger.error(f"Failed to import plugin file {path.name}: {exc}")
            return False

        registered = 0
        for _, obj in inspect.getmembers(module, inspect.isclass):
            if (
                issubclass(obj, MIATPlugin)
                and obj is not MIATPlugin
                and not inspect.isabstract(obj)
            ):
                try:
                    instance = obj(self.telemetry)
                    self._register(instance)
                    registered += 1
                except Exception as exc:
                    logger.error(
                        f"Failed to instantiate plugin {obj.__name__} "
                        f"from {path.name}: {exc}"
                    )

        return registered > 0

    def _register(self, plugin: MIATPlugin) -> None:
        """Add a plugin instance to the registry."""
        if plugin.name in self._registry:
            logger.warning(
                f"Plugin '{plugin.name}' already registered — "
                f"overwriting with new version"
            )
        self._registry[plugin.name] = plugin
        logger.info(
            f"  ✓ Plugin registered: [{plugin.name}] "
            f"v{plugin.version} — {plugin.description}"
        )

    # ── Lookup ────────────────────────────────────────────────────────────────

    def get(self, name: str) -> Optional[MIATPlugin]:
        """Return a plugin by name, or None if not found."""
        return self._registry.get(name)

    def get_all_info(self) -> list:
        """Return get_info() for every loaded plugin (sent to server on connect)."""
        return [p.get_info() for p in self._registry.values()]

    def all_names(self) -> list:
        return list(self._registry.keys())

    def stop_all(self) -> None:
        """Signal every plugin to stop. Called on agent shutdown."""
        for plugin in self._registry.values():
            plugin.stop()