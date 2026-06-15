#!/usr/bin/env python3
# agent/config.py
# =============================================================================
#  MIAT — Configuration Manager
#
#  Single source of truth for all agent configuration.
#  Loads agent_config.json, validates required fields,
#  and exposes typed properties.
# =============================================================================

import json
import logging
from pathlib import Path

logger = logging.getLogger('MIAT.Config')

CONFIG_FILE = Path(__file__).parent / 'agent_config.json'
CERT_DIR    = Path(__file__).parent / 'certs'


class AgentConfig:
    """
    Loads and validates agent_config.json.
    Raises ValueError on missing required fields.
    """

    REQUIRED = ['server_url', 'agent_id', 'auth_token',
                'secret_key', 'registration_key']

    def __init__(self, config_path: Path = CONFIG_FILE):
        self._path = config_path
        self._data = self._load()

    def _load(self) -> dict:
        if not self._path.exists():
            raise FileNotFoundError(
                f"agent_config.json not found at {self._path}.\n"
                f"Run: python orchestrator.py --register "
                f"--agent-id <id> --reg-key <key>"
            )
        with open(self._path) as f:
            data = json.load(f)

        missing = [k for k in self.REQUIRED if k not in data]
        if missing:
            raise ValueError(f"agent_config.json missing fields: {missing}")

        return data

    def save(self, data: dict) -> None:
        with open(self._path, 'w') as f:
            json.dump(data, f, indent=2)
        self._data = data
        logger.info(f"Config saved to {self._path}")

    # ── Typed properties ──────────────────────────────────────────────────────

    @property
    def server_url(self) -> str:
        return self._data['server_url'].rstrip('/')

    @property
    def agent_id(self) -> str:
        return self._data['agent_id']

    @property
    def auth_token(self) -> str:
        return self._data['auth_token']

    @property
    def secret_key(self) -> str:
        return self._data['secret_key']

    @property
    def registration_key(self) -> str:
        return self._data['registration_key']

    @property
    def ca_cert(self) -> Path:
        return CERT_DIR / 'ca.crt'

    @property
    def agent_cert(self) -> Path:
        return CERT_DIR / 'agent.crt'

    @property
    def agent_key(self) -> Path:
        return CERT_DIR / 'agent.key'

    def as_dict(self) -> dict:
        return dict(self._data)