#!/usr/bin/env python3
# agent/plugins/nmap_plugin.py
# =============================================================================
#  MIAT Plugin — Nmap Network Scanner
#
#  Implements MIATPlugin contract. Orchestrator calls execute(args).
#  Results go to telemetry queue — never posted directly.
#
#  Server command format:
#  {
#    "command": "nmap",
#    "args": {
#      "target":  "192.168.1.1",
#      "profile": "fast"          # fast|default|deep|ping
#    }
#  }
# =============================================================================

import asyncio
from plugin_base import MIATPlugin, PluginStatus

try:
    import nmap
    NMAP_AVAILABLE = True
except ImportError:
    NMAP_AVAILABLE = False

RISKY_PORTS = {
    21:   ('HIGH',   'FTP — plaintext credentials'),
    22:   ('MEDIUM', 'SSH — brute-force surface'),
    23:   ('HIGH',   'Telnet — plaintext protocol'),
    80:   ('LOW',    'HTTP — unencrypted web'),
    443:  ('INFO',   'HTTPS — encrypted web'),
    445:  ('HIGH',   'SMB — ransomware vector'),
    3306: ('HIGH',   'MySQL — database exposed'),
    3389: ('HIGH',   'RDP — brute-force target'),
    6379: ('HIGH',   'Redis — unauthenticated default'),
}

PROFILES = {
    'fast':    '-sV -T4 -F',
    'default': '-sV -T4 --top-ports 1000',
    'deep':    '-sS -sV -O -T4 -p-',
    'ping':    '-sn',
}

SEV_ORDER = {'HIGH': 0, 'MEDIUM': 1, 'LOW': 2, 'INFO': 3, 'NONE': 4}


class NmapPlugin(MIATPlugin):

    @property
    def name(self) -> str:
        return 'nmap'

    @property
    def version(self) -> str:
        return '1.0.0'

    @property
    def description(self) -> str:
        return 'Network port scanner with risk assessment'

    async def execute(self, args: dict) -> None:
        if not NMAP_AVAILABLE:
            await self._emit(
                data={'error': 'python-nmap not installed'},
                success=False
            )
            return

        target  = args.get('target', '127.0.0.1')
        profile = args.get('profile', 'default')
        flags   = PROFILES.get(profile, PROFILES['default'])

        await self._emit_live(
            f"Nmap [{profile.upper()}] starting → {target}"
        )

        loop = asyncio.get_event_loop()

        # Run nmap in executor so we don't block the event loop
        try:
            nm = await loop.run_in_executor(
                None, lambda: self._run_nmap(target, flags)
            )
        except Exception as exc:
            await self._emit(
                data={'error': str(exc), 'target': target},
                success=False
            )
            return

        # Process results
        hosts           = []
        total_open      = 0
        high_count      = 0
        scan_worst      = 'NONE'

        for ip in nm.all_hosts():
            if self._stop_event.is_set():
                break

            host_data  = nm[ip]
            host_state = host_data.state()
            hostname   = nm[ip].hostname() or ''

            os_name = 'N/A'
            if 'osmatch' in host_data and host_data['osmatch']:
                os_name = host_data['osmatch'][0].get('name', 'N/A')

            ports       = []
            host_worst  = 'NONE'
            host_open   = 0

            for proto in host_data.all_protocols():
                for port_num, info in host_data[proto].items():
                    if info.get('state') != 'open':
                        continue

                    host_open  += 1
                    total_open += 1

                    sev, note = RISKY_PORTS.get(
                        port_num, ('INFO', 'Open port — no specific rule')
                    )
                    is_crit = port_num in {21, 23, 445, 3306, 3389}

                    port_entry = {
                        'port':     port_num,
                        'protocol': proto,
                        'state':    'open',
                        'service':  info.get('name', ''),
                        'product':  info.get('product', ''),
                        'version':  info.get('version', ''),
                        'severity': sev,
                        'risk_note': note,
                        'is_critical': is_crit,
                    }
                    ports.append(port_entry)

                    if SEV_ORDER[sev] < SEV_ORDER[host_worst]:
                        host_worst = sev
                    if sev == 'HIGH':
                        high_count += 1

                    await self._emit_live(
                        f"  [{sev:6s}] {ip}:{port_num}/{proto} "
                        f"{info.get('name','')} {info.get('product','')} "
                        f"{info.get('version','')}"
                    )

            if SEV_ORDER[host_worst] < SEV_ORDER[scan_worst]:
                scan_worst = host_worst

            hosts.append({
                'ip':          ip,
                'hostname':    hostname,
                'status':      host_state,
                'os_detected': os_name,
                'host_risk':   host_worst,
                'open_count':  host_open,
                'ports':       ports,
            })

        summary = {
            'target':               target,
            'profile':              profile,
            'total_hosts':          len(nm.all_hosts()),
            'hosts_up':             sum(1 for h in hosts if h['status'] == 'up'),
            'total_open_ports':     total_open,
            'high_severity_count':  high_count,
            'overall_risk':         scan_worst,
            'hosts':                hosts,
        }

        await self._emit_live(
            f"Nmap complete — {len(hosts)} hosts, "
            f"{total_open} open ports, risk={scan_worst}"
        )

        await self._emit(
            data     = summary,
            endpoint = '/api/agent/nmap/results/',
        )

    def _run_nmap(self, target: str, flags: str):
        nm = nmap.PortScanner()
        nm.scan(hosts=target, arguments=flags)
        return nm