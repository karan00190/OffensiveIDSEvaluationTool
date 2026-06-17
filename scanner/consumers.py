# scanner/consumers.py
# Handles both AgentConsumer (agent ↔ server) and DashboardConsumer (browser ↔ server)
#
# Changes from original:
#   AgentConsumer.receive()  — added 'task_started' handler → calls _mark_task_running()
#   AgentConsumer            — added _mark_task_running() async DB helper
#   DashboardConsumer        — added task_complete() event handler

import json
import logging
from channels.generic.websocket import AsyncWebsocketConsumer
from channels.db                 import database_sync_to_async
from django.utils                import timezone

logger = logging.getLogger(__name__)


class AgentConsumer(AsyncWebsocketConsumer):
    """
    WebSocket connection for MIAT agents.
    URL: ws(s)://server/ws/agent/<agent_id>/?token=<auth_token>
    """

    async def connect(self):
        self.agent_id   = self.scope['url_route']['kwargs']['agent_id']
        self.group_name = f"agent_{self.agent_id}"

        query_string = self.scope.get('query_string', b'').decode()
        token        = self._extract_token(query_string)

        if not token:
            await self.close(code=4001)
            return

        self.agent = await self._get_agent(token)
        if not self.agent:
            logger.warning(f'WS rejected: bad token for {self.agent_id}')
            await self.close(code=4001)
            return

        await self.channel_layer.group_add(self.group_name, self.channel_name)
        await self.accept()
        await self._mark_seen()

        logger.info(f'Agent {self.agent_id} WebSocket connected')

        await self.send(text_data=json.dumps({
            'type':        'connected',
            'message':     f'Agent {self.agent_id} ready.',
            'server_time': timezone.now().isoformat(),
        }))

    async def disconnect(self, close_code):
        if hasattr(self, 'group_name'):
            await self.channel_layer.group_discard(
                self.group_name, self.channel_name
            )
        logger.info(f'Agent {getattr(self, "agent_id", "?")} disconnected')

    async def receive(self, text_data):
        try:
            data = json.loads(text_data)
        except json.JSONDecodeError:
            await self.send(text_data=json.dumps({
                'type': 'error', 'message': 'Invalid JSON',
            }))
            return

        msg_type = data.get('type', '')

        if msg_type == 'heartbeat':
            await self._mark_seen()
            await self.send(text_data=json.dumps({
                'type':        'heartbeat_ack',
                'server_time': timezone.now().isoformat(),
            }))

        elif msg_type == 'task_started':
            # ── NEW ────────────────────────────────────────────────────────
            # Sent by orchestrator._run_plugin() immediately before calling
            # plugin.execute(). Transitions the matching ModuleTask from
            # DISPATCHED → RUNNING so the browser status panel updates.
            # Safe to call even if the task_id is missing or stale — the
            # DB helper silently swallows DoesNotExist.
            task_id = data.get('task_id', '')
            command = data.get('command', '')
            if task_id:
                await self._mark_task_running(task_id)
                logger.info(
                    f"Agent {self.agent_id}: task_started "
                    f"task_id={task_id[:8].upper()} command={command}"
                )
            await self.send(text_data=json.dumps({
                'type':    'task_started_ack',
                'task_id': task_id,
            }))

        elif msg_type == 'scan_result':
            scan_id = data.get('scan_id')
            logger.info(f'Agent {self.agent_id} streamed result for scan #{scan_id}')
            await self.send(text_data=json.dumps({
                'type': 'result_ack', 'scan_id': scan_id,
            }))

        elif msg_type == 'module_output':
            # Forward live plugin output to all connected browser dashboards
            await self.channel_layer.group_send(
                'dashboard',
                {
                    'type':     'dashboard.update',
                    'agent_id': self.agent_id,
                    'module':   data.get('module', 'unknown'),
                    'output':   data.get('output', ''),
                },
            )

        elif msg_type == 'ids_alert':
            logger.warning(f'IDS ALERT from {self.agent_id}: {data.get("message")}')
            await self.send(text_data=json.dumps({'type': 'alert_ack'}))

        elif msg_type == 'scan_submitted':
            await self.channel_layer.group_send(
                'dashboard',
                {
                    'type':    'dashboard.update',
                    'message': (
                        f'Agent {self.agent_id} submitted scan '
                        f'#{data.get("scan_id")} for {data.get("target")}'
                    ),
                    'level': 'info',
                },
            )

        elif msg_type == 'connected_ack':
            logger.debug(f'Agent {self.agent_id} sent connected_ack')

    # ── Server → Agent: push a command ───────────────────────────────────────

    async def agent_command(self, event):
        """Push a command from server to agent instantly."""
        await self.send(text_data=json.dumps({
            'type':    'command',
            'command': event.get('command'),
            'args':    event.get('args', {}),
        }))
        logger.info(f'Command successfully transmitted to agent {self.agent_id}: {event.get("command")}')

    # ── DB helpers ────────────────────────────────────────────────────────────

    @database_sync_to_async
    def _get_agent(self, token: str):
        from .models import Agent
        try:
            return Agent.objects.get(auth_token=token, is_active=True)
        except Agent.DoesNotExist:
            return None

    @database_sync_to_async
    def _mark_seen(self):
        if hasattr(self, 'agent') and self.agent:
            self.agent.last_seen_at = timezone.now()
            self.agent.save(update_fields=['last_seen_at'])

    @database_sync_to_async
    def _mark_task_running(self, task_id_str: str) -> None:
        """
        Transition the ModuleTask identified by task_id_str from
        DISPATCHED → RUNNING.
        """
        from .models import ModuleTask
        try:
            # Flexible resolution tracking both UUID string layouts and numeric PK variants
            task = ModuleTask.objects.filter(task_id=task_id_str).first()
            if not task and task_id_str.isdigit():
                task = ModuleTask.objects.filter(id=int(task_id_str)).first()

            if task:
                task.mark_running()
                logger.info(f"ModuleTask tracking state altered successfully to RUNNING for ID: {task_id_str}")
            else:
                logger.warning(f"_mark_task_running: Failed to locate target record for ID: {task_id_str}")
        except Exception as exc:
            logger.error(f"Error encountered adjusting lifecycle state for task reference {task_id_str}: {exc}")

    @staticmethod
    def _extract_token(query_string: str) -> str:
        for part in query_string.split('&'):
            if part.startswith('token='):
                return part[6:].strip()
        return ''


class DashboardConsumer(AsyncWebsocketConsumer):
    """
    WebSocket connection for browser dashboards.
    URL: ws(s)://server/ws/dashboard/

    Receives push notifications from:
      - tasks.py           → scan.complete event
      - AgentConsumer      → module_output → dashboard.update event
      - dga_views.py       → task.complete event  [NEW]
      - exfil_views.py     → task.complete event  [NEW]
    """

    GROUP_NAME = 'dashboard'

    async def connect(self):
        await self.channel_layer.group_add(self.GROUP_NAME, self.channel_name)
        await self.accept()
        logger.info('Browser dashboard WebSocket connected')

    async def disconnect(self, close_code):
        await self.channel_layer.group_discard(self.GROUP_NAME, self.channel_name)

    async def receive(self, text_data):
        pass   # browser only receives — never sends to this consumer

    # ── Event handlers ────────────────────────────────────────────────────────
    # Method name = event 'type' with dots replaced by underscores

    async def scan_complete(self, event):
        """
        Called by tasks.py → notify_scan_complete() when nmap finishes.
        'type': 'scan.complete' → this method (dot → underscore).
        """
        await self.send(text_data=json.dumps({
            'type':       'scan_complete',
            'scan_id':    event.get('scan_id'),
            'risk':       event.get('risk'),
            'report_url': event.get('report_url'),
        }))

    async def dashboard_update(self, event):
        """
        General live updates — module output streamed from agent,
        scan started / failed messages.
        """
        await self.send(text_data=json.dumps({
            'type':     'live_update',
            'agent_id': event.get('agent_id', ''),
            'module':   event.get('module', ''),
            'output':   event.get('output', ''),
            'message':  event.get('message', ''),
            'level':    event.get('level', 'info'),
        }))

    async def task_complete(self, event):
        """
        ── NEW ──────────────────────────────────────────────────────────────
        Called by api_dga_results() or api_exfil_results() via group_send
        after the result has been saved and the ModuleTask has been marked
        complete. Forwards the result deep-link to every connected browser
        so the module_control.html polling panel can redirect automatically.

        'type': 'task.complete' → this method (dot → underscore).

        Payload forwarded to browser:
            type           'task_complete'
            task_id        UUID string
            task_id_short  First 8 chars for display
            module         'dga' | 'exfil' | 'nmap'
            result_url     Browser URL to the result detail page
            result_pk      Integer PK of the result row
        """
        await self.send(text_data=json.dumps({
            'type':          'task_complete',
            'task_id':       event.get('task_id'),
            'task_id_short': event.get('task_id_short'),
            'module':        event.get('module'),
            'result_url':    event.get('result_url'),
            'result_pk':     event.get('result_pk'),
        }))