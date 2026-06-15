# scanner/models.py
# =============================================================================
#  MIAT — Unified Models File
#
#  ONE file. No more models_dga_addition.py or models_exfil_addition.py.
#  All models live here. Django loads them all at startup automatically.
#
#  Model hierarchy:
#    Agent          → registered agent instances
#    ScanRequest    → one nmap scan job
#    HostResult     → one host found during a scan
#    PortFinding    → one open port on a host
#    DGAResult      → one DGA test run
#    ExfilResult    → one exfiltration simulation run
#    ModuleTask     → one web-initiated module dispatch (DGA, Exfil, Nmap)
# =============================================================================

import hashlib
import secrets
import hmac
import uuid

from django.db             import models
from django.contrib.auth.models import User
from django.utils          import timezone


# =============================================================================
# CHOICES
# =============================================================================

class ScanStatus(models.TextChoices):
    PENDING  = 'pending',  'Pending'
    RUNNING  = 'running',  'Running'
    COMPLETE = 'complete', 'Complete'
    FAILED   = 'failed',   'Failed'
    CACHED   = 'cached',   'Cached'


class ScanProfile(models.TextChoices):
    FAST    = 'fast',    'Fast (top 100 ports)'
    DEFAULT = 'default', 'Default (top 1000 ports)'
    DEEP    = 'deep',    'Deep (all ports + OS)'
    PING    = 'ping',    'Ping sweep'


class Severity(models.TextChoices):
    HIGH   = 'HIGH',   'High'
    MEDIUM = 'MEDIUM', 'Medium'
    LOW    = 'LOW',    'Low'
    INFO   = 'INFO',   'Info'
    NONE   = 'NONE',   'None'


class DGAAlgorithm(models.TextChoices):
    DATE_SEED = 'date_seed', 'Date-Seeded SHA-256'
    XOR_LCG   = 'xor_lcg',  'XOR + LCG (Conficker-style)'
    WORDLIST  = 'wordlist',  'Wordlist Combination'


class ExfilTechnique(models.TextChoices):
    DNS  = 'dns',  'DNS Tunnelling'
    HTTP = 'http', 'HTTP Header Injection'
    ICMP = 'icmp', 'ICMP Payload Stuffing'


class ExfilProfile(models.TextChoices):
    BURST     = 'burst',     'Burst'
    SLOW_DRIP = 'slow_drip', 'Slow Drip'
    JITTER    = 'jitter',    'Jitter'


class ModuleChoice(models.TextChoices):
    """
    The three attack modules that can be dispatched from the web UI.
    Used by ModuleTask to record which plugin was invoked.
    """
    DGA   = 'dga',   'DGA Simulation'
    EXFIL = 'exfil', 'Data Exfiltration'
    NMAP  = 'nmap',  'Nmap Reconnaissance'


class TaskStatus(models.TextChoices):
    """
    Lifecycle states for a web-initiated ModuleTask.

    Transition path:
      PENDING → DISPATCHED → RUNNING → COMPLETE
                                     ↘ FAILED

      PENDING:    Record created in DB; command not yet sent to agent.
      DISPATCHED: Command JSON pushed to agent via channel_layer.group_send;
                  awaiting acknowledgement from agent WebSocket.
      RUNNING:    Agent sent back a 'task_started' acknowledgement;
                  plugin is actively executing on the endpoint.
      COMPLETE:   Agent posted results to /api/agent/<module>/results/ and
                  the result row has been linked via result_pk.
      FAILED:     An error occurred at any stage — see error_message for detail.
    """
    PENDING    = 'pending',    'Pending'
    DISPATCHED = 'dispatched', 'Dispatched'
    RUNNING    = 'running',    'Running'
    COMPLETE   = 'complete',   'Complete'
    FAILED     = 'failed',     'Failed'


# =============================================================================
# MODEL 1: AGENT
# Represents one registered endpoint agent.
# =============================================================================

class Agent(models.Model):
    """
    WHY THIS EXISTS:
    Every machine running orchestrator.py must register here first.
    Registration gives the agent a unique identity (agent_id) and
    credentials (auth_token + secret_key). Every API request from
    the agent is verified against these — proving which machine
    sent the data and that the body was not tampered with.
    Without this, any script could post fake scan results.
    """

    agent_id   = models.CharField(max_length=64, unique=True, db_index=True)
    name       = models.CharField(max_length=128, blank=True)
    is_active  = models.BooleanField(default=True)

    # Credentials
    auth_token = models.CharField(max_length=64, unique=True, db_index=True)
    secret_key = models.CharField(max_length=64)

    # Capabilities — updated when agent connects and reports loaded plugins
    capabilities = models.JSONField(default=list, blank=True)

    # Tracking
    registered_by  = models.ForeignKey(
        User, on_delete=models.SET_NULL,
        null=True, blank=True, related_name='registered_agents',
    )
    registered_at  = models.DateTimeField(auto_now_add=True)
    last_seen_at   = models.DateTimeField(null=True, blank=True)
    last_seen_ip   = models.GenericIPAddressField(null=True, blank=True)
    total_requests = models.PositiveIntegerField(default=0)

    @staticmethod
    def generate_auth_token() -> str:
        return secrets.token_hex(32)

    @staticmethod
    def generate_secret_key() -> str:
        return secrets.token_hex(32)

    def verify_hmac(self, signature: str, timestamp: str, body: str) -> bool:
        expected = hmac.new(
            self.secret_key.encode('utf-8'),
            f"{timestamp}:{body}".encode('utf-8'),
            hashlib.sha256,
        ).hexdigest()
        return hmac.compare_digest(expected, signature)

    def mark_seen(self, ip_address: str = None) -> None:
        self.last_seen_at   = timezone.now()
        self.total_requests += 1
        if ip_address:
            self.last_seen_ip = ip_address
        self.save(update_fields=['last_seen_at', 'last_seen_ip', 'total_requests'])

    @property
    def is_online(self) -> bool:
        if not self.last_seen_at:
            return False
        return (timezone.now() - self.last_seen_at).seconds < 90

    @property
    def is_authenticated(self) -> bool:
        """
        Always return True. This mimics Django's AbstractBaseUser / User 
        interface so that Django Rest Framework (DRF) permission classes 
        do not crash when an API request is authenticated as an Agent.
        """
        return True
    
    def __str__(self):
        return f"Agent '{self.agent_id}' [{'active' if self.is_active else 'disabled'}]"

    class Meta:
        ordering            = ['-registered_at']
        verbose_name        = 'Agent'
        verbose_name_plural = 'Agents'


# =============================================================================
# MODEL 2: SCAN REQUEST
# One nmap scan job submitted by user or agent.
# =============================================================================

class ScanRequest(models.Model):
    user = models.ForeignKey(
        User, on_delete=models.SET_NULL,
        null=True, blank=True, related_name='scan_requests',
    )
    agent = models.ForeignKey(
        Agent, on_delete=models.SET_NULL,
        null=True, blank=True, related_name='scan_requests',
    )
    target       = models.CharField(max_length=255)
    scan_profile = models.CharField(
        max_length=20, choices=ScanProfile.choices, default=ScanProfile.DEFAULT,
    )
    token     = models.CharField(max_length=64, db_index=True, editable=False)
    status    = models.CharField(
        max_length=20, choices=ScanStatus.choices, default=ScanStatus.PENDING,
    )
    cache_hit   = models.BooleanField(default=False)
    cached_from = models.ForeignKey(
        'self', on_delete=models.SET_NULL, null=True, blank=True,
    )

    # Risk summary
    overall_risk          = models.CharField(max_length=10, choices=Severity.choices, default=Severity.NONE, blank=True)
    total_hosts           = models.IntegerField(default=0)
    hosts_up              = models.IntegerField(default=0)
    total_open_ports      = models.IntegerField(default=0)
    high_severity_count   = models.IntegerField(default=0)
    medium_severity_count = models.IntegerField(default=0)
    error_message         = models.TextField(blank=True, default='')

    created_at   = models.DateTimeField(auto_now_add=True)
    started_at   = models.DateTimeField(null=True, blank=True)
    completed_at = models.DateTimeField(null=True, blank=True)

    @property
    def duration_seconds(self):
        if self.started_at and self.completed_at:
            return (self.completed_at - self.started_at).seconds
        return None

    @staticmethod
    def generate_token(target: str, scan_profile: str) -> str:
        raw = f"{target.strip().lower()}:{scan_profile}"
        return hashlib.sha256(raw.encode()).hexdigest()

    def save(self, *args, **kwargs):
        if not self.token:
            self.token = self.generate_token(self.target, self.scan_profile)
        super().save(*args, **kwargs)

    def __str__(self):
        return f"Scan #{self.pk} — {self.target} [{self.status}]"

    class Meta:
        ordering = ['-created_at']


# =============================================================================
# MODEL 3: HOST RESULT
# One host discovered during a scan.
# =============================================================================

class HostResult(models.Model):
    scan        = models.ForeignKey(ScanRequest, on_delete=models.CASCADE, related_name='hosts')
    ip_address  = models.GenericIPAddressField()
    hostname    = models.CharField(max_length=255, blank=True, default='')
    status      = models.CharField(max_length=20, default='unknown')
    os_detected = models.CharField(max_length=255, blank=True, default='N/A')
    os_accuracy = models.IntegerField(default=0)
    host_risk   = models.CharField(max_length=10, choices=Severity.choices, default=Severity.NONE)
    open_port_count = models.IntegerField(default=0)
    scanned_at  = models.DateTimeField(auto_now_add=True)

    def __str__(self):
        return f"{self.ip_address} [{self.host_risk}]"

    class Meta:
        ordering       = ['ip_address']
        unique_together = [('scan', 'ip_address')]


# =============================================================================
# MODEL 4: PORT FINDING
# One open port found on a host.
# =============================================================================

class PortFinding(models.Model):
    host            = models.ForeignKey(HostResult, on_delete=models.CASCADE, related_name='ports')
    port            = models.IntegerField()
    protocol        = models.CharField(max_length=10)
    state           = models.CharField(max_length=20)
    service_name    = models.CharField(max_length=100, blank=True, default='')
    service_product = models.CharField(max_length=255, blank=True, default='')
    service_version = models.CharField(max_length=255, blank=True, default='')
    service_cpe     = models.CharField(max_length=255, blank=True, default='')
    severity        = models.CharField(max_length=10, choices=Severity.choices, default=Severity.INFO)
    risk_note       = models.TextField(blank=True, default='')
    is_critical_alert = models.BooleanField(default=False)
    alert_message   = models.CharField(max_length=500, blank=True, default='')
    found_at        = models.DateTimeField(auto_now_add=True)

    @property
    def full_version(self):
        parts = [self.service_product, self.service_version]
        return ' '.join(p for p in parts if p).strip() or 'N/A'

    def __str__(self):
        return f"Port {self.port}/{self.protocol} [{self.state}] {self.service_name} — {self.severity}"

    class Meta:
        ordering        = ['port']
        unique_together = [('host', 'port', 'protocol')]


# =============================================================================
# MODEL 5: DGA RESULT
# One complete DGA test run.
# =============================================================================

class DGAResult(models.Model):
    agent     = models.ForeignKey(
        Agent, on_delete=models.SET_NULL,
        null=True, blank=True, related_name='dga_results',
    )
    algorithm       = models.CharField(max_length=20, choices=DGAAlgorithm.choices, default=DGAAlgorithm.DATE_SEED)
    total_queries   = models.IntegerField(default=0)
    rate_per_sec    = models.FloatField(default=1.0)
    dns_server      = models.CharField(max_length=64, blank=True, default='system')
    seed_date       = models.DateField(null=True, blank=True)
    nxdomain_count  = models.IntegerField(default=0)
    resolved_count  = models.IntegerField(default=0)
    timeout_count   = models.IntegerField(default=0)
    error_count     = models.IntegerField(default=0)
    nxdomain_ratio  = models.FloatField(default=0.0)
    avg_entropy     = models.FloatField(default=0.0)
    max_entropy     = models.FloatField(default=0.0)
    min_entropy     = models.FloatField(default=0.0)
    duration_sec    = models.FloatField(default=0.0)
    ids_detected    = models.BooleanField(null=True, blank=True)
    ids_detection_notes = models.TextField(blank=True, default='')
    domains_json    = models.JSONField(default=list)
    created_at      = models.DateTimeField(auto_now_add=True)

    @property
    def risk_level(self) -> str:
        if self.nxdomain_ratio >= 0.8:
            return 'HIGH'
        elif self.nxdomain_ratio >= 0.5:
            return 'MEDIUM'
        return 'LOW'

    @property
    def ids_status(self) -> str:
        if self.ids_detected is None:
            return 'Unknown'
        return 'Detected' if self.ids_detected else 'Evaded'

    def __str__(self):
        return f"DGA [{self.algorithm}] {self.nxdomain_count}/{self.total_queries} NXDOMAIN"

    class Meta:
        ordering            = ['-created_at']
        verbose_name        = 'DGA Result'
        verbose_name_plural = 'DGA Results'


# =============================================================================
# MODEL 6: EXFIL RESULT
# One complete exfiltration simulation run.
# =============================================================================

class ExfilResult(models.Model):
    agent     = models.ForeignKey(
        Agent, on_delete=models.SET_NULL,
        null=True, blank=True, related_name='exfil_results',
    )
    technique        = models.CharField(max_length=10, choices=ExfilTechnique.choices, default=ExfilTechnique.DNS)
    profile          = models.CharField(max_length=20, choices=ExfilProfile.choices, default=ExfilProfile.BURST)
    target           = models.CharField(max_length=255, blank=True)
    total_chunks     = models.IntegerField(default=0)
    successful       = models.IntegerField(default=0)
    errors           = models.IntegerField(default=0)
    duration_sec     = models.FloatField(default=0.0)
    avg_interval_sec = models.FloatField(default=0.0)
    ids_severity     = models.CharField(max_length=20, blank=True)
    ids_signatures   = models.JSONField(default=list)
    ids_detected     = models.BooleanField(null=True, blank=True)
    ids_detection_notes = models.TextField(blank=True, default='')
    packets_json     = models.JSONField(default=list)
    created_at       = models.DateTimeField(auto_now_add=True)

    @property
    def success_rate(self) -> float:
        if self.total_chunks == 0:
            return 0.0
        return round(self.successful / self.total_chunks, 4)

    @property
    def ids_status(self) -> str:
        if self.ids_detected is None:
            return 'Unknown'
        return 'Detected' if self.ids_detected else 'Evaded'

    def __str__(self):
        return f"Exfil [{self.technique}/{self.profile}] {self.successful}/{self.total_chunks} sent"

    class Meta:
        ordering            = ['-created_at']
        verbose_name        = 'Exfil Result'
        verbose_name_plural = 'Exfil Results'


# =============================================================================
# MODEL 7: MODULE TASK
# Tracks a single web-initiated dispatch of any attack plugin.
#
# WHY THIS EXISTS:
#   When a user submits a DGA or Exfil task from the web UI, the HTTP
#   response must return immediately — the actual execution is async and
#   may take minutes. ModuleTask is the persistent tracking record that
#   bridges the HTTP request, the WebSocket command dispatch, the agent's
#   async plugin execution, and the final result row written back to DB.
#
#   The task_id UUID is the single identifier threaded through every layer:
#     UI form → Django dispatch view → channel_layer.group_send args →
#     agent orchestrator → telemetry POST body → api_*_results view →
#     ModuleTask.result_pk populated → WebSocket push back to browser.
#
#   result_pk is intentionally a loose IntegerField rather than a proper
#   ForeignKey. Because DGA and Exfil results live in separate tables,
#   using a GenericForeignKey would add complexity for little benefit at
#   this scale. The module field tells you which table result_pk points into:
#     module='dga'   → DGAResult.objects.get(pk=result_pk)
#     module='exfil' → ExfilResult.objects.get(pk=result_pk)
#     module='nmap'  → ScanRequest.objects.get(pk=result_pk)
# =============================================================================

class ModuleTask(models.Model):
    """
    One web-initiated module execution, tracked end-to-end.
    Created when a user submits a dispatch form; updated as the task
    progresses through the dispatch → agent → result pipeline.
    """

    # ── Identity ──────────────────────────────────────────────────────────────

    task_id = models.UUIDField(
        primary_key = True,
        default     = uuid.uuid4,
        editable    = False,
        help_text   = (
            'Unique identifier threaded through every layer of the dispatch '
            'pipeline. Included in the WebSocket command args so the agent '
            'can echo it back in the telemetry POST, allowing the result '
            'view to close the loop and populate result_pk.'
        ),
    )

    # ── Relationships ─────────────────────────────────────────────────────────

    agent = models.ForeignKey(
        Agent,
        on_delete    = models.CASCADE,
        related_name = 'module_tasks',
        help_text    = 'The agent this task was dispatched to.',
    )

    initiated_by = models.ForeignKey(
        'auth.User',
        on_delete    = models.SET_NULL,
        null         = True,
        blank        = True,
        related_name = 'initiated_module_tasks',
        help_text    = 'The web UI user who submitted this task. Null if dispatched via API.',
    )

    # ── Task classification ───────────────────────────────────────────────────

    module = models.CharField(
        max_length = 10,
        choices    = ModuleChoice.choices,
        db_index   = True,
        help_text  = (
            'Which attack plugin to invoke on the agent. '
            'Maps directly to the plugin name in orchestrator dispatch_command().'
        ),
    )

    status = models.CharField(
        max_length = 12,
        choices    = TaskStatus.choices,
        default    = TaskStatus.PENDING,
        db_index   = True,
        help_text  = 'Current lifecycle state of this task.',
    )

    # ── Configuration ─────────────────────────────────────────────────────────

    config_json = models.JSONField(
        default  = dict,
        help_text = (
            'The full parameter dictionary sent from the web UI form and '
            'forwarded verbatim to the agent as the command args payload. '
            'Stored here so tasks are fully reproducible and auditable. '
            'Example for DGA: {"algorithm": "date_seed", "count": 50, '
            '"rate": 1.0, "dns_server": null, "seed_secret": "BARC-MIAT"}. '
            'Example for Exfil: {"technique": "dns", "profile": "burst", '
            '"target": "192.168.1.1", "payload_type": "credentials"}.'
        ),
    )

    # ── Timing ────────────────────────────────────────────────────────────────

    dispatched_at = models.DateTimeField(
        auto_now_add = True,
        help_text    = 'Timestamp when the task record was created and the command was dispatched.',
    )

    completed_at = models.DateTimeField(
        null      = True,
        blank     = True,
        help_text = (
            'Timestamp when the result was received and result_pk was populated. '
            'Null until the task reaches COMPLETE or FAILED status.'
        ),
    )

    # ── Result linkage ────────────────────────────────────────────────────────

    result_pk = models.IntegerField(
        null      = True,
        blank     = True,
        help_text = (
            'Primary key of the result row written to the database once the '
            'agent posts its telemetry. Which table this pk references depends '
            'on the module field: dga → DGAResult, exfil → ExfilResult, '
            'nmap → ScanRequest. Null until status reaches COMPLETE.'
        ),
    )

    # ── Error detail ──────────────────────────────────────────────────────────

    error_message = models.TextField(
        blank     = True,
        default   = '',
        help_text = (
            'Human-readable error detail populated when status transitions to '
            'FAILED. May contain the agent exception message, a WebSocket '
            'delivery failure reason, or a timeout explanation.'
        ),
    )

    # ── Helpers ───────────────────────────────────────────────────────────────

    @property
    def task_id_short(self) -> str:
        """First 8 characters of the UUID for compact display in templates."""
        return str(self.task_id)[:8].upper()

    @property
    def duration_seconds(self) -> float | None:
        """
        Wall-clock seconds between dispatch and completion.
        Returns None if the task has not yet completed.
        """
        if self.completed_at and self.dispatched_at:
            return round(
                (self.completed_at - self.dispatched_at).total_seconds(), 1
            )
        return None

    @property
    def is_terminal(self) -> bool:
        """True once the task has reached a final state (complete or failed)."""
        return self.status in (TaskStatus.COMPLETE, TaskStatus.FAILED)

    def mark_dispatched(self) -> None:
        """
        Called by the dispatch view immediately after channel_layer.group_send
        successfully delivers the command to the agent WebSocket.
        """
        self.status = TaskStatus.DISPATCHED
        self.save(update_fields=['status'])

    def mark_running(self) -> None:
        """
        Called when the agent sends back a 'task_started' acknowledgement
        via the AgentConsumer WebSocket handler.
        """
        self.status = TaskStatus.RUNNING
        self.save(update_fields=['status'])

    def mark_complete(self, result_pk: int) -> None:
        """
        Called by the api_dga_results or api_exfil_results view once the
        result row has been committed to the database. Stores the result
        pk and timestamps the completion.
        """
        self.status       = TaskStatus.COMPLETE
        self.result_pk    = result_pk
        self.completed_at = timezone.now()
        self.save(update_fields=['status', 'result_pk', 'completed_at'])

    def mark_failed(self, reason: str) -> None:
        """
        Called when any layer of the pipeline encounters an unrecoverable
        error. Stores the reason and timestamps the failure.
        """
        self.status        = TaskStatus.FAILED
        self.error_message = reason
        self.completed_at  = timezone.now()
        self.save(update_fields=['status', 'error_message', 'completed_at'])

    def __str__(self) -> str:
        return (
            f"ModuleTask {self.task_id_short} "
            f"[{self.get_module_display()}] "
            f"→ agent:{self.agent.agent_id} "
            f"[{self.get_status_display()}]"
        )

    class Meta:
        ordering            = ['-dispatched_at']
        verbose_name        = 'Module Task'
        verbose_name_plural = 'Module Tasks'
        indexes = [
            # Dashboard queries filter heavily on status + module together
            models.Index(fields=['status', 'module'], name='idx_moduletask_status_module'),
            # Agent detail page looks up all tasks for one agent ordered by time
            models.Index(fields=['agent', 'dispatched_at'], name='idx_moduletask_agent_time'),
        ]