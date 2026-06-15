# scanner/agent_frontend_views.py
# ─────────────────────────────────────────────────────────────────────────────
#  Views for the agent management frontend pages.
#  These are browser-facing views (HTML responses), not API endpoints.
#
#  Add these to scanner/views.py or keep in a separate file.
#  If separate, import in scanner/urls.py:
#    from . import agent_frontend_views
# ─────────────────────────────────────────────────────────────────────────────

from datetime import timedelta
from django.shortcuts import render, redirect, get_object_or_404
from django.contrib.auth.decorators import login_required, user_passes_test
from django.contrib import messages
from django.utils import timezone
from django.conf import settings
from django.views.decorators.http import require_http_methods

from .models import Agent, ScanRequest

# Only staff/superusers can manage agents
staff_required = user_passes_test(lambda u: u.is_staff or u.is_superuser)


def _enrich_agent(agent):
    """
    Add computed properties to an agent object:
      - is_online: was last heartbeat within 60 seconds?
      - scan_count: how many scans submitted
    """
    # if agent.last_seen_at:
    #     # If heartbeat is less than 90 seconds old — agent is online
    #     agent.is_online = (timezone.now() - agent.last_seen_at).seconds < 90
    # else:
    #     agent.is_online = False
    return agent


# ── View 1: Agent list ────────────────────────────────────────────────────────

@login_required
@staff_required
def agent_list(request):
    """
    Lists all registered agents with their online/offline status.
    Only staff users can see this page.
    """
    agents = Agent.objects.all().order_by('-registered_at')
    agents = [_enrich_agent(a) for a in agents]

    return render(request, 'scanner/agent_list.html', {
        'agents': agents,
        'page':   'agents',
    })


# ── View 2: Register agent ────────────────────────────────────────────────────

@login_required
@staff_required
@require_http_methods(['GET', 'POST'])
def agent_register_view(request):
    """
    GET  → show the registration form
    POST → validate inputs, register agent, show credentials
    """
    new_agent    = None
    error_message = None

    class FakeForm:
        """Simple wrapper so template can use form.field.errors."""
        def __init__(self):
            self.agent_id         = type('F', (), {'value': lambda s: '', 'errors': []})()
            self.name             = type('F', (), {'value': lambda s: '', 'errors': []})()
            self.registration_key = type('F', (), {'value': lambda s: '', 'errors': []})()

    form = FakeForm()

    if request.method == 'POST':
        agent_id         = request.POST.get('agent_id', '').strip()
        name             = request.POST.get('name', '').strip()
        registration_key = request.POST.get('registration_key', '').strip()
        expected_key     = getattr(settings, 'AGENT_REGISTRATION_KEY', '')

        # Validate
        errors = {}

        if not agent_id:
            errors['agent_id'] = 'Agent ID is required.'
        elif not all(c.isalnum() or c == '-' for c in agent_id):
            errors['agent_id'] = 'Use only letters, numbers, and hyphens.'
        elif Agent.objects.filter(agent_id=agent_id).exists():
            errors['agent_id'] = f'Agent "{agent_id}" is already registered.'

        if not registration_key:
            errors['registration_key'] = 'Registration key is required.'
        elif registration_key != expected_key:
            errors['registration_key'] = 'Invalid registration key.'

        if errors:
            # Re-populate form values
            class PopForm:
                pass
            form = PopForm()
            form.agent_id         = type('F', (), {'value': lambda s, v=agent_id: v, 'errors': [errors.get('agent_id', '')]})()
            form.name             = type('F', (), {'value': lambda s, v=name: v, 'errors': []})()
            form.registration_key = type('F', (), {'value': lambda s: '', 'errors': [errors.get('registration_key', '')]})()
            error_message = 'Please fix the errors below.'

        else:
            # Create the agent
            auth_token = Agent.generate_auth_token()
            secret_key = Agent.generate_secret_key()

            agent = Agent.objects.create(
                agent_id       = agent_id,
                name           = name or agent_id,
                auth_token     = auth_token,
                secret_key     = secret_key,
                registered_by  = request.user,
            )

            # Pass raw credentials to template — shown ONCE
            new_agent = {
                'agent_id':   agent.agent_id,
                'name':       agent.name,
                'auth_token': auth_token,
                'secret_key': secret_key,
            }

            messages.success(
                request,
                f'Agent "{agent_id}" registered. '
                f'Save the credentials shown below — they will not be shown again.'
            )

    return render(request, 'scanner/agent_register.html', {
        'form':          form,
        'new_agent':     new_agent,
        'error_message': error_message,
        'page':          'agents',
    })


# ── View 3: Agent detail ──────────────────────────────────────────────────────

@login_required
@staff_required
def agent_detail(request, pk):
    """
    Shows full details for one agent: identity, token (masked),
    activity stats, and recent scans.
    """
    agent       = get_object_or_404(Agent, pk=pk)
    agent       = _enrich_agent(agent)

    # Fetch last 10 scan requests (by timestamp, since we don't link scans to agents yet)
    recent_scans = ScanRequest.objects.order_by('-created_at')[:10]

    return render(request, 'scanner/agent_detail.html', {
        'agent':        agent,
        'recent_scans': recent_scans,
        'page':         'agents',
    })


# ── View 4: Toggle agent active/inactive ──────────────────────────────────────

@login_required
@staff_required
@require_http_methods(['POST'])
def agent_toggle(request, pk):
    """Enable or disable an agent. POST only."""
    agent = get_object_or_404(Agent, pk=pk)
    agent.is_active = not agent.is_active
    agent.save(update_fields=['is_active'])

    status = 'enabled' if agent.is_active else 'disabled'
    messages.success(request, f'Agent "{agent.agent_id}" has been {status}.')
    return redirect('scanner:agent_list')


# ── View 5: Delete agent ──────────────────────────────────────────────────────

@login_required
@staff_required
@require_http_methods(['POST'])
def agent_delete(request, pk):
    """Permanently delete an agent. POST only."""
    agent = get_object_or_404(Agent, pk=pk)
    agent_id = agent.agent_id
    agent.delete()
    messages.success(request, f'Agent "{agent_id}" has been deleted.')
    return redirect('scanner:agent_list')