# scanner/payload_views.py
# =============================================================================
#  MIAT — Pull-Model Payload Management Views
#
#  Browser-facing views (login required):
#    payload_manager_view  GET  /modules/payloads/
#    upload_payload        POST /modules/payloads/upload/
#    list_payloads         GET  /api/modules/payloads/
#    delete_payload        POST /api/modules/payloads/<id>/delete/
#
#  Agent-facing view (AgentAuthentication — mTLS + JWT + HMAC):
#    payload_download      GET  /api/agent/payload/<id>/download/
#
#  Architecture note:
#    The download endpoint streams raw bytes via StreamingHttpResponse.
#    64 KB chunks prevent the Django process from loading a 35 MB file
#    into RAM in one shot.  The agent accumulates chunks into io.BytesIO
#    and never writes to disk.
# =============================================================================

import hashlib
import logging
from datetime import timedelta

from django.contrib.auth.decorators import login_required
from django.http                    import (JsonResponse, StreamingHttpResponse,
                                            HttpResponse)
from django.shortcuts               import render, get_object_or_404
from django.utils                   import timezone
from django.views.decorators.http   import require_http_methods

from rest_framework.decorators  import api_view, authentication_classes, permission_classes
from rest_framework.permissions import IsAuthenticated
from rest_framework.response    import Response
from rest_framework             import status as drf_status

from .authentication import AgentAuthentication
from .models         import ExfilPayload, PayloadSource

logger = logging.getLogger(__name__)

# ── Machine-generated payload templates (mirrored from exfil_plugin.py) ──────
_GENERATED_TEMPLATES: dict[str, bytes] = {
    'credentials': b"username=admin&password=P@ssw0rd123&token=eyJhbGciOiJSUzI1NiJ9",  # b means -> raw byte formatting
    'pii':         b"name=John Doe,dob=1990-01-15,ssn=123-45-6789,email=john@example.com",
    'api_key':     b"api_key=AKIA1234567890ABCDEF&secret=wJalrXUtnFEMI/K7MDENG/bPxRfiCY",
    'db_dump':     b"id,name,email\n1,Alice,alice@ex.com\n2,Bob,bob@ex.com",
    'config':      b"DB_HOST=192.168.1.100\nDB_PASS=SuperSecret!\nSECRET_KEY=abc123",
}

MAX_UPLOAD_BYTES = 35 * 1024 * 1024   # 35 MB hard ceiling
UPLOAD_EXPIRY_HOURS = 24               # manual uploads expire after 24 h
STREAM_CHUNK = 65_536                  # 64 KB streaming chunk size


def _stream_file(file_field):
    """Yield file contents in STREAM_CHUNK-byte pieces."""
    with file_field.open('rb') as fh:
        while True:
            chunk = fh.read(STREAM_CHUNK)
            if not chunk:
                break
            yield chunk


# =============================================================================
# BROWSER VIEWS
# =============================================================================

@login_required
def payload_manager_view(request):
    """
    GET /modules/payloads/
    Renders the payload upload and management dashboard.
    """
    payloads = (
        ExfilPayload.objects
        .select_related('created_by')
        .order_by('-created_at')
    )
    return render(request, 'scanner/payload_manager.html', {
        'payloads': payloads,
        'page':     'modules',
    })


@login_required
@require_http_methods(['POST'])
def upload_payload(request):
    """
    POST /modules/payloads/upload/
    Accepts a multipart file upload.  Computes SHA-256 while chunking —
    no full-file memory load.  Returns JSON with payload metadata.
    """
    uploaded = request.FILES.get('payload_file')
    name     = request.POST.get('name', '').strip()

    payload_type = request.POST.get('payload_type', 'custom').strip() or 'custom' #Force a default type and prevent validation crash

    if not uploaded:
        return JsonResponse({'error': 'No file attached to request.'}, status=400)

    if uploaded.size > MAX_UPLOAD_BYTES:
        return JsonResponse(
            {'error': f'File exceeds {MAX_UPLOAD_BYTES // (1024*1024)} MB limit.'},
            status=400,
        )

    # Compute SHA-256 while iterating chunks — avoids loading 35 MB into RAM
    sha = hashlib.sha256()
    for chunk in uploaded.chunks():
        sha.update(chunk)
    digest = sha.hexdigest()

    # Reset pointer so Django's storage backend can re-read the file
    uploaded.seek(0)

    payload = ExfilPayload.objects.create(
        name            = name or uploaded.name,
        source_type     = PayloadSource.MANUAL,
        payload_type = payload_type,
        created_by      = request.user,
        uploaded_file   = uploaded,
        file_size       = uploaded.size,
        checksum_sha256 = digest,
        expires_at      = timezone.now() + timedelta(hours=UPLOAD_EXPIRY_HOURS),
    )

    logger.info(
        f"Payload uploaded: #{payload.pk} '{payload.name}' "
        f"{payload.file_size} B  checksum={digest[:16]}…  "
        f"by {request.user.username}"
    )

    return JsonResponse({
        'payload_id':     payload.pk,
        'name':           payload.name,
        'size':           payload.file_size,
        'size_display':   payload.size_display,
        'checksum':       f"sha256:{digest}",
        'checksum_short': payload.checksum_short,
        'expires_at':     payload.expires_at.isoformat(),
        'download_url':   f'/api/agent/payload/{payload.pk}/download/',
        'source_type':    payload.source_type,
    }, status=201)


@login_required
@require_http_methods(['GET'])
def list_payloads(request):
    """
    GET /api/modules/payloads/
    Returns JSON list of all manual-upload payloads for the AJAX dropdown
    in module_control.html.  Only returns MANUAL payloads — generated
    payloads are handled inline by the plugin.
    """
    payloads = (
        ExfilPayload.objects
        .filter(source_type=PayloadSource.MANUAL)
        .select_related('created_by')
        .order_by('-created_at')
    )

    items = []
    for p in payloads:
        items.append({
            'id':             p.pk,
            'name':           p.name,
            'size':           p.file_size,
            'size_display':   p.size_display,
            'checksum':       f"sha256:{p.checksum_sha256}",
            'checksum_short': p.checksum_short,
            'expired':        p.is_expired,
            'expires_at':     p.expires_at.isoformat() if p.expires_at else None,
            'download_url':   f'/api/agent/payload/{p.pk}/download/',
            'created_by':     p.created_by.username if p.created_by else '—',
            'created_at':     p.created_at.isoformat(),
        })

    return JsonResponse({'payloads': items, 'count': len(items)})


@login_required
@require_http_methods(['POST'])
def delete_payload(request, payload_id):
    """
    POST /api/modules/payloads/<id>/delete/
    Removes the file from storage and the row from the database.
    """
    payload = get_object_or_404(ExfilPayload, pk=payload_id)
    name    = payload.name

    # Delete the physical file first
    if payload.uploaded_file:
        payload.uploaded_file.delete(save=False)

    payload.delete()

    logger.info(
        f"Payload #{payload_id} '{name}' deleted by {request.user.username}"
    )
    return JsonResponse({'deleted': True, 'payload_id': payload_id, 'name': name})


# =============================================================================
# AGENT-FACING DOWNLOAD ENDPOINT
# =============================================================================

@api_view(['GET'])
@authentication_classes([AgentAuthentication])
@permission_classes([IsAuthenticated])
def payload_download(request, payload_id):
    """
    GET /api/agent/payload/<payload_id>/download/
    Agent-authenticated binary download.

    Security properties:
      • Requires mTLS + JWT + HMAC — same triple-layer stack as every other
        agent endpoint.  Unauthenticated callers receive 403.
      • Expiry gate: expired payloads return 410 Gone — agent logs this and
        marks the ModuleTask as failed.
      • StreamingHttpResponse: server sends file in STREAM_CHUNK-byte pieces.
        Django process never loads a 35 MB file into a single buffer.
      • X-Payload-Checksum header carries sha256:<hex> so the agent can verify
        integrity after accumulating all chunks in io.BytesIO.

    For GENERATED payloads:
      The bytes are synthesised on the fly from the _GENERATED_TEMPLATES dict.
      No file storage involved.
    """
    payload = get_object_or_404(ExfilPayload, pk=payload_id)

    # ── Expiry gate ───────────────────────────────────────────────────────────
    if payload.is_expired:
        logger.warning(
            f"Agent {request.user} attempted download of expired "
            f"payload #{payload_id}"
        )
        return Response(
            {'error': f'Payload #{payload_id} has expired and can no longer be downloaded.'},
            status=drf_status.HTTP_410_GONE,
        )

    # ── Generated mode: synthesise bytes on the fly ───────────────────────────
    if payload.source_type == PayloadSource.GENERATED:
        raw     = _GENERATED_TEMPLATES.get(payload.payload_type, b'')
        digest  = hashlib.sha256(raw).hexdigest()
        resp    = HttpResponse(raw, content_type='application/octet-stream')
        resp['X-Payload-Checksum'] = f'sha256:{digest}'
        resp['X-Payload-ID']       = str(payload.pk)
        resp['Content-Length']     = len(raw)
        return resp

    # ── Manual mode: stream uploaded file ────────────────────────────────────
    if not payload.uploaded_file:
        return Response(
            {'error': 'Payload file not found on server storage.'},
            status=drf_status.HTTP_404_NOT_FOUND,
        )

    logger.info(
        f"Agent {request.user} downloading payload #{payload_id} "
        f"'{payload.name}' ({payload.size_display})"
    )

    response = StreamingHttpResponse(
        _stream_file(payload.uploaded_file),
        content_type='application/octet-stream',
    )
    response['Content-Length']     = payload.file_size
    response['X-Payload-Checksum'] = f'sha256:{payload.checksum_sha256}'
    response['X-Payload-ID']       = str(payload.pk)
    return response