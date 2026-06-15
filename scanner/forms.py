# scanner/forms.py
# ─────────────────────────────────────────────────────────────────────────────
#  MIAT — Forms
#
#  Django Forms do 3 things:
#    1. Render HTML input fields automatically
#    2. Validate submitted data before it touches your DB
#    3. Give clean error messages back to the user
#
#  We have one form: ScanForm — the "submit a scan" form.
# ─────────────────────────────────────────────────────────────────────────────

import ipaddress
import re
from django import forms
from .models import ScanProfile


class ScanForm(forms.Form):

    # ── Target field ─────────────────────────────────────────────────────────
    target = forms.CharField(
        label       = 'Target',
        max_length  = 255,
        widget      = forms.TextInput(attrs={
            'placeholder': 'e.g. 192.168.1.1  or  192.168.1.0/24  or  scanme.nmap.org',
            'class':       'form-control',
            'autofocus':   True,
        }),
        help_text = 'Enter an IP address, CIDR subnet, or hostname.',
    )

    # ── Scan profile dropdown ────────────────────────────────────────────────
    scan_profile = forms.ChoiceField(
        label   = 'Scan Profile',
        choices = ScanProfile.choices,
        initial = ScanProfile.DEFAULT,
        widget  = forms.Select(attrs={'class': 'form-select'}),
        help_text = (
            'Fast = top 100 ports | '
            'Default = top 1000 ports | '
            'Deep = all 65535 ports + OS detection (needs admin/root) | '
            'Ping = host discovery only'
        ),
    )

    # ── Validation ───────────────────────────────────────────────────────────
    # Django calls clean_<fieldname>() automatically during form.is_valid()
    # Raise forms.ValidationError to reject the value with an error message.

    def clean_target(self):
        """
        Validate the target field.
        Accepts: IPv4, IPv6, CIDR notation, hostnames.
        Rejects: empty strings, obviously invalid values.
        """
        target = self.cleaned_data['target'].strip()

        if not target:
            raise forms.ValidationError('Target cannot be empty.')

        # Try as IP address first
        try:
            ipaddress.ip_address(target)
            return target          # valid single IP
        except ValueError:
            pass

        # Try as CIDR network
        try:
            ipaddress.ip_network(target, strict=False)
            return target          # valid CIDR e.g. 192.168.1.0/24
        except ValueError:
            pass

        # Try as hostname — basic sanity check
        # Hostnames: letters, digits, hyphens, dots. Min 2 chars.
        hostname_pattern = re.compile(
            r'^([a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)*'
            r'[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?$'
        )
        if hostname_pattern.match(target):
            return target

        raise forms.ValidationError(
            f'"{target}" is not a valid IP address, subnet, or hostname.'
        )

    def clean_scan_profile(self):
        """Ensure the chosen profile is one of the defined options."""
        profile = self.cleaned_data['scan_profile']
        valid   = [choice[0] for choice in ScanProfile.choices]
        if profile not in valid:
            raise forms.ValidationError('Invalid scan profile selected.')
        return profile