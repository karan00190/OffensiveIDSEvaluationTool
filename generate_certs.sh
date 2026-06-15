#!/bin/bash
# generate_certs.sh
# ─────────────────────────────────────────────────────────────────────────────
#  MIAT — Certificate Generation Script
#  Run this ONCE on your server to create all certificates.
#
#  What this creates:
#    certs/ca.key          CA private key (keep SECRET — never share this)
#    certs/ca.crt          CA certificate (share with everyone — it's public)
#    certs/server.key      Server private key (keep on server only)
#    certs/server.crt      Server certificate (public)
#    certs/agent.key       Agent private key (copy to agent machine)
#    certs/agent.crt       Agent certificate (public)
#
#  How certificates work:
#    The CA (Certificate Authority) is like a trusted notary.
#    It signs both the server cert and agent cert.
#    When server and agent connect, they each check:
#    "Is this certificate signed by our CA?" — if yes, trust it.
#    This is mutual TLS — BOTH sides verify each other.
#
#  Usage:
#    chmod +x generate_certs.sh
#    ./generate_certs.sh
#    Then copy to agent machine:
#      certs/ca.crt, certs/agent.key, certs/agent.crt
# ─────────────────────────────────────────────────────────────────────────────

set -e
mkdir -p certs
cd certs

echo ""
echo "═══════════════════════════════════════════════"
echo "  MIAT Certificate Generation"
echo "═══════════════════════════════════════════════"
echo ""

# ── Step 1: Create Certificate Authority (CA) ─────────────────────────────
# The CA is the root of trust. Both server and agent will trust anything
# signed by this CA.
echo "[1/3] Creating Certificate Authority..."

# Generate CA private key (4096-bit RSA)
openssl genrsa -out ca.key 4096

# Create self-signed CA certificate (valid 10 years)
openssl req -new -x509 \
    -key ca.key \
    -out ca.crt \
    -days 3650 \
    -subj "/C=IN/ST=Maharashtra/L=Mumbai/O=BARC-MIAT/CN=MIAT-CA"

echo "    ✓ CA key:  certs/ca.key"
echo "    ✓ CA cert: certs/ca.crt"


# ── Step 2: Create Server Certificate ────────────────────────────────────────
echo ""
echo "[2/3] Creating server certificate..."

# Generate server private key
openssl genrsa -out server.key 2048

# Create Certificate Signing Request (CSR) for server
openssl req -new \
    -key server.key \
    -out server.csr \
    -subj "/C=IN/ST=Maharashtra/L=Mumbai/O=BARC-MIAT/CN=miat-server"

# Create extensions file for server cert
# subjectAltName is required for modern TLS — lists valid hostnames/IPs
cat > server_ext.cnf << EOF
[SAN]
subjectAltName=DNS:localhost,DNS:miat-server,IP:127.0.0.1
EOF

# CA signs the server CSR → creates server certificate
openssl x509 -req \
    -in server.csr \
    -CA ca.crt \
    -CAkey ca.key \
    -CAcreateserial \
    -out server.crt \
    -days 365 \
    -extfile server_ext.cnf \
    -extensions SAN

# Clean up CSR (no longer needed)
rm server.csr server_ext.cnf

echo "    ✓ Server key:  certs/server.key"
echo "    ✓ Server cert: certs/server.crt"


# ── Step 3: Create Agent Certificate ─────────────────────────────────────────
echo ""
echo "[3/3] Creating agent certificate..."

# Generate agent private key
openssl genrsa -out agent.key 2048

# Create CSR for agent
openssl req -new \
    -key agent.key \
    -out agent.csr \
    -subj "/C=IN/ST=Maharashtra/L=Mumbai/O=BARC-MIAT/CN=miat-agent"

# CA signs the agent CSR → creates agent certificate
openssl x509 -req \
    -in agent.csr \
    -CA ca.crt \
    -CAkey ca.key \
    -CAcreateserial \
    -out agent.crt \
    -days 365

# Clean up CSR
rm agent.csr

echo "    ✓ Agent key:  certs/agent.key"
echo "    ✓ Agent cert: certs/agent.crt"

echo ""
echo "═══════════════════════════════════════════════"
echo "  Done! Files created:"
echo "  certs/ca.key      ← SECRET: keep on server only"
echo "  certs/ca.crt      ← Copy to agent machine"
echo "  certs/server.key  ← Keep on server only"
echo "  certs/server.crt  ← Keep on server only"
echo "  certs/agent.key   ← Copy to agent machine"
echo "  certs/agent.crt   ← Copy to agent machine"
echo ""
echo "  Agent machine needs: ca.crt + agent.key + agent.crt"
echo "═══════════════════════════════════════════════"
echo ""