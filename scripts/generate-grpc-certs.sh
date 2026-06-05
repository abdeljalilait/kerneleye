#!/bin/bash
#
# Generate self-signed TLS certificates for gRPC server.
#
# Usage:
#   ./scripts/generate-grpc-certs.sh <grpc-domain>
#
# Example:
#   ./scripts/generate-grpc-certs.sh grpc.example.com
#
# Output:
#   certs/ca.crt         — CA certificate (share with agents for verification)
#   certs/server.crt     — Server certificate (used by backend)
#   certs/server.key     — Server private key (used by backend, keep secret)
#   certs/agent.crt      — Agent client certificate (for mTLS, one per agent)
#   certs/agent.key      — Agent client private key (for mTLS)
#
# For production, use Let's Encrypt or a proper internal CA instead.

set -e

GRPC_DOMAIN="${1:-grpc.example.com}"
CERTS_DIR="certs"
CA_KEY="${CERTS_DIR}/ca.key"
CA_CRT="${CERTS_DIR}/ca.crt"
SERVER_KEY="${CERTS_DIR}/server.key"
SERVER_CSR="${CERTS_DIR}/server.csr"
SERVER_CRT="${CERTS_DIR}/server.crt"
AGENT_KEY="${CERTS_DIR}/agent.key"
AGENT_CSR="${CERTS_DIR}/agent.csr"
AGENT_CRT="${CERTS_DIR}/agent.crt"

RED='\033[0;31m'
GREEN='\033[0;32m'
BLUE='\033[0;34m'
NC='\033[0m'

echo -e "${BLUE}╔══════════════════════════════════════════════════════════╗${NC}"
echo -e "${BLUE}║${NC}     KernelEye gRPC TLS Certificate Generator              ${BLUE}║${NC}"
echo -e "${BLUE}╚══════════════════════════════════════════════════════════╝${NC}"
echo ""
echo "  Domain: ${GRPC_DOMAIN}"
echo "  Output: ${CERTS_DIR}/"
echo ""

mkdir -p "${CERTS_DIR}"

# ==========================================
# 1. Generate CA (Certificate Authority)
# ==========================================
echo -e "${BLUE}[1/4] Generating CA certificate...${NC}"

openssl genrsa -out "${CA_KEY}" 4096 2>/dev/null
chmod 600 "${CA_KEY}"

openssl req -x509 -new -nodes \
    -key "${CA_KEY}" \
    -sha256 -days 3650 \
    -out "${CA_CRT}" \
    -subj "/C=US/O=KernelEye/CN=KernelEye gRPC CA" 2>/dev/null

echo -e "${GREEN}  ✓ CA certificate: ${CA_CRT}${NC}"

# ==========================================
# 2. Generate server certificate
# ==========================================
echo -e "${BLUE}[2/4] Generating server certificate...${NC}"

openssl genrsa -out "${SERVER_KEY}" 2048 2>/dev/null
chmod 600 "${SERVER_KEY}"

cat > "${CERTS_DIR}/server-ext.cnf" <<EOF
[req]
distinguished_name = req_distinguished_name
req_extensions = v3_req
prompt = no

[req_distinguished_name]
C = US
O = KernelEye
CN = ${GRPC_DOMAIN}

[v3_req]
keyUsage = digitalSignature, keyEncipherment
extendedKeyUsage = serverAuth
subjectAltName = @alt_names

[alt_names]
DNS.1 = ${GRPC_DOMAIN}
EOF

openssl req -new \
    -key "${SERVER_KEY}" \
    -out "${SERVER_CSR}" \
    -config "${CERTS_DIR}/server-ext.cnf" 2>/dev/null

openssl x509 -req \
    -in "${SERVER_CSR}" \
    -CA "${CA_CRT}" \
    -CAkey "${CA_KEY}" \
    -CAcreateserial \
    -out "${SERVER_CRT}" \
    -days 365 \
    -sha256 \
    -extensions v3_req \
    -extfile "${CERTS_DIR}/server-ext.cnf" 2>/dev/null

rm -f "${SERVER_CSR}" "${CERTS_DIR}/server-ext.cnf"
echo -e "${GREEN}  ✓ Server certificate: ${SERVER_CRT}${NC}"
echo -e "${GREEN}  ✓ Server key:         ${SERVER_KEY}${NC}"

# ==========================================
# 3. Generate agent client certificate (for mTLS)
# ==========================================
echo -e "${BLUE}[3/4] Generating agent client certificate (mTLS)...${NC}"

openssl genrsa -out "${AGENT_KEY}" 2048 2>/dev/null
chmod 600 "${AGENT_KEY}"

cat > "${CERTS_DIR}/agent-ext.cnf" <<EOF
[req]
distinguished_name = req_distinguished_name
req_extensions = v3_req
prompt = no

[req_distinguished_name]
C = US
O = KernelEye
CN = kerneleye-agent

[v3_req]
keyUsage = digitalSignature, keyEncipherment
extendedKeyUsage = clientAuth
EOF

openssl req -new \
    -key "${AGENT_KEY}" \
    -out "${AGENT_CSR}" \
    -config "${CERTS_DIR}/agent-ext.cnf" 2>/dev/null

openssl x509 -req \
    -in "${AGENT_CSR}" \
    -CA "${CA_CRT}" \
    -CAkey "${CA_KEY}" \
    -CAcreateserial \
    -out "${AGENT_CRT}" \
    -days 365 \
    -sha256 \
    -extensions v3_req \
    -extfile "${CERTS_DIR}/agent-ext.cnf" 2>/dev/null

rm -f "${AGENT_CSR}" "${CERTS_DIR}/agent-ext.cnf"
echo -e "${GREEN}  ✓ Agent certificate: ${AGENT_CRT}${NC}"
echo -e "${GREEN}  ✓ Agent key:         ${AGENT_KEY}${NC}"

# ==========================================
# 4. Cleanup and summary
# ==========================================
echo -e "${BLUE}[4/4] Cleaning up...${NC}"

# Remove CA private key — no longer needed after signing
# Keep it if you plan to generate more agent certs later
echo -e "${GREEN}  ✓ Cleanup complete${NC}"

echo ""
echo -e "${GREEN}╔══════════════════════════════════════════════════════════╗${NC}"
echo -e "${GREEN}║${NC}              Certificates Generated                       ${GREEN}║${NC}"
echo -e "${GREEN}╚══════════════════════════════════════════════════════════╝${NC}"
echo ""
echo "Files created in ${CERTS_DIR}/:"
echo ""
echo "  Backend (server):"
echo "    ${SERVER_CRT}"
echo "    ${SERVER_KEY}"
echo ""
echo "  Agent (client, for mTLS):"
echo "    ${AGENT_CRT}"
echo "    ${AGENT_KEY}"
echo ""
echo "  CA (trust anchor — share with all agents):"
echo "    ${CA_CRT}"
echo ""
echo -e "${BLUE}Next steps:${NC}"
echo ""
echo "  1. Backend env vars (set in .env or docker-compose):"
echo "     GRPC_TLS_CERT_FILE=${SERVER_CRT}"
echo "     GRPC_TLS_KEY_FILE=${SERVER_KEY}"
echo "     # For mTLS:"
echo "     GRPC_MTLS_CA_FILE=${CA_CRT}"
echo ""
echo "  2. Agent flags:"
echo "     --tls-ca-file ${CA_CRT}"
echo "     # For mTLS:"
echo "     --tls-cert-file ${AGENT_CRT}"
echo "     --tls-key-file ${AGENT_KEY}"
echo ""
echo -e "${YELLOW}⚠  For production, use Let's Encrypt or a real internal CA.${NC}"
echo -e "${YELLOW}   These self-signed certs are for testing/internal use only.${NC}"
