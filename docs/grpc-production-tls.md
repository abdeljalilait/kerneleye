# Production gRPC TLS Certificates

This guide covers production certificates for the KernelEye agent-to-backend
gRPC channel.

Do not use `scripts/generate-grpc-certs.sh` for production. That script creates
self-signed certificates for testing or internal development only. For
production, use either Let's Encrypt or a real internal certificate authority.

## Certificate Model

KernelEye uses two related TLS modes for gRPC:

- TLS: the backend presents a server certificate and agents verify it.
- mTLS: agents also present client certificates and the backend verifies them.

Production should use TLS at minimum. Use mTLS when you want certificate-based
agent identity in addition to KernelEye API keys and command signing.

Required files:

| File | Used by | Purpose |
|------|---------|---------|
| `server.crt` | Backend | gRPC server certificate for `grpc.example.com` |
| `server.key` | Backend | gRPC server private key |
| `ca.crt` | Agent | CA bundle used to verify the backend certificate |
| `agent.crt` | Agent | Optional mTLS client certificate |
| `agent.key` | Agent | Optional mTLS client private key |
| `client-ca.crt` | Backend | Optional mTLS CA used to verify agent certificates |

Set private keys to `0600` and keep them readable only by the service user.

## Option 1: Let's Encrypt Server Certificate

Use this path when the gRPC endpoint has a public DNS name, for example
`grpc.example.com`.

Generate or renew the certificate with your ACME client. Example with Certbot:

```bash
sudo certbot certonly \
  --standalone \
  -d grpc.example.com
```

Use an automated challenge method for production renewal. Certbot can renew
`--standalone`, `--webroot`, and supported DNS-plugin certificates
automatically. If Certbot prints this warning:

```text
This certificate will not be renewed automatically.
Autorenewal of --manual certificates requires the use of an authentication hook script.
```

then the certificate was issued with a manual challenge. It is valid, but it
will not renew by itself. Replace it with an automated challenge certificate, or
repeat the same manual command before the expiry date.

Certbot writes the certificate under:

```text
/etc/letsencrypt/live/grpc.example.com/fullchain.pem
/etc/letsencrypt/live/grpc.example.com/privkey.pem
```

Configure the backend:

```bash
export GRPC_TLS_CERT_FILE=/etc/letsencrypt/live/grpc.example.com/fullchain.pem
export GRPC_TLS_KEY_FILE=/etc/letsencrypt/live/grpc.example.com/privkey.pem
```

Agents can usually verify Let's Encrypt certificates with the system trust
store, so `--tls-ca-file` is not required unless the host lacks standard CA
roots.

Run the agent:

```bash
sudo kerneleye-agent \
  --server grpcs://grpc.example.com:9091
```

For Docker Compose, mount the certificate directory and set:

```env
GRPC_TLS_CERT_FILE=/certs/fullchain.pem
GRPC_TLS_KEY_FILE=/certs/privkey.pem
```

Restart the backend after certificate renewal so the gRPC server reloads the
new files.

Test renewal:

```bash
sudo certbot renew --dry-run
```

If the dry run succeeds, add a deploy hook so the backend reloads after renewal:

```bash
sudo certbot renew \
  --deploy-hook "docker compose restart kerneleye-api"
```

Use the service name that matches your deployment if it differs from
`kerneleye-api`.

## Option 2: Internal CA Server Certificate

Use this path for private infrastructure, non-public DNS names, or environments
where your organization already operates a CA.

Generate the backend server certificate from your internal CA with:

- Common Name or SAN matching the gRPC DNS name, for example
  `grpc.internal.example.com`.
- Extended Key Usage: `serverAuth`.
- A private key stored as `server.key`.
- A certificate chain stored as `server.crt`.

Configure the backend:

```bash
export GRPC_TLS_CERT_FILE=/etc/kerneleye/certs/server.crt
export GRPC_TLS_KEY_FILE=/etc/kerneleye/certs/server.key
```

Install the issuing CA certificate on each agent host, then either trust it at
the OS level or pass it explicitly:

```bash
sudo kerneleye-agent \
  --server grpcs://grpc.internal.example.com:9091 \
  --tls-ca-file /etc/kerneleye/certs/ca.crt
```

If the certificate DNS name differs from the connection host, set the expected
TLS name explicitly:

```bash
sudo kerneleye-agent \
  --server grpcs://10.0.0.10:9091 \
  --tls-ca-file /etc/kerneleye/certs/ca.crt \
  --tls-server-name grpc.internal.example.com
```

## Optional: Enable mTLS

mTLS requires a client certificate for each agent or agent group. Prefer
per-agent certificates when you need strong identity and revocation.

Issue each agent certificate from your internal CA with:

- Extended Key Usage: `clientAuth`.
- A unique subject or SAN that identifies the agent.
- A private key stored only on that agent host.

Configure the backend to trust the client CA:

```bash
export GRPC_MTLS_CA_FILE=/etc/kerneleye/certs/client-ca.crt
```

Run the agent with its client certificate:

```bash
sudo kerneleye-agent \
  --server grpcs://grpc.internal.example.com:9091 \
  --tls-ca-file /etc/kerneleye/certs/ca.crt \
  --tls-cert-file /etc/kerneleye/certs/agent.crt \
  --tls-key-file /etc/kerneleye/certs/agent.key
```

When `GRPC_MTLS_CA_FILE` is set, agents without a valid client certificate are
rejected during the TLS handshake.

## Verification

Check the backend certificate:

```bash
openssl s_client \
  -connect grpc.example.com:9091 \
  -servername grpc.example.com \
  -showcerts
```

Expected backend startup logs:

```text
gRPC TLS enabled
```

or, with mTLS:

```text
gRPC mTLS enabled: client certificates required
```

Expected agent behavior:

- Do not pass `--insecure` in production.
- Use `grpcs://` or a TLS-enabled gRPC URL.
- TLS handshake failures should cause retries, not plaintext fallback.

## Operational Notes

- Rotate server certificates before expiry.
- Restart the backend after replacing certificate files.
- Keep `server.key` and `agent.key` at permission `0600`.
- Store private keys outside the repository.
- Keep `CMD_SIGNING_KEY` enabled even with TLS or mTLS; TLS protects transport,
  while command signing protects remediation command integrity.
