#!/bin/sh
# KernelEye Frontend Entrypoint Script

set -e

# ==========================================
# Environment Variables with Defaults
# ==========================================

# Backend API configuration
export BACKEND_HOST="${BACKEND_HOST:-api.kerneleye.net}"
export BACKEND_PORT="${BACKEND_PORT:-443}"

# Domain configuration - strip https:// or http:// if present
LANDING_DOMAIN_RAW="${LANDING_DOMAIN:-kerneleye.net}"
DASHBOARD_DOMAIN_RAW="${DASHBOARD_DOMAIN:-app.kerneleye.net}"

# Remove protocol prefixes if present
export LANDING_DOMAIN=$(echo "$LANDING_DOMAIN_RAW" | sed 's|https://||g' | sed 's|http://||g')
export DASHBOARD_DOMAIN=$(echo "$DASHBOARD_DOMAIN_RAW" | sed 's|https://||g' | sed 's|http://||g')

# Construct API URL for dashboard
# BACKEND_USE_HTTPS can be set to 'true' to force HTTPS (useful for reverse proxy setups)
if [ "$BACKEND_USE_HTTPS" = "true" ] || [ "$BACKEND_PORT" = "443" ] || [ "$BACKEND_PORT" = "8443" ]; then
    export API_URL="https://${BACKEND_HOST}/api/v1"
    export WS_URL="wss://${BACKEND_HOST}/ws"
elif [ "$BACKEND_PORT" = "80" ]; then
    export API_URL="http://${BACKEND_HOST}/api/v1"
    export WS_URL="ws://${BACKEND_HOST}/ws"
else
    export API_URL="http://${BACKEND_HOST}:${BACKEND_PORT}/api/v1"
    export WS_URL="ws://${BACKEND_HOST}:${BACKEND_PORT}/ws"
fi

# ==========================================
# Logging Configuration
# ==========================================

echo "=========================================="
echo "KernelEye Frontend Configuration"
echo "=========================================="
echo "Landing Domain:   $LANDING_DOMAIN"
echo "Dashboard Domain: $DASHBOARD_DOMAIN"
echo "API URL:          $API_URL"
echo "WebSocket URL:    $WS_URL"
echo "=========================================="

# ==========================================
# Generate Nginx Config
# ==========================================

# Process nginx template
envsubst '\$LANDING_DOMAIN \$DASHBOARD_DOMAIN' < /etc/nginx/templates/default.conf.template > /etc/nginx/conf.d/default.conf

echo "Nginx configuration generated:"
cat /etc/nginx/conf.d/default.conf

# ==========================================
# Generate Install Script
# ==========================================

# INSTALL_DOMAIN defaults to DASHBOARD_DOMAIN
export INSTALL_DOMAIN="${INSTALL_DOMAIN:-$DASHBOARD_DOMAIN}"

echo "Install Domain: $INSTALL_DOMAIN"

if [ -f /etc/kerneleye/install.sh.template ]; then
    sed "s|__INSTALL_DOMAIN__|${INSTALL_DOMAIN}|g" \
        /etc/kerneleye/install.sh.template \
        > /usr/share/nginx/html/install.sh
    chmod 644 /usr/share/nginx/html/install.sh
    echo "Install script generated at /usr/share/nginx/html/install.sh"
else
    echo "WARNING: install.sh.template not found, skipping"
fi

# Test nginx config
nginx -t

echo "=========================================="
echo "Starting nginx..."
echo "=========================================="

exec "$@"
