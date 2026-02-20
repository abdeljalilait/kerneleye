#!/bin/sh
# KernelEye Frontend Entrypoint Script

set -e

# ==========================================
# Environment Variables with Defaults
# ==========================================

# Backend API configuration
export BACKEND_HOST="${BACKEND_HOST:-api.kerneleye.cloud}"
export BACKEND_PORT="${BACKEND_PORT:-443}"

# Domain configuration - strip https:// or http:// if present
LANDING_DOMAIN_RAW="${LANDING_DOMAIN:-kerneleye.cloud}"
DASHBOARD_DOMAIN_RAW="${DASHBOARD_DOMAIN:-app.kerneleye.cloud}"

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

# Test nginx config
nginx -t

echo "=========================================="
echo "Starting nginx..."
echo "=========================================="

exec "$@"
