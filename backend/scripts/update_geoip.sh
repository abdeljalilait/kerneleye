#!/bin/sh
# Download GeoLite2 databases from MaxMind (official source)
# Requires MAXMIND_LICENSE_KEY environment variable

set -e

GEOIP_DIR="${GEOIP_DIR:-/opt/haraka/geoip}"
LICENSE_KEY="${MAXMIND_LICENSE_KEY:-}"

# Create directory if not exists
mkdir -p "$GEOIP_DIR"

# Check for license key
if [ -z "$LICENSE_KEY" ]; then
    echo "[geoip-update] ERROR: MAXMIND_LICENSE_KEY not set"
    exit 1
fi

echo "[geoip-update] Downloading from MaxMind..."

# Database files to download
DATABASES="GeoLite2-ASN GeoLite2-City GeoLite2-Country"

for DB in $DATABASES; do
    URL="https://download.maxmind.com/app/geoip_download?edition_id=${DB}&license_key=${LICENSE_KEY}&suffix=tar.gz"
    DEST="${GEOIP_DIR}/${DB}.mmdb"
    TEMP_DIR=$(mktemp -d)
    
    echo "[geoip-update] Downloading $DB..."
    
    if wget -q -O "${TEMP_DIR}/${DB}.tar.gz" "$URL"; then
        # Extract the .mmdb file from the tar.gz
        tar -xzf "${TEMP_DIR}/${DB}.tar.gz" -C "$TEMP_DIR"
        
        # Find and move the .mmdb file
        MMDB_FILE=$(find "$TEMP_DIR" -name "*.mmdb" -type f | head -1)
        if [ -n "$MMDB_FILE" ]; then
            mv "$MMDB_FILE" "$DEST"
            echo "[geoip-update] $DB downloaded successfully"
        else
            echo "[geoip-update] Failed to find .mmdb in archive for $DB"
        fi
    else
        echo "[geoip-update] Failed to download $DB"
    fi
    
    # Cleanup
    rm -rf "$TEMP_DIR"
done

# Save timestamp
date > "${GEOIP_DIR}/.last_update"
echo "[geoip-update] Update complete"

# List downloaded files
echo "[geoip-update] Databases:"
ls -lh "$GEOIP_DIR"/*.mmdb 2>/dev/null || echo "  (no databases found)"
