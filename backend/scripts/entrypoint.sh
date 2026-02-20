#!/bin/sh
# Entrypoint script for KernelEye API
# Downloads GeoIP databases on startup if MAXMIND_LICENSE_KEY is set

set -e

GEOIP_DIR="${GEOIP_DIR:-/opt/kerneleye/geoip}"
MAXMIND_KEY="${MAXMIND_LICENSE_KEY:-}"

# Create GeoIP directory
mkdir -p "$GEOIP_DIR"

# Download GeoIP databases if license key is available
if [ -n "$MAXMIND_KEY" ]; then
    echo "[entrypoint] MaxMind license key found, checking GeoIP databases..."
    
    # Check if databases exist and are less than 7 days old
    NEED_UPDATE=false
    for DB in GeoLite2-City GeoLite2-ASN; do
        DB_PATH="${GEOIP_DIR}/${DB}.mmdb"
        if [ ! -f "$DB_PATH" ]; then
            echo "[entrypoint] $DB.mmdb not found, will download"
            NEED_UPDATE=true
            break
        fi
        
        # Check if file is older than 7 days
        if [ -n "$(find "$DB_PATH" -mtime +7 2>/dev/null)" ]; then
            echo "[entrypoint] $DB.mmdb is older than 7 days, will update"
            NEED_UPDATE=true
            break
        fi
    done
    
    if [ "$NEED_UPDATE" = true ]; then
        echo "[entrypoint] Downloading GeoIP databases from MaxMind..."
        
        for DB in GeoLite2-City GeoLite2-ASN; do
            URL="https://download.maxmind.com/app/geoip_download?edition_id=${DB}&license_key=${MAXMIND_KEY}&suffix=tar.gz"
            DEST="${GEOIP_DIR}/${DB}.mmdb"
            TEMP_DIR=$(mktemp -d)
            
            echo "[entrypoint] Downloading $DB..."
            
            if wget -q -O "${TEMP_DIR}/${DB}.tar.gz" "$URL" 2>/dev/null; then
                # Extract the .mmdb file from the tar.gz
                tar -xzf "${TEMP_DIR}/${DB}.tar.gz" -C "$TEMP_DIR" 2>/dev/null
                
                # Find and move the .mmdb file
                MMDB_FILE=$(find "$TEMP_DIR" -name "*.mmdb" -type f | head -1)
                if [ -n "$MMDB_FILE" ]; then
                    mv "$MMDB_FILE" "$DEST"
                    echo "[entrypoint] $DB downloaded successfully"
                else
                    echo "[entrypoint] Warning: Failed to find .mmdb in archive for $DB"
                fi
            else
                echo "[entrypoint] Warning: Failed to download $DB"
            fi
            
            # Cleanup
            rm -rf "$TEMP_DIR"
        done
        
        # Save timestamp
        date > "${GEOIP_DIR}/.last_update"
        echo "[entrypoint] GeoIP update complete"
    else
        echo "[entrypoint] GeoIP databases are up to date"
    fi
    
    # List available databases
    echo "[entrypoint] Available GeoIP databases:"
    ls -lh "$GEOIP_DIR"/*.mmdb 2>/dev/null || echo "  (none found)"
else
    echo "[entrypoint] MAXMIND_LICENSE_KEY not set, skipping GeoIP download"
fi

# ==========================================
# Run Database Migrations
# ==========================================

MIGRATIONS_DIR="${MIGRATIONS_DIR:-/app/migrations}"

if [ -z "$DATABASE_URL" ]; then
    echo "[entrypoint] ERROR: DATABASE_URL is not set. Cannot run migrations."
    exit 1
fi

if [ -d "$MIGRATIONS_DIR" ]; then
    echo "[entrypoint] Running database migrations..."
    for f in $(ls "$MIGRATIONS_DIR"/*.sql 2>/dev/null | sort); do
        echo "[entrypoint]   Applying $(basename $f)..."
        psql "$DATABASE_URL" -f "$f" 2>&1 | grep -v "already exists" || true
    done
    echo "[entrypoint] Migrations complete."
else
    echo "[entrypoint] Warning: No migrations directory found at $MIGRATIONS_DIR"
fi

# Start the API
echo "[entrypoint] Starting KernelEye API..."
exec "$@"
