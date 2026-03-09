#!/bin/bash
# Migrate device data from historical Zeek logs

set -e

WORKDIR="${HOMENETSEC_WORKDIR:-/mnt/5TB/HomeNetSec/output}"
DEVICES_DB="$WORKDIR/state/devices.sqlite"
ZEEK_FLAT_DIR="$WORKDIR/zeek-flat"

echo "Migrating device data from historical Zeek logs..."
echo "Device database: $DEVICES_DB"
echo ""

count=0
for dir in "$ZEEK_FLAT_DIR"/2026-*; do
    if [ ! -d "$dir" ]; then
        continue
    fi

    if [ ! -f "$dir/conn.log" ]; then
        continue
    fi

    day=$(basename "$dir")
    echo "Processing $day..."

    python3 "$(dirname "$0")/device_inventory_update.py" \
        --day "$day" \
        --zeek-flat-dir "$dir" \
        --db "$DEVICES_DB" 2>&1 | grep -E "(Parsing|Found|✓|⚠|Warning)"

    count=$((count + 1))
    echo ""
done

echo "================================"
echo "Migration complete!"
echo "Processed $count days"
echo "================================"
