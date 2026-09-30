#!/bin/bash
# Usage: ./file_integrity_monitor.sh baseline   -> record current hashes
#        ./file_integrity_monitor.sh check      -> compare against baseline

WATCH_DIR="$HOME/cyber-bootcamp/watched_files"
BASELINE_FILE="$HOME/cyber-bootcamp/baseline_hashes.txt"

mkdir -p "$WATCH_DIR"

if [ "$1" == "baseline" ]; then
    echo "Recording baseline hashes for files in $WATCH_DIR ..."
    find "$WATCH_DIR" -type f -exec sha256sum {} \; > "$BASELINE_FILE"
    echo "Baseline saved to $BASELINE_FILE"
    cat "$BASELINE_FILE"

elif [ "$1" == "check" ]; then
    if [ ! -f "$BASELINE_FILE" ]; then
        echo "No baseline found. Run with 'baseline' first."
        exit 1
    fi
    echo "Checking current files against baseline..."
    echo ""
    CHANGED=0
    while read -r expected_hash filepath; do
        if [ -f "$filepath" ]; then
            current_hash=$(sha256sum "$filepath" | awk '{print $1}')
            if [ "$current_hash" != "$expected_hash" ]; then
                echo "ALERT: $filepath has been MODIFIED since baseline!"
                echo "   Expected: $expected_hash"
                echo "   Current:  $current_hash"
                CHANGED=1
            else
                echo "OK: $filepath unchanged"
            fi
        else
            echo "ALERT: $filepath is MISSING (was in baseline, not found now)"
            CHANGED=1
        fi
    done < "$BASELINE_FILE"
    echo ""
    if [ $CHANGED -eq 0 ]; then
        echo "Result: No changes detected. All files match baseline."
    else
        echo "Result: CHANGES DETECTED — investigate immediately."
    fi

else
    echo "Usage: $0 [baseline|check]"
fi
