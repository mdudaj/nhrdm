# -*- shell-script -*-
# This file is part of NHRDM.

#!/bin/bash
# check_pipfile_lock.sh
# Script to inspect Python version and installed packages in Pipfile.lock

LOCK_FILE="Pipfile.lock"

if [ ! -f "$LOCK_FILE" ]; then
    echo "Error: $LOCK_FILE not found in current directory."
    exit 1
fi

echo "Python version required in Pipfile.lock:"
jq -r '._meta.requires.python_version' "$LOCK_FILE"
echo ""

echo "Default packages (with versions):"
jq -r '.default | to_entries[] | "\(.key) \(.value.version)"' "$LOCK_FILE"
echo ""

echo "Development packages (with versions):"
jq -r '.develop | to_entries[] | "\(.key) \(.value.version)"' "$LOCK_FILE"
