#!/bin/bash
# One-time import of virt-who test cases to Polarion RHELSS project.
# Prerequisites: VPN connected, POLARION_USER, POLARION_PASS and
# POLARION_URL set.
# Run from virtwho-test repo root after generating test-cases.xml:
#
#   PYTHONPATH=. betelgeuse --config-module custom_betelgeuse_config \
#     test-case tests/ RHELSS test-cases.xml
#
#   ./import_polarion_testcases.sh

set -euo pipefail

XML_FILE="${1:-test-cases.xml}"

if [[ ! -f "$XML_FILE" ]]; then
    echo "ERROR: $XML_FILE not found. Generate it first with betelgeuse test-case."
    exit 1
fi

if [[ -z "${POLARION_USER:-}" || -z "${POLARION_PASS:-}" || -z "${POLARION_URL:-}" ]]; then
    echo "ERROR: Set POLARION_USER, POLARION_PASS and POLARION_URL environment variables."
    exit 1
fi

echo "Importing $(grep -c "<testcase " "$XML_FILE") test cases to Polarion RHELSS..."
# The Polarion URL is operator-supplied (POLARION_URL); the default is
# an RFC 2606 placeholder, not a real service.
POLARION_URL=${POLARION_URL:-https://polarion.example.invalid/polarion/import/testcase}
# -k skips TLS verification; internal Polarion uses a corporate CA
# that isn't in the default trust store on most dev machines.
curl -k -u "$POLARION_USER:$POLARION_PASS" \
    -X POST \
    -F file=@"$XML_FILE" \
    "$POLARION_URL"

echo ""
echo "Import submitted. Check Polarion for status."

