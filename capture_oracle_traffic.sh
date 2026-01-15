#!/bin/bash
# Script to capture Oracle TNS traffic for comparison

ORACLE_HOST="${1:-10.60.41.229}"
ORACLE_PORT="${2:-1521}"
OUTPUT_FILE="${3:-oracle_traffic.pcap}"

echo "Capturing Oracle TNS traffic to ${ORACLE_HOST}:${ORACLE_PORT}"
echo "Output file: ${OUTPUT_FILE}"
echo ""
echo "Run your Oracle connection test in another terminal."
echo "Press Ctrl+C when done capturing."
echo ""

# Capture only traffic to/from Oracle server
sudo tcpdump -i any -s 65535 -w "${OUTPUT_FILE}" \
  "host ${ORACLE_HOST} and port ${ORACLE_PORT}"
