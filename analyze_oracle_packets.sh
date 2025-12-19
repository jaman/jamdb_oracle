#!/bin/bash
# Analyze captured Oracle traffic to find advanced negotiation packets

PCAP_FILE="${1:-oracle_traffic.pcap}"

if [ ! -f "$PCAP_FILE" ]; then
    echo "Error: File $PCAP_FILE not found"
    exit 1
fi

echo "Analyzing Oracle TNS packets in: $PCAP_FILE"
echo ""

# Use tshark to decode Oracle TNS packets
# Advanced negotiation packets are typically DATA packets (type 6)
# that occur right after TNS_ACCEPT (type 2)

echo "=== All TNS Packets ==="
tshark -r "$PCAP_FILE" -Y "tns" -T fields \
    -e frame.number \
    -e ip.src \
    -e ip.dst \
    -e tcp.srcport \
    -e tcp.dstport \
    -e tns.type \
    -e tns.length \
    -E separator='|' 2>/dev/null | \
    awk -F'|' '{printf "%4s: %15s:%-5s -> %15s:%-5s  Type=%-2s Len=%-5s\n", $1, $2, $5, $3, $4, $6, $7}'

echo ""
echo "=== TNS Packet Types ==="
echo "1=CONNECT, 2=ACCEPT, 4=REFUSE, 5=REDIRECT, 6=DATA, 11=RESEND, 12=MARKER"
echo ""

# Extract DATA packets that might be advanced negotiation
echo "=== Extracting DATA packets after ACCEPT ==="
tshark -r "$PCAP_FILE" -Y "tns.type == 6" -T fields \
    -e frame.number \
    -e data.data \
    2>/dev/null | while read frame_num data; do
    echo "Frame $frame_num:"
    echo "$data" | xxd -r -p | xxd -g 1 | head -20
    echo ""
done

echo ""
echo "=== Looking for DEADBEEF signature (advanced negotiation) ==="
tshark -r "$PCAP_FILE" -Y "tns.type == 6 and data contains de:ad:be:ef" \
    -T fields -e frame.number -e data.data 2>/dev/null | while read frame_num data; do
    echo "Found DEADBEEF in frame $frame_num"
    echo "$data" | xxd -r -p | xxd -g 1
    echo ""
done

echo ""
echo "To view in Wireshark:"
echo "  wireshark $PCAP_FILE"
echo ""
echo "To extract specific packet data:"
echo "  tshark -r $PCAP_FILE -Y 'frame.number == N' -x"
