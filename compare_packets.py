#!/usr/bin/env python3
"""
Compare two Oracle advanced negotiation packets byte-by-byte.
Usage: python3 compare_packets.py packet1.hex packet2.hex
"""

import sys

def parse_hex_file(filename):
    """Parse hex dump file, extracting just the hex bytes."""
    bytes_list = []
    with open(filename, 'r') as f:
        for line in f:
            # Handle various hex dump formats
            line = line.strip()
            if not line or line.startswith('#'):
                continue

            # Remove common prefixes (xxd format: "00000000: ")
            if ':' in line:
                line = line.split(':', 1)[1]

            # Extract hex bytes (handle spaces, commas, etc)
            parts = line.replace(',', ' ').split()
            for part in parts:
                # Skip ASCII representation at end of xxd lines
                if len(part) == 2 and all(c in '0123456789abcdefABCDEF' for c in part):
                    bytes_list.append(int(part, 16))

    return bytes(bytes_list)

def compare_packets(data1, data2):
    """Compare two packet byte arrays and show differences."""
    max_len = max(len(data1), len(data2))

    print(f"Packet 1: {len(data1)} bytes")
    print(f"Packet 2: {len(data2)} bytes")
    print()

    if len(data1) != len(data2):
        print(f"⚠️  WARNING: Different lengths! (diff: {abs(len(data1) - len(data2))} bytes)")
        print()

    differences = 0
    offset = 0

    print("Offset  Byte1  Byte2  Diff?  Context")
    print("-" * 70)

    while offset < max_len:
        # Get 16 bytes at a time for context
        chunk1 = data1[offset:min(offset+16, len(data1))]
        chunk2 = data2[offset:min(offset+16, len(data2))]

        for i in range(max(len(chunk1), len(chunk2))):
            pos = offset + i
            b1 = chunk1[i] if i < len(chunk1) else None
            b2 = chunk2[i] if i < len(chunk2) else None

            if b1 != b2:
                differences += 1
                b1_str = f"{b1:02x}" if b1 is not None else "--"
                b2_str = f"{b2:02x}" if b2 is not None else "--"

                # Show surrounding context
                ctx_start = max(0, pos - 2)
                ctx_end = min(max_len, pos + 3)
                ctx1 = ' '.join(f"{data1[j]:02x}" if j < len(data1) else "--"
                               for j in range(ctx_start, ctx_end))

                marker = "❌" if b1 is None or b2 is None else "≠"

                print(f"{pos:06x}  {b1_str:4s}   {b2_str:4s}   {marker:3s}   {ctx1}")

        offset += 16

    print("-" * 70)
    print(f"\nTotal differences: {differences} bytes")

    if differences == 0:
        print("✅ Packets are identical!")

    return differences

def annotate_packet(data):
    """Annotate an Oracle advanced negotiation packet structure."""
    if len(data) < 13:
        print("Packet too short to be valid advanced negotiation")
        return

    print("\n=== Packet Structure Analysis ===\n")

    offset = 0

    # Check for TNS DATA header (if present)
    if len(data) >= 10:
        tns_len = (data[0] << 8) | data[1]
        tns_type = data[4] if len(data) > 4 else 0

        if tns_type == 6:  # DATA packet
            print(f"TNS DATA Header (10 bytes):")
            print(f"  Length: {tns_len}")
            print(f"  Type: {tns_type} (DATA)")
            print(f"  Bytes: {data[0:10].hex()}")
            offset = 10
            print()

    # Main header
    if len(data) >= offset + 13:
        magic = int.from_bytes(data[offset:offset+4], 'big')
        length = int.from_bytes(data[offset+4:offset+6], 'big')
        version = int.from_bytes(data[offset+6:offset+10], 'big')
        service_count = int.from_bytes(data[offset+10:offset+12], 'big')
        error_flags = data[offset+12]

        print(f"Advanced Negotiation Header ({offset:04x}-{offset+13:04x}):")
        print(f"  Magic: 0x{magic:08X} {'✅' if magic == 0xDEADBEEF else '❌'}")
        print(f"  Length: {length}")
        print(f"  Version: 0x{version:08X}")
        print(f"  Services: {service_count}")
        print(f"  Error Flags: {error_flags}")
        print()

        offset += 13

    # Parse services
    service_num = 0
    while offset < len(data) and offset + 8 <= len(data):
        svc_type = int.from_bytes(data[offset:offset+2], 'big')
        sub_pkts = int.from_bytes(data[offset+2:offset+4], 'big')
        error_code = int.from_bytes(data[offset+4:offset+8], 'big')

        svc_names = {1: "AUTH", 2: "ENCRYPTION", 3: "DATA_INTEGRITY", 4: "SUPERVISOR"}
        svc_name = svc_names.get(svc_type, "UNKNOWN")

        print(f"Service {service_num} - {svc_name} ({offset:04x}-{offset+8:04x}):")
        print(f"  Type: {svc_type}")
        print(f"  Sub-packets: {sub_pkts}")
        print(f"  Error Code: {error_code}")

        offset += 8
        service_num += 1

        # Would need more complex parsing to show sub-packets
        # For now, just show we found the service header
        if offset >= len(data) - 20:  # Stop if near end
            break

    print()

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage:")
        print("  Compare two packets:")
        print("    python3 compare_packets.py packet1.hex packet2.hex")
        print()
        print("  Annotate single packet:")
        print("    python3 compare_packets.py packet.hex")
        sys.exit(1)

    file1 = sys.argv[1]

    try:
        data1 = parse_hex_file(file1)
        print(f"Loaded {file1}: {len(data1)} bytes")

        if len(sys.argv) >= 3:
            file2 = sys.argv[2]
            data2 = parse_hex_file(file2)
            print(f"Loaded {file2}: {len(data2)} bytes")
            print()

            compare_packets(data1, data2)
        else:
            annotate_packet(data1)

    except FileNotFoundError as e:
        print(f"Error: {e}")
        sys.exit(1)
    except Exception as e:
        print(f"Error: {e}")
        import traceback
        traceback.print_exc()
        sys.exit(1)
