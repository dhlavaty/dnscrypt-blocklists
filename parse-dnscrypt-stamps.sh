#!/usr/bin/env bash
set -euo pipefail

# DNSCrypt Stamp Parser
# Decodes DNS stamps from DNSCrypt resolver lists and extracts IP addresses and hostnames

# DNSCrypt resolver list sources
readonly RESOLVER_URLS=(
    "https://raw.githubusercontent.com/DNSCrypt/dnscrypt-resolvers/refs/heads/master/v3/onion-services.md"
    "https://raw.githubusercontent.com/DNSCrypt/dnscrypt-resolvers/refs/heads/master/v3/opennic.md"
    "https://raw.githubusercontent.com/DNSCrypt/dnscrypt-resolvers/refs/heads/master/v3/odoh-relays.md"
    "https://raw.githubusercontent.com/DNSCrypt/dnscrypt-resolvers/refs/heads/master/v3/odoh-servers.md"
    "https://raw.githubusercontent.com/DNSCrypt/dnscrypt-resolvers/refs/heads/master/v3/parental-control.md"
    "https://raw.githubusercontent.com/DNSCrypt/dnscrypt-resolvers/refs/heads/master/v3/public-resolvers.md"
    "https://raw.githubusercontent.com/DNSCrypt/dnscrypt-resolvers/refs/heads/master/v3/relays.md"
)

readonly SDNS_FILE="sdns.txt"
readonly DOMAINS_FILE="domains.txt"
readonly IPV4_FILE="ipv4.txt"
readonly IPV6_FILE="ipv6.txt"

# Initialize output files
> "$SDNS_FILE"
> "$DOMAINS_FILE"
> "$IPV4_FILE"
> "$IPV6_FILE"

# Function to convert base64url to standard base64
base64url_to_base64() {
    local input="$1"
    # Replace URL-safe characters with standard base64 characters
    input="${input//-/+}"
    input="${input//_//}"
    # Add padding if necessary
    local padding=$((4 - ${#input} % 4))
    if [ $padding -ne 4 ]; then
        printf '%s%*s' "$input" $padding '' | tr ' ' '='
    else
        printf '%s' "$input"
    fi
}

# Function to extract length-prefixed string from hex data at given position
extract_lp_string() {
    local hex_data="$1"
    local offset="$2"  # Offset in hex chars (2 chars = 1 byte)

    # Get string length (first byte at offset)
    local len_hex="${hex_data:$offset:2}"
    [ -z "$len_hex" ] && return 1

    local len=$((16#$len_hex))
    [ $len -eq 0 ] && return 1

    # Extract string hex data
    local str_offset=$((offset + 2))
    local str_hex="${hex_data:$str_offset:$((len * 2))}"

    # Convert hex to ASCII
    local str=""
    for ((i=0; i<${#str_hex}; i+=2)); do
        local byte="${str_hex:$i:2}"
        str+=$(printf "\\x$byte")
    done

    echo "$str"
}

# Function to decode a DNS stamp and extract hostname/IP
decode_stamp() {
    local stamp="$1"

    # Remove sdns:// prefix
    stamp="${stamp#sdns://}"

    # Convert base64url to standard base64 and decode
    local base64_data
    base64_data=$(base64url_to_base64 "$stamp")

    # Decode base64 to binary and convert to hex
    local hex_data
    hex_data=$(echo "$base64_data" | base64 -d 2>/dev/null | hexdump -ve '1/1 "%.2x"')

    [ -z "$hex_data" ] && return 1

    # Parse protocol ID (first byte)
    local protocol="${hex_data:0:2}"

    local addr=""
    local hostname=""
    local offset

    case "$protocol" in
        00|01|02|03|04)
            # Standard protocols with props field
            # Format: protocol || props || LP(addr) || ...
            offset=18  # Skip protocol (2) + props (16)

            # Try to extract addr (may be empty for some stamps)
            addr=$(extract_lp_string "$hex_data" "$offset" 2>/dev/null || echo "")

            # For protocols 02, 03, 04 (DoH, DoT, DoQ), there's also a hostname field
            if [[ "$protocol" =~ ^(02|03|04)$ ]]; then
                # Skip addr: 2 (length) + addr_len*2 (data)
                local addr_len=${#addr}
                offset=$((offset + 2 + addr_len * 2))

                # Skip VLP hash list (find next non-0x80 byte)
                while [ $offset -lt ${#hex_data} ]; do
                    local byte="${hex_data:$offset:2}"
                    offset=$((offset + 2))
                    # If high bit not set (< 0x80), this is the last/only hash length
                    if [ $((16#$byte)) -lt 128 ]; then
                        # Skip hash data
                        offset=$((offset + 16#$byte * 2))
                        break
                    else
                        # Skip hash data (remove high bit to get length)
                        local hash_len=$((16#$byte - 128))
                        offset=$((offset + hash_len * 2))
                    fi
                done

                # Now extract hostname
                hostname=$(extract_lp_string "$hex_data" "$offset" 2>/dev/null || echo "")
            fi

            # Must have at least addr or hostname
            [ -z "$addr" ] && [ -z "$hostname" ] && return 1
            ;;
        81)
            # DNSCrypt relay - no props field
            # Format: protocol || LP(addr)
            offset=2  # Skip only protocol
            addr=$(extract_lp_string "$hex_data" "$offset" 2>/dev/null)
            [ -z "$addr" ] && return 1
            ;;
        05|06)
            # ODoH protocols with props field
            # Format: protocol || props || LP(hostname) || ...
            offset=18  # Skip protocol (2) + props (16)
            hostname=$(extract_lp_string "$hex_data" "$offset" 2>/dev/null)
            [ -z "$hostname" ] && return 1
            ;;
        85|86)
            # ODoH relay protocols with props field and extra padding
            # Format: protocol || props || ?? || ?? || LP(hostname) || ...
            # Note: These have 2 extra bytes after props (observed in actual stamps)
            offset=22  # Skip protocol (2) + props (16) + padding (4)
            hostname=$(extract_lp_string "$hex_data" "$offset" 2>/dev/null)
            [ -z "$hostname" ] && return 1
            ;;
        *)
            return 1
            ;;
    esac

    # Clean up and output addresses
    # Handle format: [ipv6]:port or hostname:port or ip:port

    # Process addr
    if [ -n "$addr" ]; then
        # Check for bracket-enclosed IPv6 with port: [addr]:port
        if [[ "$addr" == "["*"]:"* ]]; then
            # Remove brackets and port
            addr="${addr#[}"      # Remove leading [
            addr="${addr%%]:*}"   # Remove ]:port suffix
        elif [[ "$addr" == "["*"]" ]]; then
            # Just brackets, no port
            addr="${addr#[}"
            addr="${addr%]}"
        elif [[ "$addr" =~ ^[^:]+:[0-9]+$ ]]; then
            # hostname:port or ipv4:port (single colon followed by digits)
            addr="${addr%:*}"
        fi
        # If IPv6 without brackets (has multiple colons), leave as-is
    fi

    # Process hostname (same logic)
    if [ -n "$hostname" ]; then
        if [[ "$hostname" == "["*"]:"* ]]; then
            hostname="${hostname#[}"
            hostname="${hostname%%]:*}"
        elif [[ "$hostname" == "["*"]" ]]; then
            hostname="${hostname#[}"
            hostname="${hostname%]}"
        elif [[ "$hostname" =~ ^[^:]+:[0-9]+$ ]]; then
            hostname="${hostname%:*}"
        fi
    fi

    # Output both addr and hostname if present (one per line)
    local output_count=0
    if [ -n "$addr" ]; then
        echo "$addr"
        output_count=1
    fi
    if [ -n "$hostname" ]; then
        echo "$hostname"
        output_count=1
    fi

    # Return error if nothing was output
    [ $output_count -eq 0 ] && return 1
    return 0
}

# Function to classify address as IPv4, IPv6, or domain
classify_and_save() {
    local addr="$1"

    [ -z "$addr" ] && return

    # Check if it's an IPv6 address (contains colons and hex digits)
    if [[ "$addr" =~ ^[0-9a-fA-F:]+$ ]] && [[ "$addr" == *:* ]]; then
        # Validate IPv6 format
        if [[ "$addr" =~ ^([0-9a-fA-F]{0,4}:){2,7}[0-9a-fA-F]{0,4}$ ]]; then
            echo "$addr" >> "$IPV6_FILE"
            return
        fi
    fi

    # Check if it's an IPv4 address (four decimal numbers separated by dots)
    if [[ "$addr" =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
        # Validate each octet is 0-255
        local valid=1
        IFS='.' read -ra octets <<< "$addr"
        for octet in "${octets[@]}"; do
            if [ "$octet" -lt 0 ] || [ "$octet" -gt 255 ]; then
                valid=0
                break
            fi
        done
        if [ $valid -eq 1 ]; then
            echo "$addr" >> "$IPV4_FILE"
            return
        fi
    fi

    # Otherwise, treat it as a domain name
    echo "$addr" >> "$DOMAINS_FILE"
}

main() {
    local total_count=0

    # Process each resolver list
    for url in "${RESOLVER_URLS[@]}"; do
        local filename
        filename=$(basename "$url")
        echo "Downloading $filename..."

        local content
        content=$(curl -sfL "$url")

        if [ -z "$content" ]; then
            echo "  Warning: Failed to download $filename" >&2
            continue
        fi

        # Extract all sdns:// stamps
        local stamps
        stamps=$(echo "$content" | grep -o 'sdns://[A-Za-z0-9_-]*' || true)

        if [ -z "$stamps" ]; then
            echo "  Warning: No DNS stamps found in $filename" >&2
            continue
        fi

        local count=0
        while IFS= read -r stamp; do
            [ -z "$stamp" ] && continue

            # Save the stamp to sdns.txt
            echo "$stamp" >> "$SDNS_FILE"

            # Decode the stamp and extract hostname/IP (may return multiple lines)
            local decoded_output
            if decoded_output=$(decode_stamp "$stamp" 2>/dev/null); then
                # Process each line of output (addr and/or hostname)
                while IFS= read -r address; do
                    [ -n "$address" ] && classify_and_save "$address"
                done <<< "$decoded_output"
                count=$((count + 1))
            fi
        done <<< "$stamps"

        echo "  Processed $count DNS stamps from $filename"
        total_count=$((total_count + count))
    done

    echo ""
    echo "Total processed: $total_count DNS stamps"
    echo ""

    # Sort and deduplicate all output files
    for file in "$SDNS_FILE" "$DOMAINS_FILE" "$IPV4_FILE" "$IPV6_FILE"; do
        if [ -s "$file" ]; then
            sort -u "$file" -o "$file"
            local line_count
            line_count=$(wc -l < "$file")
            echo "  $(basename "$file"): $line_count entries"
        fi
    done

    echo ""
    echo "Converting to JSON format..."

    # Convert all text files to JSON
    local awk_tool
    awk_tool="$(command -v awk)"

    for file in "$SDNS_FILE" "$DOMAINS_FILE" "$IPV4_FILE" "$IPV6_FILE"; do
        if [ -s "$file" ]; then
            local json_file="${file%.txt}.json"
            "$awk_tool" 'BEGIN{print "["} {printf "%s\"%s\"", (NR>1?",\n":""), $1} END{print "\n]"}' "$file" > "$json_file"
            echo "  $(basename "$json_file")"
        fi
    done

    echo ""
    echo "Done!"
}

main "$@"
