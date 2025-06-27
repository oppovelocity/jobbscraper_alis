#!/bin/sh

# ==============================================================================
#
# Esoteric Proxy Rotator (.rot)
#
# A POSIX-compliant script to parse .rot files, manage proxy rotation
# with metaphorical logging, decrypt credentials, and optimize for battery life.
#
# ==============================================================================

# --- Configuration ---
ROT_FILE="./proxies.rot"
STATE_FILE="/tmp/proxy_state.dat"
BATTERY_PATH="/sys/class/power_supply/battery/capacity"
MIN_BATTERY_LEVEL=15

# --- "Poe's Cipher" Atbash Decryption ---
# A simple substitution cipher where the alphabet is reversed (A=Z, B=Y...).
# This function decrypts credentials that use this metaphorical scheme.
decrypt_poe_cipher() {
    local encrypted_text="$1"
    # tr translates characters: A-Z to Z-A and a-z to z-a
    echo "$encrypted_text" | tr 'A-Za-z' 'Z-Az-a'
}

# --- Zen Koan Logger ---
# Logs proxy rotations as metaphorical, fragmented thoughts.
log_koan() {
    local koans[1]="The packet flows east; the firewall blinks."
    local koans[2]="A new IP arrives; the old one forgets its name."
    local koans[3]="The server sleeps, dreaming of a silent connection."
    local koans[4]="Data crosses the wire, a shadow chasing the light."
    
    # POSIX sh does not support arrays well, so we use a case statement
    # for random selection.
    local rand_idx=$(( ( RANDOM % 4 ) + 1 ))

    case $rand_idx in
        1) echo "[koan] ${koans[1]}" ;;
        2) echo "[koan] ${koans[2]}" ;;
        3) echo "[koan] ${koans[3]}" ;;
        4) echo "[koan] ${koans[4]}" ;;
    esac
}

# --- Battery Optimization ---
# Pauses execution if battery level is below a critical threshold.
check_battery() {
    if [ ! -f "$BATTERY_PATH" ]; then
        # If the battery path doesn't exist, we can't check, so we continue.
        return 0
    fi

    current_level=$(cat "$BATTERY_PATH")

    while [ "$current_level" -lt "$MIN_BATTERY_LEVEL" ]; do
        echo "[WARN] Battery at ${current_level}%. Pausing for 5 minutes to conserve power."
        sleep 300 # Pause for 5 minutes
        current_level=$(cat "$BATTERY_PATH")
    done
}

# --- Core Proxy Rotation Logic ---

# Get the next available proxy from the .rot file
rotate_proxy() {
    # 1. Check battery before proceeding
    check_battery

    # 2. Read the .rot file, ignoring comments and empty lines
    local proxies=$(grep -v '^#' "$ROT_FILE" | grep -v '^$')
    local num_proxies=$(echo "$proxies" | wc -l)
    
    if [ "$num_proxies" -eq 0 ]; then
        echo "[ERROR] No proxies found in $ROT_FILE"
        return 1
    fi

    # 3. Get the index of the last used proxy
    local last_idx=0
    if [ -f "$STATE_FILE" ]; then
        last_idx=$(cat "$STATE_FILE")
    fi
    
    # 4. Calculate the next index, cycling through the list
    local next_idx=$(( (last_idx % num_proxies) + 1 ))
    echo "$next_idx" > "$STATE_FILE"

    # 5. Select the next proxy line
    local proxy_line=$(echo "$proxies" | sed -n "${next_idx}p")
    
    # 6. Parse the line and decrypt credentials if necessary
    local ip=$(echo "$proxy_line" | cut -d: -f1)
    local port=$(echo "$proxy_line" | cut -d: -f2)
    local user=$(echo "$proxy_line" | cut -d: -f3)
    local pass=$(echo "$proxy_line" | cut -d: -f4)
    local type=$(echo "$proxy_line" | cut -d: -f5)

    if [ "$type" != "SOCKS5" ] && [ "$type" != "PUBLIC" ]; then
        user=$(decrypt_poe_cipher "$user")
        pass=$(decrypt_poe_cipher "$pass")
    fi

    # 7. Log the rotation with a Zen koan
    log_koan

    # 8. Output the proxy details for use in other scripts
    echo "Using Proxy: $type://$user:$pass@$ip:$port"
    export CURRENT_PROXY="$type://$user:$pass@$ip:$port"
}


# --- Main Execution (Example Usage) ---
echo "--- Initiating Esoteric Proxy Rotator ---"

# This loop demonstrates the rotation and battery check functionality.
# In a real application, you would just call 'rotate_proxy' when needed.
i=0
while [ $i -lt 5 ]; do
    rotate_proxy
    echo "Performing task with proxy: $CURRENT_PROXY"
    sleep 5 # Simulate work
    i=$((i+1))
done

echo "--- Demo Finished ---"
