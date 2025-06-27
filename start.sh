#!/data/data/com.termux/files/usr/bin/bash

python scrape_groups.py
# --- Color Definitions ---
C_GREEN='\033[0;32m'
C_YELLOW='\033[0;33m'
C_BLUE='\033[0;34m'
C_RED='\033[0;31m'
C_NC='\033[0m' # No Color

# --- Configuration ---
MAIN_SCRIPT="main.py"
CRON_JOB_COMMAND="0 */2 * * * cd $PROJECT_DIR && ./start.sh"
# --- Helper Functions ---
SRC_DIR="$PROJECT_DIR"                # All your Python scripts/modules are here
CONFIG_DIR="$PROJECT_DIR/config"      # For .env, YAML, or other config files
DATA_DIR="$PROJECT_DIR/data"          # Raw or processed datasets, scraped results, temp files
LOG_DIR="$PROJECT_DIR/logs"           # Log files from your scripts and bots
OUTPUT_DIR="$PROJECT_DIR/output"      # Final reports, exports, deliverables to users
SCRIPTS_DIR="$PROJECT_DIR/scripts"    # Utility or one-off shell/Python scripts
TESTS_DIR="$PROJECT_DIR/tests"        # Unit and integration tests
DOCS_DIR="$PROJECT_DIR/docs"          # Additional documentation, guides, API info
CACHE_DIR="$PROJECT_DIR/cache"        # Temporary or cache files (optional)
BACKUP_DIR="$PROJECT_DIR/backup"      # For database or data backups (optional)
# --- Helper Functions ---

# Function to print a formatted message
# Usage: log_msg "This is a message" "INFO"
log_msg() {
    local message="$1"
    local level="$2"
    local color="$C_NC"

    case "$level" in
        "INFO") color="$C_BLUE" ;;
        "SUCCESS") color="$C_GREEN" ;;
        "WARNING") color="$C_YELLOW" ;;
        "ERROR") color="$C_RED" ;;
    esac
    echo -e "${color}[$level]${C_NC} $message"
}

check_tor() {
    log_msg "Checking for running TOR daemon..." "INFO"
    # Use pgrep to check if the 'tor' process is running
    if pgrep -x "tor" > /dev/null; then
        log_msg "TOR daemon is active." "SUCCESS"
        return 0
    else
        log_msg "TOR daemon is not running. Please start TOR to continue." "ERROR"
        return 1
    fi
}

check_vpn() {
    log_msg "Verifying VPN connection..." "INFO"
    # Check for common VPN network interfaces like 'tun0' or 'ppp0'
    # 'ip addr' is a more modern alternative to ifconfig
    if ip addr | grep -q -E 'tun[0-9]+|ppp[0-9]+'; then
        log_msg "VPN interface detected." "SUCCESS"
        return 0
    else
        log_msg "No active VPN interface (tun/ppp) found." "ERROR"
        return 1
    fi
}

check_storage() {
    log_msg "Checking for sufficient storage..." "INFO"
    # Use 'df' to get free space in MB for the Termux home directory
    # The 'tail -1' gets the relevant line, and 'awk' extracts the 4th column (available space in KB)
    local free_space_kb=$(df -k "$HOME" | tail -1 | awk '{print $4}')
    local free_space_mb=$((free_space_kb / 1024))
    local required_mb=100

    if [ "$free_space_mb" -ge "$required_mb" ]; then
        log_msg "Available storage: ${free_space_mb}MB. Check passed." "SUCCESS"
        return 0
    else
        log_msg "Insufficient storage. Found ${free_space_mb}MB, require ${required_mb}MB." "ERROR"
        return 1
    fi
}

# --- Setup Functions ---

setup_dependencies() {
    log_msg "Checking Python dependencies from requirements.txt..." "INFO"
    if [ ! -f "requirements.txt" ]; then
        log_msg "'requirements.txt' not found. Skipping dependency check." "WARNING"
        return
    fi

    # Check if pip is installed
    if ! command -v pip &> /dev/null; then
        log_msg "'pip' is not installed. Please install it with 'pkg install python'." "ERROR"
        exit 1
    fi

    # Install dependencies
    pip install --upgrade pip
    pip install -r requirements.txt
    log_msg "Dependencies are up to date." "SUCCESS"
}

setup_cron_job() {
    log_msg "Setting up crontab for automated execution..." "INFO"
    # Ensure crond is installed and running
    if ! pgrep -x "crond" > /dev/null; then
        log_msg "crond is not running. Please start it to enable automated tasks." "WARNING"
    fi

    # Check if the job already exists to avoid duplicates
    if crontab -l | grep -Fxq "$CRON_JOB_COMMAND"; then
        log_msg "Cron job already exists." "SUCCESS"
    else
        log_msg "Cron job not found. Adding now..." "INFO"
        # Add the new cron job
        (crontab -l 2>/dev/null; echo "$CRON_JOB_COMMAND") | crontab -
        log_msg "Cron job for biennial execution has been set." "SUCCESS"
    fi
}

if ! pgrep -x "tor" > /dev/null; then
    log_msg "TOR not running, attempting to start..." "WARNING"
    tor &
    sleep 5    # give it a moment to start
fi

# --- Main Execution Logic ---

# Navigate to the project directory
cd "$PROJECT_DIR" || { log_msg "Project directory $PROJECT_DIR not found." "ERROR"; exit 1; }

log_msg "Initiating startup sequence for JobScraper Alias..." "INFO"
echo "--------------------------------------------------------"

# Run pre-flight checks
check_tor || exit 1
check_vpn || exit 1
check_storage || exit 1

echo "--------------------------------------------------------"
log_msg "All system checks passed." "SUCCESS"
echo "--------------------------------------------------------"

# Run setup tasks
setup_dependencies
setup_cron_job

echo "--------------------------------------------------------"

# Launch the main Python script, passing all arguments from this script
log_msg "Bootstrapping complete. Launching main application..." "INFO"
python "$MAIN_SCRIPT" "$@"
