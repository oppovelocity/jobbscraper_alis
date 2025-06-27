

#!/usr/bin/env python3
"""
 Secure Config Initializer for Flask AI App
"""

import argparse
import logging
from pathlib import Path
import sys
import yaml

# 🧠 Add './config' folder to Python import path
sys.path.append(str(Path(__file__).parent / 'config'))

# ✅ Import from the correct loader
from perfect_config_loader import ConfigVault

try:
    from config_loader import ConfigVault
except ImportError as e:
    raise ImportError("❌ Could not import ConfigVault. Make sure 'config_loader.py' exists in ./config.") from e

# --- Logging Setup ---
logging.basicConfig(
    level=logging.INFO,
    format="📘 [%(levelname)s] %(message)s"
)
logger = logging.getLogger(__name__)

# --- Default Paths ---
DEFAULT_YAML_PATH = CONFIG_DIR / "default.yaml"
DEFAULT_SECURE_PATH = CONFIG_DIR / "production.json"

# --- Fields to Encrypt ---
SENSITIVE_KEYS = [
    "telegram.token",
    "telegram.chat_id",
    "gemini.api_key",
]

# --- Helper Function ---
def load_yaml_config(path: Path) -> dict:
    if not path.exists():
        raise FileNotFoundError(f"❌ Config file not found at: {path}")
    with open(path, "r") as file:
        return yaml.safe_load(file)


def encrypt_and_save_config(source_path: Path, output_path: Path, dry_run: bool = False) -> None:
    logger.info(f"📥 Loading plaintext config from: {source_path}")
    config = load_yaml_config(source_path)

    vault = ConfigVault(output_path)
    encrypted = vault.encrypt_fields(config, SENSITIVE_KEYS)

    if dry_run:
        logger.info("🧪 Dry run complete. Encrypted config not saved.")
        logger.info(f"Encrypted preview:\n{yaml.dump(encrypted, sort_keys=False)}")
    else:
        vault.save(encrypted)
        logger.info(f"✅ Encrypted config saved to: {output_path}")


# --- CLI Entry Point ---
def main():
    parser = argparse.ArgumentParser(description="🔐 Encrypt YAML fields into secure JSON vault.")
    parser.add_argument("-i", "--input", type=Path, default=DEFAULT_YAML_PATH,
                        help="Path to input YAML config.")
    parser.add_argument("-o", "--output", type=Path, default=DEFAULT_SECURE_PATH,
                        help="Path to output encrypted JSON.")
    parser.add_argument("--dry-run", action="store_true", help="Only print output, don't save.")
    args = parser.parse_args()

    try:
        encrypt_and_save_config(args.input, args.output, dry_run=args.dry_run)
    except Exception as e:
        logger.exception("💥 An error occurred during config encryption.")


if __name__ == "__main__":
    main()
