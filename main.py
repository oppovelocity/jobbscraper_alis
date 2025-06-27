from pathlib import Path
from config.perfect_config_loader import ConfigVault
import hashlib

def main():
    # Use your actual config file path and schema path
    config_path = Path("config/production.json")  # or your encrypted config file path
    schema_path = Path("config/schema.json")      # if you have a schema

    # Use your secure 32-byte master key here
    master_key = hashlib.sha256(b"your-secure-password-or-key").digest()

    vault = ConfigVault(config_path=config_path, schema_path=schema_path, master_key=master_key)

    # Load existing config
    config = vault.load()

    # Update config dictionary
    config["new_key"] = "new_value"

    # Save updated config securely
    vault.save(config)

    print("Config updated and saved successfully.")

if __name__ == "__main__":
    main()

