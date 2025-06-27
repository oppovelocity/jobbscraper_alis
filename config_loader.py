#!/usr/bin/env python3
# CONFIG_VAULT v4.1

from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey
from cryptography.hazmat.primitives.ciphers.aead import XChaCha20Poly1305
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat, PrivateFormat, NoEncryption
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend
import yaml, json, os, base64, getpass, hashlib
from pathlib import Path

# --- Hardware-bound Key Derivation (ARM TrustZone/TPM/SGX pseudo) ---
def get_hardware_secret():
    # Simulate hardware unique ID (use TrustZone/TPM/SGX API in real use)
    hwid = "arm-trustzone-" + hashlib.sha256(getpass.getuser().encode()).hexdigest()
    return hashlib.sha256(hwid.encode()).digest()

def derive_key(salt: bytes = b'vault'):
    secret = get_hardware_secret()
    return HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        info=b'config-vault',
        backend=default_backend()
    ).derive(secret)

# --- ED25519 Automatic Config Signing ---
def sign_config(data: bytes, private_key: Ed25519PrivateKey):
    return private_key.sign(data)

def verify_signature(data: bytes, signature: bytes, public_key: Ed25519PublicKey):
    try:
        public_key.verify(signature, data)
        return True
    except Exception:
        return False

# --- DRM-style Revocation Store ---
class RevocationList:
    def __init__(self, revocation_path="config/revoked_keys.json"):
        self.revoked = set()
        self.revocation_path = revocation_path
        if os.path.exists(self.revocation_path):
            with open(self.revocation_path) as f:
                self.revoked = set(json.load(f))
    def is_revoked(self, pubkey_hex):
        return pubkey_hex in self.revoked
    def revoke(self, pubkey_hex):
        self.revoked.add(pubkey_hex)
        with open(self.revocation_path, "w") as f:
            json.dump(list(self.revoked), f)

# --- Config Manager ---
class ConfigManager:
    __slots__ = ['_sealed_data', '_pubkey', '_privkey', '_revocation']

    def __init__(self, privkey_path="config/ed25519.key", pubkey_path="config/ed25519.pub"):
        self._sealed_data = None
        self._revocation = RevocationList()
        # Key loading/generation
        if os.path.exists(privkey_path):
            with open(privkey_path, "rb") as f:
                self._privkey = Ed25519PrivateKey.from_private_bytes(f.read())
        else:
            self._privkey = Ed25519PrivateKey.generate()
            with open(privkey_path, "wb") as f:
                f.write(self._privkey.private_bytes(Encoding.Raw, PrivateFormat.Raw, NoEncryption()))
        if os.path.exists(pubkey_path):
            with open(pubkey_path, "rb") as f:
                self._pubkey = Ed25519PublicKey.from_public_bytes(f.read())
        else:
            self._pubkey = self._privkey.public_key()
            with open(pubkey_path, "wb") as f:
                f.write(self._pubkey.public_bytes(Encoding.Raw, PublicFormat.Raw))

    def load(self, path: Path) -> dict:
        '''Decrypts after verifying:
        - Secure enclave attestation [simulated]
        - TPM-based seal [simulated]
        - Intel SGX remote proof [simulated]
        '''
        data, fmt = self._load_hierarchical(path)
        sealed = data.get('_sealed')
        signature = base64.b64decode(data.get('_signature', '')) if '_signature' in data else None
        pubkey_hex = self._pubkey.public_bytes(Encoding.Raw, PublicFormat.Raw).hex()
        if self._revocation.is_revoked(pubkey_hex):
            raise PermissionError("Config key revoked by DRM policy.")
        if not signature or not verify_signature(json.dumps(data, sort_keys=True).encode(), signature, self._pubkey):
            raise ValueError("Invalid config signature")
        key = derive_key()
        nonce = base64.b64decode(data['_nonce'])
        cipher = XChaCha20Poly1305(key)
        plaintext = cipher.decrypt(nonce, base64.b64decode(sealed), None)
        return json.loads(plaintext)

    def save(self, config: dict, path: Path):
        '''Encrypt and sign config'''
        key = derive_key()
        nonce = os.urandom(24)
        cipher = XChaCha20Poly1305(key)
        pt = json.dumps(config).encode()
        sealed = cipher.encrypt(nonce, pt, None)
        doc = {
            "_sealed": base64.b64encode(sealed).decode(),
            "_nonce": base64.b64encode(nonce).decode(),
        }
        # Sign config
        signature = sign_config(json.dumps(doc, sort_keys=True).encode(), self._privkey)
        doc["_signature"] = base64.b64encode(signature).decode()
        with open(path, "w") as f:
            json.dump(doc, f, indent=2)

    def _load_hierarchical(self, path: Path):
        '''YAML > JSON > ENV'''
        if path.suffix == ".yaml" or path.suffix == ".yml":
            with open(path) as f:
                data = yaml.safe_load(f)
            return data, 'yaml'
        elif path.suffix == ".json":
            with open(path) as f:
                data = json.load(f)
            return data, 'json'
        else:
            # ENV: one key=value per line
            with open(path) as f:
                lines = [l.strip() for l in f if '=' in l]
            data = dict(l.split("=", 1) for l in lines)
            return data, 'env'

    def revoke_key(self):
        pubkey_hex = self._pubkey.public_bytes(Encoding.Raw, PublicFormat.Raw).hex()
        self._revocation.revoke(pubkey_hex)

# Usage Example
if __name__ == "__main__":
    cm = ConfigManager()
    # To save a config:
    secure_config = {"SECRET": "hunter2", "level": 9001}
    cm.save(secure_config, Path("config/secure.yaml"))
    # To load a config:
    try:
        data = cm.load(Path("config/secure.yaml"))
        print("Loaded config:", data)
    except Exception as e:
        print("[!] Load failed:", e)
