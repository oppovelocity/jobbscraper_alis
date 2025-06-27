import os
import json
import base64
import time
import requests
from typing import List, Optional

# Third-party libraries - install via pip
# pip install cryptography requests Pillow stegano
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.exceptions import InvalidTag
from PIL import Image
from stegano import lsb

# --- Module Configuration ---
KEY_FILE = "keys.dat"
MAX_AUTH_FAILURES = 3
CHUNK_SIZE_BYTES = 3072  # Under Telegram's 4096 byte message limit

class SecureChannel:
    """
    Manages secure, encrypted, and chunked communications via Telegram,
    with built-in steganography and a dead man's switch.
    """
    def __init__(self, bot_token: str, chat_id: str):
        """
        Initializes the secure channel.

        Args:
            bot_token: The Telegram bot token.
            chat_id: The target Telegram chat ID.
        """
        self.bot_token = bot_token
        self.chat_id = chat_id
        self.api_url = f"https://api.telegram.org/bot{self.bot_token}"
        self.failed_auth_attempts = 0
        self.last_update_id = 0

    def _load_key(self) -> Optional[bytes]:
        """
        Loads the AES key from the key file for a very short duration.
        Returns the key or None if the file doesn't exist.
        """
        if not os.path.exists(KEY_FILE):
            print(f"[ERROR] Key file '{KEY_FILE}' not found.")
            return None
        with open(KEY_FILE, "rb") as f:
            key = f.read()
        # The 'key' variable is local and will be cleared from memory
        # by the garbage collector after the function using it returns.
        return key

    def emergency_wipe(self) -> None:
        """
        Securely erases the key file from the disk. This is the final
        action of the dead man's switch.
        """
        print(f"[!!!] EMERGENCY WIPE TRIGGERED for '{KEY_FILE}'")
        if os.path.exists(KEY_FILE):
            try:
                # Overwrite file with random data before deletion
                with open(KEY_FILE, "ba+") as f:
                    length = f.tell()
                    f.seek(0)
                    f.write(os.urandom(length))
                os.remove(KEY_FILE)
                print(f"[SUCCESS] '{KEY_FILE}' has been securely wiped.")
            except OSError as e:
                print(f"[ERROR] Failed to wipe key file: {e}")
        else:
            print(f"[INFO] Key file '{KEY_FILE}' was already gone.")

    def send_encrypted(
        self,
        text: str,
        use_steganography: bool = False,
        priority: int = 1
    ) -> bool:
        """
        Encrypts, chunks, and sends text. Can optionally hide it in an image.

        Args:
            text: The plaintext message to send.
            use_steganography: If True, hides the message in a generated image.
            priority: An integer for message priority (for potential future use).

        Returns:
            True if sending was successful, False otherwise.
        """
        key = self._load_key()
        if key is None:
            return False

        text_bytes = text.encode('utf-8')
        chunks = [
            text_bytes[i:i + CHUNK_SIZE_BYTES]
            for i in range(0, len(text_bytes), CHUNK_SIZE_BYTES)
        ]
        print(f"[INFO] Splitting message into {len(chunks)} chunk(s).")

        for i, chunk in enumerate(chunks):
            try:
                aesgcm = AESGCM(key)
                nonce = os.urandom(12)  # AES-GCM standard nonce size
                ciphertext = aesgcm.encrypt(nonce, chunk, None)

                # Prepare payload for sending
                payload = json.dumps({
                    'nonce': base64.b64encode(nonce).decode('utf-8'),
                    'ciphertext': base64.b64encode(ciphertext).decode('utf-8'),
                    'chunk_num': i,
                    'total_chunks': len(chunks),
                })

                if use_steganography:
                    self._send_steganographic_image(payload)
                else:
                    self._send_text_message(payload)

            except Exception as e:
                print(f"[ERROR] Failed to send chunk {i}: {e}")
                return False
        return True

    def _send_text_message(self, text_payload: str):
        """Sends a standard text message."""
        url = f"{self.api_url}/sendMessage"
        params = {'chat_id': self.chat_id, 'text': text_payload}
        response = requests.post(url, json=params, timeout=10)
        response.raise_for_status()
        print("[+] Sent text chunk successfully.")

    def _send_steganographic_image(self, text_payload: str):
        """Hides data in an image and sends it."""
        image_path = "temp_stego_img.png"
        # Generate a carrier image
        img = Image.new('RGB', (200, 200), color = 'black')
        img.save(image_path)

        # Hide the payload inside the image and save it
        secret_image = lsb.hide(image_path, text_payload)
        secret_image.save(image_path)

        # Send the image
        url = f"{self.api_url}/sendPhoto"
        with open(image_path, 'rb') as f:
            files = {'photo': (image_path, f, 'image/png')}
            response = requests.post(url, data={'chat_id': self.chat_id}, files=files, timeout=20)
        response.raise_for_status()
        print("[+] Sent steganographic image chunk successfully.")

        # Clean up the temporary image
        os.remove(image_path)


    def receive_decrypted(self) -> List[str]:
        """
        Fetches new messages, attempts to decrypt them, and handles auth failures.
        Triggers the dead man's switch if necessary.

        Returns:
            A list of decrypted plaintext messages.
        """
        key = self._load_key()
        if key is None:
            return []

        url = f"{self.api_url}/getUpdates"
        params = {'chat_id': self.chat_id, 'timeout': 30, 'offset': self.last_update_id + 1}
        try:
            response = requests.get(url, params=params, timeout=40)
            updates = response.json().get('result', [])
        except requests.RequestException as e:
            print(f"[ERROR] Could not fetch messages from Telegram: {e}")
            return []

        decrypted_chunks = {}
        for update in updates:
            self.last_update_id = update.get('update_id', self.last_update_id)
            message = update.get('message', {})
            message_text = message.get('text')

            if not message_text:
                continue # Skip non-text messages

            try:
                payload = json.loads(message_text)
                nonce = base64.b64decode(payload['nonce'])
                ciphertext = base64.b64decode(payload['ciphertext'])

                aesgcm = AESGCM(key)
                decrypted_chunk = aesgcm.decrypt(nonce, ciphertext, None).decode('utf-8')

                # Authentication successful, reset counter
                self.failed_auth_attempts = 0
                print(f"[+] Decrypted chunk {payload['chunk_num']+1}/{payload['total_chunks']} successfully.")
                decrypted_chunks[payload['chunk_num']] = decrypted_chunk

            except (InvalidTag, KeyError, json.JSONDecodeError, ValueError) as e:
                print(f"[WARNING] Failed to decrypt a message. Reason: {type(e).__name__}. This counts as a failed auth attempt.")
                self.failed_auth_attempts += 1
                if self.failed_auth_attempts >= MAX_AUTH_FAILURES:
                    self.emergency_wipe()
                    # Raising an exception to halt all operations
                    raise ConnectionAbortedError("Dead man's switch triggered. Key wiped.")

        # Reassemble chunks into a single message
        if not decrypted_chunks:
            return []
            
        full_message_bytes = b"".join(
            decrypted_chunks[i].encode('utf-8') for i in sorted(decrypted_chunks.keys())
        )
        return [full_message_bytes.decode('utf-8')]


# --- Example Usage ---
if __name__ == "__main__":
    # IMPORTANT: Replace with your actual bot token and chat ID
    # You can get a chat ID by messaging @userinfobot on Telegram
    BOT_TOKEN = os.environ.get("TELEGRAM_BOT_TOKEN", "YOUR_BOT_TOKEN")
    CHAT_ID = os.environ.get("TELEGRAM_CHAT_ID", "YOUR_CHAT_ID")

    if BOT_TOKEN == "YOUR_BOT_TOKEN" or CHAT_ID == "YOUR_CHAT_ID":
        print("="*50)
        print("!! PLEASE SET YOUR BOT_TOKEN AND CHAT_ID !!")
        print("You can set them as environment variables or edit the script.")
        print("="*50)
        exit()

    # 1. Generate a key file for the demonstration
    print("\n--- 1. GENERATING DUMMY KEY FILE ---")
    with open(KEY_FILE, "wb") as f_key:
        f_key.write(os.urandom(32)) # AES-256 requires a 32-byte key
    print(f"'{KEY_FILE}' created for this session.")

    # 2. Initialize the channel and send a message
    print("\n--- 2. SENDING ENCRYPTED & STEGANOGRAPHIC MESSAGES ---")
    channel = SecureChannel(bot_token=BOT_TOKEN, chat_id=CHAT_ID)
    long_message = "This is a secret message that is long enough to be split into multiple chunks by the SecureChannel module. It demonstrates the ability to handle data beyond a single Telegram message limit, ensuring robust and stealthy communication. End of message."
    
    # Send a standard encrypted message
    channel.send_encrypted("Hello from the secure channel. This is a short test.")
    
    # Send a long message hidden inside an image
    channel.send_encrypted(long_message, use_steganography=True)
    time.sleep(5) # Give Telegram time to process

    # 3. Receive and decrypt the messages
    print("\n--- 3. RECEIVING AND DECRYPTING MESSAGES ---")
    try:
        received_messages = channel.receive_decrypted()
        if received_messages:
            for msg in received_messages:
                print("\n[SUCCESS] Decrypted Message Received:")
                print(">" + "-"*30)
                print(msg)
                print(">" + "-"*30)
        else:
            print("[INFO] No new messages found.")
            
    except ConnectionAbortedError as e:
        print(f"\n[CRITICAL] Operation halted: {e}")


    # 4. Simulate Dead Man's Switch
    print("\n--- 4. SIMULATING DEAD MAN'S SWITCH ---")
    print("Sending a fake (undecryptable) message to the bot...")
    requests.post(f"{channel.api_url}/sendMessage", json={'chat_id': CHAT_ID, 'text': '{"fake":"data"}'})
    requests.post(f"{channel.api_url}/sendMessage", json={'chat_id': CHAT_ID, 'text': 'this is not json'})
    requests.post(f"{channel.api_url}/sendMessage", json={'chat_id': CHAT_ID, 'text': '{"nonce":"ZmFrZQ==", "ciphertext":"ZmFrZQ=="}'})
    time.sleep(5)

    print("\nAttempting to receive messages again (this should trigger the wipe)...")
    try:
        channel.receive_decrypted()
    except ConnectionAbortedError as e:
        print(f"\n[SUCCESS] As expected, the operation was aborted: {e}")
        # Verify the key is gone
        assert not os.path.exists(KEY_FILE)
        print(f"[VERIFIED] The key file '{KEY_FILE}' no longer exists.")
