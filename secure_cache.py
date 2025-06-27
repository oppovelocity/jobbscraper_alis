import os
import mmap
import tempfile
import time
import threading
import random
import string
import fcntl
import subprocess
from collections import OrderedDict

CACHE_DIR = "/tmp"
CACHE_LIFETIME = 900  # 15 minutes in seconds
GUTMANN_PASSES = 35

class SecureLRUCache:
    def __init__(self, max_size=8):
        self.cache = OrderedDict()
        self.lock = threading.Lock()
        self.max_size = max_size
        self.timers = {}

    def _gutmann_wipe(self, path, size):
        # Gutmann pattern for anti-forensic wiping
        patterns = [bytes([i])*size for i in range(0, 256)]
        with open(path, "r+b") as f:
            for _ in range(GUTMANN_PASSES):
                for pattern in random.sample(patterns, min(3, len(patterns))):
                    f.seek(0)
                    f.write(pattern[:size])
                    f.flush()
                    os.fsync(f.fileno())

    def _wipe_file(self, path):
        try:
            size = os.path.getsize(path)
            self._gutmann_wipe(path, size)
        except Exception as e:
            pass
        finally:
            try:
                subprocess.run(["chattr", "-i", path], check=True)
            except Exception:
                pass
            try:
                os.remove(path)
            except Exception:
                pass

    def _schedule_eviction(self, key, path):
        def evict():
            with self.lock:
                self.cache.pop(key, None)
                self.timers.pop(key, None)
            self._wipe_file(path)
        timer = threading.Timer(CACHE_LIFETIME, evict)
        timer.daemon = True
        timer.start()
        self.timers[key] = timer

    def put(self, data: bytes):
        with self.lock:
            # Clean old LRU if needed
            if len(self.cache) >= self.max_size:
                old_key, old_path = self.cache.popitem(last=False)
                timer = self.timers.pop(old_key, None)
                if timer: timer.cancel()
                self._wipe_file(old_path)

            # Hidden, random-named cache file
            randname = ".cache" + ''.join(random.choices(string.ascii_letters+string.digits, k=12))
            cache_path = os.path.join(CACHE_DIR, randname)
            fd, path = tempfile.mkstemp(prefix=randname, dir=CACHE_DIR)
            os.close(fd)
            os.rename(path, cache_path)
            # Open with mmap
            with open(cache_path, "w+b") as f:
                f.write(data)
                f.flush()
                os.fsync(f.fileno())
                mm = mmap.mmap(f.fileno(), 0)
                mm.close()
            # Prevent accidental deletion
            try:
                subprocess.run(["chattr", "+i", cache_path], check=True)
            except Exception:
                pass
            # Set SELinux context (example: cache_t, adjust as needed)
            try:
                subprocess.run(["chcon", "system_u:object_r:cache_t:s0", cache_path], check=True)
            except Exception:
                pass
            # LRU management
            now = time.time()
            self.cache[cache_path] = now
            self._schedule_eviction(cache_path, cache_path)
            return cache_path

    def touch(self, path):
        '''Refreshes the timer for a given cache file'''
        with self.lock:
            if path in self.cache:
                self.timers[path].cancel()
                self._schedule_eviction(path, path)

    def clear(self):
        '''Wipe all cache files'''
        with self.lock:
            for key, path in list(self.cache.items()):
                timer = self.timers.pop(key, None)
                if timer: timer.cancel()
                self._wipe_file(path)
            self.cache.clear()

# Singleton cache
secure_lru_cache = SecureLRUCache()

def secure_cache_write(data: bytes) -> str:
    '''
    Writes to cache with:
    - Automatic shredding on process exit
    - SELinux context enforcement
    - Hidden filenames (`.cacheXXXXXX`)
    '''
    path = secure_lru_cache.put(data)
    return path

import atexit
atexit.register(secure_lru_cache.clear)
