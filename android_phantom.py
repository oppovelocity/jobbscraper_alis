import os
import subprocess
import time
import random
import math

# --- Device Behavior Profiles ---
# Profiles containing screen dimensions and behavioral characteristics for different devices.
# These can be expanded with more specific quirks (e.g., touch offset, pressure ranges).
DEVICE_PROFILES = {
    "samsung_galaxy": {
        "screen_width": 1080,
        "screen_height": 2340,
        "tap_delay_mu": 0.09,  # Mean delay after a tap (seconds)
        "tap_delay_sigma": 0.04, # Standard deviation of delay
        "pressure_range": (50, 150), # Simulated pressure value range
    },
    "pixel_pro": {
        "screen_width": 1440,
        "screen_height": 3120,
        "tap_delay_mu": 0.07,
        "tap_delay_sigma": 0.025,
        "pressure_range": (40, 120),
    },
    "default": {
        "screen_width": 1080,
        "screen_height": 1920,
        "tap_delay_mu": 0.08,
        "tap_delay_sigma": 0.03,
        "pressure_range": (40, 150),
    }
}

class HumanTouch:
    """
    Simulates human-like touch input on an Android device via Termux.
    """
    def __init__(self, device_profile: dict):
        """
        Initializes the simulator with a specific device profile.

        Args:
            device_profile: A dictionary containing screen dimensions and behaviors.
        """
        self.profile = device_profile
        self.width = self.profile["screen_width"]
        self.height = self.profile["screen_height"]
        # Ensure we are in a Termux environment
        if "com.termux" not in os.environ.get("PREFIX", ""):
            print("[WARNING] Not running in Termux. The 'input' command may fail.")

    def _execute_command(self, command: str):
        """Wrapper to execute a shell command via subprocess."""
        try:
            # Using 'input' command which is available in Termux environments
            full_command = f"input {command}"
            subprocess.run(full_command, shell=True, check=True, timeout=5)
        except (subprocess.CalledProcessError, subprocess.TimeoutExpired) as e:
            print(f"[ERROR] Failed to execute touch command: {e}")
            print("Please ensure you are running this within a Termux session.")
        except FileNotFoundError:
            print("[ERROR] 'input' command not found. This script requires a Termux environment.")

    def _apply_jitter(self, x: int, y: int) -> (int, int):
        """
        Applies a random micro-jitter to coordinates to avoid perfect lines.

        Returns:
            A tuple (x, y) with jitter applied, clamped to screen bounds.
        """
        jitter_x = x + random.randint(-3, 3)
        jitter_y = y + random.randint(-3, 3)
        # Clamp coordinates to screen dimensions to prevent out-of-bounds errors
        clamped_x = max(0, min(self.width - 1, jitter_x))
        clamped_y = max(0, min(self.height - 1, jitter_y))
        return clamped_x, clamped_y

    def tap(self, x: int, y: int):
        """
        Performs a human-like tap with randomized delays and jitter.

        Args:
            x: The x-coordinate of the tap.
            y: The y-coordinate of the tap.
        """
        jx, jy = self._apply_jitter(x, y)
        print(f"Tapping at ({jx}, {jy}) with simulated pressure.")
        
        # NOTE: The standard 'input tap' command does not support pressure.
        # This simulation is conceptual. For true pressure, a rooted device
        # and direct 'sendevent' commands would be necessary.
        _ = random.randint(*self.profile["pressure_range"])

        self._execute_command(f"tap {jx} {jy}")

        # Gaussian-distributed delay to mimic human reaction time variance
        delay = abs(random.gauss(
            self.profile["tap_delay_mu"],
            self.profile["tap_delay_sigma"]
        ))
        time.sleep(max(0.05, delay)) # Ensure a minimum delay

    def swipe(self, start_x: int, start_y: int, end_x: int, end_y: int):
        """
        Performs a human-like swipe with variable velocity and jitter.

        Args:
            start_x, start_y: The starting coordinates of the swipe.
            end_x, end_y: The ending coordinates of the swipe.
        """
        sx, sy = self._apply_jitter(start_x, start_y)
        ex, ey = self._apply_jitter(end_x, end_y)

        # Calculate duration based on a randomized velocity
        distance = math.sqrt((ex - sx)**2 + (ey - sy)**2)
        velocity = random.uniform(1200, 1800)  # px/s variance
        duration_ms = int((distance / velocity) * 1000)
        # Ensure duration is at least a small amount of time
        duration_ms = max(50, duration_ms)

        print(f"Swiping from ({sx}, {sy}) to ({ex}, {ey}) over {duration_ms}ms (Velocity: {velocity:.0f} px/s)")
        self._execute_command(f"swipe {sx} {sy} {ex} {ey} {duration_ms}")
        time.sleep(random.uniform(0.1, 0.3))


# --- Factory functions for specific device simulations ---

def simulate_samsung_galaxy() -> HumanTouch:
    """Instantiates the simulator with a Samsung Galaxy profile."""
    print("[INFO] Simulating Samsung Galaxy device behavior.")
    return HumanTouch(device_profile=DEVICE_PROFILES["samsung_galaxy"])

def simulate_pixel_pro() -> HumanTouch:
    """Instantiates the simulator with a Pixel Pro profile."""
    print("[INFO] Simulating Pixel Pro device behavior.")
    return HumanTouch(device_profile=DEVICE_PROFILES["pixel_pro"])

def run_calibration():
    """
    An interactive calibration mode to help users create a new device profile.
    """
    print("--- Android Phantom Calibration Mode ---")
    print("This will help you create a new device profile for this script.")
    
    # 1. Get screen size
    print("\n[Step 1] Please run this command in another Termux session: wm size")
    size_str = input("Paste the output here (e.g., 'Physical size: 1080x2340'): ")
    try:
        dims = size_str.split(':')[1].strip().split('x')
        width, height = int(dims[0]), int(dims[1])
        print(f"[SUCCESS] Detected screen size: {width}x{height}")
    except Exception:
        print("[ERROR] Could not parse size. Using default 1080x1920.")
        width, height = 1080, 1920

    # 2. Test tap
    print("\n[Step 2] Let's test a tap at the center of your screen.")
    test_phantom = HumanTouch({"screen_width": width, "screen_height": height, **DEVICE_PROFILES["default"]})
    test_phantom.tap(width // 2, height // 2)
    input("Did you see a tap event on your screen? Press Enter to continue.")
    
    # 3. Output profile
    profile_name = input("\n[Step 3] Enter a name for your new device profile (e.g., 'oneplus_10'): ").strip()
    profile_code = f"""
    "{profile_name}": {{
        "screen_width": {width},
        "screen_height": {height},
        "tap_delay_mu": 0.08,
        "tap_delay_sigma": 0.03,
        "pressure_range": (40, 150),
    }},"""
    print("\n[SUCCESS] Calibration complete! Copy the code below and add it to the 'DEVICE_PROFILES' dictionary in the script:\n")
    print("="*40)
    print(profile_code)
    print("="*40)


if __name__ == "__main__":
    print("--- Android Phantom Demo ---")
    
    # To run calibration:
    # run_calibration()
    # exit()

    # To run a device simulation:
    # phantom = simulate_samsung_galaxy()
    phantom = simulate_pixel_pro()

    print("\n[DEMO] Performing a series of human-like actions...")
    time.sleep(2)

    # Simulate opening an app from the home screen
    print("\n1. Tapping an icon on the home screen.")
    phantom.tap(phantom.width // 4, phantom.height // 3)

    # Simulate scrolling through a list
    print("\n2. Scrolling down a feed.")
    start_y = int(phantom.height * 0.8)
    end_y = int(phantom.height * 0.2)
    phantom.swipe(phantom.width // 2, start_y, phantom.width // 2, end_y)

    # Tapping a button in the app
    print("\n3. Tapping a button.")
    phantom.tap(int(phantom.width * 0.75), int(phantom.height * 0.5))

    print("\n[DEMO] Simulation finished.")
