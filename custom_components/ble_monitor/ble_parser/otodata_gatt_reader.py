"""
One-time GATT reader for Otodata device serial numbers.

This script connects to Otodata devices and reads their serial numbers
from the Device Information Service (0x180A), then caches them for
use by the passive BLE advertisement parser.

Usage:
    python3 otodata_gatt_reader.py <MAC_ADDRESS>

Example:
    python3 otodata_gatt_reader.py EA:10:90:60:BC:01
"""

import asyncio
import json
import sys
from pathlib import Path
from bleak import BleakClient

# Device Information Service UUIDs
SERVICE_DEVICE_INFO = "0000180a-0000-1000-8000-00805f9b34fb"
CHAR_MANUFACTURER = "00002a29-0000-1000-8000-00805f9b34fb"
CHAR_MODEL_NUMBER = "00002a24-0000-1000-8000-00805f9b34fb"
CHAR_SERIAL_NUMBER = "00002a25-0000-1000-8000-00805f9b34fb"
CHAR_HARDWARE_REV = "00002a27-0000-1000-8000-00805f9b34fb"
CHAR_FIRMWARE_REV = "00002a26-0000-1000-8000-00805f9b34fb"
CHAR_SOFTWARE_REV = "00002a28-0000-1000-8000-00805f9b34fb"

# Cache file location (in the ble_parser directory)
CACHE_FILE = Path(__file__).parent / "otodata_device_cache.json"


async def read_otodata_info(mac_address: str) -> dict:
    """Connect to Otodata device and read device information."""
    
    print(f"Connecting to {mac_address}...")
    
    async with BleakClient(mac_address) as client:
        print(f"Connected: {client.is_connected}")
        
        device_info = {
            "mac": mac_address.replace(":", "").upper(),
        }
        
        # Read all available device information characteristics
        characteristics = {
            "manufacturer": CHAR_MANUFACTURER,
            "model": CHAR_MODEL_NUMBER,
            "serial_number": CHAR_SERIAL_NUMBER,
            "hardware_revision": CHAR_HARDWARE_REV,
            "firmware_revision": CHAR_FIRMWARE_REV,
            "software_revision": CHAR_SOFTWARE_REV,
        }
        
        for name, uuid in characteristics.items():
            try:
                value = await client.read_gatt_char(uuid)
                decoded = value.decode('utf-8').strip()
                device_info[name] = decoded
                print(f"{name}: {decoded}")
            except Exception as e:
                print(f"Could not read {name}: {e}")
        
        return device_info


def save_to_cache(device_info: dict):
    """Save device info to cache file."""
    
    # Load existing cache
    if CACHE_FILE.exists():
        with open(CACHE_FILE, 'r') as f:
            cache = json.load(f)
    else:
        cache = {}
    
    # Update with new device info
    mac = device_info["mac"]
    cache[mac] = device_info
    
    # Save back to file
    with open(CACHE_FILE, 'w') as f:
        json.dump(cache, f, indent=2)
    
    print(f"\nDevice info cached to: {CACHE_FILE}")


async def main():
    if len(sys.argv) != 2:
        print("Usage: python3 otodata_gatt_reader.py <MAC_ADDRESS>")
        print("Example: python3 otodata_gatt_reader.py EA:10:90:60:BC:01")
        sys.exit(1)
    
    mac_address = sys.argv[1]
    
    try:
        device_info = await read_otodata_info(mac_address)
        save_to_cache(device_info)
        print("\n✓ Device information successfully cached!")
        print("The BLE Monitor parser will now include this info in sensor attributes.")
    except Exception as e:
        print(f"\n✗ Error: {e}")
        sys.exit(1)


if __name__ == "__main__":
    asyncio.run(main())
