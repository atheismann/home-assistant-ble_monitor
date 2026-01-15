"""Parser for Otodata propane tank monitor BLE advertisements"""
import logging
import struct
import json
import asyncio
from pathlib import Path
from struct import unpack

from .helpers import to_mac, to_unformatted_mac

_LOGGER = logging.getLogger(__name__)

# Cache device attributes from OTO3281 packets to use in OTOTELE packets
_device_cache = {}

# Track which devices we've already tried to read GATT info from
_gatt_read_attempted = set()

# Load GATT-read device info from cache file (serial numbers, etc.)
_gatt_cache_file = Path(__file__).parent / "otodata_device_cache.json"
_gatt_cache = {}
try:
    if _gatt_cache_file.exists():
        with open(_gatt_cache_file, 'r') as f:
            _gatt_cache = json.load(f)
        _LOGGER.info("Loaded Otodata GATT cache with %d devices", len(_gatt_cache))
except Exception as e:
    _LOGGER.debug("Could not load Otodata GATT cache: %s", e)


async def _read_gatt_info(mac_address: str):
    """Read device info from GATT characteristics."""
    try:
        from bleak import BleakClient
    except ImportError:
        _LOGGER.warning("bleak not installed - cannot read GATT characteristics. Install with: pip install bleak")
        return None
    
    try:
        _LOGGER.info("Connecting to %s to read device info...", mac_address)
        
        async with BleakClient(mac_address, timeout=10.0) as client:
            device_info = {"mac": mac_address.replace(":", "").upper()}
            
            # Device Information Service characteristics
            chars = {
                "serial_number": "00002a25-0000-1000-8000-00805f9b34fb",
                "hardware_revision": "00002a27-0000-1000-8000-00805f9b34fb",
                "firmware_revision": "00002a26-0000-1000-8000-00805f9b34fb",
            }
            
            for name, uuid in chars.items():
                try:
                    value = await client.read_gatt_char(uuid)
                    device_info[name] = value.decode('utf-8').strip()
                except Exception:
                    pass  # Skip if characteristic not available
            
            if len(device_info) > 1:  # More than just MAC
                # Save to cache
                global _gatt_cache
                _gatt_cache[device_info["mac"]] = device_info
                
                with open(_gatt_cache_file, 'w') as f:
                    json.dump(_gatt_cache, f, indent=2)
                
                _LOGGER.info("Cached GATT info for %s: %s", mac_address, device_info)
                return device_info
    except Exception as e:
        _LOGGER.debug("Could not read GATT info from %s: %s", mac_address, e)
    
    return None


def _trigger_gatt_read(mac_address: str):
    """Trigger background GATT read if not already done."""
    mac_str = mac_address.replace(":", "").upper()
    
    # Skip if already attempted or already in cache
    if mac_str in _gatt_read_attempted or mac_str in _gatt_cache:
        return
    
    _gatt_read_attempted.add(mac_str)
    
    # Try to get the event loop and schedule the read
    try:
        loop = asyncio.get_event_loop()
        if loop.is_running():
            asyncio.create_task(_read_gatt_info(mac_address))
        else:
            # If no loop, schedule for later
            asyncio.run(_read_gatt_info(mac_address))
    except Exception as e:
        _LOGGER.debug("Could not schedule GATT read for %s: %s", mac_address, e)


def parse_otodata(self, data: bytes, mac: bytes):
    """Otodata propane tank monitor parser
    
    The device sends multiple packet types:
    - OTO3281: Device identifier/info packet
    - OTOSTAT: Status packet  
    - OTOTELE: Telemetry packet (contains sensor data like tank level)
    
    Packet structure (man_spec_data format):
    - Byte 0: Data length
    - Byte 1: Type flag (0xFF)
    - Bytes 2-3: Company ID (0x03B1 little-endian: \xb1\x03)
    - Bytes 4-10: Packet type identifier (7 chars, e.g., "OTOTELE")
    - Bytes 11+: Sensor data (format varies by packet type)
    """
    msg_length = len(data)
    firmware = "Otodata"
    result = {"firmware": firmware}
    
    _LOGGER.info("Otodata parse_otodata called - length=%d, data=%s", msg_length, data.hex())
    
    # Minimum packet size validation
    if msg_length < 18:
        if self.report_unknown == "Otodata":
            _LOGGER.info(
                "BLE ADV from UNKNOWN Otodata DEVICE: MAC: %s, ADV: %s",
                to_mac(mac),
                data.hex()
            )
        return None
    
    # Parse packet type from man_spec_data
    # Byte 0: length, Byte 1: type flag, Bytes 2-3: company ID
    # Bytes 4-10 contain the 7-character packet type (OTO3281, OTOSTAT, OTOTELE)
    # Bytes 11+: Sensor data
    try:
        packet_type = data[4:11].decode('ascii', errors='ignore').strip()
        _LOGGER.info("Otodata packet_type decoded: '%s'", packet_type)
        if packet_type.startswith('OTO'):
            device_type = f"Propane Tank Monitor"
        else:
            device_type = "Propane Tank Monitor"
        
        _LOGGER.debug("Otodata packet type: '%s', length: %d bytes", packet_type, msg_length)
    except Exception:
        device_type = "Propane Tank Monitor"
        packet_type = "UNKNOWN"
    
    try:
        # Parse different packet types
        # Three packet types observed:
        # - OTO3281 or OTO32##: Device identifier/info
        # - OTOSTAT: Status information  
        # - OTOTELE: Telemetry data (primary sensor readings)
        
        _LOGGER.debug("Processing %s packet (length: %d)", packet_type, msg_length)
        _LOGGER.info("About to check packet_type == 'OTOTELE': %s", packet_type == "OTOTELE")
        
        # Parse based on packet type
        if packet_type == "OTOTELE":
            _LOGGER.info("ENTERED OTOTELE block!")
            # Telemetry packet - contains tank level
            # Packet type ends at byte 10, data starts at byte 11
            # Byte 14: Empty percentage (100 - value = tank level)
            # Example from logs: byte 14 = 0x1c (28) → 100 - 28 = 72% full
            
            if msg_length < 15:
                _LOGGER.warning("OTOTELE packet too short: %d bytes", msg_length)
                return None
            
            empty_percent = data[14]
            tank_level = 100 - empty_percent
            battery_depleted = data[13]
            battery_level = 100 - battery_depleted  # Inverted like tank level
            _LOGGER.info("OTOTELE: Extracted tank_level=%d%% (empty=%d%%), battery=%d%% (depleted=%d%%), byte13=0x%02x, byte14=0x%02x", 
                        tank_level, empty_percent, battery_level, battery_depleted, data[13], data[14])
            
            # Extract additional telemetry data
            # Byte 11: Unknown flag (0x02)
            # Byte 12: Unknown value (0x00)
            # Byte 13: Battery depleted percentage (100 - value = battery level)
            # Byte 14: Tank empty percentage (100 - value = tank level)
            # Bytes 15-16: Unknown 16-bit value
            # Bytes 17-20: Could be serial or device ID
            
            result.update({
                "tank level": tank_level,
                "battery": battery_level,
            })
            _LOGGER.info("OTOTELE: result dict updated with tank_level")
            
            # Add cached device attributes if available
            mac_str = to_unformatted_mac(mac)
            _LOGGER.info("OTOTELE: mac_str=%s, checking cache", mac_str)
            if mac_str in _device_cache:
                _LOGGER.info("OTOTELE: Found device in cache: %s", _device_cache[mac_str])
                result.update(_device_cache[mac_str])
            else:
                _LOGGER.info("OTOTELE: Device NOT in cache")
            
            # Add GATT-read attributes if available (serial number, etc.)
            if mac_str in _gatt_cache:
                _LOGGER.info("OTOTELE: Found GATT info in cache")
                gatt_info = _gatt_cache[mac_str]
                if "serial_number" in gatt_info:
                    result["serial_number"] = gatt_info["serial_number"]
                if "hardware_revision" in gatt_info:
                    result["hardware_revision"] = gatt_info["hardware_revision"]
                if "firmware_revision" in gatt_info:
                    result["firmware_revision"] = gatt_info["firmware_revision"]
            else:
                _LOGGER.info("OTOTELE: No GATT info in cache")
            
            _LOGGER.info("OTOTELE: Final result dict before return: %s", result)
            
        elif packet_type == "OTOSTAT":
            # Status packet - contains unknown device status values
            # Byte 12: Incrementing value (purpose unknown)
            # Byte 13: Constant 0x06 (purpose unknown)
            # Until we identify what these represent, we skip this packet type
            
            _LOGGER.debug("OTOSTAT packet received - skipping (unknown data format)")
            
            # Skip OTOSTAT - unknown data format
            return None
            
        elif packet_type.startswith("OTO3") or packet_type.startswith("OTO32"):
            # Device info packet - contains product info and serial number
            # Example: 1affb1034f544f333238319060bc011018210384060304b0130205
            # Bytes 4-10: "OTO3281" - packet type identifier
            # Bytes 20-21: Model number (e.g., 0x13B0 = 5040 for TM5040)
            
            if msg_length < 22:
                _LOGGER.warning("OTO3xxx packet too short: %d bytes", msg_length)
                return None
            
            # Extract model number from bytes 20-21 (little-endian)
            # Full model format: MT4AD-TM5040 (5040 from bytes 20-21)
            if msg_length >= 22:
                model_number = unpack("<H", data[20:22])[0]
                product_name = f"MT4AD-TM{model_number}"
            else:
                product_name = packet_type[3:] if len(packet_type) > 3 else "Unknown"
            
            # Cache device attributes to add to future OTOTELE packets
            mac_str = to_unformatted_mac(mac)
            _device_cache[mac_str] = {
                "product": f"Otodata {product_name}",
                "model": product_name,
            }
            
            # Trigger automatic GATT read on first discovery
            mac_formatted = to_mac(mac)
            _trigger_gatt_read(mac_formatted)
            
            _LOGGER.info("Otodata device detected - Model: %s, MAC: %s", 
                        product_name, mac_formatted)
            
            # Don't create sensor entities for device info packets
            return None
            
        else:
            _LOGGER.warning("Unknown Otodata packet type: %s", packet_type)
            return None
        
    except (IndexError, struct.error) as e:
        _LOGGER.debug("Failed to parse Otodata data: %s", e)
        return None

    result.update({
        "mac": to_unformatted_mac(mac),
        "type": device_type,
        "packet": "no packet id",
        "data": True
    })
    
    _LOGGER.info("Returning result dict: %s", result)
    return result
