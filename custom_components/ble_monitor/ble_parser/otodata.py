"""Parser for Otodata propane tank monitor BLE advertisements"""
import logging
import struct
from struct import unpack

from .helpers import to_mac, to_unformatted_mac

_LOGGER = logging.getLogger(__name__)


def parse_otodata(self, data: bytes, mac: bytes):
    """Otodata propane tank monitor parser
    
    The device sends multiple packet types:
    - OTO3281: Device identifier/info packet
    - OTOSTAT: Status packet  
    - OTOTELE: Telemetry packet (contains sensor data like tank level)
    
    Packet structure (variable length):
    - Bytes 0-1: Company ID (0x03B1 in little-endian)
    - Bytes 2-9: Packet type identifier (e.g., "OTOTELE")
    - Bytes 9+: Sensor data (format varies by packet type)
    """
    msg_length = len(data)
    firmware = "Otodata"
    result = {"firmware": firmware}
    
    # Minimum packet size validation
    if msg_length < 18:
        if self.report_unknown == "Otodata":
            _LOGGER.info(
                "BLE ADV from UNKNOWN Otodata DEVICE: MAC: %s, ADV: %s",
                to_mac(mac),
                data.hex()
            )
        return None
    
    # Parse packet type from bytes 4-10 (after company ID at bytes 2-3)
    # Packet structure:
    # Byte 0-1: Length + AD Type (BLE header, stripped by parser)
    # Byte 0-1: Company ID 0x03B1 (little-endian: \xb1\x03)
    # Byte 2-8: 7-character packet type (OTOTELE, OTOSTAT, OTO3281, etc.)
    # Byte 9+: Sensor data
    try:
        packet_type = data[2:9].decode('ascii', errors='ignore').strip()
        if packet_type.startswith('OTO'):
            device_type = f"Propane Tank Monitor"
        else:
            device_type = "Propane Tank Monitor"
        
        _LOGGER.info("Otodata packet type: '%s', length: %d bytes", packet_type, msg_length)
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
        
        # Parse based on packet type
        if packet_type == "OTOTELE":
            # Telemetry packet - contains tank level
            # Data starts at byte 9 (after 7-char packet type)
            # Byte 11: Empty percentage (100 - value = tank level)
            # Example: byte 11 = 0x1c (28) → 100 - 28 = 72% full
            
            if msg_length < 12:
                _LOGGER.warning("OTOTELE packet too short: %d bytes", msg_length)
                return None
            
            empty_percent = data[11]
            tank_level = 100 - empty_percent
            
            result.update({
                "tank level": tank_level,
            })
            
            _LOGGER.debug("OTOTELE: tank_level=%d%% (empty=%d%%, byte11=0x%02X)", tank_level, empty_percent, data[11])
            
        elif packet_type == "OTOSTAT":
            # Status packet - contains unknown sensor data
            # Data starts at byte 9
            # Bytes 8-9 and 10-11 change between readings but don't appear to be temperature
            # Earlier: 0x0386 (902) → Now: 0x0431 (1073) → Latest: 0x044C (1100)
            # Could be: voltage (mV), signal strength, status codes, or other metrics
            
            if msg_length < 13:
                _LOGGER.warning("OTOSTAT packet too short: %d bytes", msg_length)
                return None
            
            # Parse 16-bit values for monitoring (data starts at byte 9)
            val_9_10 = unpack("<H", data[9:11])[0]
            val_11_12 = unpack("<H", data[11:13])[0]
            
            _LOGGER.info(
                "OTOSTAT values - bytes[9-10]=%d, bytes[11-12]=%d, full_hex=%s",
                val_9_10, val_11_12, data.hex()
            )
            
            # Skip OTOSTAT until we identify what the values represent
            # User should monitor logs and tell us what correlates with actual readings
            _LOGGER.debug("Skipping OTOSTAT packet - unknown data format")
            return None
            
        elif packet_type.startswith("OTO3") or packet_type.startswith("OTO32"):
            # Device info packet - contains device ID, maybe firmware version
            # Packet: \x1a\xff\xb1\x03OTO3281\x90`\xbc\x01\x10\x18!\x03\x84\x06\x03\x04\xb0\x13\x02\x05
            
            if msg_length < 15:
                _LOGGER.warning("OTO3xxx packet too short: %d bytes", msg_length)
                return None
            
            # Bytes 9-12 appear to be MAC address (last 4 bytes: \x90`\xbc\x01)
            # Remaining bytes might contain firmware version, hardware info, etc.
            
            # Log for analysis
            _LOGGER.info("OTO3xxx (device info) packet: %s", data.hex())
            for i in range(9, min(msg_length, 20)):
                _LOGGER.info("  Byte %d: 0x%02X = %d", i, data[i], data[i])
            
            # Skip device info packets for now - they don't contain sensor readings
            _LOGGER.debug("Skipping device info packet: %s", packet_type)
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
    
    return result
