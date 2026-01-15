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
        
        # Parse based on packet type
        if packet_type == "OTOTELE":
            # Telemetry packet - contains tank level
            # Packet type ends at byte 10, data starts at byte 11
            # Byte 13: Empty percentage (100 - value = tank level)
            # Example from logs: byte 13 = 0x1d (29) → 100 - 29 = 71% full
            
            if msg_length < 14:
                _LOGGER.warning("OTOTELE packet too short: %d bytes", msg_length)
                return None
            
            empty_percent = data[13]
            tank_level = 100 - empty_percent
            
            result.update({
                "tank level": tank_level,
            })
            
            _LOGGER.info("OTOTELE: tank_level=%d%% (empty=%d%%)", tank_level, empty_percent)
            
        elif packet_type == "OTOSTAT":
            # Status packet - contains unknown sensor data
            # Packet type ends at byte 10, data starts at byte 11
            # Looking at packet: b'\x1b\xff\xb1\x03OTOSTAT\x01|\x05|\x05...'
            # After header: bytes 11+ contain data
            # Bytes 12-13: 0x057c (1404), Bytes 14-15: 0x057c (1404)
            
            if msg_length < 16:
                _LOGGER.warning("OTOSTAT packet too short: %d bytes", msg_length)
                return None
            
            # Parse 16-bit values for monitoring (little-endian)
            val_12_13 = unpack("<H", data[12:14])[0]
            val_14_15 = unpack("<H", data[14:16])[0]
            
            _LOGGER.debug(
                "OTOSTAT values - bytes[12-13]=%d, bytes[14-15]=%d",
                val_12_13, val_14_15
            )
            
            # Skip OTOSTAT until we identify what the values represent
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
