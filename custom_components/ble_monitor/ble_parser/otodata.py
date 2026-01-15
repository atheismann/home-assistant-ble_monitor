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
    Note: man_spec_data starts AFTER company ID is stripped by BLE parser
    - Bytes 0-6: Packet type identifier (7 chars, e.g., "OTOTELE")
    - Bytes 7+: Sensor data (format varies by packet type)
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
    
    # Parse packet type - man_spec_data starts AFTER company ID
    # So data[0:7] contains the 7-character packet type (OTO3281, OTOSTAT, OTOTELE)
    # Byte 7+: Sensor data
    try:
        packet_type = data[0:7].decode('ascii', errors='ignore').strip()
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
            # Data starts at byte 7 (after packet type)
            # Byte 9: Empty percentage (100 - value = tank level)
            # Example: byte 9 = 0x1d (29) → 100 - 29 = 71% full
            
            if msg_length < 10:
                _LOGGER.warning("OTOTELE packet too short: %d bytes", msg_length)
                return None
            
            empty_percent = data[9]
            tank_level = 100 - empty_percent
            
            result.update({
                "tank level": tank_level,
            })
            
            _LOGGER.info("OTOTELE: tank_level=%d%% (empty=%d%%)", tank_level, empty_percent)
            
        elif packet_type == "OTOSTAT":
            # Status packet - contains unknown sensor data
            # Data starts at byte 7 (after packet type)
            # Looking at packet: b'\x1b\xff\xb1\x03OTOSTAT\x01|\x05|\x05...'
            # After company ID strip: OTOSTAT\x01|\x05|\x05...
            # Bytes 8-9: 0x057c (1404), Bytes 10-11: 0x057c (1404)
            
            if msg_length < 12:
                _LOGGER.warning("OTOSTAT packet too short: %d bytes", msg_length)
                return None
            
            # Parse 16-bit values for monitoring (little-endian)
            val_8_9 = unpack("<H", data[8:10])[0]
            val_10_11 = unpack("<H", data[10:12])[0]
            
            _LOGGER.debug(
                "OTOSTAT values - bytes[8-9]=%d, bytes[10-11]=%d",
                val_8_9, val_10_11
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
